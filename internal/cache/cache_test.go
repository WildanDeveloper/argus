package cache

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func TestMemoryTTLExpiry(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	c := NewMemory(10).WithClock(func() time.Time { return now })

	c.Put("k", "v", time.Minute)
	if _, ok := c.Get("k"); !ok {
		t.Fatal("expected a hit before expiry")
	}
	now = now.Add(90 * time.Second)
	if _, ok := c.Get("k"); ok {
		t.Error("expected a miss after the TTL elapsed")
	}
}

func TestMemoryNonPositiveTTLIsNotStored(t *testing.T) {
	c := NewMemory(10)
	c.Put("k", "v", 0)
	c.Put("k2", "v", -time.Second)
	if c.Len() != 0 {
		t.Errorf("a non-positive TTL must not store anything, len=%d", c.Len())
	}
}

func TestMemoryLRUEviction(t *testing.T) {
	c := NewMemory(3)
	for _, k := range []string{"a", "b", "c"} {
		c.Put(k, k, time.Hour)
	}
	// Touch "a" so "b" becomes least-recently-used.
	if _, ok := c.Get("a"); !ok {
		t.Fatal("expected a hit")
	}
	c.Put("d", "d", time.Hour)

	if c.Len() != 3 {
		t.Errorf("len = %d, want 3", c.Len())
	}
	if _, ok := c.Get("b"); ok {
		t.Error("the least recently used key should have been evicted")
	}
	for _, k := range []string{"a", "c", "d"} {
		if _, ok := c.Get(k); !ok {
			t.Errorf("key %q should have survived", k)
		}
	}
	_, _, evictions := c.Stats()
	if evictions != 1 {
		t.Errorf("evictions = %d, want 1", evictions)
	}
}

func TestMemoryOverwriteKeepsOneEntry(t *testing.T) {
	c := NewMemory(10)
	c.Put("k", "v1", time.Hour)
	c.Put("k", "v2", time.Hour)
	if c.Len() != 1 {
		t.Errorf("len = %d, want 1", c.Len())
	}
	v, _ := c.Get("k")
	if v != "v2" {
		t.Errorf("value = %v, want v2", v)
	}
}

func TestMemorySweepReclaimsExpired(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	c := NewMemory(10).WithClock(func() time.Time { return now })
	c.Put("short", 1, time.Minute)
	c.Put("long", 2, time.Hour)
	now = now.Add(2 * time.Minute)

	if n := c.Sweep(); n != 1 {
		t.Errorf("sweep removed %d, want 1", n)
	}
	if _, ok := c.Get("long"); !ok {
		t.Error("unexpired entry should survive the sweep")
	}
}

func TestMemoryClear(t *testing.T) {
	c := NewMemory(10)
	c.Put("a", 1, time.Hour)
	c.Put("b", 2, time.Hour)
	c.Clear()
	if c.Len() != 0 {
		t.Errorf("len after Clear = %d", c.Len())
	}
	if _, ok := c.Get("a"); ok {
		t.Error("Clear must empty the cache")
	}
}

func TestMemoryConcurrentAccess(t *testing.T) {
	c := NewMemory(64)
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				k := string(rune('a' + (i+j)%26))
				c.Put(k, j, time.Hour)
				c.Get(k)
				if j%7 == 0 {
					c.Delete(k)
				}
				c.Stats()
			}
		}(i)
	}
	wg.Wait()
}

func TestSingleflightCoalesces(t *testing.T) {
	// 32 concurrent callers must produce exactly one upstream call.
	//
	// The barrier below matters: if the leader finished while other goroutines
	// were still waiting to be scheduled, a late caller would find the map
	// empty, become a second leader, and make this assertion flaky. Holding the
	// leader inside fn until every goroutine has passed the barrier removes that
	// window deterministically.
	sf := NewSingleflight()
	var mu sync.Mutex
	calls := 0
	inFn := make(chan struct{}, 1)

	const n = 32
	var ready sync.WaitGroup
	ready.Add(n)
	allReady := make(chan struct{})
	go func() {
		ready.Wait()
		close(allReady)
	}()

	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ready.Done()
			<-start
			v, err, _ := sf.Do("key", func() (any, error) {
				mu.Lock()
				calls++
				mu.Unlock()
				select {
				case inFn <- struct{}{}:
				default:
				}
				// Hold the slot until every goroutine has been released, so no
				// caller can miss the in-flight entry.
				<-allReady
				return "value", nil
			})
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if v != "value" {
				t.Errorf("value = %v, want value", v)
			}
		}()
	}
	close(start)
	<-inFn
	wg.Wait()

	mu.Lock()
	got := calls
	mu.Unlock()
	if got != 1 {
		t.Errorf("upstream called %d times, want exactly 1", got)
	}
	if sf.InFlight() != 0 {
		t.Errorf("InFlight = %d after completion, want 0", sf.InFlight())
	}
}

func TestSingleflightPropagatesError(t *testing.T) {
	sf := NewSingleflight()
	want := errors.New("boom")
	_, err, leader := sf.Do("k", func() (any, error) { return nil, want })
	if err != want {
		t.Errorf("err = %v, want %v", err, want)
	}
	if !leader {
		t.Error("first caller should be reported as the leader")
	}
	// A failed key must not be cached: the next caller must retry.
	_, _, leader2 := sf.Do("k", func() (any, error) { return "ok", nil })
	if !leader2 {
		t.Error("after a failure the next caller should lead a fresh call")
	}
}

func TestSingleflightDistinctKeysRunConcurrently(t *testing.T) {
	sf := NewSingleflight()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			k := string(rune('a' + i))
			if _, err, _ := sf.Do(k, func() (any, error) { return k, nil }); err != nil {
				t.Errorf("err: %v", err)
			}
		}(i)
	}
	wg.Wait()
	if sf.InFlight() != 0 {
		t.Errorf("InFlight = %d, want 0", sf.InFlight())
	}
}
