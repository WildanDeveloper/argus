// Package cache provides the layered cache behind the egress broker: an in-memory
// L1 and an on-disk L2.
package cache

import (
	"container/list"
	"sync"
	"time"
)

// Store is the cache interface used by the egress broker.
type Store interface {
	Get(key string) (any, bool)
	Put(key string, val any, ttl time.Duration)
	Delete(key string)
	Len() int
	Clear()
}

type entry struct {
	key       string
	val       any
	expiresAt time.Time
}

// Memory is an LRU cache with per-entry TTL and a request coalescing helper.
//
// It is safe for concurrent use. Expired entries are treated as absent and are
// evicted lazily on access, which avoids a background sweeper goroutine: a
// sweeper would need lifecycle management and would keep the process awake.
type Memory struct {
	mu       sync.Mutex
	maxItems int
	ll       *list.List
	items    map[string]*list.Element
	now      func() time.Time

	hits, misses, evictions int64
}

// DefaultMaxItems bounds memory. Each cached entry can be a multi-megabyte
// response body, so the count limit is what actually protects the process.
const DefaultMaxItems = 4096

// NewMemory builds an in-memory cache with an LRU bound.
func NewMemory(maxItems int) *Memory {
	if maxItems <= 0 {
		maxItems = DefaultMaxItems
	}
	return &Memory{
		maxItems: maxItems,
		ll:       list.New(),
		items:    make(map[string]*list.Element, maxItems),
		now:      time.Now,
	}
}

// WithClock overrides the clock for tests.
func (m *Memory) WithClock(now func() time.Time) *Memory {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.now = now
	return m
}

// Get returns the cached value for key.
func (m *Memory) Get(key string) (any, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	el, ok := m.items[key]
	if !ok {
		m.misses++
		return nil, false
	}
	e := el.Value.(*entry)
	if m.now().After(e.expiresAt) {
		m.ll.Remove(el)
		delete(m.items, key)
		m.misses++
		return nil, false
	}
	m.ll.MoveToFront(el)
	m.hits++
	return e.val, true
}

// Put stores a value with a TTL. A non-positive TTL stores nothing rather than
// storing something that can never expire.
func (m *Memory) Put(key string, val any, ttl time.Duration) {
	if ttl <= 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if el, ok := m.items[key]; ok {
		e := el.Value.(*entry)
		e.val, e.expiresAt = val, m.now().Add(ttl)
		m.ll.MoveToFront(el)
		return
	}
	el := m.ll.PushFront(&entry{key: key, val: val, expiresAt: m.now().Add(ttl)})
	m.items[key] = el
	for m.ll.Len() > m.maxItems {
		back := m.ll.Back()
		if back == nil {
			break
		}
		m.ll.Remove(back)
		delete(m.items, back.Value.(*entry).key)
		m.evictions++
	}
}

// Delete removes a key.
func (m *Memory) Delete(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if el, ok := m.items[key]; ok {
		m.ll.Remove(el)
		delete(m.items, key)
	}
}

// Len returns the number of stored entries, including not-yet-reaped expired ones.
func (m *Memory) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ll.Len()
}

// Clear empties the cache.
func (m *Memory) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ll.Init()
	m.items = make(map[string]*list.Element, m.maxItems)
}

// Stats reports hit and miss counters for the metrics endpoint.
func (m *Memory) Stats() (hits, misses, evictions int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.hits, m.misses, m.evictions
}

// Sweep removes expired entries eagerly. The broker calls this occasionally so
// memory of stale entries is reclaimed without waiting for LRU pressure.
func (m *Memory) Sweep() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	removed := 0
	for el := m.ll.Back(); el != nil; {
		prev := el.Prev()
		e := el.Value.(*entry)
		if now.After(e.expiresAt) {
			m.ll.Remove(el)
			delete(m.items, e.key)
			removed++
		}
		el = prev
	}
	return removed
}

// Singleflight collapses concurrent identical calls into one upstream request.
//
// Without it, 32 workers that all need the same subdomain would each query the
// same API in the same instant: the provider sees a burst, and a paid quota is
// spent N times for one answer.
type Singleflight struct {
	mu    sync.Mutex
	calls map[string]*sfCall
}

type sfCall struct {
	done chan struct{}
	val  any
	err  error
}

// NewSingleflight builds a coalescer.
func NewSingleflight() *Singleflight {
	return &Singleflight{calls: map[string]*sfCall{}}
}

// Do runs fn for key, or joins an in-flight call for the same key.
func (s *Singleflight) Do(key string, fn func() (any, error)) (any, error, bool) {
	s.mu.Lock()
	if c, ok := s.calls[key]; ok {
		s.mu.Unlock()
		<-c.done
		return c.val, c.err, false
	}
	c := &sfCall{done: make(chan struct{})}
	s.calls[key] = c
	s.mu.Unlock()

	c.val, c.err = fn()

	s.mu.Lock()
	delete(s.calls, key)
	s.mu.Unlock()
	close(c.done)

	return c.val, c.err, true
}

// InFlight reports how many calls are currently coalescing.
func (s *Singleflight) InFlight() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.calls)
}
