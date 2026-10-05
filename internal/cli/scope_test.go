package cli

import "testing"

func TestNormalizeCIDRs(t *testing.T) {
	// A bare address is the obvious thing for an operator to write into a prefix
	// field, and it must not silently scope nothing.
	got := normalizeCIDRs([]string{"8.8.8.8", "2001:db8::1"})
	want := []string{"8.8.8.8/32", "2001:db8::1/128"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got %v, want %v", got, want)
		}
	}
}

func TestNormalizeCIDRsMasksHostBits(t *testing.T) {
	// 8.8.8.8/24 is stored as 8.8.8.0/24. Storing the host bits would make a scope
	// file read as narrower than what the guard actually enforces.
	got := normalizeCIDRs([]string{"8.8.8.8/24", "10.1.2.3/8"})
	want := []string{"8.8.8.0/24", "10.0.0.0/8"}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("normalizeCIDRs = %v, want %v", got, want)
		}
	}
}

func TestNormalizeCIDRsDropsUnusableInput(t *testing.T) {
	// A scope file that fails validation later, away from the command that caused
	// it, is a worse outcome than an explicit omission here.
	got := normalizeCIDRs([]string{"", "  ", "not-an-address", "8.8.8.8/99", "example.com"})
	if len(got) != 0 {
		t.Errorf("normalizeCIDRs kept unusable entries: %v", got)
	}
}

func TestNormalizeCIDRsDeduplicates(t *testing.T) {
	got := normalizeCIDRs([]string{"8.8.8.0/24", "8.8.8.0/24", "8.8.8.8/24"})
	if len(got) != 2 {
		t.Errorf("normalizeCIDRs = %v, want the two distinct prefixes", got)
	}
}

func TestNormalizeCIDRsEmptyInput(t *testing.T) {
	if got := normalizeCIDRs(nil); len(got) != 0 {
		t.Errorf("normalizeCIDRs(nil) = %v, want empty", got)
	}
}
