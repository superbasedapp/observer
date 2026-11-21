package cost

import "testing"

func TestCacheReadShare(t *testing.T) {
	cases := []struct {
		name string
		b    TokenBundle
		want float64
		ok   bool
	}{
		{"empty is unknown", TokenBundle{}, 0, false},
		{"output only is unknown", TokenBundle{Output: 100}, 0, false},
		{"no cache", TokenBundle{Input: 100}, 0, true},
		{"all cache", TokenBundle{CacheRead: 100}, 1, true},
		{"mixed", TokenBundle{Input: 10, CacheRead: 70, CacheCreation: 20}, 0.7, true},
		{"1h writes are a subset, not added twice", TokenBundle{Input: 10, CacheRead: 70, CacheCreation: 20, CacheCreation1h: 20}, 0.7, true},
	}
	for _, c := range cases {
		got, ok := CacheReadShare(c.b)
		if ok != c.ok || got != c.want {
			t.Errorf("%s: got (%v, %v) want (%v, %v)", c.name, got, ok, c.want, c.ok)
		}
	}
}
