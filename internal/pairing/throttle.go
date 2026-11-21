package pairing

import (
	"sync"
	"time"
)

// Redemption throttling (plan 06 section 19.3: "redemption attempts throttled
// per source and per org"). A code carries at least 128 bits, so guessing
// one is not the threat; the throttle bounds how fast one source, or the
// whole internet against one org, can spend the server's work and fill its
// logs. Every ATTEMPT is charged, before the code is looked up, so a wrong
// guess costs the same as a right one.
//
// The limits are token buckets keyed by a scope ("source" or "org") and a
// key (the client address, the org id). State lives in memory, in one
// Throttle per server process; a server with several replicas admits up to
// the limit per replica (docs/security.md PAIR-3).

// Scope is what a bucket is keyed by.
type Scope string

// The scopes.
const (
	// ScopeSource keys a bucket by the redeeming client's address.
	ScopeSource Scope = "source"
	// ScopeOrg keys a bucket by the organization the code names.
	ScopeOrg Scope = "org"
)

// Limit is one scope's bucket: Burst attempts at once, refilled at Burst per
// Per.
type Limit struct {
	Scope Scope
	Burst int
	Per   time.Duration
}

// DefaultLimits are the redemption limits, charged in order: a source over
// its own limit does not drain its org's.
func DefaultLimits() []Limit {
	return []Limit{
		{Scope: ScopeSource, Burst: 5, Per: time.Minute},
		{Scope: ScopeOrg, Burst: 60, Per: time.Minute},
	}
}

// maxThrottleKeys bounds each scope's table; when full, idle (fully
// refilled) buckets are dropped first, and failing that the table is reset
// (a bounded leniency, never unbounded memory).
const maxThrottleKeys = 10000

// Throttle is the in-memory redemption limiter. The zero value is not
// usable; build one with NewThrottle.
type Throttle struct {
	mu      sync.Mutex
	limits  []Limit
	now     func() time.Time
	buckets map[Scope]map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

// NewThrottle builds a Throttle over limits (DefaultLimits when nil) and a
// clock (time.Now when nil).
func NewThrottle(limits []Limit, now func() time.Time) *Throttle {
	if limits == nil {
		limits = DefaultLimits()
	}
	if now == nil {
		now = time.Now
	}
	t := &Throttle{limits: limits, now: now, buckets: map[Scope]map[string]*bucket{}}
	for _, l := range limits {
		t.buckets[l.Scope] = map[string]*bucket{}
	}
	return t
}

// Allow charges one redemption attempt against every limit, in order, and
// reports whether it may proceed and, when it may not, the scope that
// refused. keys maps a scope to its key; a scope with no key is not charged.
func (t *Throttle) Allow(keys map[Scope]string) (bool, Scope) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	for _, l := range t.limits {
		k, ok := keys[l.Scope]
		if !ok || k == "" || l.Burst <= 0 || l.Per <= 0 {
			continue
		}
		if !t.take(l, k, now) {
			return false, l.Scope
		}
	}
	return true, ""
}

func (t *Throttle) take(l Limit, key string, now time.Time) bool {
	table := t.buckets[l.Scope]
	rate := float64(l.Burst) / l.Per.Seconds()
	b, ok := table[key]
	if !ok {
		if len(table) >= maxThrottleKeys {
			t.evict(l, table, now)
		}
		b = &bucket{tokens: float64(l.Burst), last: now}
		table[key] = b
	}
	if el := now.Sub(b.last).Seconds(); el > 0 {
		b.tokens += el * rate
		if b.tokens > float64(l.Burst) {
			b.tokens = float64(l.Burst)
		}
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// evict drops every bucket idle long enough to have refilled (dropping one
// admits exactly what keeping it would), and resets the table if none was.
func (t *Throttle) evict(l Limit, table map[string]*bucket, now time.Time) {
	for k, b := range table {
		if now.Sub(b.last) >= l.Per {
			delete(table, k)
		}
	}
	if len(table) >= maxThrottleKeys {
		for k := range table {
			delete(table, k)
		}
	}
}
