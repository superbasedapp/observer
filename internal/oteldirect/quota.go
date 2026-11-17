package oteldirect

import (
	"math"
	"sort"
	"sync"
	"time"
)

// QuotaConfig is the per-token rate quota.
type QuotaConfig struct {
	// RequestsPerMinute is the sustained export-request rate.
	RequestsPerMinute int
	// Burst is the request bucket's size (requests allowed at once).
	Burst int
	// RowsPerMinute is the sustained accepted-row rate; its bucket holds one
	// minute of rows.
	RowsPerMinute int
	// MaxKeys bounds the tracked tokens; DefaultMaxKeys when <= 0.
	MaxKeys int
}

// DefaultQuota is the design's per-token quota: 60 requests per minute with
// a burst of 120, and 2,000 accepted rows per minute.
var DefaultQuota = QuotaConfig{RequestsPerMinute: 60, Burst: 120, RowsPerMinute: 2000}

// DefaultMaxKeys bounds a Limiter's tracked keys when QuotaConfig.MaxKeys is
// unset.
const DefaultMaxKeys = 100_000

// bucket is one token bucket: level tokens at time at. The level may go
// negative (rows overdraft, see AllowRows).
type bucket struct {
	level float64
	at    time.Time
}

// refill advances b to now at rate per second, capped at capacity.
func (b *bucket) refill(now time.Time, ratePerSec, capacity float64) {
	if dt := now.Sub(b.at).Seconds(); dt > 0 {
		b.level = math.Min(capacity, b.level+dt*ratePerSec)
		b.at = now
	}
}

// wait is how long until b's level reaches need at rate.
func (b *bucket) wait(need, ratePerSec float64) time.Duration {
	if ratePerSec <= 0 {
		return time.Minute
	}
	d := time.Duration(math.Ceil((need - b.level) / ratePerSec * float64(time.Second)))
	if d < time.Second {
		d = time.Second
	}
	return d
}

// keyState is one token's two buckets.
type keyState struct {
	req, rows bucket
	seen      time.Time
}

// Limiter is a per-key (per-token) rate limiter: a request bucket and an
// accepted-rows bucket per key. It holds no clock: every call takes now. It
// is safe for concurrent use. Memory is bounded: a key whose buckets have
// refilled to full is indistinguishable from a new key and is evicted at the
// next sweep, and past MaxKeys the least recently seen keys are evicted.
type Limiter struct {
	mu        sync.Mutex
	cfg       QuotaConfig
	keys      map[string]*keyState
	lastSweep time.Time
}

// NewLimiter builds a limiter for cfg. A zero rate field takes the
// DefaultQuota value.
func NewLimiter(cfg QuotaConfig) *Limiter {
	if cfg.RequestsPerMinute <= 0 {
		cfg.RequestsPerMinute = DefaultQuota.RequestsPerMinute
	}
	if cfg.Burst <= 0 {
		cfg.Burst = DefaultQuota.Burst
	}
	if cfg.RowsPerMinute <= 0 {
		cfg.RowsPerMinute = DefaultQuota.RowsPerMinute
	}
	if cfg.MaxKeys <= 0 {
		cfg.MaxKeys = DefaultMaxKeys
	}
	return &Limiter{cfg: cfg, keys: map[string]*keyState{}}
}

func (l *Limiter) reqRate() float64  { return float64(l.cfg.RequestsPerMinute) / 60 }
func (l *Limiter) rowsRate() float64 { return float64(l.cfg.RowsPerMinute) / 60 }

// state returns key's refilled state, creating it full.
func (l *Limiter) state(key string, now time.Time) *keyState {
	l.sweep(now)
	s := l.keys[key]
	if s == nil {
		s = &keyState{
			req:  bucket{level: float64(l.cfg.Burst), at: now},
			rows: bucket{level: float64(l.cfg.RowsPerMinute), at: now},
		}
		l.keys[key] = s
	}
	s.req.refill(now, l.reqRate(), float64(l.cfg.Burst))
	s.rows.refill(now, l.rowsRate(), float64(l.cfg.RowsPerMinute))
	if now.After(s.seen) {
		s.seen = now
	}
	return s
}

// AllowRequest takes one request from key's bucket. When the bucket is
// empty it refuses with the time until one request is available (the HTTP
// Retry-After).
func (l *Limiter) AllowRequest(key string, now time.Time) (ok bool, retryAfter time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := l.state(key, now)
	if s.req.level >= 1 {
		s.req.level--
		return true, 0
	}
	return false, s.req.wait(1, l.reqRate())
}

// AllowRows takes rows accepted rows from key's bucket. A batch is admitted
// whenever the bucket is positive and may overdraw it (so a single batch
// larger than a minute's allowance is never refused forever); the overdraft
// is repaid before the next batch passes. A refused batch gets the time
// until the bucket is positive again. rows <= 0 always passes.
func (l *Limiter) AllowRows(key string, rows int, now time.Time) (ok bool, retryAfter time.Duration) {
	if rows <= 0 {
		return true, 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	s := l.state(key, now)
	if s.rows.level > 0 {
		s.rows.level -= float64(rows)
		return true, 0
	}
	return false, s.rows.wait(0, l.rowsRate())
}

// Len is the number of keys the limiter tracks.
func (l *Limiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.keys)
}

// sweep evicts every key whose buckets are full again at now (lossless: a
// fresh key starts full) at most once a minute, or at once when over
// MaxKeys; then, if still over MaxKeys, the least recently seen keys. Caller
// holds mu.
func (l *Limiter) sweep(now time.Time) {
	over := len(l.keys) >= l.cfg.MaxKeys
	if !over && now.Sub(l.lastSweep) < time.Minute {
		return
	}
	l.lastSweep = now
	for k, s := range l.keys {
		req, rows := s.req, s.rows
		req.refill(now, l.reqRate(), float64(l.cfg.Burst))
		rows.refill(now, l.rowsRate(), float64(l.cfg.RowsPerMinute))
		if req.level >= float64(l.cfg.Burst) && rows.level >= float64(l.cfg.RowsPerMinute) {
			delete(l.keys, k)
		}
	}
	if len(l.keys) < l.cfg.MaxKeys {
		return
	}
	type aged struct {
		key  string
		seen time.Time
	}
	all := make([]aged, 0, len(l.keys))
	for k, s := range l.keys {
		all = append(all, aged{k, s.seen})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].seen.Before(all[j].seen) })
	// Leave room for the key about to be added.
	for i := 0; i < len(all) && len(l.keys) >= l.cfg.MaxKeys; i++ {
		delete(l.keys, all[i].key)
	}
}
