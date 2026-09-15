package aigateway

import (
	"fmt"
	"sync"
	"time"
)

// Streaming defaults (design §2.7). SSE is the dominant traffic shape; the
// gateway never buffers a whole response. These bounds cap the blast radius
// of a stuck or hostile stream without adding a latency tax to a healthy one.
const (
	// DefaultMaxStreamDuration bounds how long one streamed turn may run. It
	// also bounds revocation blast radius (§2.3): a non-strict revocation lets
	// in-flight streams complete, but never longer than this.
	DefaultMaxStreamDuration = 10 * time.Minute
	// DefaultMaxBodyBytes caps the request body BEFORE any parse work, so a
	// hostile client cannot force unbounded memory/CPU. 8 MiB comfortably fits
	// a large coding-agent context window.
	DefaultMaxBodyBytes int64 = 8 << 20
	// DefaultPerKeyConcurrency caps simultaneous in-flight streams per virtual
	// key. Independent of cache freshness, it bounds a compromised key's abuse
	// within the revocation window (§2.3).
	DefaultPerKeyConcurrency = 16
	// DefaultGlobalConcurrency caps simultaneous in-flight streams across the
	// whole gateway — the capacity-envelope backstop (Sol S18).
	DefaultGlobalConcurrency = 512
	// DefaultReconcileSweep is how often the startup + periodic reconciliation
	// sweep runs to close crash-orphaned reservations (§2.7 / Sol S6).
	DefaultReconcileSweep = 5 * time.Minute
	// DefaultStaleReservation is how old an open reservation must be before the
	// sweep settles it at worst-case. It sits COMFORTABLY past
	// DefaultMaxStreamDuration so the sweep never force-settles a live stream —
	// an invariant ValidateReconcileWindow enforces against operator overrides.
	DefaultStaleReservation = 15 * time.Minute
)

// ValidateReconcileWindow reports an error when the stale-reservation sweep
// threshold does not strictly exceed the max stream duration (m2). A stale
// threshold at or below the stream ceiling force-settles LIVE streams out from
// under an in-flight turn. Zero values mean "use the package default", so the
// comparison is on EFFECTIVE durations — the same normalization the daemon and
// the standalone binary apply — and both the org-server [aigateway] validator
// and the standalone binary's config parsing call it.
func ValidateReconcileWindow(maxStream, staleAfter time.Duration) error {
	if maxStream <= 0 {
		maxStream = DefaultMaxStreamDuration
	}
	if staleAfter <= 0 {
		staleAfter = DefaultStaleReservation
	}
	if staleAfter <= maxStream {
		return fmt.Errorf("aigateway: stale_reservation_seconds (%s effective) must exceed max_stream_seconds (%s effective) — a stale threshold at or below the max stream duration force-settles live streams", staleAfter, maxStream)
	}
	return nil
}

// StreamLimits are the enforced per-stream and gateway-wide bounds. A zero
// field normalizes to its default.
type StreamLimits struct {
	MaxDuration       time.Duration
	MaxBodyBytes      int64
	PerKeyConcurrency int
	GlobalConcurrency int
}

// Normalize fills any zero field with its default, so a partially-configured
// limits block is always safe to enforce.
func (l StreamLimits) Normalize() StreamLimits {
	if l.MaxDuration <= 0 {
		l.MaxDuration = DefaultMaxStreamDuration
	}
	if l.MaxBodyBytes <= 0 {
		l.MaxBodyBytes = DefaultMaxBodyBytes
	}
	if l.PerKeyConcurrency <= 0 {
		l.PerKeyConcurrency = DefaultPerKeyConcurrency
	}
	if l.GlobalConcurrency <= 0 {
		l.GlobalConcurrency = DefaultGlobalConcurrency
	}
	return l
}

// ScanClass is the classification of a response-side egress-guard hit
// (design §2.7). The gateway scans response chunks as they pass; only a
// critical hit aborts the stream, mirroring the node proxy's flag-only
// posture for non-critical hits.
type ScanClass int

const (
	// ScanClean — no guard hit.
	ScanClean ScanClass = iota
	// ScanNonCritical — a hit that is flagged but does not abort.
	ScanNonCritical
	// ScanCritical — a secret-egress-class hit; abort the remaining stream.
	ScanCritical
)

// AbortOnScan reports whether a scan verdict aborts the remainder of the
// stream. Only a critical hit does. Bytes already delivered cannot be unsent
// (physics, recorded as structural in HG7); the abort stops FURTHER leakage.
// No mid-stream rewriting ever — abort is the only response-side action.
func AbortOnScan(class ScanClass) bool { return class == ScanCritical }

// GuardScanner is the egress-guard seam (design §2.4 step 4 / §2.7). The
// gateway runs the org's guard policy server-side — defense in depth over the
// node's own run — on the request pre-first-byte and on each response chunk as
// it passes. It is a pure classification: no I/O, no rewriting. The default
// wiring is NoopGuardScanner (clean everywhere); a later lane injects the real
// internal/guard-backed scanner.
type GuardScanner interface {
	// ScanRequest classifies the request body pre-first-byte. A critical hit
	// denies the request before the upstream is dialed.
	ScanRequest(body []byte) ScanClass
	// ScanChunk classifies one response chunk as it streams. A critical hit
	// aborts the remainder (AbortOnScan); a non-critical hit flags only.
	ScanChunk(chunk []byte) ScanClass
}

// NoopGuardScanner passes everything. It is the honest default until the real
// guard-backed scanner is injected — it never fabricates a clean verdict it
// did not compute, it simply performs no scan.
type NoopGuardScanner struct{}

// ScanRequest always returns ScanClean.
func (NoopGuardScanner) ScanRequest([]byte) ScanClass { return ScanClean }

// ScanChunk always returns ScanClean.
func (NoopGuardScanner) ScanChunk([]byte) ScanClass { return ScanClean }

// ConcurrencyLimiter enforces per-key and global caps on simultaneous
// in-flight streams. It is a pure counter (sync only — no I/O), so the gwhttp
// handler acquires a slot before opening the upstream connection and releases
// it at stream end. Acquire is non-blocking: over a cap it returns false and
// the handler answers 429, rather than queueing (a queued coding-agent request
// is worse than a fast, retryable rejection).
type ConcurrencyLimiter struct {
	mu       sync.Mutex
	perKey   int
	global   int
	byKey    map[string]int
	inflight int
}

// NewConcurrencyLimiter builds a limiter from normalized limits.
func NewConcurrencyLimiter(l StreamLimits) *ConcurrencyLimiter {
	l = l.Normalize()
	return &ConcurrencyLimiter{
		perKey: l.PerKeyConcurrency,
		global: l.GlobalConcurrency,
		byKey:  make(map[string]int),
	}
}

// LimitReject names which cap an Acquire hit, for the 429 body and metrics.
type LimitReject string

const (
	// LimitNone — the slot was acquired.
	LimitNone LimitReject = ""
	// LimitPerKey — the key's concurrency cap is full.
	LimitPerKey LimitReject = "per_key_concurrency"
	// LimitGlobal — the gateway-wide concurrency cap is full.
	LimitGlobal LimitReject = "global_concurrency"
)

// Acquire reserves one in-flight slot for keyID. It returns LimitNone on
// success (the caller MUST later Release), or the cap that was full. The
// global cap is checked first so a single hot key cannot starve the check.
func (c *ConcurrencyLimiter) Acquire(keyID string) LimitReject {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.inflight >= c.global {
		return LimitGlobal
	}
	if c.byKey[keyID] >= c.perKey {
		return LimitPerKey
	}
	c.byKey[keyID]++
	c.inflight++
	return LimitNone
}

// Release returns a slot acquired for keyID. It is safe to call once per
// successful Acquire; releasing a key with no outstanding slot is a no-op
// guard against double-release.
func (c *ConcurrencyLimiter) Release(keyID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.byKey[keyID] > 0 {
		c.byKey[keyID]--
		if c.byKey[keyID] == 0 {
			delete(c.byKey, keyID)
		}
	}
	if c.inflight > 0 {
		c.inflight--
	}
}

// Inflight reports the current global in-flight count, for the capacity
// envelope's metrics.
func (c *ConcurrencyLimiter) Inflight() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.inflight
}
