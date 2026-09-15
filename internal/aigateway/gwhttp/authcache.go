package gwhttp

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/aigateway"
)

// AuthCache is the watermark-aware virtual-key resolution cache (design §2.3,
// Sol S9). It keeps authn off the hot DB path but can never resurrect a key a
// concurrent revocation has invalidated: every entry is stamped with the
// revocation watermark observed at fill, and a fill older than the currently
// observed watermark is rejected and re-resolved against the store.
type AuthCache struct {
	keys aigateway.KeyStore
	ttl  time.Duration
	now  func() time.Time

	mu                sync.Mutex
	entries           map[string]aigateway.AuthCacheEntry // keyed by key hash
	observedWatermark int64
}

// NewAuthCache builds a cache over a KeyStore. ttl <= 0 disables TTL expiry
// (the watermark check still applies). now defaults to time.Now.
func NewAuthCache(keys aigateway.KeyStore, ttl time.Duration, now func() time.Time) *AuthCache {
	if now == nil {
		now = time.Now
	}
	return &AuthCache{keys: keys, ttl: ttl, now: now, entries: map[string]aigateway.AuthCacheEntry{}}
}

// Resolve authenticates a presented virtual key for orgID, the presented
// machine fingerprint, and whether this is a thin-mode request. It returns the
// resolved key and a reject reason (RejectNone on success). A cache hit that is
// TTL-expired or watermark-stale falls through to a fresh store resolution, so
// a revocation always wins.
func (c *AuthCache) Resolve(ctx context.Context, orgID, presentedKey, machine string, thin bool) (aigateway.VirtualKey, aigateway.KeyRejectReason, error) {
	if !aigateway.ValidVirtualKeyFormat(presentedKey) {
		return aigateway.VirtualKey{}, aigateway.RejectMalformed, nil
	}
	hash := aigateway.HashVirtualKey(presentedKey)

	c.mu.Lock()
	entry, ok := c.entries[hash]
	observed := c.observedWatermark
	c.mu.Unlock()

	if ok {
		verdict := entry.Verdict(machine, thin, c.now(), c.ttl, observed)
		// A stale-watermark or TTL-expired entry must be re-resolved, not
		// trusted; any other verdict (valid, or a definite reject on the key's
		// own fields) is authoritative from cache.
		if verdict != aigateway.RejectStaleWatermark && verdict != aigateway.RejectUnknown {
			return entry.Key, verdict, nil
		}
		c.mu.Lock()
		delete(c.entries, hash)
		c.mu.Unlock()
	}

	// Miss (or invalidated): resolve from the store and refresh the observed
	// watermark so the fresh entry is stamped current.
	key, err := c.keys.ResolveByHash(ctx, orgID, hash)
	if errors.Is(err, aigateway.ErrKeyNotFound) {
		return aigateway.VirtualKey{}, aigateway.RejectUnknown, nil
	}
	if err != nil {
		return aigateway.VirtualKey{}, aigateway.RejectUnknown, err
	}
	wm, err := c.keys.Watermark(ctx, orgID)
	if err != nil {
		return aigateway.VirtualKey{}, aigateway.RejectUnknown, err
	}

	c.mu.Lock()
	if wm > c.observedWatermark {
		c.observedWatermark = wm
	}
	c.entries[hash] = aigateway.AuthCacheEntry{Key: key, Watermark: c.observedWatermark, FilledAt: c.now()}
	c.mu.Unlock()

	return key, aigateway.EvaluateKey(key, machine, thin, c.now()), nil
}

// BumpObservedWatermark advances the observed revocation watermark. The gateway
// calls it immediately after a revoke (which bumped the store's watermark) so
// cached "active" entries older than the bump are rejected on their next use —
// closing the propagation window without a per-request DB read.
func (c *AuthCache) BumpObservedWatermark(wm int64) {
	c.mu.Lock()
	if wm > c.observedWatermark {
		c.observedWatermark = wm
	}
	c.mu.Unlock()
}

// ObservedWatermark returns the currently observed watermark (for tests/metrics).
func (c *AuthCache) ObservedWatermark() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.observedWatermark
}

// StrictRevocationCheck returns a ForwardRequest.AbortCheck for one in-flight
// request holding key (design §2.3 HG8 — "a compromised-key revocation aborts
// in-flight streams; a routine rotation lets them complete"). Each invocation
// is throttled to at most one store round trip per `every` (<= 0 ⇒ every
// chunk): it reads the org's revocation watermark and, ONLY when the
// watermark has advanced since the key was resolved, re-resolves the key by
// hash and reports abort iff it is now revoked with the strict flag. A
// non-strict revocation never aborts (the auth cache refuses the key on its
// NEXT request instead). Store errors fail open for the stream in flight — a
// transient DB blip must not kill every open stream; the next request still
// re-authenticates against the store.
func (c *AuthCache) StrictRevocationCheck(ctx context.Context, orgID string, key aigateway.VirtualKey, every time.Duration) func() (bool, string) {
	var last time.Time
	c.mu.Lock()
	seen := c.observedWatermark
	c.mu.Unlock()
	decided := false
	return func() (bool, string) {
		if decided {
			return true, aigateway.MarkerRevoked
		}
		now := c.now()
		if every > 0 && !last.IsZero() && now.Sub(last) < every {
			return false, ""
		}
		last = now
		wm, err := c.keys.Watermark(ctx, orgID)
		if err != nil || wm <= seen {
			return false, ""
		}
		seen = wm
		c.BumpObservedWatermark(wm)
		k, err := c.keys.ResolveByHash(ctx, orgID, key.Hash)
		if err != nil {
			return false, ""
		}
		if !k.RevokedAt.IsZero() && k.RevokedStrict {
			decided = true
			return true, aigateway.MarkerRevoked
		}
		return false, ""
	}
}
