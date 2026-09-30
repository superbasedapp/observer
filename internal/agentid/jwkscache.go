package agentid

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// DefaultMinRefetchInterval bounds unknown-kid refetches (one per interval).
const DefaultMinRefetchInterval = 30 * time.Second

// ErrKeySetUnavailable reports that the verifier could not obtain a CURRENT
// key set: the Fetch failed, or the cached set is older than MaxAge and could
// not be refreshed. It is an outage of the key source, never a verdict on the
// token, so a caller answers it retryable (503), not 401.
var ErrKeySetUnavailable = errors.New("agentid.JWKSCache: key set unavailable")

// JWKSCache is a verifier-side key cache with a BOUNDED unknown-kid refetch:
// a miss triggers exactly one refetch, and never more than one per
// MinRefetchInterval (mirroring the OIDC rail's keyForKID in the serving
// direction, §4.2). Fetch is injected - the package does no I/O itself.
//
// With MaxAge set the cache also honours key RETIREMENT: a lookup that finds
// the cached set older than MaxAge refetches first (at most once per
// MinRefetchInterval, serialized), so a kid removed from the source stops
// resolving within MaxAge of its removal with no restart. A set older than
// MaxAge is never used: when the refresh fails the lookup fails with
// ErrKeySetUnavailable rather than verifying against keys that may have been
// retired. MaxAge zero keeps the purely miss-driven behaviour.
type JWKSCache struct {
	// Fetch loads the current key set (e.g. from /.well-known/jwks.json or
	// the in-process ring). Required.
	Fetch func(ctx context.Context) ([]JWK, error)
	// MinRefetchInterval bounds refetches (zero -> DefaultMinRefetchInterval).
	MinRefetchInterval time.Duration
	// MaxAge bounds how long a fetched set may be used before it is
	// refreshed (zero -> no bound: the cache refetches only on a miss).
	MaxAge time.Duration
	// Now is the clock (nil -> time.Now).
	Now func() time.Time

	mu        sync.Mutex
	keys      []JWK
	fetchedAt time.Time // last fetch ATTEMPT (the refetch throttle)
	loadedAt  time.Time // last SUCCESSFUL fetch (the MaxAge clock)
	fetches   int
}

func (c *JWKSCache) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *JWKSCache) interval() time.Duration {
	if c.MinRefetchInterval > 0 {
		return c.MinRefetchInterval
	}
	return DefaultMinRefetchInterval
}

// Fetches reports how many times Fetch has been called (observability/tests).
func (c *JWKSCache) Fetches() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.fetches
}

// refetchLocked calls Fetch and replaces the key set on success. A failure is
// ErrKeySetUnavailable.
func (c *JWKSCache) refetchLocked(ctx context.Context) error {
	if c.Fetch == nil {
		return fmt.Errorf("%w: no Fetch configured", ErrKeySetUnavailable)
	}
	c.fetches++
	c.fetchedAt = c.now()
	keys, err := c.Fetch(ctx)
	if err != nil {
		return fmt.Errorf("%w: fetch: %w", ErrKeySetUnavailable, err)
	}
	c.keys, c.loadedAt = keys, c.fetchedAt
	return nil
}

// freshLocked makes the cached set usable: it loads it on first use and,
// when MaxAge is set and the set is older than MaxAge, refreshes it (at most
// once per MinRefetchInterval). An over-age set that cannot be refreshed is
// ErrKeySetUnavailable - never served.
func (c *JWKSCache) freshLocked(ctx context.Context) error {
	if c.loadedAt.IsZero() {
		if !c.fetchedAt.IsZero() && c.now().Sub(c.fetchedAt) < c.interval() {
			return fmt.Errorf("%w: last fetch failed (refetch rate-limited)", ErrKeySetUnavailable)
		}
		return c.refetchLocked(ctx)
	}
	if c.MaxAge <= 0 || c.now().Sub(c.loadedAt) < c.MaxAge {
		return nil
	}
	if c.now().Sub(c.fetchedAt) < c.interval() {
		return fmt.Errorf("%w: key set older than %s and the refresh failed (refetch rate-limited)", ErrKeySetUnavailable, c.MaxAge)
	}
	return c.refetchLocked(ctx)
}

// Keys returns the cached key set, fetching once if it has never loaded (and
// refreshing it past MaxAge).
func (c *JWKSCache) Keys(ctx context.Context) ([]JWK, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.freshLocked(ctx); err != nil {
		return nil, err
	}
	out := make([]JWK, len(c.keys))
	copy(out, c.keys)
	return out, nil
}

// KeyForKID resolves kid. On a miss it refetches EXACTLY ONCE - and only if
// the last fetch is at least MinRefetchInterval old - then looks again. A
// kid still unknown is a TokErrUnknownKID error; a key source that cannot be
// read is ErrKeySetUnavailable.
func (c *JWKSCache) KeyForKID(ctx context.Context, kid string) (JWK, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.freshLocked(ctx); err != nil {
		return JWK{}, err
	}
	if k, err := selectKey(c.keys, kid); err == nil {
		return k, nil
	}
	if c.now().Sub(c.fetchedAt) < c.interval() {
		return JWK{}, tokErr(TokErrUnknownKID, "kid %q unknown (refetch rate-limited)", kid)
	}
	if err := c.refetchLocked(ctx); err != nil {
		return JWK{}, err
	}
	return selectKey(c.keys, kid)
}

// VerifyToken resolves the token's kid through the cache and runs
// VerifyFull.
func (c *JWKSCache) VerifyToken(ctx context.Context, o VerifyOptions, token, expectedAud, expectedIss string, now time.Time) (Claims, error) {
	kid, err := TokenKID(token)
	if err != nil {
		return Claims{}, err
	}
	key, err := c.KeyForKID(ctx, kid)
	if err != nil {
		return Claims{}, err
	}
	return VerifyFull(o, []JWK{key}, token, expectedAud, expectedIss, now)
}
