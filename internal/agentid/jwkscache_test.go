package agentid

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/dpop/jose"
)

// TestJWKSCacheMaxAgeHonoursRetirement (AA-37): with MaxAge set, a kid that
// has been RETIRED at the source stops resolving within MaxAge of the
// retirement - no restart, no unknown-kid miss needed - while the unknown-kid
// refetch throttle is unchanged. Each row advances the clock from the
// previous row and names what the source serves at that moment.
func TestJWKSCacheMaxAgeHonoursRetirement(t *testing.T) {
	k1 := newSigner(t, jose.AlgEdDSA, "k1")
	k2 := newSigner(t, jose.AlgEdDSA, "k2")
	both := ringOf(t, publicEntry(k1, "k1", KeyRetiring), activeEntry(k2, "k2"))
	onlyK2 := ringOf(t, activeEntry(k2, "k2"))
	fetchErr := errors.New("control store down")

	type src int
	const (
		srcBoth src = iota
		srcOnlyK2
		srcDown
	)
	rows := []struct {
		name        string
		advance     time.Duration
		serves      src
		kid         string
		wantErr     error // nil = resolves; ErrKeySetUnavailable; or errUnknown
		wantFetches int
	}{
		{"first use loads the set", 0, srcBoth, "k1", nil, 1},
		{"k1 retired at the source; inside MaxAge the cached set still serves it", time.Second, srcOnlyK2, "k1", nil, 1},
		{"past MaxAge the set is refreshed first: the retired k1 no longer resolves", 10 * time.Second, srcOnlyK2, "k1", errUnknown, 2},
		{"the active k2 still resolves from the refreshed set (no extra fetch)", 0, srcOnlyK2, "k2", nil, 2},
		{"a bogus kid right after is throttled (no fetch)", 0, srcOnlyK2, "bogus", errUnknown, 2},
		{"past MaxAge with the source DOWN: never served stale - unavailable", 10 * time.Second, srcDown, "k2", ErrKeySetUnavailable, 3},
		{"inside the refetch interval after the failure: still unavailable, no fetch", 500 * time.Millisecond, srcDown, "k2", ErrKeySetUnavailable, 3},
		{"after the interval the source is back: refreshed and resolving", 2 * time.Second, srcOnlyK2, "k2", nil, 4},
	}

	now := t0
	var serving src
	cache := &JWKSCache{
		Fetch: func(context.Context) ([]JWK, error) {
			switch serving {
			case srcBoth:
				return both.JWKS()
			case srcOnlyK2:
				return onlyK2.JWKS()
			}
			return nil, fetchErr
		},
		MinRefetchInterval: time.Second,
		MaxAge:             5 * time.Second,
		Now:                func() time.Time { return now },
	}
	ctx := context.Background()
	for _, r := range rows {
		now = now.Add(r.advance)
		serving = r.serves
		_, err := cache.KeyForKID(ctx, r.kid)
		switch {
		case r.wantErr == nil && err != nil:
			t.Fatalf("%s: KeyForKID(%s) = %v, want it to resolve", r.name, r.kid, err)
		case errors.Is(r.wantErr, errUnknown) && CodeOf(err) != TokErrUnknownKID:
			t.Fatalf("%s: KeyForKID(%s) = %v, want unknown_kid", r.name, r.kid, err)
		case errors.Is(r.wantErr, ErrKeySetUnavailable) && !errors.Is(err, ErrKeySetUnavailable):
			t.Fatalf("%s: KeyForKID(%s) = %v, want ErrKeySetUnavailable", r.name, r.kid, err)
		}
		if errors.Is(r.wantErr, ErrKeySetUnavailable) && CodeOf(err) != "" {
			t.Fatalf("%s: an unavailable key source must not read as a token verdict (code %q)", r.name, CodeOf(err))
		}
		if got := cache.Fetches(); got != r.wantFetches {
			t.Fatalf("%s: fetches = %d, want %d", r.name, got, r.wantFetches)
		}
	}
}

// errUnknown is the table's marker for a TokErrUnknownKID outcome.
var errUnknown = errors.New("unknown kid marker")

// TestJWKSCacheNoMaxAgeIsMissDriven pins the zero-value behaviour every
// other caller keeps: without MaxAge the cache refetches only on a miss, so a
// retired kid that is still cached keeps resolving (the AA-37 defect the
// front's MaxAge closes).
func TestJWKSCacheNoMaxAgeIsMissDriven(t *testing.T) {
	k1 := newSigner(t, jose.AlgEdDSA, "k1")
	k2 := newSigner(t, jose.AlgEdDSA, "k2")
	served := ringOf(t, activeEntry(k1, "k1"))
	now := t0
	cache := &JWKSCache{
		Fetch:              func(context.Context) ([]JWK, error) { return served.JWKS() },
		MinRefetchInterval: time.Second,
		Now:                func() time.Time { return now },
	}
	ctx := context.Background()
	if _, err := cache.KeyForKID(ctx, "k1"); err != nil {
		t.Fatal(err)
	}
	served = ringOf(t, activeEntry(k2, "k2"))
	now = now.Add(time.Hour)
	if _, err := cache.KeyForKID(ctx, "k1"); err != nil || cache.Fetches() != 1 {
		t.Fatalf("zero MaxAge: cached k1 = %v (fetches %d), want it still served from the cache", err, cache.Fetches())
	}
}

// TestJWKSCacheFetchFailureIsUnavailable: a key source that cannot be read
// is an outage (ErrKeySetUnavailable), never an unknown_kid verdict - on the
// first load, on an unknown-kid refetch, and while the failed first load's
// throttle holds.
func TestJWKSCacheFetchFailureIsUnavailable(t *testing.T) {
	k1 := newSigner(t, jose.AlgEdDSA, "k1")
	served := ringOf(t, activeEntry(k1, "k1"))
	down := true
	now := t0
	cache := &JWKSCache{
		Fetch: func(context.Context) ([]JWK, error) {
			if down {
				return nil, errors.New("down")
			}
			return served.JWKS()
		},
		MinRefetchInterval: time.Second,
		Now:                func() time.Time { return now },
	}
	ctx := context.Background()
	for i, want := range []int{1, 1} {
		if _, err := cache.KeyForKID(ctx, "k1"); !errors.Is(err, ErrKeySetUnavailable) || CodeOf(err) != "" || cache.Fetches() != want {
			t.Fatalf("attempt %d: %v fetches=%d, want unavailable after %d fetch(es)", i, err, cache.Fetches(), want)
		}
	}
	now, down = now.Add(2*time.Second), false
	if _, err := cache.KeyForKID(ctx, "k1"); err != nil || cache.Fetches() != 2 {
		t.Fatalf("recovered: %v fetches=%d", err, cache.Fetches())
	}
	now, down = now.Add(2*time.Second), true
	if _, err := cache.KeyForKID(ctx, "k9"); !errors.Is(err, ErrKeySetUnavailable) || cache.Fetches() != 3 {
		t.Fatalf("unknown-kid refetch against a down source: %v fetches=%d, want unavailable", err, cache.Fetches())
	}
}
