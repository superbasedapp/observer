package identity

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// jwksBody marshals a JWKS document from the given keys, using the same jwkJSON
// encoder the rest of the identity suite uses.
func jwksBody(t *testing.T, keys map[string]*rsa.PublicKey) []byte {
	t.Helper()
	var arr []map[string]string
	for kid, pub := range keys {
		arr = append(arr, jwkJSON(t, kid, pub))
	}
	b, _ := json.Marshal(map[string]any{"keys": arr})
	return b
}

// Stream 4 (row G2-13): identity-verifier §10 rows not already covered by
// workos_test.go. The existing suite pins alg-confusion, expired, wrong
// issuer/client_id, no-exp, empty-sub, unknown-kid, wrong-key and JWKS rotation;
// this file adds the nbf-in-future refusal and the provider-outage behaviour
// (§10 "provider outage" / "refresh/JWKS rotation").

// TestS10_VerifierRejectsFutureNbf pins that a token whose nbf is in the future
// is refused (not-yet-valid) even though its signature, issuer, client_id and
// exp are all sound.
func TestS10_VerifierRejectsFutureNbf(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	js := newJWKSServer(t, map[string]*rsa.PublicKey{"kid-1": &priv.PublicKey})
	now := time.Unix(1_800_000_000, 0)
	v := newVerifier(t, js.srv.URL, now)

	claims := baseClaims(now)
	claims["nbf"] = now.Add(10 * time.Minute).Unix()
	tok := mintToken(t, priv, "kid-1", "RS256", claims)
	if _, err := v.Verify(context.Background(), tok); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("future-nbf token must be refused, got %v", err)
	}
}

// TestS10_VerifierProviderOutageUsesCachedKey pins the outage posture: once a
// key is cached, a later JWKS fetch failure (a stale cache miss / TTL refresh
// that cannot reach the provider) does NOT fail a token that key still verifies
// — the verifier falls back to the cached key rather than failing closed on a
// transient provider outage. A never-seen kid during the outage still fails.
func TestS10_VerifierProviderOutageUsesCachedKey(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	now := time.Unix(1_800_000_000, 0)

	// A JWKS server we can switch to a hard failure mid-test.
	var down bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if down {
			http.Error(w, "provider down", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksBody(t, map[string]*rsa.PublicKey{"kid-1": &priv.PublicKey}))
	}))
	t.Cleanup(srv.Close)

	// A very short TTL so the second Verify triggers a refresh attempt.
	v, err := NewWorkOSVerifier(
		testClientID,
		WithJWKSURL(srv.URL),
		WithClock(func() time.Time { return now }),
		WithJWKSCacheTTL(time.Nanosecond),
	)
	if err != nil {
		t.Fatalf("NewWorkOSVerifier: %v", err)
	}
	ctx := context.Background()

	// Warm the cache.
	if _, err := v.Verify(ctx, mintToken(t, priv, "kid-1", "RS256", baseClaims(now))); err != nil {
		t.Fatalf("initial verify: %v", err)
	}

	// Provider goes down; the TTL has lapsed so keyForKID attempts a refresh,
	// which fails — but the cached kid-1 must still verify a fresh token.
	down = true
	if _, err := v.Verify(ctx, mintToken(t, priv, "kid-1", "RS256", baseClaims(now))); err != nil {
		t.Fatalf("verify during provider outage with a cached key: %v", err)
	}
	// A kid we have never cached cannot be conjured during the outage.
	if _, err := v.Verify(ctx, mintToken(t, priv, "kid-NEVER", "RS256", baseClaims(now))); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("unknown kid during outage must fail, got %v", err)
	}
}

// TestS10_VerifierJWKSMissCooldownBoundsThrashButNotRotation closes the last
// §10 row this package owns: "JWKS key rotation mid-flight" (already partly
// covered by TestWorkOSVerifierRefetchesOnRotation in workos_test.go) plus the
// row's other half, "must not thrash" — which was NOT covered anywhere. A kid
// is read straight out of the unverified JWT header, so before this bound a
// flood of tokens carrying the SAME bogus kid would drive one JWKS fetch to
// the provider PER REQUEST (a cache miss always looked stale). This test pins
// both halves in one place: a repeated probe of the identical bogus kid is
// bounded to one fetch, while a GENUINELY rotating (different) kid is never
// held back by that bound.
func TestS10_VerifierJWKSMissCooldownBoundsThrashButNotRotation(t *testing.T) {
	priv1, _ := rsa.GenerateKey(rand.Reader, 2048)
	priv2, _ := rsa.GenerateKey(rand.Reader, 2048)
	keys := map[string]*rsa.PublicKey{"kid-1": &priv1.PublicKey}
	js := newJWKSServer(t, keys)
	now := time.Unix(1_800_000_000, 0)
	// A fixed clock, deliberately: every repeat probe below happens at the SAME
	// instant, so "within the cooldown" holds for all of them by construction —
	// exactly the flood shape the bound exists to survive.
	v := newVerifier(t, js.srv.URL, now)
	ctx := context.Background()

	// Warm the cache with the real key (itself a first-ever miss; costs one
	// fetch).
	if _, err := v.Verify(ctx, mintToken(t, priv1, "kid-1", "RS256", baseClaims(now))); err != nil {
		t.Fatalf("warm verify: %v", err)
	}
	if got := js.fetch.Load(); got != 1 {
		t.Fatalf("warm fetch count=%d, want 1", got)
	}

	// A flood of tokens carrying the SAME bogus kid: only the first probe may
	// refetch; every repeat must be refused WITHOUT another fetch.
	for i := 0; i < 5; i++ {
		if _, err := v.Verify(ctx, mintToken(t, priv1, "kid-BOGUS", "RS256", baseClaims(now))); !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("bogus kid probe %d: got %v, want ErrInvalidToken", i, err)
		}
	}
	if got := js.fetch.Load(); got != 2 {
		t.Fatalf("fetch count after 5 bogus-kid probes=%d, want 2 (1 warm + 1 bounded probe, never 6)", got)
	}

	// A GENUINE rotation — a DIFFERENT unknown kid — is not held back by the
	// bogus kid's cooldown: it still gets its own fetch and validates.
	keys["kid-2"] = &priv2.PublicKey
	if _, err := v.Verify(ctx, mintToken(t, priv2, "kid-2", "RS256", baseClaims(now))); err != nil {
		t.Fatalf("post-rotation verify: %v", err)
	}
	if got := js.fetch.Load(); got != 3 {
		t.Fatalf("fetch count after rotation=%d, want 3", got)
	}
}

// TestS10_VerifierJWKSMissCooldownAlternatingKids is the 2026-09-11 review's
// P3-a regression: the OLD single lastMissKID/lastMissAt pair bounded a
// REPEATED probe of the identical bogus kid (pinned above), but an attacker
// ALTERNATING between two (or more) bogus kids defeated it completely —
// neither kid ever matched the OTHER kid's cooldown record, so every single
// probe re-triggered a fetch regardless of how tight the cooldown window
// was. The bounded per-kid recent-miss map must hold each kid to its own
// cooldown independently, so alternating gains an attacker nothing over
// probing one kid repeatedly.
func TestS10_VerifierJWKSMissCooldownAlternatingKids(t *testing.T) {
	priv1, _ := rsa.GenerateKey(rand.Reader, 2048)
	keys := map[string]*rsa.PublicKey{"kid-1": &priv1.PublicKey}
	js := newJWKSServer(t, keys)
	now := time.Unix(1_800_000_000, 0)
	// A fixed clock: every probe below happens at the SAME instant, so
	// "within the cooldown" holds for all of them by construction.
	v := newVerifier(t, js.srv.URL, now)
	ctx := context.Background()

	// Warm the cache with the real key (one fetch).
	if _, err := v.Verify(ctx, mintToken(t, priv1, "kid-1", "RS256", baseClaims(now))); err != nil {
		t.Fatalf("warm verify: %v", err)
	}
	if got := js.fetch.Load(); got != 1 {
		t.Fatalf("warm fetch count=%d, want 1", got)
	}

	// Alternate between TWO bogus kids, 10 probes total. Each kid gets its
	// own first-miss fetch (2 more, total 3); every REPEAT of either must be
	// refused WITHOUT triggering another fetch — the old code fetched on
	// every single one of these 10 probes.
	for i := 0; i < 10; i++ {
		kid := "kid-BOGUS-A"
		if i%2 == 1 {
			kid = "kid-BOGUS-B"
		}
		if _, err := v.Verify(ctx, mintToken(t, priv1, kid, "RS256", baseClaims(now))); !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("alternating bogus kid probe %d (%s): got %v, want ErrInvalidToken", i, kid, err)
		}
	}
	if got := js.fetch.Load(); got != 3 {
		t.Fatalf("fetch count after alternating bogus-kid flood=%d, want 3 (1 warm + 1 per distinct bogus kid, never 11)", got)
	}
}
