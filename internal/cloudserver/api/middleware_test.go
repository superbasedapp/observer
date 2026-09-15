package api_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/api"
)

// TestPoPEncodedPathNotConfusable proves FC1: the middleware reconstructs the
// PoP htu from r.URL.EscapedPath(), so an encoded reserved character stays
// security-significant. "/v1/devices/a%3Bb" and "/v1/devices/a;b" are distinct
// targets (';' = %3B is a reserved sub-delim CanonicalHTU keeps encoded), so a
// proof minted for one must NOT authorize a request for the other, and vice
// versa. %3B decodes to a single non-'/' segment, so the {id} route still
// matches and the request reaches authenticate.
func TestPoPEncodedPathNotConfusable(t *testing.T) {
	h := newHarness(t) // rate limiting disabled here
	c := h.login(t, "encpath")

	// (a) A proof bound to the DECODED path must NOT authorize a request whose
	// raw target is the ENCODED form ⇒ htu mismatch ⇒ 401.
	req, _ := http.NewRequest("DELETE", c.base+"/v1/devices/a%3Bb", nil)
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("SBO-PoP", c.proof("DELETE", "/v1/devices/a;b", nil, ""))
	if resp := c.do(req); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("decoded-path proof on encoded target: status=%d, want 401 (htu mismatch)", resp.StatusCode)
	}

	// (b) A proof bound to the ENCODED path presented on the matching encoded
	// target PASSES proof-of-possession (it then 404s the nonexistent device).
	// The point is that it is NOT rejected at PoP ⇒ status != 401.
	req2, _ := http.NewRequest("DELETE", c.base+"/v1/devices/a%3Bb", nil)
	req2.Header.Set("Authorization", "Bearer "+c.token)
	req2.Header.Set("SBO-PoP", c.proof("DELETE", "/v1/devices/a%3Bb", nil, ""))
	if resp := c.do(req2); resp.StatusCode == http.StatusUnauthorized {
		t.Fatalf("encoded-path proof on matching encoded target rejected at PoP (status 401); the two proofs must be interchangeable-proof-free but a MATCHING proof must pass")
	}
}

// TestOverLimitValidProofsLeaveNoReplayRow proves FC2: an over-limit valid
// proof returns 429 WITHOUT committing a pop_replay row, because the
// per-device cap is now checked before the durable replay insert.
func TestOverLimitValidProofsLeaveNoReplayRow(t *testing.T) {
	h := newHarnessRL(t, api.RateLimitConfig{Window: time.Minute, DevicePerWindow: 2})
	c := h.login(t, "rl-noreplay")

	got200, got429 := 0, 0
	for i := 0; i < 5; i++ {
		resp := c.do(c.signedReq("GET", "/v1/usage", nil)) // fresh random jti each
		switch resp.StatusCode {
		case http.StatusOK:
			got200++
		case http.StatusTooManyRequests:
			got429++
		default:
			t.Fatalf("request %d unexpected status=%d body=%s", i, resp.StatusCode, readAll(resp))
		}
		resp.Body.Close()
	}
	if got200 != 2 || got429 != 3 {
		t.Fatalf("device cap 2: got %d×200 %d×429, want 2 and 3", got200, got429)
	}

	var rows int
	if err := h.store.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM pop_replay`).Scan(&rows); err != nil {
		t.Fatalf("count pop_replay: %v", err)
	}
	if rows != 2 {
		t.Fatalf("pop_replay rows=%d, want 2 (over-limit valid proofs must leave no durable row)", rows)
	}
}

// TestInvalidBearerIPCapped proves FC2: a flood of invalid bearer tokens is
// bounded by an early per-IP cap that runs BEFORE token introspection, so the
// authentication work (SECURITY DEFINER lookup + audit write) stops growing.
func TestInvalidBearerIPCapped(t *testing.T) {
	h := newHarnessRL(t, api.RateLimitConfig{Window: time.Minute, IPPerWindow: 3})
	hc := h.srv.Client()

	got401, got429 := 0, 0
	for i := 0; i < 10; i++ {
		req, _ := http.NewRequest("GET", h.srv.URL+"/v1/usage", nil)
		req.Header.Set("Authorization", "Bearer bogus-token")
		resp, err := hc.Do(req)
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		switch resp.StatusCode {
		case http.StatusUnauthorized:
			got401++
		case http.StatusTooManyRequests:
			got429++
		default:
			t.Fatalf("request %d unexpected status=%d", i, resp.StatusCode)
		}
		resp.Body.Close()
	}
	if got401 != 3 || got429 != 7 {
		t.Fatalf("IP cap 3: got %d×401 %d×429, want 3 and 7 (IP cap must front introspection)", got401, got429)
	}

	// The audit trail (one auth_token_invalid per introspection) stops growing at
	// the cap: only the 3 admitted-past-the-IP-cap requests reached introspection.
	var audits int
	if err := h.store.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM security_audit_events WHERE event_type = 'auth_token_invalid'`).Scan(&audits); err != nil {
		t.Fatalf("count audits: %v", err)
	}
	if audits != 3 {
		t.Fatalf("auth_token_invalid audit rows=%d, want 3 (introspection must stop at the IP cap)", audits)
	}
}
