package api_test

import (
	"context"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/api"
)

// TestRateLimitUnauthPerIP proves the per-IP cap on the unauthenticated surface
// (GET /v1/auth/nonce) returns 429 with a usable Retry-After once exhausted.
func TestRateLimitUnauthPerIP(t *testing.T) {
	h := newHarnessRL(t, api.RateLimitConfig{Window: time.Minute, IPPerWindow: 2})
	hc := h.srv.Client()

	for i := 0; i < 2; i++ {
		resp, err := hc.Get(h.srv.URL + "/v1/auth/nonce")
		if err != nil {
			t.Fatalf("nonce %d: %v", i+1, err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("nonce %d status=%d, want 200", i+1, resp.StatusCode)
		}
		resp.Body.Close()
	}
	resp, err := hc.Get(h.srv.URL + "/v1/auth/nonce")
	if err != nil {
		t.Fatalf("nonce 3: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("nonce 3 status=%d, want 429", resp.StatusCode)
	}
	ra := resp.Header.Get("Retry-After")
	if secs, err := strconv.Atoi(ra); err != nil || secs < 1 {
		t.Fatalf("Retry-After=%q, want a positive integer", ra)
	}
}

// TestRateLimitPerAccountAuthedRoute proves the per-account cap gates the
// authenticated /v1 surface. IP + device dimensions are disabled so only the
// account budget is under test (login itself uses the unauth surface).
func TestRateLimitPerAccountAuthedRoute(t *testing.T) {
	h := newHarnessRL(t, api.RateLimitConfig{Window: time.Minute, AccountPerWindow: 2})
	c := h.login(t, "rl-account")

	for i := 0; i < 2; i++ {
		if resp := c.do(c.signedReq("GET", "/v1/usage", nil)); resp.StatusCode != http.StatusOK {
			t.Fatalf("usage %d status=%d, want 200", i+1, resp.StatusCode)
		}
	}
	resp := c.do(c.signedReq("GET", "/v1/usage", nil))
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("usage 3 status=%d, want 429", resp.StatusCode)
	}
	if ra := resp.Header.Get("Retry-After"); ra == "" {
		t.Fatal("429 missing Retry-After header")
	}
}

// TestRateLimitPerDevice proves the per-device cap gates the authenticated
// surface independently of the account budget.
func TestRateLimitPerDevice(t *testing.T) {
	h := newHarnessRL(t, api.RateLimitConfig{Window: time.Minute, DevicePerWindow: 2})
	c := h.login(t, "rl-device")

	for i := 0; i < 2; i++ {
		if resp := c.do(c.signedReq("GET", "/v1/usage", nil)); resp.StatusCode != http.StatusOK {
			t.Fatalf("usage %d status=%d, want 200", i+1, resp.StatusCode)
		}
	}
	if resp := c.do(c.signedReq("GET", "/v1/usage", nil)); resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("usage 3 status=%d, want 429 (per-device)", resp.StatusCode)
	}
}

// TestSubmitBlockedByGlobalKillSwitch proves the API refuses NEW job
// submissions with an honest 503 while the global free-tier kill switch is on,
// and admits again once it is flipped off. Rate limiting is disabled here
// (newHarness) so only the kill switch is under test.
func TestSubmitBlockedByGlobalKillSwitch(t *testing.T) {
	h := newHarness(t)
	c := h.login(t, "kill-karl")
	raw, ud, cd := makeEnvelope(t, false)
	c.previewConfirm(t, ud, cd, []string{"structural_activity_insights"})

	// Flip the global kill switch ON (operator control-plane action).
	if err := h.store.SetKillSwitch(context.Background(), "global", "all", true); err != nil {
		t.Fatalf("SetKillSwitch on: %v", err)
	}
	resp := c.do(c.signedReq("POST", "/v1/intelligence/jobs", raw))
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("submit under kill switch status=%d, want 503 body=%s", resp.StatusCode, readAll(resp))
	}
	var body struct {
		Code string `json:"code"`
	}
	decode(t, resp, &body)
	if body.Code != "service_paused" {
		t.Fatalf("kill-switch code=%q, want service_paused", body.Code)
	}

	// Flip it OFF ⇒ submission is admitted again.
	if err := h.store.SetKillSwitch(context.Background(), "global", "all", false); err != nil {
		t.Fatalf("SetKillSwitch off: %v", err)
	}
	if resp := c.do(c.signedReq("POST", "/v1/intelligence/jobs", raw)); resp.StatusCode != http.StatusAccepted {
		t.Fatalf("submit after kill switch off status=%d, want 202 body=%s", resp.StatusCode, readAll(resp))
	}
}
