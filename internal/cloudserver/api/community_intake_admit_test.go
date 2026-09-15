package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
)

// community_intake_admit_test.go covers the HTTP surface of the Sol re-review
// server fixes: the single admission transaction's cross-device rejection through
// two PoP principals (N8b), the Sol F9 recovery-hint body, and the N5 grant-terms
// header bindings (UTC-only declared timezone + the source-window rule).

// postContributionWith POSTs sealed bytes with the grant-binding headers plus any
// extra headers (used to exercise the declared-timezone / source-window-rule
// bindings).
func (c *testClient) postContributionWith(body []byte, generation int64, dictionary string, extra map[string]string) *http.Response {
	c.t.Helper()
	req := c.signedReq("POST", "/v1/community/contribution", body)
	req.Header.Set("SBO-Consent-Generation", strconv.FormatInt(generation, 10))
	req.Header.Set("SBO-Data-Dictionary-Digest", dictionary)
	req.Header.Set("SBO-Feature", "community_contribution")
	// Defaults mirror what the node CLI always sends (Sol N1/N5); `extra`
	// overrides them, and an explicit empty value removes the header so the
	// required-rule path can be exercised.
	req.Header.Set("SBO-Source-Window-Rule", "in_progress_utc_month_after_grant")
	req.Header.Set("SBO-Declared-Timezone", "UTC")
	for k, v := range extra {
		if v == "" {
			req.Header.Del(k)
			continue
		}
		req.Header.Set(k, v)
	}
	return c.do(req)
}

// TestCommunityContributionCrossDeviceConflictHTTP drives the Sol F9/N8b
// cross-device rejection through TWO signed-in devices on ONE account (the same
// dev subject re-exchanges to the same account with a fresh device key). The
// second device is refused with the honest 409 recovery body, the first device's
// value is untouched, and — Sol N3 — the losing device's grant was rolled back
// (only one grant remains on the account).
func TestCommunityContributionCrossDeviceConflictHTTP(t *testing.T) {
	h := newHarness(t)
	a := h.login(t, "dup-cross")
	b := h.login(t, "dup-cross")
	if a.accountID != b.accountID {
		t.Fatalf("expected two devices on ONE account, got %s vs %s", a.accountID, b.accountID)
	}
	window := currentWindow()

	if resp := a.contribute(sealCommunity(t, baseContribution(window, 3.5))); resp.StatusCode != http.StatusAccepted {
		t.Fatalf("device A contribution status=%d, want 202; body=%s", resp.StatusCode, readAll(resp))
	}

	resp := b.contribute(sealCommunity(t, baseContribution(window, 9.9)))
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("device B status=%d, want 409; body=%s", resp.StatusCode, readAll(resp))
	}
	var body struct {
		Error           string `json:"error"`
		Code            string `json:"code"`
		OwnerDeviceHint string `json:"owner_device_hint"`
		NextWindow      string `json:"next_window"`
	}
	if err := json.Unmarshal([]byte(readAll(resp)), &body); err != nil {
		t.Fatalf("decode conflict body: %v", err)
	}
	if body.Code != "cross_device_conflict" {
		t.Fatalf("code=%q, want cross_device_conflict", body.Code)
	}
	// F9 honesty: the body must carry an owner hint and the next writable window.
	if len(body.OwnerDeviceHint) != 8 {
		t.Fatalf("owner_device_hint=%q, want an 8-char hint", body.OwnerDeviceHint)
	}
	if want := time.Now().UTC().AddDate(0, 1, 0).Format("2006-01"); body.NextWindow != want {
		t.Fatalf("next_window=%q, want %q", body.NextWindow, want)
	}
	if body.Error == "" {
		t.Fatalf("conflict body carried no recovery message")
	}

	// Device A's value is untouched (first device wins).
	got, err := h.store.AccountContribution(context.Background(), a.accountID, "global", "sessions_per_active_day", 1, window)
	if err != nil || got != 3.5 {
		t.Fatalf("device A value=%v err=%v after B's refused write, want 3.5", got, err)
	}
	// Sol N3: device B's grant was rolled back — only device A's grant remains.
	grants, err := h.store.ListCommunityGrants(context.Background(), a.accountID)
	if err != nil {
		t.Fatalf("ListCommunityGrants: %v", err)
	}
	if len(grants) != 1 {
		t.Fatalf("account has %d grants after B's refusal, want 1 (device B rolled back)", len(grants))
	}
}

// TestCommunityContributionHeaderBindings covers the Sol N5 additive grant-terms
// bindings: the declared timezone is UTC-only for this purpose, and a present
// source-window rule must name the expected in-progress-UTC-month rule, and a
// MISSING rule is a clean 400 (communityRequireSourceWindowRule — the node has
// sent the rule since the same release).
func TestCommunityContributionHeaderBindings(t *testing.T) {
	dict := cloudcontract.CommunityDataDictionaryDigest()
	window := currentWindow()

	cases := []struct {
		name     string
		extra    map[string]string
		wantCode int
		wantErr  string // "" means expect 202 Accepted
	}{
		{
			name:     "non-UTC declared timezone refused",
			extra:    map[string]string{"SBO-Declared-Timezone": "Asia/Kolkata"},
			wantCode: http.StatusForbidden, wantErr: "grant_terms_mismatch",
		},
		{
			name:     "UTC declared timezone accepted",
			extra:    map[string]string{"SBO-Declared-Timezone": "UTC"},
			wantCode: http.StatusAccepted,
		},
		{
			name:     "unrecognized source-window rule refused",
			extra:    map[string]string{"SBO-Source-Window-Rule": "completed_utc_months_after_grant"},
			wantCode: http.StatusForbidden, wantErr: "grant_terms_mismatch",
		},
		{
			name:     "expected source-window rule accepted",
			extra:    map[string]string{"SBO-Source-Window-Rule": "in_progress_utc_month_after_grant"},
			wantCode: http.StatusAccepted,
		},
		{
			name:     "missing source-window rule refused",
			extra:    map[string]string{"SBO-Source-Window-Rule": ""},
			wantCode: http.StatusBadRequest, wantErr: "missing_source_window_rule",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			c := h.login(t, "hdr-bind")
			resp := c.postContributionWith(sealCommunity(t, baseContribution(window, 3.5)), 1, dict, tc.extra)
			if tc.wantErr == "" {
				if resp.StatusCode != http.StatusAccepted {
					t.Fatalf("status=%d, want 202; body=%s", resp.StatusCode, readAll(resp))
				}
				return
			}
			if got := errCodeOf(t, resp, tc.wantCode); got != tc.wantErr {
				t.Fatalf("error code=%q, want %q", got, tc.wantErr)
			}
		})
	}
}
