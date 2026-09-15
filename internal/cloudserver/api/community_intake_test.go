package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
)

// community_intake_test.go covers POST /v1/community/contribution (W5). It
// mirrors structural_test.go's discipline: canonical sealed bytes, the grant
// binding riding as headers, and the honest refusal code on every guard.

// sealCommunity computes the non-self-referential digest, embeds it, and returns
// the canonical upload bytes — exactly what the node serializer produces.
func sealCommunity(t *testing.T, c cloudcontract.CommunityContribution) []byte {
	t.Helper()
	c.Digest = ""
	d, err := cloudcontract.CommunityDigest(c)
	if err != nil {
		t.Fatalf("CommunityDigest: %v", err)
	}
	c.Digest = d
	b, err := cloudcontract.CommunityUploadBytes(c)
	if err != nil {
		t.Fatalf("CommunityUploadBytes: %v", err)
	}
	return b
}

func baseContribution(window string, value float64) cloudcontract.CommunityContribution {
	return cloudcontract.CommunityContribution{
		SchemaVersion: cloudcontract.CommunityContributionSchemaVersion,
		CohortKey:     "global",
		MetricID:      "sessions_per_active_day",
		MetricVersion: 1,
		WindowID:      window,
		Value:         value,
	}
}

// currentWindow is the in-progress UTC month — the only window UpsertContribution
// accepts.
func currentWindow() string { return time.Now().UTC().Format("2006-01") }

// postContribution POSTs sealed bytes with the two grant-binding headers.
func (c *testClient) postContribution(body []byte, generation int64, dictionary string) *http.Response {
	c.t.Helper()
	req := c.signedReq("POST", "/v1/community/contribution", body)
	req.Header.Set("SBO-Consent-Generation", strconv.FormatInt(generation, 10))
	req.Header.Set("SBO-Data-Dictionary-Digest", dictionary)
	req.Header.Set("SBO-Feature", "community_contribution")
	// The node CLI always sends the community rule + UTC (Sol N1/N5); the
	// server requires the rule (communityRequireSourceWindowRule).
	req.Header.Set("SBO-Source-Window-Rule", "in_progress_utc_month_after_grant")
	req.Header.Set("SBO-Declared-Timezone", "UTC")
	return c.do(req)
}

// contribute is the happy-path shorthand: generation 1, the service's own
// current community data dictionary.
func (c *testClient) contribute(body []byte) *http.Response {
	c.t.Helper()
	return c.postContribution(body, 1, cloudcontract.CommunityDataDictionaryDigest())
}

func TestCommunityContributionStores(t *testing.T) {
	h := newHarness(t)
	c := h.login(t, "contrib-alice")

	window := currentWindow()
	resp := c.contribute(sealCommunity(t, baseContribution(window, 3.5)))
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("status=%d, want 202; body=%s", resp.StatusCode, readAll(resp))
	}

	got, err := h.store.AccountContribution(context.Background(), c.accountID, "global", "sessions_per_active_day", 1, window)
	if err != nil {
		t.Fatalf("AccountContribution: %v", err)
	}
	if got != 3.5 {
		t.Fatalf("stored value=%v, want 3.5", got)
	}

	// The standing grant registered itself on the first contribution.
	grants, err := h.store.ListCommunityGrants(context.Background(), c.accountID)
	if err != nil {
		t.Fatalf("ListCommunityGrants: %v", err)
	}
	if len(grants) != 1 || grants[0].Purpose != string(cloudcontract.PurposeCohortBenchmarking) {
		t.Fatalf("registered grants = %+v, want one cohort-benchmarking grant", grants)
	}

	// A re-contribution updates the value in place (idempotent on the natural key).
	if resp := c.contribute(sealCommunity(t, baseContribution(window, 4.0))); resp.StatusCode != http.StatusAccepted {
		t.Fatalf("re-contribution status=%d, want 202", resp.StatusCode)
	}
	got, _ = h.store.AccountContribution(context.Background(), c.accountID, "global", "sessions_per_active_day", 1, window)
	if got != 4.0 {
		t.Fatalf("value after re-contribution=%v, want 4.0", got)
	}
}

func TestCommunityContributionGuards(t *testing.T) {
	window := currentWindow()
	tests := []struct {
		name     string
		build    func(t *testing.T, c *testClient) *http.Response
		wantCode int
		wantErr  string
	}{
		{
			name: "digest tamper",
			build: func(t *testing.T, c *testClient) *http.Response {
				// Embed a valid-shaped but WRONG digest: the bytes stay canonical
				// (so the noncanonical guard passes), but the embedded digest no
				// longer matches a recomputation over the values.
				k := baseContribution(window, 3.5)
				k.Digest = "sha256:" + strings.Repeat("0", 64)
				body, err := cloudcontract.CommunityUploadBytes(k)
				if err != nil {
					t.Fatalf("CommunityUploadBytes: %v", err)
				}
				return c.contribute(body)
			},
			wantCode: http.StatusUnprocessableEntity, wantErr: "digest_mismatch",
		},
		{
			name: "unknown cohort",
			build: func(t *testing.T, c *testClient) *http.Response {
				k := baseContribution(window, 3.5)
				k.CohortKey = "lang:cobol" // not a registered cohort
				return c.contribute(sealCommunity(t, k))
			},
			wantCode: http.StatusBadRequest, wantErr: "unknown_cohort",
		},
		{
			name: "unknown metric",
			build: func(t *testing.T, c *testClient) *http.Response {
				k := baseContribution(window, 3.5)
				k.MetricID = "not_a_metric"
				return c.contribute(sealCommunity(t, k))
			},
			wantCode: http.StatusBadRequest, wantErr: "unknown_metric",
		},
		{
			name: "missing consent generation",
			build: func(t *testing.T, c *testClient) *http.Response {
				body := sealCommunity(t, baseContribution(window, 3.5))
				req := c.signedReq("POST", "/v1/community/contribution", body)
				req.Header.Set("SBO-Data-Dictionary-Digest", cloudcontract.CommunityDataDictionaryDigest())
				return c.do(req)
			},
			wantCode: http.StatusBadRequest, wantErr: "missing_consent_generation",
		},
		{
			name: "dictionary mismatch",
			build: func(t *testing.T, c *testClient) *http.Response {
				return c.postContribution(sealCommunity(t, baseContribution(window, 3.5)), 1, "sha256:not-the-served-dictionary")
			},
			wantCode: http.StatusForbidden, wantErr: "data_dictionary_mismatch",
		},
		{
			name: "finalized window",
			build: func(t *testing.T, c *testClient) *http.Response {
				// A fully-elapsed past window is frozen; UpsertContribution refuses it.
				past := time.Now().UTC().AddDate(0, -2, 0).Format("2006-01")
				return c.contribute(sealCommunity(t, baseContribution(past, 3.5)))
			},
			wantCode: http.StatusConflict, wantErr: "window_not_current",
		},
		{
			name: "future window",
			build: func(t *testing.T, c *testClient) *http.Response {
				// Sol F10: a window that has not yet STARTED is rejected exactly like
				// one that has already elapsed — only the current in-progress month
				// is writable.
				future := time.Now().UTC().AddDate(0, 2, 0).Format("2006-01")
				return c.contribute(sealCommunity(t, baseContribution(future, 3.5)))
			},
			wantCode: http.StatusConflict, wantErr: "window_not_current",
		},
		{
			// Sol F12: verification_coverage_pct's own domain is [0,100] — narrower
			// than cloudcontract's shared, data-independent 1e9 sanity ceiling, which
			// a value of 101 would otherwise sail through.
			name: "metric out of domain",
			build: func(t *testing.T, c *testClient) *http.Response {
				k := baseContribution(window, 101)
				k.MetricID = "verification_coverage_pct"
				return c.contribute(sealCommunity(t, k))
			},
			wantCode: http.StatusBadRequest, wantErr: "metric_out_of_domain",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			c := h.login(t, "contrib-guard")
			resp := tc.build(t, c)
			if got := errCodeOf(t, resp, tc.wantCode); got != tc.wantErr {
				t.Fatalf("error code=%q, want %q", got, tc.wantErr)
			}
		})
	}
}

// TestCommunityContributionStaleGenerationRefused proves the monotonic-generation
// guard: after a grant registers at generation 2, a contribution declaring
// generation 1 is refused (nothing regresses).
func TestCommunityContributionStaleGenerationRefused(t *testing.T) {
	h := newHarness(t)
	c := h.login(t, "contrib-gen")
	window := currentWindow()
	dict := cloudcontract.CommunityDataDictionaryDigest()

	if resp := c.postContribution(sealCommunity(t, baseContribution(window, 3.5)), 2, dict); resp.StatusCode != http.StatusAccepted {
		t.Fatalf("gen-2 contribution status=%d, want 202; body=%s", resp.StatusCode, readAll(resp))
	}
	resp := c.postContribution(sealCommunity(t, baseContribution(window, 4.0)), 1, dict)
	if got := errCodeOf(t, resp, http.StatusConflict); got != "consent_generation_stale" {
		t.Fatalf("stale-gen error=%q, want consent_generation_stale", got)
	}
}

// TestCommunityContributionRejectedUploadDoesNotAdvanceGrant proves the Sol F7
// fix: window-currency (and domain) validation now runs BEFORE
// RegisterCommunityGrant, so a canonical-but-doomed request — here, a finalized
// past window carrying a very high consent generation — leaves NO grant
// creation/advance at all. Before the fix, registration committed first, then
// UpsertContribution 409'd; the grant was left registered/advanced at the huge
// generation, permanently stranding every legitimate lower-generation device
// (its future contributions would all read as stale).
func TestCommunityContributionRejectedUploadDoesNotAdvanceGrant(t *testing.T) {
	h := newHarness(t)
	c := h.login(t, "contrib-f7")
	dict := cloudcontract.CommunityDataDictionaryDigest()

	past := time.Now().UTC().AddDate(0, -2, 0).Format("2006-01")
	const doomedGeneration = int64(1) << 40 // absurdly high, would strand every other device
	resp := c.postContribution(sealCommunity(t, baseContribution(past, 3.5)), doomedGeneration, dict)
	if got := errCodeOf(t, resp, http.StatusConflict); got != "window_not_current" {
		t.Fatalf("error code=%q, want window_not_current", got)
	}

	grants, err := h.store.ListCommunityGrants(context.Background(), c.accountID)
	if err != nil {
		t.Fatalf("ListCommunityGrants: %v", err)
	}
	if len(grants) != 0 {
		t.Fatalf("rejected upload registered/advanced %d grant(s) at generation %d — F7 regression", len(grants), doomedGeneration)
	}

	// A legitimate, lower-generation contribution to the CURRENT window must
	// still be accepted afterward — proving no grant was left behind to strand it.
	window := currentWindow()
	if resp := c.postContribution(sealCommunity(t, baseContribution(window, 3.5)), 1, dict); resp.StatusCode != http.StatusAccepted {
		t.Fatalf("legitimate low-generation contribution status=%d, want 202; body=%s", resp.StatusCode, readAll(resp))
	}
}

// noncanonical bytes: a body whose values match the digest but whose framing is
// not the canonical serialization is refused (defends the store against
// persisting bytes the node never digested).
func TestCommunityContributionNoncanonicalRejected(t *testing.T) {
	h := newHarness(t)
	c := h.login(t, "contrib-canon")
	window := currentWindow()

	sealed := sealCommunity(t, baseContribution(window, 3.5))
	// Re-frame the JSON: unmarshal and re-marshal COMPACT (no indentation), which
	// carries the same values (and thus the same embedded digest) but is not the
	// canonical indented serialization.
	var m map[string]any
	if err := json.Unmarshal(sealed, &m); err != nil {
		t.Fatalf("unmarshal sealed: %v", err)
	}
	compact, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("re-marshal compact: %v", err)
	}
	resp := c.contribute(compact)
	if got := errCodeOf(t, resp, http.StatusUnprocessableEntity); got != "noncanonical_bytes" {
		t.Fatalf("error code=%q, want noncanonical_bytes", got)
	}
}
