package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// validResultJSON marshals a result that survives toResultRecord's Normalize
// (schema version + valid confidence + non-empty title), so the results handler
// returns 200 rather than the "corrupt result row" 500 a raw stub would trip.
func validResultJSON(t *testing.T, title string) []byte {
	t.Helper()
	b, err := json.Marshal(cloudcontract.Result{
		Title:         title,
		Confidence:    cloudcontract.ConfidenceMedium,
		SchemaVersion: cloudcontract.ResultSchemaVersion,
	})
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	return b
}

// raiseCaps lifts an account's allowance so seeding several results doesn't trip
// the default daily cap (mirrors the store suite's setEntitlement).
func raiseCaps(t *testing.T, h *harness, accountID string) {
	t.Helper()
	if _, err := h.store.Pool().Exec(context.Background(),
		`UPDATE entitlements SET daily_cap=1000, monthly_cap=10000, concurrency_cap=1000, overrides_plan=true
		  WHERE account_id=$1::uuid AND feature='session_enrichment'`, accountID); err != nil {
		t.Fatalf("raiseCaps: %v", err)
	}
}

// seedResult drives one job for accountID to a stored result via the store
// (submit → lease → running → complete). Completing before the next submit keeps
// exactly one job queued, so the lease is deterministic.
func seedResult(t *testing.T, h *harness, accountID, key string) {
	t.Helper()
	ctx := context.Background()
	now := time.Now()
	if _, err := h.store.SubmitJob(ctx, store.SubmitJobInput{
		AccountID: accountID, CloudProjectID: "p", CloudSessionID: "cs-" + key,
		Tool: "codex", ModelFamily: "gpt-5.6", Feature: store.FeatureSessionEnrichment,
		RouteID: "session_enrichment.luna.v1", RouteVersion: 1, PromptVersion: 1,
		CanonicalKey: key, UploadDigest: "sha256:" + key, ContentDigest: "sha256:c",
		BlobRef: "evidence/" + key, SizeBytes: 4, EvidenceBytes: []byte(`{"a":1}`),
		ConsentGeneration: 0, Now: now,
	}); err != nil {
		t.Fatalf("SubmitJob(%s): %v", key, err)
	}
	lj, err := h.store.LeaseNextJob(ctx, "w1", []string{store.FeatureSessionEnrichment}, time.Hour, now)
	if err != nil || lj == nil || lj.AccountID != accountID {
		t.Fatalf("lease(%s): %v (lj=%v)", key, err, lj)
	}
	if err := h.store.MarkJobRunning(ctx, accountID, lj.JobID, now); err != nil {
		t.Fatalf("mark running(%s): %v", key, err)
	}
	_, committed, err := h.store.CompleteJobWithResult(ctx, accountID, lj.JobID, lj.EvidencePK, lj.ReservationID,
		"w1", lj.LeaseGeneration, "session_enrichment.v2-candidate",
		validResultJSON(t, key), store.ResultProvenance{}, now)
	if err != nil || !committed {
		t.Fatalf("complete(%s): err=%v committed=%v", key, err, committed)
	}
}

type resultsPage struct {
	Results    []cloudcontract.ResultRecord `json:"results"`
	NextCursor string                       `json:"next_cursor"`
}

func getResults(t *testing.T, c *testClient, after string) resultsPage {
	t.Helper()
	path := "/v1/results"
	if after != "" {
		path += "?after=" + after
	}
	resp := c.do(c.signedReq("GET", path, nil))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("results status=%d body=%s", resp.StatusCode, readAll(resp))
	}
	var page resultsPage
	decode(t, resp, &page)
	return page
}

// TestW6bResultsDualReadCursorPaths exercises the E1 / W6b dual-read handler:
//
//	empty          ⇒ account path from 0, next_cursor "v2:<n>"
//	"v2:<n>"       ⇒ account path from that account_seq
//	bare "<n>"     ⇒ legacy global-seq path, next_cursor a bare decimal
//	malformed      ⇒ 400 bad_cursor
//
// and asserts every record carries BOTH cursor (legacy int64) and account_cursor
// ("v2:<n>").
func TestW6bResultsDualReadCursorPaths(t *testing.T) {
	h := newHarness(t)
	c := h.login(t, "w6b-dualread")
	raiseCaps(t, h, c.accountID)

	seedResult(t, h, c.accountID, "r1")
	seedResult(t, h, c.accountID, "r2")
	seedResult(t, h, c.accountID, "r3")

	// Empty after ⇒ account path from 0 ⇒ all three, next_cursor "v2:3".
	page := getResults(t, c, "")
	if len(page.Results) != 3 {
		t.Fatalf("empty after: want 3 results, got %d", len(page.Results))
	}
	if page.NextCursor != "v2:3" {
		t.Fatalf("empty after: next_cursor=%q, want v2:3", page.NextCursor)
	}
	for i, rec := range page.Results {
		wantAcct := "v2:" + itoa(i+1)
		if rec.AccountCursor != wantAcct {
			t.Fatalf("record %d: account_cursor=%q, want %q", i, rec.AccountCursor, wantAcct)
		}
		if rec.Cursor == 0 {
			t.Fatalf("record %d: legacy Cursor (global seq) must be carried alongside account_cursor, got 0", i)
		}
	}
	// Capture the first record's GLOBAL seq for the legacy-path assertion.
	firstGlobalSeq := page.Results[0].Cursor

	// after=v2:1 ⇒ account path ⇒ account_seq 2,3.
	page = getResults(t, c, "v2:1")
	if len(page.Results) != 2 {
		t.Fatalf("after=v2:1: want 2 results, got %d", len(page.Results))
	}
	if page.Results[0].AccountCursor != "v2:2" || page.Results[1].AccountCursor != "v2:3" {
		t.Fatalf("after=v2:1: got account_cursors %q,%q want v2:2,v2:3",
			page.Results[0].AccountCursor, page.Results[1].AccountCursor)
	}
	if page.NextCursor != "v2:3" {
		t.Fatalf("after=v2:1: next_cursor=%q, want v2:3", page.NextCursor)
	}

	// Bare decimal ⇒ LEGACY global-seq path. Passing the first row's global seq
	// returns the two later rows, and next_cursor is a BARE decimal (no v2:).
	page = getResults(t, c, itoa64(firstGlobalSeq))
	if len(page.Results) != 2 {
		t.Fatalf("legacy after=%d: want 2 results, got %d", firstGlobalSeq, len(page.Results))
	}
	if page.NextCursor == "" || page.NextCursor[0] == 'v' {
		t.Fatalf("legacy path: next_cursor=%q must be a bare decimal, not v2:-prefixed", page.NextCursor)
	}
	// The legacy next_cursor equals the last row's global seq.
	if page.NextCursor != itoa64(page.Results[1].Cursor) {
		t.Fatalf("legacy next_cursor=%q, want %d (last global seq)", page.NextCursor, page.Results[1].Cursor)
	}

	// Malformed cursors ⇒ 400 bad_cursor (both a non-numeric bare token and a
	// non-numeric v2 payload).
	for _, bad := range []string{"not-a-number", "v2:xyz"} {
		resp := c.do(c.signedReq("GET", "/v1/results?after="+bad, nil))
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("after=%q: status=%d, want 400", bad, resp.StatusCode)
		}
		if code := errCodeOf(t, resp, http.StatusBadRequest); code != "bad_cursor" {
			t.Fatalf("after=%q: error code=%q, want bad_cursor", bad, code)
		}
	}
}

// TestW6bResultsAccountCursorIsSideChannelFree confirms the account cursor a
// tenant sees is its OWN dense sequence, independent of another tenant's volume
// (E1). Account A sees v2:1,v2:2 regardless of how many results account B
// produced in between.
func TestW6bResultsAccountCursorIsSideChannelFree(t *testing.T) {
	h := newHarness(t)
	a := h.login(t, "w6b-tenant-a")
	b := h.login(t, "w6b-tenant-b")
	raiseCaps(t, h, a.accountID)
	raiseCaps(t, h, b.accountID)

	seedResult(t, h, a.accountID, "a1")
	for i := 0; i < 4; i++ {
		seedResult(t, h, b.accountID, "b"+itoa(i))
	}
	seedResult(t, h, a.accountID, "a2")

	page := getResults(t, a, "")
	if len(page.Results) != 2 {
		t.Fatalf("tenant A: want 2 results, got %d", len(page.Results))
	}
	if page.Results[0].AccountCursor != "v2:1" || page.Results[1].AccountCursor != "v2:2" {
		t.Fatalf("tenant A account_cursors leaked B's volume: got %q,%q want v2:1,v2:2",
			page.Results[0].AccountCursor, page.Results[1].AccountCursor)
	}
	if page.NextCursor != "v2:2" {
		t.Fatalf("tenant A next_cursor=%q, want v2:2 (unaffected by B's 4 results)", page.NextCursor)
	}
}

// small int→string helpers to avoid importing strconv into the test's prose.
func itoa(n int) string { return itoa64(int64(n)) }

func itoa64(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
