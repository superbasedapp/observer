package orgclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// THE NODE INTELLIGENCE RESULT RAIL, node half (org-served-cloud-intelligence
// plan §2.4, W3). Every rung of the pricing-shaped ladder gets a case; the one
// that most matters is 404, which must leave any cached results untouched (a
// 404 is indistinguishable from a pre-feature server).

// intelServer is a settable fake for GET /api/agent/intel/results.
type intelServer struct {
	srv      *httptest.Server
	status   int
	body     orgcontract.IntelResultsResponse
	raw      string // when non-empty, served verbatim instead of body (malformed tests)
	gotSince string
	hits     int
}

func newIntelServer(t *testing.T) *intelServer {
	t.Helper()
	is := &intelServer{status: http.StatusOK}
	is.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/agent/intel/results" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		is.hits++
		is.gotSince = r.URL.Query().Get("since")
		if is.status != http.StatusOK {
			w.WriteHeader(is.status)
			return
		}
		if is.raw != "" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(is.raw))
			return
		}
		writeTestJSON(w, http.StatusOK, is.body)
	}))
	t.Cleanup(is.srv.Close)
	return is
}

// enrolledIntelClient stands up an enrolled client WITH a signing key (the
// rail signs a per-request proof) pointed at the fake server, with the rail on.
func enrolledIntelClient(t *testing.T, srvURL string) (*Client, *store.Store) {
	t.Helper()
	s := newAgentStore(t)
	if err := s.WriteEnrolment(context.Background(), store.Enrolment{
		OrgID: "org-1", OrgName: "Acme", OrgServerURL: srvURL,
		UserID: "scim-42", UserEmail: "dev@acme.example",
		EnrolledAt: time.Now().UTC().Format(time.RFC3339), BearerKeyID: "test",
	}); err != nil {
		t.Fatalf("WriteEnrolment: %v", err)
	}
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	bs := &memBearerStore{bearer: "bearer-xyz", key: key}
	c := newTestClient(t, s, bs)
	c.SetIntelRail(func() bool { return true })
	return c, s
}

func TestFetchIntelResultsLadder(t *testing.T) {
	cases := []struct {
		name   string
		status int
		want   string
		// wantErr: the 404 not_supported rung is deliberately errorless (it is
		// the "pre-feature server, never clear" posture, not a failure to log),
		// exactly like the pricing rail's 404. Every genuine failure rung
		// returns an error for logging (fail-open).
		wantErr bool
	}{
		{"ok", http.StatusOK, IntelFetchOK, false},
		{"not_supported", http.StatusNotFound, IntelFetchNotSupported, false},
		{"auth_failed_401", http.StatusUnauthorized, IntelFetchAuthFailed, true},
		{"auth_failed_403", http.StatusForbidden, IntelFetchAuthFailed, true},
		{"channel_off", http.StatusConflict, IntelFetchChannelOff, true},
		{"unreachable_5xx", http.StatusBadGateway, IntelFetchUnreachable, true},
		{"unreachable_429", http.StatusTooManyRequests, IntelFetchUnreachable, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			is := newIntelServer(t)
			is.status = tc.status
			c, _ := enrolledIntelClient(t, is.srv.URL)
			out, err := c.FetchIntelResults(context.Background())
			if out.State != tc.want {
				t.Fatalf("state=%q, want %q (err=%v)", out.State, tc.want, err)
			}
			if tc.wantErr && err == nil {
				t.Fatalf("rung %q returned no error", tc.want)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("rung %q returned an unexpected error: %v", tc.want, err)
			}
		})
	}
}

func TestFetchIntelResultsDisabledMakesNoRequest(t *testing.T) {
	is := newIntelServer(t)
	c, _ := enrolledIntelClient(t, is.srv.URL)
	c.SetIntelRail(func() bool { return false }) // opt back out
	out, err := c.FetchIntelResults(context.Background())
	if err != nil || out.State != IntelFetchDisabled {
		t.Fatalf("state=%q err=%v, want disabled/no-error", out.State, err)
	}
	if is.hits != 0 {
		t.Fatalf("a disabled rail made %d requests, want 0", is.hits)
	}
}

func TestFetchIntelResultsNilGateMakesNoRequest(t *testing.T) {
	is := newIntelServer(t)
	c, _ := enrolledIntelClient(t, is.srv.URL)
	c.SetIntelRail(nil) // no gate installed at all
	out, _ := c.FetchIntelResults(context.Background())
	if out.State != IntelFetchDisabled || is.hits != 0 {
		t.Fatalf("nil gate: state=%q hits=%d, want disabled/0", out.State, is.hits)
	}
}

func TestFetchIntelResultsOKUpsertsAndAdvancesCursor(t *testing.T) {
	is := newIntelServer(t)
	is.body = orgcontract.IntelResultsResponse{
		Results: []orgcontract.IntelResultRow{
			{SessionID: "s1", JobID: "j1", Title: "first", TaxonomyTags: []string{"bugfix"}, Confidence: "high", GeneratedAt: "2026-09-11T10:00:00Z"},
			{SessionID: "s1", JobID: "j2", Title: "second", GeneratedAt: "2026-09-11T11:00:00Z"},
		},
		NextCursor: "2026-09-11T11:00:00Z",
	}
	c, s := enrolledIntelClient(t, is.srv.URL)

	out, err := c.FetchIntelResults(context.Background())
	if err != nil {
		t.Fatalf("FetchIntelResults: %v", err)
	}
	if out.State != IntelFetchOK || out.Applied != 2 {
		t.Fatalf("outcome=%+v, want ok/applied=2", out)
	}
	rows, err := s.OrgIntelResultsForSession(context.Background(), "s1")
	if err != nil {
		t.Fatalf("OrgIntelResultsForSession: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("cached rows=%d, want 2", len(rows))
	}

	// Second cycle must carry the advanced cursor.
	is.body = orgcontract.IntelResultsResponse{} // nothing new
	if _, err := c.FetchIntelResults(context.Background()); err != nil {
		t.Fatalf("second fetch: %v", err)
	}
	if is.gotSince != "2026-09-11T11:00:00Z" {
		t.Fatalf("since=%q, want the advanced cursor", is.gotSince)
	}
}

// The 404-leaves-the-cache-untouched invariant: a cached result survives a 404
// (pre-feature server / feature off). This is the rung the no-clear rule exists
// for.
func TestFetchIntelResults404LeavesCacheUntouched(t *testing.T) {
	is := newIntelServer(t)
	c, s := enrolledIntelClient(t, is.srv.URL)
	// Seed a cached result directly through the store seam, bound to THIS node's
	// enrolment org so the identity-guard keeps it (finding 6): a row stamped
	// with the current org is not foreign and is never swept on a fetch.
	if err := s.UpsertOrgIntelResult(context.Background(), store.OrgIntelResult{
		OrgID: "org-1", SessionID: "s9", JobID: "j9", Title: "kept", SchemaVersion: "v2",
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	is.status = http.StatusNotFound
	out, err := c.FetchIntelResults(context.Background())
	if err != nil {
		t.Fatalf("404 must be fail-open (no error), got %v", err)
	}
	if out.State != IntelFetchNotSupported {
		t.Fatalf("state=%q, want not_supported", out.State)
	}
	rows, err := s.OrgIntelResultsForSession(context.Background(), "s9")
	if err != nil || len(rows) != 1 || rows[0].Title != "kept" {
		t.Fatalf("404 cleared or mutated the cache: rows=%+v err=%v", rows, err)
	}
}

func TestFetchIntelResultsMalformedBody(t *testing.T) {
	is := newIntelServer(t)
	is.raw = "{not json"
	c, _ := enrolledIntelClient(t, is.srv.URL)
	out, err := c.FetchIntelResults(context.Background())
	if out.State != IntelFetchMalformed || err == nil {
		t.Fatalf("state=%q err=%v, want malformed/error", out.State, err)
	}
}

func TestFetchIntelResultsNotEnrolled(t *testing.T) {
	is := newIntelServer(t)
	s := newAgentStore(t) // no enrolment written
	c := newTestClient(t, s, &memBearerStore{bearer: "b"})
	c.SetIntelRail(func() bool { return true })
	out, _ := c.FetchIntelResults(context.Background())
	if out.State != IntelFetchNotEnrolled {
		t.Fatalf("state=%q, want not_enrolled", out.State)
	}
	if is.hits != 0 {
		t.Fatalf("an unenrolled node hit the server %d times", is.hits)
	}
}

// round-trip sanity: the wire row maps cleanly into the store row.
func TestIntelResultRowMapsToStoreRow(t *testing.T) {
	row := orgcontract.IntelResultRow{
		SessionID: "s", JobID: "j", Title: "t",
		TaxonomyTags: []string{"a"}, SuggestedTags: []string{"b"},
		Limitations: []string{"c"}, Confidence: "low", SchemaVersion: "v2",
	}
	b, _ := json.Marshal(row)
	var back orgcontract.IntelResultRow
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("round-trip: %v", err)
	}
	if back.SessionID != "s" || back.JobID != "j" || len(back.TaxonomyTags) != 1 {
		t.Fatalf("round-trip lost fields: %+v", back)
	}
}

// TestFetchIntelResultsFailedWriteRetainsCursor pins finding 5: when a row in a
// page fails to persist (here a hostile field the node-side SafeText gate
// rejects), the cursor is NOT advanced, so the next cycle re-fetches the page
// and retries the failed row. A later clean page then advances the cursor.
func TestFetchIntelResultsFailedWriteRetainsCursor(t *testing.T) {
	is := newIntelServer(t)
	// One good row and one hostile row (ANSI control in the title): the hostile
	// row is rejected by the node writer, so the page is NOT fully persisted.
	is.body = orgcontract.IntelResultsResponse{
		Results: []orgcontract.IntelResultRow{
			{SessionID: "s1", JobID: "j1", Title: "clean"},
			{SessionID: "s2", JobID: "j2", Title: "bad \x1b[31mANSI"},
		},
		NextCursor: "cursor-1",
	}
	c, s := enrolledIntelClient(t, is.srv.URL)

	out, err := c.FetchIntelResults(context.Background())
	if err != nil {
		t.Fatalf("FetchIntelResults: %v", err)
	}
	if out.State != IntelFetchOK || out.Applied != 1 {
		t.Fatalf("outcome=%+v, want ok/applied=1 (one good, one rejected)", out)
	}
	// Cursor must NOT have advanced — a failed row holds it back (finding 5).
	if c.intelSince != "" {
		t.Fatalf("cursor advanced to %q despite a failed write; want retained (empty)", c.intelSince)
	}
	if out.NextCursor != "" {
		t.Fatalf("outcome reported NextCursor=%q despite a failed write", out.NextCursor)
	}

	// Recovery: the server now returns a clean page; the cursor advances.
	is.body = orgcontract.IntelResultsResponse{
		Results: []orgcontract.IntelResultRow{
			{SessionID: "s1", JobID: "j1", Title: "clean"},
			{SessionID: "s2", JobID: "j2", Title: "now clean"},
		},
		NextCursor: "cursor-1",
	}
	out2, err := c.FetchIntelResults(context.Background())
	if err != nil {
		t.Fatalf("recovery fetch: %v", err)
	}
	if out2.State != IntelFetchOK || out2.Applied != 2 {
		t.Fatalf("recovery outcome=%+v, want ok/applied=2", out2)
	}
	if c.intelSince != "cursor-1" {
		t.Fatalf("cursor=%q after recovery, want advanced to cursor-1", c.intelSince)
	}
	// The previously-failed row is now cached.
	rows, _ := s.OrgIntelResultsForSession(context.Background(), "s2")
	if len(rows) != 1 || rows[0].Title != "now clean" {
		t.Fatalf("recovered row not cached: %+v", rows)
	}
}

// TestDecideIntelReject is the table over the PURE dead-letter rule. Each row
// is one (prior attempts, threshold) pair and the verdict it must produce. The
// two rules that matter: a row is held (cursor retained) while it is still
// under the threshold, and released exactly once it reaches it — never earlier
// (which would drop a row a single transient write error would have stored) and
// never later (which is the freeze the bound exists to prevent).
func TestDecideIntelReject(t *testing.T) {
	for _, tc := range []struct {
		name      string
		prior     int
		threshold int
		want      intelRejectVerdict
	}{
		{"first failure holds", 0, 3, intelRejectVerdict{Attempts: 1, DeadLetter: false, HoldCursor: true}},
		{"second failure holds", 1, 3, intelRejectVerdict{Attempts: 2, DeadLetter: false, HoldCursor: true}},
		{"third failure dead-letters", 2, 3, intelRejectVerdict{Attempts: 3, DeadLetter: true, HoldCursor: false}},
		{"past the threshold stays dead", 7, 3, intelRejectVerdict{Attempts: 8, DeadLetter: true, HoldCursor: false}},
		{"threshold of one dead-letters immediately", 0, 1, intelRejectVerdict{Attempts: 1, DeadLetter: true, HoldCursor: false}},
		// A non-positive threshold must NOT mean "dead-letter on sight" — it
		// falls back to the default, so a mis-wired caller loses no row.
		{"zero threshold falls back to the default", 0, 0, intelRejectVerdict{Attempts: 1, DeadLetter: false, HoldCursor: true}},
		{"negative threshold falls back to the default", 2, -5, intelRejectVerdict{Attempts: 3, DeadLetter: true, HoldCursor: false}},
		{"negative prior count is clamped", -4, 3, intelRejectVerdict{Attempts: 1, DeadLetter: false, HoldCursor: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := decideIntelReject(tc.prior, tc.threshold); got != tc.want {
				t.Errorf("decideIntelReject(%d, %d) = %+v, want %+v", tc.prior, tc.threshold, got, tc.want)
			}
		})
	}
}

// TestFetchIntelResultsDeadLettersUnpersistableRow pins the bound: a row the
// node can NEVER persist (here, an ANSI control the SafeText gate refuses on
// every attempt) must not hold the cursor forever. Without the bound the same
// page is re-fetched and re-rejected every cycle and the rail FREEZES — the node
// stops receiving any later result for the daemon's lifetime, which is a strictly
// worse outcome than not caching the one bad row.
func TestFetchIntelResultsDeadLettersUnpersistableRow(t *testing.T) {
	is := newIntelServer(t)
	is.body = orgcontract.IntelResultsResponse{
		Results: []orgcontract.IntelResultRow{
			{SessionID: "s1", JobID: "j1", Title: "clean"},
			// Permanently unpersistable: an ANSI escape in a narrative item,
			// which is exactly the surface this wave widened (five lists).
			{SessionID: "s2", JobID: "j2", Title: "ok", NextSteps: []string{"bad \x1b[31mANSI"}},
		},
		NextCursor: "cursor-1",
	}
	c, s := enrolledIntelClient(t, is.srv.URL)
	ctx := context.Background()

	// Cycles 1 and 2: still retryable, so the cursor is held.
	for i := 1; i <= intelDeadLetterAfter-1; i++ {
		out, err := c.FetchIntelResults(ctx)
		if err != nil {
			t.Fatalf("cycle %d: %v", i, err)
		}
		if out.DeadLettered != 0 {
			t.Fatalf("cycle %d dead-lettered %d rows too early", i, out.DeadLettered)
		}
		if c.intelSince != "" {
			t.Fatalf("cycle %d advanced the cursor to %q while the row was still retryable", i, c.intelSince)
		}
	}

	// Cycle 3 reaches the threshold: the row is dead-lettered and the cursor
	// is released so the rail can keep moving.
	out, err := c.FetchIntelResults(ctx)
	if err != nil {
		t.Fatalf("threshold cycle: %v", err)
	}
	if out.DeadLettered != 1 {
		t.Fatalf("outcome=%+v, want DeadLettered=1 at the threshold", out)
	}
	if out.Applied != 1 {
		t.Fatalf("outcome=%+v, want the good row still applied", out)
	}
	if c.intelSince != "cursor-1" || out.NextCursor != "cursor-1" {
		t.Fatalf("cursor=%q outcome.NextCursor=%q; a dead-lettered row must NOT hold the rail", c.intelSince, out.NextCursor)
	}
	// Fail-open: the dead-lettered row is simply absent, never half-stored.
	if rows, _ := s.OrgIntelResultsForSession(ctx, "s2"); len(rows) != 0 {
		t.Fatalf("a dead-lettered row was partially cached: %+v", rows)
	}
	// The good row from the same page is cached normally.
	if rows, _ := s.OrgIntelResultsForSession(ctx, "s1"); len(rows) != 1 {
		t.Fatalf("the good row on a page with a dead-letter was lost: %+v", rows)
	}
	// The strike is cleared once the row is given up on, so the bookkeeping
	// only ever holds rows currently failing.
	if _, still := c.intelRejects[intelRowKey{SessionID: "s2", JobID: "j2"}]; still {
		t.Error("a dead-lettered row kept its strike count")
	}
}

// TestFetchIntelResultsSuccessClearsRejectionStreak pins the other half of the
// bound: the count is CONSECUTIVE. A row that fails twice and then persists must
// start from zero the next time it fails, so an intermittently-failing row is
// never dead-lettered by accumulated, non-consecutive strikes.
func TestFetchIntelResultsSuccessClearsRejectionStreak(t *testing.T) {
	is := newIntelServer(t)
	bad := orgcontract.IntelResultsResponse{
		Results:    []orgcontract.IntelResultRow{{SessionID: "s1", JobID: "j1", Title: "bad \x1b[31mANSI"}},
		NextCursor: "cursor-1",
	}
	good := orgcontract.IntelResultsResponse{
		Results:    []orgcontract.IntelResultRow{{SessionID: "s1", JobID: "j1", Title: "now clean"}},
		NextCursor: "cursor-1",
	}
	c, _ := enrolledIntelClient(t, is.srv.URL)
	ctx := context.Background()
	key := intelRowKey{SessionID: "s1", JobID: "j1"}

	is.body = bad
	for i := 1; i <= intelDeadLetterAfter-1; i++ {
		if _, err := c.FetchIntelResults(ctx); err != nil {
			t.Fatalf("cycle %d: %v", i, err)
		}
	}
	if got := c.intelRejects[key]; got != intelDeadLetterAfter-1 {
		t.Fatalf("strike count = %d, want %d", got, intelDeadLetterAfter-1)
	}

	is.body = good
	if _, err := c.FetchIntelResults(ctx); err != nil {
		t.Fatalf("recovery cycle: %v", err)
	}
	if _, still := c.intelRejects[key]; still {
		t.Fatal("a successful persist did not clear the row's rejection streak")
	}

	// Failing again starts a FRESH streak: one more failure must still hold the
	// cursor, not dead-letter on the strength of the earlier strikes.
	c.intelSince = ""
	is.body = bad
	out, err := c.FetchIntelResults(ctx)
	if err != nil {
		t.Fatalf("post-recovery failure: %v", err)
	}
	if out.DeadLettered != 0 {
		t.Fatalf("outcome=%+v: non-consecutive strikes dead-lettered the row", out)
	}
	if got := c.intelRejects[key]; got != 1 {
		t.Fatalf("strike count after recovery = %d, want 1 (a fresh streak)", got)
	}
}

// TestFetchIntelResultsIdentityChangeResetsCursorAndDropsForeignRows pins
// finding 6: when the node re-enrols into a DIFFERENT org, the in-memory cursor
// resets and the previous org's cached rows are dropped, so org A's results can
// never render under org B.
func TestFetchIntelResultsIdentityChangeResetsCursorAndDropsForeignRows(t *testing.T) {
	is := newIntelServer(t)
	is.body = orgcontract.IntelResultsResponse{
		Results:    []orgcontract.IntelResultRow{{SessionID: "a1", JobID: "1", Title: "orgA"}},
		NextCursor: "cursorA",
	}
	c, s := enrolledIntelClient(t, is.srv.URL) // enrolled to org-1

	if _, err := c.FetchIntelResults(context.Background()); err != nil {
		t.Fatalf("first fetch: %v", err)
	}
	if c.intelSince != "cursorA" || c.intelCursorOrgID != "org-1" {
		t.Fatalf("after first fetch cursor=%q org=%q, want cursorA/org-1", c.intelSince, c.intelCursorOrgID)
	}

	// Re-enrol into a DIFFERENT org (same process, same server URL).
	if err := s.WriteEnrolment(context.Background(), store.Enrolment{
		OrgID: "org-2", OrgName: "Other", OrgServerURL: is.srv.URL,
		UserID: "scim-99", UserEmail: "dev@other.example",
		EnrolledAt: time.Now().UTC().Format(time.RFC3339), BearerKeyID: "test",
	}); err != nil {
		t.Fatalf("re-enrol: %v", err)
	}
	is.body = orgcontract.IntelResultsResponse{} // org-2 has nothing yet

	if _, err := c.FetchIntelResults(context.Background()); err != nil {
		t.Fatalf("post-re-enrol fetch: %v", err)
	}
	// The cursor reset to page org-2 from the start, and its bound org updated.
	if c.intelCursorOrgID != "org-2" {
		t.Fatalf("cursor org=%q, want org-2 after re-enrol", c.intelCursorOrgID)
	}
	if is.gotSince != "" {
		t.Fatalf("org-2 was paged with org-1's cursor %q; want reset", is.gotSince)
	}
	// org-1's cached row was dropped (foreign to org-2).
	if rows, _ := s.OrgIntelResultsForSession(context.Background(), "a1"); len(rows) != 0 {
		t.Fatalf("org-1 cached row survived a re-enrol into org-2: %+v", rows)
	}
}

// TestFetchIntelResultsRefusesObsoleteEnrolment pins finding 6's "refuse a
// response from an obsolete enrolment": if the enrolment changes org WHILE the
// request is in flight, the returned page belongs to an enrolment that is no
// longer current and is discarded without caching or advancing.
func TestFetchIntelResultsRefusesObsoleteEnrolment(t *testing.T) {
	s := newAgentStore(t)
	if err := s.WriteEnrolment(context.Background(), store.Enrolment{
		OrgID: "org-1", OrgName: "Acme", OrgServerURL: "http://replaced-below",
		UserID: "scim-42", UserEmail: "dev@acme.example",
		EnrolledAt: time.Now().UTC().Format(time.RFC3339), BearerKeyID: "test",
	}); err != nil {
		t.Fatalf("enrol: %v", err)
	}
	// The server, mid-request, re-enrols the node into a different org — so by
	// the time FetchIntelResults re-checks after decoding, the enrolment is
	// obsolete relative to the one the request was signed under.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = s.WriteEnrolment(r.Context(), store.Enrolment{
			OrgID: "org-2", OrgName: "Other", OrgServerURL: "http://replaced-below",
			UserID: "scim-42", UserEmail: "dev@acme.example",
			EnrolledAt: time.Now().UTC().Format(time.RFC3339), BearerKeyID: "test",
		})
		writeTestJSON(w, http.StatusOK, orgcontract.IntelResultsResponse{
			Results: []orgcontract.IntelResultRow{{SessionID: "x", JobID: "1", Title: "stale"}},
		})
	}))
	t.Cleanup(srv.Close)
	// Point the (still org-1) enrolment at the server.
	_ = s.WriteEnrolment(context.Background(), store.Enrolment{
		OrgID: "org-1", OrgName: "Acme", OrgServerURL: srv.URL,
		UserID: "scim-42", UserEmail: "dev@acme.example",
		EnrolledAt: time.Now().UTC().Format(time.RFC3339), BearerKeyID: "test",
	})
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	c := newTestClient(t, s, &memBearerStore{bearer: "b", key: key})
	c.SetIntelRail(func() bool { return true })

	out, err := c.FetchIntelResults(context.Background())
	if err != nil {
		t.Fatalf("FetchIntelResults: %v", err)
	}
	if out.State != IntelFetchIdentityChanged {
		t.Fatalf("state=%q, want identity_changed (obsolete enrolment refused)", out.State)
	}
	// The stale page was NOT cached.
	if rows, _ := s.OrgIntelResultsForSession(context.Background(), "x"); len(rows) != 0 {
		t.Fatalf("a page from an obsolete enrolment was cached: %+v", rows)
	}
}
