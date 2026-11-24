package store_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/availcompose"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/staffauth"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
	pc "github.com/marmutapp/superbased-observer/internal/platformcontract"
)

// availissue_test.go proves cloud 0154 and its store seam against a real
// PostgreSQL: the two tables' grants and role-bound policies, one pending
// request at a time, the staff request logged with its reason, the worker
// storing an envelope and the request's outcome in one transaction, the
// delivery state, and the per-org component toggle (SR-17). Skipped loudly
// without SBCI_TEST_PG_DSN.

func TestAvailabilityIssueTablesGrantsAndRLS(t *testing.T) {
	t.Parallel()
	_, pool := newStore(t)
	ctx := context.Background()
	tables := []struct {
		table  string
		grants map[string][]string
	}{
		{"availability_issue_requests", map[string][]string{"sbci_staff": {"SELECT", "INSERT"}, "sbci_worker": {"SELECT"}}},
		{"availability_deliveries", map[string][]string{"sbci_staff": {"SELECT"}, "sbci_worker": {"SELECT", "INSERT", "UPDATE"}}},
	}
	for _, c := range tables {
		var rls, force bool
		if err := pool.QueryRow(ctx, `SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE oid = $1::regclass`, c.table).Scan(&rls, &force); err != nil {
			t.Fatalf("%s: %v", c.table, err)
		}
		if !rls || !force {
			t.Errorf("%s: row-level security enabled %v forced %v, want both", c.table, rls, force)
		}
		for _, role := range []string{"sbci_api", "sbci_worker", "sbci_aggregator", "sbci_app", "sbci_staff"} {
			for _, p := range []string{"SELECT", "INSERT", "UPDATE", "DELETE"} {
				want := false
				for _, g := range c.grants[role] {
					want = want || g == p
				}
				if got := tableLevelPriv(t, pool, role, c.table, p); got != want {
					t.Errorf("%s table-level %s on %s = %v, want %v", role, p, c.table, got, want)
				}
			}
		}
	}
	// Column UPDATE: the worker finishes a request (outcome columns); staff
	// only cancel one (state, error class, done time; no result version).
	for _, c := range []struct {
		column        string
		worker, staff bool
	}{
		{"state", true, true},
		{"result_version", true, false},
		{"error_class", true, true},
		{"done_at", true, true},
		{"reason", false, false},
		{"inputs_digest", false, false},
		{"base_version", false, false},
		{"requested_by", false, false},
		{"requested_at", false, false},
		{"request_id", false, false},
	} {
		for role, want := range map[string]bool{"sbci_worker": c.worker, "sbci_staff": c.staff} {
			if got := columnPriv(t, pool, role, "availability_issue_requests", c.column, "UPDATE"); got != want {
				t.Errorf("%s UPDATE on availability_issue_requests.%s = %v, want %v", role, c.column, got, want)
			}
		}
	}
}

const (
	issOrgA = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	issOrgB = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
)

func newDocKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func TestAvailabilityIssueRoundTrip(t *testing.T) {
	t.Parallel()
	s, pool := newStore(t)
	w := newWorkerStore(t, pool)
	ctx := context.Background()
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	staffID, _ := registerTestStaff(t, s, staffauth.RoleOps, 61, now)

	in, err := staffauth.ValidateAvailabilityInput("components", "org.security", []byte(`{"reach":"named","orgs":["`+issOrgA+`"]}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetAvailabilityInput(ctx, staffID, in, "offer to A", now); err != nil {
		t.Fatal(err)
	}
	rows, err := w.AvailabilityInputsForIssue(ctx)
	if err != nil || len(rows) != 1 {
		t.Fatalf("worker inputs = %v, %v", rows, err)
	}
	inputs := []availcompose.Input{{Section: rows[0].Section, Key: rows[0].Key, Value: rows[0].Value, Reason: rows[0].Reason, Author: rows[0].Author}}
	digest := availcompose.Digest(inputs)

	// Staff: a request, logged; a second one while it is pending is refused.
	req, err := s.RequestAvailabilityIssue(ctx, staffID, store.AvailabilityIssueInput{Reason: "ship SR-17", InputsDigest: digest, BaseVersion: 0, Changes: 1}, now)
	if err != nil || req.State != store.IssueStatePending {
		t.Fatalf("RequestAvailabilityIssue = %+v, %v", req, err)
	}
	if _, err := s.RequestAvailabilityIssue(ctx, staffID, store.AvailabilityIssueInput{Reason: "again", InputsDigest: digest}, now); !errors.Is(err, store.ErrIssuePending) {
		t.Fatalf("second request = %v, want ErrIssuePending", err)
	}
	for _, bad := range []store.AvailabilityIssueInput{
		{Reason: " ", InputsDigest: digest},
		{Reason: "x", InputsDigest: "nothex"},
		{Reason: "x", InputsDigest: digest, BaseVersion: -1},
	} {
		if _, err := s.RequestAvailabilityIssue(ctx, staffID, bad, now); err == nil {
			t.Errorf("RequestAvailabilityIssue(%+v) accepted", bad)
		}
	}
	var logged int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM staff_actions WHERE verb = 'availability.issue_requested' AND reason = 'ship SR-17'
		AND detail->>'request_id' = $1 AND detail->>'inputs_digest' = $2`, req.RequestID, digest).Scan(&logged); err != nil || logged != 1 {
		t.Fatalf("issue_requested rows = %d (%v)", logged, err)
	}

	// Worker: the pending request, signed and stored with its outcome.
	pending, err := w.PendingAvailabilityIssue(ctx)
	if err != nil || pending.RequestID != req.RequestID || pending.RequestedBy != staffauth.Actor(staffID) || pending.InputsDigest != digest {
		t.Fatalf("PendingAvailabilityIssue = %+v, %v", pending, err)
	}
	composed, err := availcompose.Compose(inputs, now)
	if err != nil {
		t.Fatal(err)
	}
	priv := newDocKey(t)
	doc, err := pc.SignAvailability(priv, now.Unix(), composed.JSON)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.IssueAvailabilityDocument(ctx, req.RequestID, doc, pending.RequestedBy, now); err != nil {
		t.Fatalf("IssueAvailabilityDocument: %v", err)
	}
	if err := w.IssueAvailabilityDocument(ctx, req.RequestID, doc, pending.RequestedBy, now); !errors.Is(err, pc.ErrVersionNotNewer) {
		t.Fatalf("second store of the same version = %v, want ErrVersionNotNewer", err)
	}
	if _, err := w.PendingAvailabilityIssue(ctx); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("pending after issue = %v", err)
	}
	st, err := s.StaffAvailabilityIssueState(ctx)
	if err != nil || st.Pending != nil || st.Last == nil || st.Last.State != store.IssueStateIssued || st.Last.ResultVersion != doc.Version {
		t.Fatalf("issue state = %+v %v", st, err)
	}
	sd, err := s.StaffAvailabilityDocument(ctx)
	if err != nil || sd.Version != doc.Version || sd.IssuedBy != staffauth.Actor(staffID) {
		t.Fatalf("StaffAvailabilityDocument = %+v, %v", sd, err)
	}

	// A request whose envelope a newer version beat is stale; finishing a
	// finished request is refused.
	later := now.Add(time.Minute)
	req2, err := s.RequestAvailabilityIssue(ctx, staffID, store.AvailabilityIssueInput{Reason: "again", InputsDigest: digest, BaseVersion: doc.Version}, later)
	if err != nil {
		t.Fatal(err)
	}
	stale, _ := pc.SignAvailability(priv, doc.Version, composed.JSON) // equal version
	if err := w.IssueAvailabilityDocument(ctx, req2.RequestID, stale, req2.RequestedBy, now); !errors.Is(err, pc.ErrVersionNotNewer) {
		t.Fatalf("equal version = %v", err)
	}
	if err := w.FinishAvailabilityIssue(ctx, req2.RequestID, store.IssueStateStale, "nothing_to_issue", later); err != nil {
		t.Fatalf("FinishAvailabilityIssue: %v", err)
	}
	if err := w.FinishAvailabilityIssue(ctx, req2.RequestID, store.IssueStateFailed, "sign", now); !errors.Is(err, store.ErrIssueNotPending) {
		t.Fatalf("finishing twice = %v", err)
	}
	if err := w.FinishAvailabilityIssue(ctx, req2.RequestID, store.IssueStateIssued, "x", now); !errors.Is(err, store.ErrIssueInvalid) {
		t.Fatalf("finish as issued = %v, want ErrIssueInvalid", err)
	}
	st, _ = s.StaffAvailabilityIssueState(ctx)
	if st.Last == nil || st.Last.RequestID != req2.RequestID || st.Last.State != store.IssueStateStale || st.Last.ErrorClass != "nothing_to_issue" {
		t.Fatalf("last request = %+v", st.Last)
	}

	// The roles cannot step outside their part (staff UPDATE: see
	// TestCancelAvailabilityIssue).
	if err := asRole(t, pool, "sbci_staff", `UPDATE availability_issue_requests SET result_version = 1`); err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("staff UPDATE of a result version = %v, want permission denied", err)
	}
	if err := asRole(t, pool, "sbci_worker", `INSERT INTO availability_issue_requests (request_id, requested_by, reason, inputs_digest, base_version, requested_at)
		VALUES (gen_random_uuid(), 'staff:x', 'r', repeat('a', 64), 0, now())`); err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("worker INSERT of a request = %v, want permission denied", err)
	}
	if err := asRole(t, pool, "sbci_staff", `INSERT INTO availability_issue_requests (request_id, requested_by, reason, inputs_digest, base_version, state, result_version, requested_at, done_at)
		VALUES (gen_random_uuid(), 'staff:x', 'r', repeat('a', 64), 0, 'issued', 5, now(), now())`); err == nil {
		t.Error("staff inserted a request already issued")
	}
}

// asRoleRows runs one statement as role in a transaction that is rolled
// back, and reports the rows it changed.
func asRoleRows(t *testing.T, pool *pgxpool.Pool, role, sql string, args ...any) (int64, error) {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// role is one of this file's literals, never input.
	if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+role); err != nil {
		t.Fatalf("set role %s: %v", role, err)
	}
	tag, err := tx.Exec(ctx, sql, args...)
	return tag.RowsAffected(), err
}

// TestCancelAvailabilityIssue: staff can cancel a pending request (and only a
// pending one) with a reason, logged in the same transaction; the request is
// failed/cancelled, the next issue is no longer refused, and the worker can
// no longer issue the cancelled request. The policy allows staff exactly the
// pending -> failed/cancelled move.
func TestCancelAvailabilityIssue(t *testing.T) {
	t.Parallel()
	s, pool := newStore(t)
	w := newWorkerStore(t, pool)
	ctx := context.Background()
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	staffID, _ := registerTestStaff(t, s, staffauth.RoleOps, 63, now)
	digest := strings.Repeat("ab", 32)
	req, err := s.RequestAvailabilityIssue(ctx, staffID, store.AvailabilityIssueInput{Reason: "issue with no worker", InputsDigest: digest}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.RequestAvailabilityIssue(ctx, staffID, store.AvailabilityIssueInput{Reason: "again", InputsDigest: digest}, now); !errors.Is(err, store.ErrIssuePending) {
		t.Fatalf("second request = %v, want ErrIssuePending (the block the cancel clears)", err)
	}

	later := now.Add(time.Hour)
	for _, bad := range []struct {
		name, id, reason string
		want             error
	}{
		{"blank reason", req.RequestID, " ", staffauth.ErrReasonRequired},
		{"malformed id", "not-a-uuid", "r", store.ErrIssueInvalid},
		{"unknown id", "00000000-0000-4000-8000-000000000000", "r", store.ErrIssueNotPending},
	} {
		if _, err := s.CancelAvailabilityIssue(ctx, staffID, bad.id, bad.reason, later); !errors.Is(err, bad.want) {
			t.Errorf("%s: CancelAvailabilityIssue = %v, want %v", bad.name, err, bad.want)
		}
	}
	got, err := s.CancelAvailabilityIssue(ctx, staffID, req.RequestID, "worker loops are off", later)
	if err != nil {
		t.Fatalf("CancelAvailabilityIssue: %v", err)
	}
	if got.RequestID != req.RequestID || got.State != store.IssueStateFailed || got.ErrorClass != store.IssueClassCancelled ||
		got.DoneAt == nil || !got.DoneAt.Equal(later) || got.RequestedBy != staffauth.Actor(staffID) {
		t.Fatalf("cancelled request = %+v", got)
	}
	if _, err := s.CancelAvailabilityIssue(ctx, staffID, req.RequestID, "again", later); !errors.Is(err, store.ErrIssueNotPending) {
		t.Fatalf("cancelling twice = %v, want ErrIssueNotPending", err)
	}
	var logged int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM staff_actions WHERE verb = 'availability.issue_cancelled' AND reason = 'worker loops are off'
		AND actor = $1 AND target = 'availability:issue' AND detail->>'request_id' = $2 AND result = 'ok'`, staffauth.Actor(staffID), req.RequestID).Scan(&logged); err != nil || logged != 1 {
		t.Fatalf("issue_cancelled rows = %d (%v), want 1", logged, err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM staff_actions WHERE verb = 'availability.issue_cancelled'`).Scan(&logged); err != nil || logged != 1 {
		t.Fatalf("all issue_cancelled rows = %d (%v), want 1 (refusals write none)", logged, err)
	}
	st, err := s.StaffAvailabilityIssueState(ctx)
	if err != nil || st.Pending != nil || st.Last == nil || st.Last.RequestID != req.RequestID || st.Last.ErrorClass != store.IssueClassCancelled {
		t.Fatalf("issue state after the cancel = %+v %v", st, err)
	}
	// The worker cannot issue the cancelled request: nothing is stored.
	priv := newDocKey(t)
	composed, err := availcompose.Compose(nil, now)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := pc.SignAvailability(priv, now.Unix(), composed.JSON)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.IssueAvailabilityDocument(ctx, req.RequestID, doc, req.RequestedBy, later); !errors.Is(err, store.ErrIssueNotPending) {
		t.Fatalf("issuing a cancelled request = %v, want ErrIssueNotPending", err)
	}
	if _, err := w.LatestAvailabilityDocument(ctx); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("an envelope was stored for a cancelled request: %v", err)
	}
	// The next issue is accepted again.
	next, err := s.RequestAvailabilityIssue(ctx, staffID, store.AvailabilityIssueInput{Reason: "after the cancel", InputsDigest: digest}, later)
	if err != nil {
		t.Fatalf("request after the cancel = %v", err)
	}

	// The policy, as the staff login: one move only, pending -> failed with
	// error class cancelled. Each statement is rolled back.
	for _, c := range []struct {
		name string
		sql  string
		id   string
		rows int64
		err  string
	}{
		{"cancel a pending request", `UPDATE availability_issue_requests SET state = 'failed', error_class = 'cancelled', done_at = now() WHERE request_id = $1::uuid`, next.RequestID, 1, ""},
		{"a finished request is out of reach", `UPDATE availability_issue_requests SET state = 'failed', error_class = 'cancelled', done_at = now() WHERE request_id = $1::uuid`, req.RequestID, 0, ""},
		{"pending -> stale", `UPDATE availability_issue_requests SET state = 'stale', error_class = 'cancelled', done_at = now() WHERE request_id = $1::uuid`, next.RequestID, 0, "row-level security"},
		{"pending -> failed with another class", `UPDATE availability_issue_requests SET state = 'failed', error_class = 'sign', done_at = now() WHERE request_id = $1::uuid`, next.RequestID, 0, "row-level security"},
		{"pending -> failed with no class", `UPDATE availability_issue_requests SET state = 'failed', done_at = now() WHERE request_id = $1::uuid`, next.RequestID, 0, "row-level security"},
		{"pending -> issued", `UPDATE availability_issue_requests SET state = 'issued', error_class = 'cancelled', done_at = now() WHERE request_id = $1::uuid`, next.RequestID, 0, "row-level security"},
		{"the reason", `UPDATE availability_issue_requests SET reason = 'rewritten' WHERE request_id = $1::uuid`, next.RequestID, 0, "permission denied"},
		{"the requester", `UPDATE availability_issue_requests SET requested_by = 'staff:x' WHERE request_id = $1::uuid`, next.RequestID, 0, "permission denied"},
		{"a result version", `UPDATE availability_issue_requests SET result_version = 7 WHERE request_id = $1::uuid`, next.RequestID, 0, "permission denied"},
		{"a delete", `DELETE FROM availability_issue_requests WHERE request_id = $1::uuid`, next.RequestID, 0, "permission denied"},
	} {
		n, err := asRoleRows(t, pool, "sbci_staff", c.sql, c.id)
		switch {
		case c.err == "" && (err != nil || n != c.rows):
			t.Errorf("%s: rows %d, err %v; want %d rows", c.name, n, err, c.rows)
		case c.err != "" && (err == nil || !strings.Contains(err.Error(), c.err)):
			t.Errorf("%s: rows %d, err %v; want an error containing %q", c.name, n, err, c.err)
		}
	}
	for _, role := range []string{"sbci_api", "sbci_app", "sbci_aggregator"} {
		if _, err := asRoleRows(t, pool, role, `UPDATE availability_issue_requests SET state = 'failed', error_class = 'cancelled', done_at = now()`); err == nil || !strings.Contains(err.Error(), "permission denied") {
			t.Errorf("%s cancel = %v, want permission denied", role, err)
		}
	}
	if p, err := w.PendingAvailabilityIssue(ctx); err != nil || p.RequestID != next.RequestID {
		t.Fatalf("the worker's pending request = %+v, %v; want the request made after the cancel", p, err)
	}
}

func TestAvailabilityDeliveries(t *testing.T) {
	t.Parallel()
	s, pool := newStore(t)
	w := newWorkerStore(t, pool)
	ctx := context.Background()
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	rec := store.AvailabilityDelivery{HostID: "app-0", Version: 0, AttemptedVersion: 10, State: store.DeliveryRetry, Attempts: 1, ErrorClass: "transport:dial", UpdatedAt: now}
	if err := w.RecordAvailabilityDelivery(ctx, rec); err != nil {
		t.Fatal(err)
	}
	rec = store.AvailabilityDelivery{HostID: "app-0", Version: 10, AttemptedVersion: 10, State: store.DeliveryDelivered, Attempts: 2, UpdatedAt: now.Add(time.Minute)}
	if err := w.RecordAvailabilityDelivery(ctx, rec); err != nil {
		t.Fatal(err)
	}
	// A lower version in force never replaces a higher one.
	if err := w.RecordAvailabilityDelivery(ctx, store.AvailabilityDelivery{HostID: "app-0", Version: 3, AttemptedVersion: 11, State: store.DeliveryRefused, Attempts: 1, ErrorClass: "refused:invalid", UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	st, err := s.StaffAvailabilityIssueState(ctx)
	if err != nil || len(st.Deliveries) != 1 {
		t.Fatalf("staff deliveries = %+v %v", st.Deliveries, err)
	}
	if d := st.Deliveries[0]; d.Version != 10 || d.AttemptedVersion != 11 || d.State != store.DeliveryRefused || d.ErrorClass != "refused:invalid" {
		t.Fatalf("delivery = %+v", d)
	}
	for _, bad := range []store.AvailabilityDelivery{
		{HostID: "app 0", AttemptedVersion: 1, State: store.DeliveryRetry},
		{HostID: "app-0", AttemptedVersion: 0, State: store.DeliveryRetry},
		{HostID: "app-0", AttemptedVersion: 1, State: "lost"},
		{HostID: "app-0", AttemptedVersion: 1, State: store.DeliveryRetry, ErrorClass: "Has Spaces"},
	} {
		if err := w.RecordAvailabilityDelivery(ctx, bad); !errors.Is(err, store.ErrIssueInvalid) {
			t.Errorf("RecordAvailabilityDelivery(%+v) = %v, want ErrIssueInvalid", bad, err)
		}
	}
	if err := asRole(t, pool, "sbci_staff", `UPDATE availability_deliveries SET version = 0`); err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("staff UPDATE of deliveries = %v, want permission denied", err)
	}
}

func TestSetOrgComponentInput(t *testing.T) {
	t.Parallel()
	s, pool := newStore(t)
	ctx := context.Background()
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	staffID, _ := registerTestStaff(t, s, staffauth.RoleAdmin, 62, now)
	value := func() string {
		var v []byte
		err := pool.QueryRow(ctx, `SELECT value::text FROM availability_inputs WHERE section = 'components' AND key = 'org.security'`).Scan(&v)
		if err != nil {
			return ""
		}
		var m map[string]any
		_ = json.Unmarshal(v, &m)
		b, _ := json.Marshal(m)
		return string(b)
	}
	steps := []struct {
		org  string
		on   bool
		want string // "" = no row
		err  error
	}{
		{issOrgA, true, `{"orgs":["` + issOrgA + `"],"reach":"named"}`, nil},
		{issOrgA, true, `{"orgs":["` + issOrgA + `"],"reach":"named"}`, store.ErrNoChange},
		{issOrgB, true, `{"orgs":["` + issOrgA + `","` + issOrgB + `"],"reach":"named"}`, nil},
		{issOrgA, false, `{"orgs":["` + issOrgB + `"],"reach":"named"}`, nil},
		{issOrgB, false, "", nil},
		{issOrgB, false, "", store.ErrNoChange},
	}
	for i, st := range steps {
		_, err := s.SetOrgComponentInput(ctx, staffID, st.org, "org.security", st.on, "sr-17 step", now.Add(time.Duration(i)*time.Second))
		if !errors.Is(err, st.err) && (err != nil || st.err != nil) {
			t.Fatalf("step %d: err = %v, want %v", i, err, st.err)
		}
		if got := value(); got != st.want {
			t.Fatalf("step %d: value = %s, want %s", i, got, st.want)
		}
	}
	// Every change is logged against the org it was about.
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM staff_actions WHERE target = 'availability:components/org.security' AND org_id IS NOT NULL`).Scan(&n); err != nil || n != 4 {
		t.Fatalf("logged changes with an org = %d (%v), want 4", n, err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM staff_actions WHERE target = 'availability:components/org.security' AND org_id = $1::uuid AND verb = 'availability.deleted'`, issOrgB).Scan(&n); err != nil || n != 1 {
		t.Fatalf("the removal of the last org is not logged as a delete for org B: %d (%v)", n, err)
	}
	// A cohort row cannot be changed for one org.
	in, _ := staffauth.ValidateAvailabilityInput("components", "org.security", []byte(`{"reach":"cohort","cohort":"ring-1"}`))
	if err := s.SetAvailabilityInput(ctx, staffID, in, "cohort", now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetOrgComponentInput(ctx, staffID, issOrgA, "org.security", true, "x", now); !errors.Is(err, availcompose.ErrToggle) {
		t.Fatalf("toggle on a cohort row = %v, want ErrToggle", err)
	}
	if _, err := s.SetOrgComponentInput(ctx, staffID, issOrgA, "org.security", true, " ", now); !errors.Is(err, staffauth.ErrReasonRequired) {
		t.Fatalf("blank reason = %v", err)
	}
}
