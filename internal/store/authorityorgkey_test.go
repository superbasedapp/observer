package store

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// Org attribution (agent migration 250, managed SaaS plan 07 row M8.1,
// operator ruling D-43): data captured under one organization never reaches
// another.

var (
	attrEnrolA = Enrolment{OrgID: "org-A", OrgName: "A", OrgServerURL: "https://a.example/", UserID: "u1", UserEmail: "dev@a.example"}
	attrEnrolB = Enrolment{OrgID: "org-B", OrgName: "B", OrgServerURL: "https://b.example", UserID: "u1", UserEmail: "dev@b.example"}
)

// attrEnrol enrols the store the way orgclient.Enroll does: the push cursor
// (and the re-send floors) seeded at the current high-water mark, then the
// enrolment row.
func attrEnrol(t *testing.T, s *Store, e Enrolment) {
	t.Helper()
	ctx := context.Background()
	maxIDs, err := s.CurrentMaxIDs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SavePushCursor(ctx, maxIDs); err != nil {
		t.Fatal(err)
	}
	if err := s.WriteEnrolment(ctx, e); err != nil {
		t.Fatal(err)
	}
}

// attrCapture captures one session (when new) with one action and one token
// row, each identified by event.
func attrCapture(t *testing.T, s *Store, db *sql.DB, pid int64, session, event string, at time.Time) {
	t.Helper()
	ctx := context.Background()
	if err := s.UpsertSession(ctx, models.Session{ID: session, ProjectID: pid, Tool: models.ToolClaudeCode, StartedAt: at}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.InsertActions(ctx, []models.Action{{
		SessionID: session, ProjectID: pid, Timestamp: at, ActionType: models.ActionReadFile,
		Target: "a.go", Success: true, Tool: models.ToolClaudeCode, SourceFile: "f.jsonl", SourceEventID: event,
	}}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO token_usage(session_id, timestamp, tool, model, input_tokens, output_tokens, source, source_file, source_event_id)
		VALUES(?, ?, 'claude-code', 'claude', 1, 1, 'jsonl', 'f.jsonl', ?)`, session, at.Format(time.RFC3339), event); err != nil {
		t.Fatal(err)
	}
}

// attrPushCycle composes one batch for orgID from the stored cursor and
// commits it as an accepted push would.
func attrPushCycle(t *testing.T, s *Store, orgID string) PushBatch {
	t.Helper()
	ctx := context.Background()
	cur, err := s.LoadPushCursor(ctx)
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.SelectUnpushedSince(ctx, cur, 1<<22, orgID, "dev@example.com", ShareOptions{FullContent: true}, ScopeOptions{})
	if err != nil {
		t.Fatalf("SelectUnpushedSince: %v", err)
	}
	if _, err := s.SavePushCursorIfUnchanged(ctx, cur, b.Cursor); err != nil {
		t.Fatal(err)
	}
	if err := s.AckPushedChanges(ctx, b.Acks); err != nil {
		t.Fatal(err)
	}
	return b
}

// attrShipped lists the session ids and action/token event ids a batch
// carries.
func attrShipped(b PushBatch) (sessions, events []string) {
	for _, r := range b.Sessions {
		sessions = append(sessions, r.ID)
	}
	for _, r := range b.Actions {
		events = append(events, "action:"+r.SourceEventID)
	}
	for _, r := range b.TokenUsage {
		events = append(events, "token:"+r.SourceEventID)
	}
	sort.Strings(sessions)
	sort.Strings(events)
	return sessions, events
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestSwitchOrgNeverShipsPriorRows is the M8.1 proof: capture under org A,
// switch to org B, capture more. From every path - the push cursor lane, the
// re-send lane, the org-intel sweep and submission, and `observer org
// backfill --all --confirm` (a cursor reset to zero) - B receives only the
// rows captured under B. A's unpushed tail, and a session that was live
// across the switch, never reach B.
func TestSwitchOrgNeverShipsPriorRows(t *testing.T) {
	t.Parallel()
	s, db := newTestStore(t)
	ctx := context.Background()
	pid, err := s.UpsertProject(ctx, "/tmp/attr", "")
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now().UTC().Add(-3 * time.Hour).Truncate(time.Second)

	// Under A: one session pushed to A, one left as A's unpushed tail, one
	// still live when the node switches.
	attrEnrol(t, s, attrEnrolA)
	attrCapture(t, s, db, pid, "a-shipped", "a-shipped-1", base)
	if got, _ := attrShipped(attrPushCycle(t, s, attrEnrolA.OrgID)); !sameStrings(got, []string{"a-shipped"}) {
		t.Fatalf("A's own push = %v, want [a-shipped]", got)
	}
	attrCapture(t, s, db, pid, "a-tail", "a-tail-1", base.Add(time.Minute))
	attrCapture(t, s, db, pid, "a-live", "a-live-1", base.Add(2*time.Minute))

	// Switch to B (the drain was skipped: A's tail stays unsent), then
	// capture under B while the A session keeps going.
	attrEnrol(t, s, attrEnrolB)
	attrCapture(t, s, db, pid, "b1", "b1-1", base.Add(10*time.Minute))
	attrCapture(t, s, db, pid, "a-live", "a-live-2", base.Add(11*time.Minute))

	wantSessions := []string{"b1"}
	wantEvents := []string{"action:b1-1", "token:b1-1"}

	t.Run("push", func(t *testing.T) {
		sessions, events := attrShipped(attrPushCycle(t, s, attrEnrolB.OrgID))
		if !sameStrings(sessions, wantSessions) || !sameStrings(events, wantEvents) {
			t.Fatalf("B's push = sessions %v events %v, want %v %v", sessions, events, wantSessions, wantEvents)
		}
		if again := attrPushCycle(t, s, attrEnrolB.OrgID); batchRowCount(again) != 0 {
			t.Fatalf("the cursor did not move past the other org's rows: %d rows on the next push", batchRowCount(again))
		}
	})

	t.Run("resend", func(t *testing.T) {
		// Both rows sit above B's re-send floor and at or below the cursor:
		// a change to either is queued. Only B's is re-sent.
		if _, err := db.Exec(`UPDATE actions SET success = 0 WHERE source_event_id IN ('a-live-2', 'b1-1')`); err != nil {
			t.Fatal(err)
		}
		_, events := attrShipped(attrPushCycle(t, s, attrEnrolB.OrgID))
		if !sameStrings(events, []string{"action:b1-1"}) {
			t.Fatalf("B's re-send = %v, want [action:b1-1]", events)
		}
	})

	t.Run("intel", func(t *testing.T) {
		now := time.Now().UTC()
		cands, err := s.ListOrgIntelSubmitCandidates(ctx, attrEnrolB.OrgID, now.Add(-7*24*time.Hour), time.Minute, 1, 10, now)
		if err != nil {
			t.Fatal(err)
		}
		var ids []string
		for _, c := range cands {
			ids = append(ids, c.SessionID)
		}
		if !sameStrings(ids, []string{"b1"}) {
			t.Fatalf("B's intel candidates = %v, want [b1]", ids)
		}
		for _, tc := range []struct {
			session string
			wantErr error
		}{
			{"a-shipped", ErrOrgIntelSessionNotThisOrg},
			{"a-live", ErrOrgIntelSessionNotThisOrg},
			{"b1", nil},
		} {
			row := OrgIntelSubmission{
				OrgID: attrEnrolB.OrgID, SessionID: tc.session, Purpose: "structural_activity_insights", EvidenceLevel: "titles",
				Trigger: OrgIntelTriggerDeveloper, EvidenceDigest: "e-" + tc.session, UploadDigest: "u-" + tc.session, Envelope: []byte(`{"b":1}`),
			}
			if _, _, err := s.EnqueueOrgIntelSubmission(ctx, row, now); !errors.Is(err, tc.wantErr) {
				t.Errorf("enqueue %s for B: err = %v, want %v", tc.session, err, tc.wantErr)
			}
		}
	})

	t.Run("backfill", func(t *testing.T) {
		// `observer org backfill --all --confirm`: the counts it shows, then
		// the cursor reset to zero and the push loop draining everything.
		counts, err := s.PushEligibleCounts(ctx, PushCursor{})
		if err != nil {
			t.Fatal(err)
		}
		if counts.Sessions != 1 || counts.Actions != 1 || counts.TokenUsage != 1 {
			t.Fatalf("backfill counts for B = %+v, want one session, one action, one token row (b1's)", counts)
		}
		if err := s.SavePushCursor(ctx, PushCursor{}); err != nil {
			t.Fatal(err)
		}
		var sessions, events []string
		for i := 0; i < 10; i++ {
			b := attrPushCycle(t, s, attrEnrolB.OrgID)
			if batchRowCount(b) == 0 {
				break
			}
			ss, es := attrShipped(b)
			sessions, events = append(sessions, ss...), append(events, es...)
		}
		sort.Strings(sessions)
		sort.Strings(events)
		if !sameStrings(sessions, wantSessions) || !sameStrings(events, wantEvents) {
			t.Fatalf("B's backfill = sessions %v events %v, want %v %v", sessions, events, wantSessions, wantEvents)
		}
	})

	t.Run("composing for the org just left is refused", func(t *testing.T) {
		cur, _ := s.LoadPushCursor(ctx)
		if _, err := s.SelectUnpushedSince(ctx, cur, 1<<20, attrEnrolA.OrgID, "dev@a.example", ShareOptions{}, ScopeOptions{}); !errors.Is(err, errOrgDestinationChanged) {
			t.Fatalf("composing for A while enrolled in B: err = %v, want errOrgDestinationChanged", err)
		}
	})
}

// TestUpsertSessionStampsAuthorityOrgKey pins the capture stamp: the first
// determinable stamp wins and is never rewritten.
func TestUpsertSessionStampsAuthorityOrgKey(t *testing.T) {
	t.Parallel()
	s, db := newTestStore(t)
	ctx := context.Background()
	pid, err := s.UpsertProject(ctx, "/tmp/stamp", "")
	if err != nil {
		t.Fatal(err)
	}
	keyA := authorityOrgKey(attrEnrolA.OrgServerURL, attrEnrolA.OrgID)
	keyB := authorityOrgKey(attrEnrolB.OrgServerURL, attrEnrolB.OrgID)
	upsert := func(id string) {
		t.Helper()
		if err := s.UpsertSession(ctx, models.Session{ID: id, ProjectID: pid, Tool: models.ToolClaudeCode, StartedAt: time.Now().UTC()}); err != nil {
			t.Fatal(err)
		}
	}
	keyOf := func(id string) sql.NullString {
		t.Helper()
		var k sql.NullString
		if err := db.QueryRow(`SELECT authority_org_key FROM sessions WHERE id = ?`, id).Scan(&k); err != nil {
			t.Fatal(err)
		}
		return k
	}

	upsert("personal") // not enrolled
	if err := s.WriteEnrolment(ctx, attrEnrolA); err != nil {
		t.Fatal(err)
	}
	upsert("under-a")
	upsert("personal") // keeps capturing after the enrolment
	upsert("unknown")
	if _, err := db.Exec(`UPDATE sessions SET authority_org_key = NULL WHERE id = 'unknown'`); err != nil {
		t.Fatal(err)
	}
	if err := s.WriteEnrolment(ctx, attrEnrolB); err != nil {
		t.Fatal(err)
	}
	upsert("under-a") // rewritten under B
	upsert("unknown") // first determinable stamp
	upsert("under-b")

	for _, tc := range []struct {
		session string
		want    string
	}{
		{"personal", AuthorityOrgKeyPersonal},
		{"under-a", keyA},
		{"unknown", keyB},
		{"under-b", keyB},
	} {
		if got := keyOf(tc.session); !got.Valid || got.String != tc.want {
			t.Errorf("%s: authority_org_key = %+v, want %q", tc.session, got, tc.want)
		}
	}
}

// TestResolvePendingAuthorityOrgKeys: migration 250's pending rows resolve to
// the enrolment in force when the migration ran (its schema_meta pre-image),
// not to whatever the node is enrolled in when the resolution runs.
func TestResolvePendingAuthorityOrgKeys(t *testing.T) {
	t.Parallel()
	s, db := newTestStore(t)
	ctx := context.Background()
	pid, err := s.UpsertProject(ctx, "/tmp/pending", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertSession(ctx, models.Session{ID: "legacy", ProjectID: pid, Tool: models.ToolClaudeCode, StartedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE sessions SET authority_org_key = ? WHERE id = 'legacy'`, authorityOrgKeyPending); err != nil {
		t.Fatal(err)
	}
	for k, v := range map[string]string{
		authorityOrgKeyPendingOrgIDKey: attrEnrolA.OrgID,
		authorityOrgKeyPendingURLKey:   attrEnrolA.OrgServerURL,
	} {
		if _, err := db.Exec(`INSERT INTO schema_meta(key, value) VALUES(?, ?)`, k, v); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.WriteEnrolment(ctx, attrEnrolB); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ { // the second run finds nothing to do
		if _, err := s.orgDestinationFor(ctx, ""); err != nil {
			t.Fatal(err)
		}
	}
	var got string
	if err := db.QueryRow(`SELECT authority_org_key FROM sessions WHERE id = 'legacy'`).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if want := authorityOrgKey(attrEnrolA.OrgServerURL, attrEnrolA.OrgID); got != want {
		t.Fatalf("resolved key = %q, want A's %q", got, want)
	}
	var left int
	if err := db.QueryRow(`SELECT COUNT(*) FROM schema_meta WHERE key IN (?, ?)`,
		authorityOrgKeyPendingOrgIDKey, authorityOrgKeyPendingURLKey).Scan(&left); err != nil || left != 0 {
		t.Fatalf("pre-image left behind: %d (%v)", left, err)
	}
}

// TestDecideOrgDestination: one case per orgDestinationRules row.
func TestDecideOrgDestination(t *testing.T) {
	t.Parallel()
	keyA := authorityOrgKey("https://a.example", "org-A")
	cases := []struct {
		name    string
		in      destinationInput
		want    orgDestination
		wantErr error
	}{
		{"not enrolled", destinationInput{callerOrgID: "org-A"}, orgDestination{open: true}, nil},
		{"caller's org is not the enrolled org", destinationInput{enrolled: true, liveOrgID: "org-B", liveURL: "https://b.example", callerOrgID: "org-A"}, orgDestination{}, errOrgDestinationChanged},
		{"enrolled, caller names it", destinationInput{enrolled: true, liveOrgID: "org-A", liveURL: "https://a.example", callerOrgID: "org-A"}, orgDestination{key: keyA}, nil},
		{"enrolled, caller names none", destinationInput{enrolled: true, liveOrgID: "org-A", liveURL: "https://a.example/ "}, orgDestination{key: keyA}, nil},
	}
	if len(cases) < len(orgDestinationRules) {
		t.Fatalf("%d cases for %d rules", len(cases), len(orgDestinationRules))
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := decideOrgDestination(tc.in)
			if !errors.Is(err, tc.wantErr) || got != tc.want {
				t.Fatalf("decideOrgDestination = %+v, %v; want %+v, %v", got, err, tc.want, tc.wantErr)
			}
		})
	}
}

// TestKeepAttributedRow: one case per rowAttributionRules row.
func TestKeepAttributedRow(t *testing.T) {
	t.Parallel()
	dest := orgDestination{key: "kA"}
	key := func(v string) sql.NullString { return sql.NullString{String: v, Valid: true} }
	cases := []struct {
		name    string
		session string
		found   bool
		key     sql.NullString
		dest    orgDestination
		want    bool
	}{
		{"not enrolled", "s", true, key("kB"), orgDestination{open: true}, true},
		{"session-less row", "", false, sql.NullString{}, dest, true},
		{"session not captured yet", "s", false, sql.NullString{}, dest, true},
		{"the destination org's session", "s", true, key("kA"), dest, true},
		{"another org's session", "s", true, key("kB"), dest, false},
		{"a personal session", "s", true, key(AuthorityOrgKeyPersonal), dest, false},
		{"an unknown session", "s", true, sql.NullString{}, dest, false},
		{"a pending session", "s", true, key(authorityOrgKeyPending), dest, false},
	}
	if len(cases) < len(rowAttributionRules) {
		t.Fatalf("%d cases for %d rules", len(cases), len(rowAttributionRules))
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := keepAttributedRow(tc.session, tc.found, tc.key, tc.dest); got != tc.want {
				t.Fatalf("keepAttributedRow = %v, want %v", got, tc.want)
			}
		})
	}
}

// notAttributedFamilies are the PushBatch families whose rows carry a session
// id field but are deliberately NOT filtered by org attribution, each with
// its reason.
var notAttributedFamilies = map[string]string{
	"Deletions":        "identity-only correction of rows this org already holds; tracked only above the enrolment's floor",
	"SessionManifests": "identity-only resync manifest of rows this org already holds",
	"RemoteAudit":      "remote-access audit of this node; its session_id names the dashboard terminal session, not a captured session",
}

// TestAttributedFamiliesCoverEverySessionFamily: every PushBatch family whose
// row type carries a sessions.id field is either filtered by
// applyOrgAttribution (attributedFamilies) or excluded with a reason, so a new
// family cannot silently ship another org's sessions. Plane A (Obs*) rows
// carry the hosted app's own end-user session ids, not sessions.id, and are
// recognised by their field prefix.
func TestAttributedFamiliesCoverEverySessionFamily(t *testing.T) {
	t.Parallel()
	listed := map[string]bool{}
	for _, f := range attributedFamilies {
		listed[f.name] = true
	}
	sessionFields := map[string]bool{"SessionID": true, "OwnerSessionID": true, "CodingSessionID": true}
	bt := reflect.TypeOf(PushBatch{})
	for i := 0; i < bt.NumField(); i++ {
		f := bt.Field(i)
		if f.Type.Kind() != reflect.Slice || f.Type.Elem().Kind() != reflect.Struct || len(f.Name) >= 3 && f.Name[:3] == "Obs" {
			continue
		}
		carries := f.Name == "Sessions"
		for j := 0; j < f.Type.Elem().NumField(); j++ {
			if sessionFields[f.Type.Elem().Field(j).Name] {
				carries = true
			}
		}
		_, excluded := notAttributedFamilies[f.Name]
		switch {
		case carries && !listed[f.Name] && !excluded:
			t.Errorf("PushBatch.%s carries a session id but is neither in attributedFamilies nor in notAttributedFamilies", f.Name)
		case listed[f.Name] && !carries:
			t.Errorf("attributedFamilies lists %s, whose rows carry no session id", f.Name)
		}
	}
	for name := range listed {
		if _, ok := bt.FieldByName(name); !ok {
			t.Errorf("attributedFamilies lists %s, which is not a PushBatch field", name)
		}
	}
}
