package store

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// TestSetSessionExecution pins the cloud-execution columns (agent migration
// 240) under FIRST-WINS-UNLESS-EMPTY semantics, the SetSessionSurface shape:
// one table row per behaviour, applied in order to one session.
func TestSetSessionExecution(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	pid, _ := s.UpsertProject(ctx, "/tmp/exec", "")
	if err := s.UpsertSession(ctx, models.Session{
		ID: "exec-sess", ProjectID: pid, Tool: models.ToolClaudeCode,
		StartedAt: time.Date(2026, 10, 31, 10, 0, 0, 0, time.UTC),
	}); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name        string
		in          models.SessionExecution
		wantChanged bool
		wantErr     bool
		wantLoc     string
		wantRef     string
	}{
		{
			name:        "first stamp, location only",
			in:          models.SessionExecution{SessionID: "exec-sess", ExecutionLocation: models.ExecutionVendorCloud},
			wantChanged: true, wantLoc: "vendor_cloud",
		},
		{
			name:        "later stamp FILLS the still-empty reference",
			in:          models.SessionExecution{SessionID: "exec-sess", VendorSessionRef: "cse_01ABC"},
			wantChanged: true, wantLoc: "vendor_cloud", wantRef: "cse_01ABC",
		},
		{
			name:    "identical re-stamp is not a change",
			in:      models.SessionExecution{SessionID: "exec-sess", ExecutionLocation: models.ExecutionVendorCloud, VendorSessionRef: "cse_01ABC"},
			wantLoc: "vendor_cloud", wantRef: "cse_01ABC",
		},
		{
			name:    "differing later stamp is a no-op (first wins)",
			in:      models.SessionExecution{SessionID: "exec-sess", ExecutionLocation: models.ExecutionLocal, VendorSessionRef: "cse_02XYZ"},
			wantLoc: "vendor_cloud", wantRef: "cse_01ABC",
		},
		{
			name:    "all-empty stamp is a no-op",
			in:      models.SessionExecution{SessionID: "exec-sess"},
			wantLoc: "vendor_cloud", wantRef: "cse_01ABC",
		},
		{
			name:    "out-of-vocabulary location is refused",
			in:      models.SessionExecution{SessionID: "exec-sess", ExecutionLocation: "cloud"},
			wantErr: true, wantLoc: "vendor_cloud", wantRef: "cse_01ABC",
		},
		{
			name:    "malformed reference is refused",
			in:      models.SessionExecution{SessionID: "exec-sess", VendorSessionRef: "https://example.com/session/1"},
			wantErr: true, wantLoc: "vendor_cloud", wantRef: "cse_01ABC",
		},
		{
			name:    "missing session id is an error",
			in:      models.SessionExecution{ExecutionLocation: models.ExecutionLocal},
			wantErr: true, wantLoc: "vendor_cloud", wantRef: "cse_01ABC",
		},
		{
			name:    "unknown session is a silent no-op",
			in:      models.SessionExecution{SessionID: "no-such-session", ExecutionLocation: models.ExecutionLocal},
			wantLoc: "vendor_cloud", wantRef: "cse_01ABC",
		},
	}
	for _, c := range cases {
		changed, err := s.SetSessionExecution(ctx, c.in)
		if (err != nil) != c.wantErr {
			t.Fatalf("%s: err = %v, wantErr %v", c.name, err, c.wantErr)
		}
		if changed != c.wantChanged {
			t.Errorf("%s: changed = %v, want %v", c.name, changed, c.wantChanged)
		}
		got, err := s.LoadSessionExecution(ctx, "exec-sess")
		if err != nil {
			t.Fatalf("%s: LoadSessionExecution: %v", c.name, err)
		}
		if got.ExecutionLocation != c.wantLoc || got.VendorSessionRef != c.wantRef {
			t.Errorf("%s: stored (%q, %q), want (%q, %q)", c.name, got.ExecutionLocation, got.VendorSessionRef, c.wantLoc, c.wantRef)
		}
	}

	if _, err := s.LoadSessionExecution(ctx, "no-such-session"); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("LoadSessionExecution(missing) err = %v, want sql.ErrNoRows", err)
	}
}

// TestUpsertSessionLeavesExecutionAlone proves the columns have ONE writer:
// a re-upsert of the session (a whole-file re-parse) never clears a stamp.
func TestUpsertSessionLeavesExecutionAlone(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	pid, _ := s.UpsertProject(ctx, "/tmp/exec2", "")
	sess := models.Session{
		ID: "exec-2", ProjectID: pid, Tool: models.ToolCodex,
		StartedAt: time.Date(2026, 10, 31, 11, 0, 0, 0, time.UTC),
	}
	if err := s.UpsertSession(ctx, sess); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetSessionExecution(ctx, models.SessionExecution{
		SessionID:         "exec-2",
		ExecutionLocation: models.ExecutionCustomerWorker, VendorSessionRef: "task_9",
	}); err != nil {
		t.Fatal(err)
	}
	sess.TotalActions = 7
	if err := s.UpsertSession(ctx, sess); err != nil {
		t.Fatal(err)
	}
	got, err := s.LoadSessionExecution(ctx, "exec-2")
	if err != nil {
		t.Fatal(err)
	}
	if got.ExecutionLocation != models.ExecutionCustomerWorker || got.VendorSessionRef != "task_9" {
		t.Fatalf("re-upsert changed the stamp: %+v", got)
	}
}

func TestSessionIDByVendorRef(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	pid, _ := s.UpsertProject(ctx, "/tmp/exec3", "")
	for _, sess := range []models.Session{
		{ID: "cc-late", ProjectID: pid, Tool: models.ToolClaudeCode, StartedAt: time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)},
		{ID: "cc-early", ProjectID: pid, Tool: models.ToolClaudeCode, StartedAt: time.Date(2026, 10, 31, 9, 0, 0, 0, time.UTC)},
		{ID: "codex-1", ProjectID: pid, Tool: models.ToolCodex, StartedAt: time.Date(2026, 10, 31, 8, 0, 0, 0, time.UTC)},
	} {
		if err := s.UpsertSession(ctx, sess); err != nil {
			t.Fatal(err)
		}
	}
	for id, ref := range map[string]string{"cc-late": "ref-shared", "cc-early": "ref-shared", "codex-1": "ref-codex"} {
		if _, err := s.SetSessionExecution(ctx, models.SessionExecution{SessionID: id, VendorSessionRef: ref}); err != nil {
			t.Fatal(err)
		}
	}

	cases := []struct {
		name   string
		tool   string
		ref    string
		wantID string
		wantOK bool
	}{
		{"earliest of two sharing one ref", models.ToolClaudeCode, "ref-shared", "cc-early", true},
		{"other tool's ref is not a match", models.ToolClaudeCode, "ref-codex", "", false},
		{"matching tool", models.ToolCodex, "ref-codex", "codex-1", true},
		{"unknown ref", models.ToolCodex, "ref-none", "", false},
	}
	for _, c := range cases {
		id, ok, err := s.SessionIDByVendorRef(ctx, c.tool, c.ref)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if id != c.wantID || ok != c.wantOK {
			t.Errorf("%s: got (%q, %v), want (%q, %v)", c.name, id, ok, c.wantID, c.wantOK)
		}
	}
	if _, _, err := s.SessionIDByVendorRef(ctx, "", "x"); err == nil {
		t.Error("empty tool: want an error")
	}
}

// TestResolveRemoteProject walks the CA-D3 resolution order as a table, in
// sequence against one store: synthetic root when nothing matches, the same
// synthetic row on a second resolve, a real local checkout winning once it
// exists, and the refusals.
func TestResolveRemoteProject(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	otherLocal, err := s.UpsertProject(ctx, "/home/dev/other", "git@github.com:acme/other.git")
	if err != nil {
		t.Fatal(err)
	}

	var syntheticID, localID int64
	cases := []struct {
		name     string
		setup    func()
		remote   string
		wantErr  bool
		wantRoot string
		wantID   func() int64
	}{
		{
			name:     "no match creates the synthetic cloud root",
			remote:   "https://github.com/acme/widget.git",
			wantRoot: "cloud:github.com/acme/widget",
		},
		{
			name:     "a second resolve (scp spelling) lands on the same synthetic row",
			remote:   "git@github.com:acme/widget.git",
			wantRoot: "cloud:github.com/acme/widget",
			wantID:   func() int64 { return syntheticID },
		},
		{
			name: "a real local checkout with the remote wins over the synthetic",
			setup: func() {
				id, err := s.UpsertProject(ctx, "/home/dev/widget", "ssh://git@github.com/acme/widget")
				if err != nil {
					t.Fatal(err)
				}
				localID = id
			},
			remote:   "github.com/acme/widget",
			wantRoot: "/home/dev/widget",
			wantID:   func() int64 { return localID },
		},
		{
			name:     "an existing local project is found directly",
			remote:   "https://github.com/acme/other",
			wantRoot: "/home/dev/other",
			wantID:   func() int64 { return otherLocal },
		},
		{name: "empty remote is refused", remote: "", wantErr: true},
		{name: "a filesystem path is not a remote", remote: "/srv/git/widget", wantErr: true},
		{name: "a relative path is not a remote", remote: "./widget", wantErr: true},
	}
	for _, c := range cases {
		if c.setup != nil {
			c.setup()
		}
		id, err := s.ResolveRemoteProject(ctx, c.remote)
		if (err != nil) != c.wantErr {
			t.Fatalf("%s: err = %v, wantErr %v", c.name, err, c.wantErr)
		}
		if c.wantErr {
			continue
		}
		var root string
		if err := s.db.QueryRowContext(ctx, `SELECT root_path FROM projects WHERE id = ?`, id).Scan(&root); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if root != c.wantRoot {
			t.Errorf("%s: root = %q, want %q", c.name, root, c.wantRoot)
		}
		if c.wantID != nil && id != c.wantID() {
			t.Errorf("%s: id = %d, want %d", c.name, id, c.wantID())
		}
		if syntheticID == 0 && strings.HasPrefix(root, models.CloudProjectRootPrefix) {
			syntheticID = id
		}
	}

	// The one merge rule: the synthetic project pairs with its local twin.
	twins, err := s.CloudProjectTwins(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := []CloudProjectTwin{{SyntheticID: syntheticID, LocalID: localID, Remote: "github.com/acme/widget"}}
	if !reflect.DeepEqual(twins, want) {
		t.Fatalf("CloudProjectTwins = %+v, want %+v", twins, want)
	}
}

func TestProjectByRemote(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	if _, ok, err := s.ProjectByRemote(ctx, "github.com/acme/none"); err != nil || ok {
		t.Fatalf("empty store: ok=%v err=%v, want no match", ok, err)
	}
	if _, _, err := s.ProjectByRemote(ctx, " "); err == nil {
		t.Fatal("blank remote: want an error")
	}
	synth, err := s.UpsertProject(ctx, "cloud:github.com/acme/app", "github.com/acme/app")
	if err != nil {
		t.Fatal(err)
	}
	p, ok, err := s.ProjectByRemote(ctx, "https://github.com/acme/app.git")
	if err != nil || !ok || p.ID != synth || !p.Synthetic {
		t.Fatalf("synthetic only: got %+v ok=%v err=%v", p, ok, err)
	}
	// Two local checkouts of one repository: the oldest row wins.
	first, _ := s.UpsertProject(ctx, "/a/app", "git@github.com:acme/app.git")
	if _, err := s.UpsertProject(ctx, "/b/app", "https://github.com/acme/app"); err != nil {
		t.Fatal(err)
	}
	p, ok, err = s.ProjectByRemote(ctx, "github.com/acme/app")
	if err != nil || !ok || p.ID != first || p.Synthetic || p.RootPath != "/a/app" {
		t.Fatalf("two locals + synthetic: got %+v ok=%v err=%v, want the oldest local %d", p, ok, err, first)
	}
}

func TestRemoteProjectPreference(t *testing.T) {
	cases := []struct {
		name string
		in   []RemoteProject
		want []int64
	}{
		{"local before synthetic regardless of id", []RemoteProject{{ID: 1, Synthetic: true}, {ID: 9}}, []int64{9, 1}},
		{"oldest local first", []RemoteProject{{ID: 5}, {ID: 2}}, []int64{2, 5}},
		{"oldest synthetic first among synthetics", []RemoteProject{{ID: 7, Synthetic: true}, {ID: 3, Synthetic: true}}, []int64{3, 7}},
	}
	for _, c := range cases {
		sortRemoteProjects(c.in)
		var got []int64
		for _, p := range c.in {
			got = append(got, p.ID)
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: order %v, want %v", c.name, got, c.want)
		}
	}
}

// TestSetSessionExecutionQueuesResend proves agent migration 240 put both
// columns on the org_push_change_sessions trigger: a stamp landed after the
// session shipped queues it for re-push, and a no-op re-stamp does not.
func TestSetSessionExecutionQueuesResend(t *testing.T) {
	t.Parallel()
	s, database := newTestStore(t)
	ctx := context.Background()
	pid, _ := s.UpsertProject(ctx, "/tmp/exec-resend", "")
	if err := s.UpsertSession(ctx, models.Session{
		ID: "resend-1", ProjectID: pid, Tool: models.ToolClaudeCode,
		StartedAt: time.Date(2026, 10, 31, 10, 0, 0, 0, time.UTC),
	}); err != nil {
		t.Fatal(err)
	}
	// Arm the re-send lane as an enrolled node would: rows above the floor
	// are tracked.
	if _, err := database.ExecContext(ctx,
		`INSERT INTO schema_meta (key, value) VALUES ('org_push_floor_sessions', '0')
		 ON CONFLICT (key) DO UPDATE SET value = '0'`); err != nil {
		t.Fatal(err)
	}
	queued := func() int {
		var n int
		if err := database.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM org_push_changes WHERE tbl = 'sessions'`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	before := queued()
	steps := []struct {
		name string
		in   models.SessionExecution
		want int
	}{
		{"location stamp queues the session", models.SessionExecution{SessionID: "resend-1", ExecutionLocation: models.ExecutionVendorCloud}, before + 1},
		{"reference stamp keeps it queued once", models.SessionExecution{SessionID: "resend-1", VendorSessionRef: "cse_9"}, before + 1},
	}
	for _, st := range steps {
		if _, err := s.SetSessionExecution(ctx, st.in); err != nil {
			t.Fatal(err)
		}
		if got := queued(); got != st.want {
			t.Errorf("%s: %d queued session rows, want %d", st.name, got, st.want)
		}
	}
	var seqBefore, seqAfter int64
	_ = database.QueryRowContext(ctx, `SELECT seq FROM org_push_changes WHERE tbl = 'sessions'`).Scan(&seqBefore)
	if _, err := s.SetSessionExecution(ctx, models.SessionExecution{SessionID: "resend-1", ExecutionLocation: models.ExecutionVendorCloud}); err != nil {
		t.Fatal(err)
	}
	_ = database.QueryRowContext(ctx, `SELECT seq FROM org_push_changes WHERE tbl = 'sessions'`).Scan(&seqAfter)
	if seqAfter != seqBefore {
		t.Errorf("an identical re-stamp bumped the re-send seq (%d -> %d)", seqBefore, seqAfter)
	}
}
