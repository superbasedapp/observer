package store

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/update"
)

// update_test.go covers the W3 store seam: the singleton update_state row,
// the update_events ledger, the pre-apply snapshot and the enum-only posture
// composer.

func updateTestStore(t *testing.T) *Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "update.db")
	database, err := dbtemplate.Open(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return New(database)
}

// TestMigration105CreatesTheSingletonRow: every reader must be able to SELECT
// without a NULL-vs-missing branch, so migration 105 inserts the row itself.
func TestMigration105CreatesTheSingletonRow(t *testing.T) {
	s := updateTestStore(t)
	ctx := context.Background()
	row, err := s.LoadUpdateState(ctx)
	if err != nil {
		t.Fatalf("LoadUpdateState: %v", err)
	}
	if row.State != update.StateIdle {
		t.Fatalf("a fresh node reports state %q, want idle", row.State)
	}
	if row.LastManifestVersion != 0 || row.PreviousBinaryPath != "" {
		t.Fatalf("a fresh row is not zeroed: %+v", row)
	}
	// The CHECK(id = 1) must actually hold.
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM update_state`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("update_state holds %d rows, want exactly 1", n)
	}
	if _, err := s.db.ExecContext(ctx, `INSERT INTO update_state (id) VALUES (2)`); err == nil {
		t.Fatal("a second update_state row was accepted; CHECK(id = 1) is not enforced")
	}
}

// TestSaveAndLoadUpdateStateRoundTrips pins that every column the rollback
// path depends on survives a write/read — especially previous_schema_version,
// which is unrecoverable once a new binary has booted.
func TestSaveAndLoadUpdateStateRoundTrips(t *testing.T) {
	s := updateTestStore(t)
	ctx := context.Background()
	want := UpdateStateRow{
		NodeState: update.NodeState{
			Channel: update.ChannelStable, LastManifestVersion: 17,
			LastManifestSeenAt: "2026-09-07T10:00:00Z", TargetVersion: "v1.33.0",
			State: update.StateApplying, PreviousVersion: "v1.32.0",
			PreviousBinaryPath:    "/state/rollback/observer-v1.32.0",
			PreviousSchemaVersion: 104,
			PreviousDBBackupPath:  "/state/preupgrade-v1.32.0.db",
			ApplyingStartedAt:     "2026-09-07T10:01:00Z",
		},
		ManifestJSON: `{"schema":"sbo.update-manifest.v1"}`,
	}
	if err := s.SaveUpdateState(ctx, want); err != nil {
		t.Fatalf("SaveUpdateState: %v", err)
	}
	got, err := s.LoadUpdateState(ctx)
	if err != nil {
		t.Fatalf("LoadUpdateState: %v", err)
	}
	for _, c := range []struct {
		name      string
		got, want any
	}{
		{"channel", got.Channel, want.Channel},
		{"last_manifest_version", got.LastManifestVersion, want.LastManifestVersion},
		{"target_version", got.TargetVersion, want.TargetVersion},
		{"state", got.State, want.State},
		{"previous_version", got.PreviousVersion, want.PreviousVersion},
		{"previous_binary_path", got.PreviousBinaryPath, want.PreviousBinaryPath},
		{"previous_schema_version", got.PreviousSchemaVersion, want.PreviousSchemaVersion},
		{"previous_db_backup_path", got.PreviousDBBackupPath, want.PreviousDBBackupPath},
		{"manifest_json", got.ManifestJSON, want.ManifestJSON},
	} {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.name, c.got, c.want)
		}
	}
	if got.UpdatedAt == "" {
		t.Error("updated_at was not stamped")
	}
}

// TestSaveRefusesAnUnknownState: the state column feeds the org board through
// the posture composer, so a value outside the closed vocabulary must fail at
// the seam rather than arrive as an enum nobody can render.
func TestSaveRefusesAnUnknownState(t *testing.T) {
	s := updateTestStore(t)
	row := UpdateStateRow{NodeState: update.NodeState{State: update.State("mostly-fine")}}
	if err := s.SaveUpdateState(context.Background(), row); err == nil {
		t.Fatal("SaveUpdateState accepted a state outside the vocabulary")
	}
}

// TestTransitionUpdateStateEnforcesTheTable: an impossible sequence must fail
// where it happens, not surface as a nonsensical row on the org board two
// push cycles later.
func TestTransitionUpdateStateEnforcesTheTable(t *testing.T) {
	s := updateTestStore(t)
	ctx := context.Background()

	legal := []update.State{update.StateAvailable, update.StateDownloading, update.StateVerified, update.StateApplying, update.StateApplied}
	for _, next := range legal {
		if err := s.TransitionUpdateState(ctx, next, nil, UpdateEventRow{Detail: "step"}); err != nil {
			t.Fatalf("legal transition to %q refused: %v", next, err)
		}
	}
	// applied -> downloading is NOT legal; a new manifest must re-arm the
	// node through `available` first.
	if err := s.TransitionUpdateState(ctx, update.StateDownloading, nil, UpdateEventRow{}); err == nil {
		t.Fatal("applied -> downloading was accepted; the transition table is not enforced")
	}

	events, err := s.LoadUpdateEvents(ctx, 100)
	if err != nil {
		t.Fatalf("LoadUpdateEvents: %v", err)
	}
	if len(events) != len(legal) {
		t.Fatalf("ledger holds %d rows, want %d (one per accepted transition, none for the refusal)", len(events), len(legal))
	}
}

// TestHistoryListsEveryApplyAndRollbackWithReasons is the plan's
// `observer update history` requirement: every apply and rollback appears,
// newest first, each with a reason.
func TestHistoryListsEveryApplyAndRollbackWithReasons(t *testing.T) {
	s := updateTestStore(t)
	ctx := context.Background()
	base := time.Date(2026, 9, 7, 10, 0, 0, 0, time.UTC)
	rows := []UpdateEventRow{
		{At: base, FromVersion: "v1.31.0", ToVersion: "v1.32.0", State: update.StateApplied, Detail: "self-check passed"},
		{At: base.Add(time.Hour), FromVersion: "v1.32.0", ToVersion: "v1.33.0", State: update.StateRolledBack, ErrorClass: update.ErrorHealthcheck, Detail: "restored the previous binary and the pre-apply snapshot"},
		{At: base.Add(2 * time.Hour), FromVersion: "v1.32.0", ToVersion: "v1.33.0", State: update.StateFailed, ErrorClass: update.ErrorDrain, Detail: "2 requests still in flight"},
	}
	for _, r := range rows {
		if err := s.AppendUpdateEvent(ctx, r); err != nil {
			t.Fatalf("AppendUpdateEvent: %v", err)
		}
	}
	got, err := s.LoadUpdateEvents(ctx, 10)
	if err != nil {
		t.Fatalf("LoadUpdateEvents: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("history has %d rows, want 3", len(got))
	}
	// Newest first.
	if got[0].State != update.StateFailed || got[2].State != update.StateApplied {
		t.Fatalf("history is not newest-first: %v -> %v", got[0].State, got[2].State)
	}
	for i, r := range got {
		if r.Detail == "" {
			t.Errorf("row %d has no reason; a ledger without reasons cannot answer why a node is where it is", i)
		}
		if r.At.IsZero() {
			t.Errorf("row %d has no timestamp", i)
		}
	}
	if got[1].ErrorClass != update.ErrorHealthcheck {
		t.Errorf("rollback row error_class = %q, want healthcheck", got[1].ErrorClass)
	}
	// The limit must actually bound the page.
	if page, err := s.LoadUpdateEvents(ctx, 2); err != nil || len(page) != 2 {
		t.Fatalf("LoadUpdateEvents(2) = %d rows, err %v", len(page), err)
	}
}

// TestSnapshotDatabaseProducesAReadableCopy: the snapshot is the only thing
// standing between a failed migrating apply and a brick, so it must be a real
// database, not a zero-byte file.
func TestSnapshotDatabaseProducesAReadableCopy(t *testing.T) {
	s := updateTestStore(t)
	ctx := context.Background()
	dest := filepath.Join(t.TempDir(), "preupgrade-v1.32.0.db")
	if err := s.SnapshotDatabase(ctx, dest); err != nil {
		t.Fatalf("SnapshotDatabase: %v", err)
	}
	info, err := os.Stat(dest)
	if err != nil {
		t.Fatalf("no snapshot at %s: %v", dest, err)
	}
	if info.Size() == 0 {
		t.Fatal("the snapshot is empty")
	}
	// It must open as a database at the SAME schema version — restoring a
	// snapshot that cannot be opened is not a rollback.
	copyDB, err := dbtemplate.Open(ctx, db.Options{Path: dest})
	if err != nil {
		t.Fatalf("the snapshot does not open: %v", err)
	}
	defer func() { _ = copyDB.Close() }()
	live, err := s.SchemaVersion(ctx)
	if err != nil {
		t.Fatal(err)
	}
	snap, err := db.Version(ctx, copyDB)
	if err != nil {
		t.Fatal(err)
	}
	if live != snap {
		t.Fatalf("snapshot schema %d, live %d", snap, live)
	}
	// A second snapshot to the same path must overwrite rather than fail on
	// a stale file from an abandoned apply.
	if err := s.SnapshotDatabase(ctx, dest); err != nil {
		t.Fatalf("SnapshotDatabase (second call): %v", err)
	}
}

// TestPruneUpdateArtifactsSparesTheLiveRollbackTarget: keep_previous_days is
// a retention policy, not a garbage collector. Deleting the binary or the
// snapshot the current state row points at would turn a recoverable rollback
// into the brick this feature exists to prevent.
func TestPruneUpdateArtifactsSparesTheLiveRollbackTarget(t *testing.T) {
	s := updateTestStore(t)
	ctx := context.Background()
	stateDir := t.TempDir()
	rollbackDir := filepath.Join(stateDir, "rollback")
	if err := os.MkdirAll(rollbackDir, 0o755); err != nil {
		t.Fatal(err)
	}
	live := filepath.Join(rollbackDir, "observer-v1.32.0")
	oldOne := filepath.Join(rollbackDir, "observer-v1.20.0")
	liveSnap := filepath.Join(stateDir, "preupgrade-v1.32.0.db")
	oldSnap := filepath.Join(stateDir, "preupgrade-v1.20.0.db")
	operatorFile := filepath.Join(stateDir, "notes.txt")
	for _, p := range []string{live, oldOne, liveSnap, oldSnap, operatorFile} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		old := time.Now().Add(-30 * 24 * time.Hour)
		if err := os.Chtimes(p, old, old); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.SaveUpdateState(ctx, UpdateStateRow{NodeState: update.NodeState{
		State: update.StateApplied, PreviousBinaryPath: live, PreviousDBBackupPath: liveSnap,
	}}); err != nil {
		t.Fatal(err)
	}

	removed, err := s.PruneUpdateArtifacts(ctx, stateDir, 14)
	if err != nil {
		t.Fatalf("PruneUpdateArtifacts: %v", err)
	}
	if removed != 2 {
		t.Errorf("removed %d entries, want 2 (the two stale ones)", removed)
	}
	for _, p := range []string{live, liveSnap} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("the LIVE rollback target %s was pruned", p)
		}
	}
	for _, p := range []string{oldOne, oldSnap} {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("the stale entry %s survived", p)
		}
	}
	if _, err := os.Stat(operatorFile); err != nil {
		t.Error("a file this feature does not own was deleted by the retention pass")
	}
	// keep_previous_days = 0 disables pruning entirely.
	if n, err := s.PruneUpdateArtifacts(ctx, stateDir, 0); err != nil || n != 0 {
		t.Errorf("PruneUpdateArtifacts with keepDays=0 removed %d entries (err %v), want none", n, err)
	}
}

// TestPostureIsNilUntilWired: a node without the feature must push a
// byte-identical envelope, which is the compat shape acceptance 4 requires.
func TestPostureIsNilUntilWired(t *testing.T) {
	ClearUpdatePostureEnv()
	t.Cleanup(ClearUpdatePostureEnv)
	s := updateTestStore(t)
	got, err := s.SelectUpdatePosture(context.Background())
	if err != nil {
		t.Fatalf("SelectUpdatePosture: %v", err)
	}
	if got != nil {
		t.Fatalf("posture = %+v with nothing wired, want nil", got)
	}
}

// TestPostureCarriesNoPathOrHostname is ruling R10 enforced against a row
// whose SOURCE is full of paths: every path column in update_state is stuffed
// with a sentinel, and none of them may appear anywhere in the composed row.
func TestPostureCarriesNoPathOrHostname(t *testing.T) {
	ClearUpdatePostureEnv()
	t.Cleanup(ClearUpdatePostureEnv)
	s := updateTestStore(t)
	ctx := context.Background()

	const sentinel = "SENTINEL-PATH-MUST-NOT-SHIP"
	if err := s.SaveUpdateState(ctx, UpdateStateRow{NodeState: update.NodeState{
		Channel: update.ChannelStable, LastManifestVersion: 17, TargetVersion: "v1.33.0",
		State: update.StateFailed, ErrorClass: update.ErrorSwap,
		PreviousVersion:      "v1.32.0",
		PreviousBinaryPath:   "/home/" + sentinel + "/rollback/observer",
		PreviousDBBackupPath: "/home/" + sentinel + "/preupgrade.db",
		ApplyingStartedAt:    "2026-09-07T10:00:00Z",
	}, ManifestJSON: `{"notes":"` + sentinel + `"}`}); err != nil {
		t.Fatal(err)
	}
	// The ledger's free-text detail is the other path carrier.
	if err := s.AppendUpdateEvent(ctx, UpdateEventRow{
		State: update.StateFailed, Detail: "could not write /home/" + sentinel + "/x",
	}); err != nil {
		t.Fatal(err)
	}

	SetUpdatePostureEnv(UpdatePostureEnv{
		Version: "v1.32.0", OS: "linux", Arch: "amd64",
		InstallMethod: string(update.MethodBinary), AutoApply: true,
	})
	row, err := s.SelectUpdatePosture(ctx)
	if err != nil {
		t.Fatalf("SelectUpdatePosture: %v", err)
	}
	if row == nil {
		t.Fatal("posture is nil although the environment is wired")
	}
	for _, f := range []struct{ name, val string }{
		{"version", row.Version},
		{"channel", row.Channel},
		{"os", row.OS},
		{"arch", row.Arch},
		{"state", row.State},
		{"reason", row.Reason},
		{"target_version", row.TargetVersion},
		{"error_class", row.ErrorClass},
		{"install_method", row.InstallMethod},
		{"extension_version", row.ExtensionVersion},
	} {
		if f.val == sentinel || containsSentinel(f.val, sentinel) {
			t.Errorf("posture field %s leaked a local path: %q", f.name, f.val)
		}
	}
	if row.State != string(update.StateFailed) || row.ErrorClass != string(update.ErrorSwap) {
		t.Errorf("posture = %+v, want the recorded enums", row)
	}
	if !row.AutoApply {
		t.Error("auto_apply was not carried; the server cannot otherwise know it")
	}
	// And the row must still be exactly the enum-only wire type.
	var _ orgcontract.UpdatePostureRow = *row
}

func containsSentinel(s, sentinel string) bool {
	return len(s) >= len(sentinel) && indexOfSub(s, sentinel) >= 0
}

func indexOfSub(h, n string) int {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return i
		}
	}
	return -1
}

// TestPostureChannelPrefersTheLocalPin: [update].channel overrides whatever
// the org assigned, because a node may pin ITSELF behind the fleet.
func TestPostureChannelPrefersTheLocalPin(t *testing.T) {
	ClearUpdatePostureEnv()
	t.Cleanup(ClearUpdatePostureEnv)
	s := updateTestStore(t)
	ctx := context.Background()
	if err := s.SaveUpdateState(ctx, UpdateStateRow{NodeState: update.NodeState{
		State: update.StateIdle, Channel: update.ChannelStable,
	}}); err != nil {
		t.Fatal(err)
	}
	SetUpdatePostureEnv(UpdatePostureEnv{Version: "v1.32.0", Channel: string(update.ChannelLTS)})
	row, err := s.SelectUpdatePosture(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if row.Channel != string(update.ChannelLTS) {
		t.Fatalf("channel = %q, want the local pin %q", row.Channel, update.ChannelLTS)
	}
}

// --- review fix round 2 -----------------------------------------------------

// TestSaveVerifiedManifestIsTheDurableHomeOfANotifyOnlyNode is the store half
// of H3: W3 shipped the columns and nothing ever wrote them.
func TestSaveVerifiedManifestIsTheDurableHomeOfANotifyOnlyNode(t *testing.T) {
	s := updateTestStore(t)
	ctx := context.Background()
	seen := time.Date(2026, 9, 8, 10, 0, 0, 0, time.UTC)
	if err := s.SaveVerifiedManifest(ctx, VerifiedManifest{
		Channel: update.ChannelStable, ManifestVersion: 17, TargetVersion: "v1.33.0",
		ManifestJSON: `{"version":"v1.33.0"}`, State: update.StateAvailable,
		SeenAt: seen, Detail: "manifest verified and accepted",
	}); err != nil {
		t.Fatalf("SaveVerifiedManifest: %v", err)
	}
	row, err := s.LoadUpdateState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if row.State != update.StateAvailable || row.TargetVersion != "v1.33.0" ||
		row.LastManifestVersion != 17 || row.ManifestJSON == "" || row.Channel != update.ChannelStable {
		t.Fatalf("row = %+v, want the verified manifest durably recorded", row)
	}
	if row.LastManifestSeenAt != seen.Format(time.RFC3339) {
		t.Errorf("last_manifest_seen_at = %q, want %q", row.LastManifestSeenAt, seen.Format(time.RFC3339))
	}

	// Re-verifying the SAME state is not an illegal available -> available
	// move; it just refreshes what was seen and when.
	if err := s.SaveVerifiedManifest(ctx, VerifiedManifest{
		Channel: update.ChannelStable, ManifestVersion: 17, TargetVersion: "v1.33.0",
		State: update.StateAvailable, SeenAt: seen.Add(time.Hour),
	}); err != nil {
		t.Fatalf("re-verifying the same manifest failed: %v", err)
	}

	// An APPLY in flight owns the row: a fetch that lands mid-handshake must
	// not rewrite target_version under the rollback decision that reads it.
	applying := UpdateStateRow{NodeState: update.NodeState{
		State: update.StateApplying, TargetVersion: "v1.33.0", PreviousVersion: "v1.32.0",
	}}
	if err := s.SaveUpdateState(ctx, applying); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveVerifiedManifest(ctx, VerifiedManifest{
		Channel: update.ChannelStable, ManifestVersion: 18, TargetVersion: "v1.34.0",
		State: update.StateAvailable, SeenAt: seen,
	}); err != nil {
		t.Fatalf("SaveVerifiedManifest during an apply: %v", err)
	}
	row, err = s.LoadUpdateState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if row.State != update.StateApplying || row.TargetVersion != "v1.33.0" {
		t.Fatalf("a mid-apply fetch rewrote the row: %+v", row)
	}
}

// TestSaveVerifiedManifestReArmsThroughAvailable: applied -> blocked is not a
// legal edge, but a node that applied and then met a manifest with no artifact
// for its platform must still report blocked.
func TestSaveVerifiedManifestReArmsThroughAvailable(t *testing.T) {
	s := updateTestStore(t)
	ctx := context.Background()
	if err := s.SaveUpdateState(ctx, UpdateStateRow{NodeState: update.NodeState{State: update.StateApplied}}); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveVerifiedManifest(ctx, VerifiedManifest{
		Channel: update.ChannelStable, ManifestVersion: 20, TargetVersion: "v1.34.0",
		State: update.StateBlocked, Reason: update.ReasonNoArtifact, SeenAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("SaveVerifiedManifest: %v", err)
	}
	row, err := s.LoadUpdateState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if row.State != update.StateBlocked || row.Reason != update.ReasonNoArtifact {
		t.Fatalf("row = %+v, want blocked{no_artifact}", row)
	}
}

// TestPruneUpdateArtifactsAllowListMatchesVersionShapes is L6: the allow-list
// was a ONE-LETTER prefix, in a delete loop pointed at an operator-chosen
// state_dir. `vault/`, `venv/` and `vendor/` all start with v.
func TestPruneUpdateArtifactsAllowListMatchesVersionShapes(t *testing.T) {
	s := updateTestStore(t)
	ctx := context.Background()
	stateDir := t.TempDir()
	ours := filepath.Join(stateDir, "v1.20.0")
	theirs := []string{
		filepath.Join(stateDir, "venv"),
		filepath.Join(stateDir, "vendor"),
		filepath.Join(stateDir, "vault"),
	}
	for _, d := range append([]string{ours}, theirs...) {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		old := time.Now().Add(-30 * 24 * time.Hour)
		if err := os.Chtimes(d, old, old); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.PruneUpdateArtifacts(ctx, stateDir, 14); err != nil {
		t.Fatalf("PruneUpdateArtifacts: %v", err)
	}
	if _, err := os.Stat(ours); err == nil {
		t.Error("our own stale staging directory survived")
	}
	for _, d := range theirs {
		if _, err := os.Stat(d); err != nil {
			t.Errorf("the retention pass deleted %s, which this feature does not own", d)
		}
	}
}
