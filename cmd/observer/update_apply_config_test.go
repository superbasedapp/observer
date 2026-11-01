//go:build !sbo_omit_org_update

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/fsatomic"
	"github.com/marmutapp/superbased-observer/internal/quiesce"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/update"
)

// The pre-apply config.toml snapshot (lane SEC-E milestone 4): a child that
// writes keys the older binary refuses (the managed accept-list backfill
// adding security.scanning, for one) and then fails its handshake must leave
// the node with the exact pre-apply bytes, or the restored binary would not
// start.

const preApplyConfig = "# the developer's own file, byte for byte\r\n[org_client.policy]\naccept_families = [\"node.features\"]   # trailing note\n"

func failingChildWrites(f *applyFixture, configPath, written string) {
	f.deps.Supervise = func(context.Context, string, string, time.Duration) (handshakeResult, error) {
		f.st.swapped = true
		if err := os.WriteFile(configPath, []byte(written), 0o600); err != nil {
			f.t.Fatal(err)
		}
		return handshakeResult{Detail: "self-check failed"}, errors.New("self-check failed")
	}
}

func TestAFailedChildRestoresTheExactConfigBytes(t *testing.T) {
	f := newApplyFixture(t)
	cfgPath := filepath.Join(f.dir, "config.toml")
	if err := os.WriteFile(cfgPath, []byte(preApplyConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	f.opts.ConfigPath = cfgPath
	newer := "[org_client.policy]\naccept_families = [\"node.features\", \"security.scanning\"]\n"
	failingChildWrites(f, cfgPath, newer)
	out, _ := f.run()
	if out.State != update.StateRolledBack {
		t.Fatalf("outcome = %+v, want rolled_back", out)
	}
	got, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte(preApplyConfig)) {
		t.Fatalf("config.toml after the rollback:\n%q\nwant the exact pre-apply bytes:\n%q", got, preApplyConfig)
	}
	// The file the failed child wrote is kept, never deleted.
	kept := fsatomic.DisplacedCopies(cfgPath)
	if len(kept) != 1 {
		t.Fatalf("displaced copies = %v, want the child's file kept once", kept)
	}
	if b, _ := os.ReadFile(kept[0]); string(b) != newer {
		t.Fatalf("displaced copy holds %q", b)
	}
	if _, err := os.Stat(configSnapshotPathFor(f.mustPlanRollbackPath())); err != nil {
		t.Fatalf("the snapshot is not beside the preserved binary: %v", err)
	}
}

func TestAFailedChildRemovesAConfigItCreated(t *testing.T) {
	f := newApplyFixture(t)
	cfgPath := filepath.Join(f.dir, "config.toml") // absent before the apply
	f.opts.ConfigPath = cfgPath
	failingChildWrites(f, cfgPath, "[security]\n")
	if out, _ := f.run(); out.State != update.StateRolledBack {
		t.Fatalf("outcome = %+v", out)
	}
	if _, err := os.Stat(cfgPath); !os.IsNotExist(err) {
		t.Fatalf("a config.toml the failed child created must not stay in place: %v", err)
	}
	if len(fsatomic.DisplacedCopies(cfgPath)) != 1 {
		t.Fatal("the created file must be kept aside, not deleted")
	}
}

func TestASuccessfulApplyLeavesTheConfigAlone(t *testing.T) {
	f := newApplyFixture(t)
	cfgPath := filepath.Join(f.dir, "config.toml")
	if err := os.WriteFile(cfgPath, []byte(preApplyConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	f.opts.ConfigPath = cfgPath
	newer := "[org_client.policy]\naccept_families = [\"security.scanning\"]\n"
	f.deps.Supervise = func(context.Context, string, string, time.Duration) (handshakeResult, error) {
		f.st.swapped = true
		_ = os.WriteFile(cfgPath, []byte(newer), 0o600)
		return handshakeResult{Ready: true, Detail: "ok", ChildPID: 1}, nil
	}
	if out, err := f.run(); err != nil || !out.Applied {
		t.Fatalf("apply: %+v %v", out, err)
	}
	if got, _ := os.ReadFile(cfgPath); string(got) != newer {
		t.Fatalf("a successful apply must keep what the new binary wrote: %q", got)
	}
}

func TestAnUnwritableConfigSnapshotAbortsTheApply(t *testing.T) {
	f := newApplyFixture(t)
	cfgPath := filepath.Join(f.dir, "config.toml")
	if err := os.WriteFile(cfgPath, []byte(preApplyConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	f.opts.ConfigPath = cfgPath
	f.deps.Supervise = func(context.Context, string, string, time.Duration) (handshakeResult, error) {
		t.Fatal("the handshake must not run when the config snapshot failed")
		return handshakeResult{}, nil
	}
	// A directory where the snapshot file must go: the write cannot succeed.
	if err := os.MkdirAll(configSnapshotPathFor(f.mustPlanRollbackPath()), 0o700); err != nil {
		t.Fatal(err)
	}
	out, _ := f.run()
	if out.State != update.StateFailed || !strings.Contains(out.Detail, "config.toml snapshot") {
		t.Fatalf("outcome = %+v, want a failed apply naming the config snapshot", out)
	}
	if got := f.installedBinary(); !strings.Contains(got, "OLD") {
		t.Fatalf("the running binary was touched: %q", got)
	}
}

// TestTheOperatorRollbackRestoresTheConfig: `observer update rollback`
// finds the snapshot from the stored previous binary path alone.
func TestTheOperatorRollbackRestoresTheConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(cfgPath, []byte(preApplyConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	prev := filepath.Join(dir, "updates", "rollback", "observer-v1.2.3")
	snap, err := snapshotConfigFile(cfgPath, configSnapshotPathFor(prev))
	if err != nil || !snap.Existed {
		t.Fatalf("snapshot: %+v %v", snap, err)
	}
	if err := os.WriteFile(cfgPath, []byte("[later]\nedit = true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	back, ok := configSnapshotFrom(cfgPath, configSnapshotPathFor(prev))
	if !ok || !back.Existed {
		t.Fatalf("read back: %+v %v", back, ok)
	}
	if err := restoreConfigFile(back, time.Now()); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(cfgPath); string(got) != preApplyConfig {
		t.Fatalf("restored %q", got)
	}
	if strings.TrimSpace(configSnapshotPathFor("")) != "" {
		t.Fatal("no rollback binary path means no snapshot path")
	}
}

// mustPlanRollbackPath is the plan's preserved-binary path for the fixture.
func (f *applyFixture) mustPlanRollbackPath() string {
	f.t.Helper()
	plan, err := update.BuildApplyPlan(update.PlanInput{
		Installed: f.opts.Installed, Manifest: f.opts.Manifest, Artifact: f.opts.Artifact,
		TargetSchemaVersion: f.opts.TargetSchemaVersion, StateDir: f.opts.StateDir, Now: time.Now(),
		Window: f.opts.Window, Force: f.opts.Force,
	})
	if err != nil {
		f.t.Fatal(err)
	}
	return plan.RollbackBinaryPath
}

// rollbackRig is a daemon-side rollback over a real temporary database: a
// fake installed binary behind the executable seam, a preserved previous
// binary, and the exit seam captured so the handover never ends the test
// binary.
type rollbackRig struct {
	t       *testing.T
	dir     string
	exe     string
	prev    string
	cfgPath string
	st      *store.Store
	cfg     config.Config
	codes   chan int
}

func newRollbackRig(t *testing.T) *rollbackRig {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "observer.db")
	database, err := db.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	r := &rollbackRig{
		t: t, dir: dir, st: store.New(database), codes: make(chan int, 1),
		exe:     filepath.Join(dir, "bin", "observer"),
		prev:    filepath.Join(dir, "updates", "rollback", "observer-v1.2.3"),
		cfgPath: filepath.Join(dir, "custom", "config.toml"),
	}
	for path, body := range map[string]string{r.exe: "NEW", r.prev: "PREVIOUS", r.cfgPath: preApplyConfig} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	schema, err := r.st.SchemaVersion(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// The apply records the steps the database had run (T-979), so the
	// rollback sees a target that ran nothing and keeps the database.
	applied, err := r.st.AppliedMigrationSteps(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var row store.UpdateStateRow
	row.State = update.StateApplied
	row.TargetVersion = "v9.9.9"
	row.PreviousVersion = "v1.2.3"
	row.PreviousBinaryPath = r.prev
	row.PreviousSchemaVersion = schema
	row.PreviousAppliedSteps = applied
	if err := r.st.SaveUpdateState(ctx, row); err != nil {
		t.Fatal(err)
	}
	// The apply's snapshot, then the newer binary's own write.
	if _, err := snapshotConfigFile(r.cfgPath, configSnapshotPathFor(r.prev)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(r.cfgPath, []byte("[org_client.policy]\naccept_families = [\"security.scanning\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	restoreExe := updateExecutablePath
	updateExecutablePath = func() string { return r.exe }
	t.Cleanup(func() { updateExecutablePath = restoreExe })
	restoreExit := updateExitFunc
	updateExitFunc = func(code int) { r.codes <- code }
	t.Cleanup(func() { updateExitFunc = restoreExit })
	r.cfg.Observer.DBPath = dbPath
	return r
}

// waitExit waits for the handover's exit seam (it must fire before the
// cleanup puts the real os.Exit back).
func (r *rollbackRig) waitExit() int {
	r.t.Helper()
	select {
	case code := <-r.codes:
		return code
	case <-time.After(5 * time.Second):
		r.t.Fatal("the rollback never handed over")
		return -1
	}
}

func (r *rollbackRig) assertRestored() {
	r.t.Helper()
	if got, _ := os.ReadFile(r.exe); string(got) != "PREVIOUS" {
		r.t.Fatalf("installed binary = %q, want the previous binary", got)
	}
	if got, _ := os.ReadFile(r.cfgPath); string(got) != preApplyConfig {
		r.t.Fatalf("config.toml after the rollback:\n%q\nwant the exact pre-apply bytes:\n%q", got, preApplyConfig)
	}
	if kept := fsatomic.DisplacedCopies(r.cfgPath); len(kept) != 1 {
		r.t.Fatalf("displaced copies = %v, want the newer file kept once", kept)
	}
}

// TestTheDaemonRollbackRestoresTheConfig drives updateRuntime.rollback, the
// path the dashboard's Roll back and `observer update rollback` take while
// the daemon runs (merge audit finding 1): the previous binary AND the exact
// pre-apply config.toml bytes come back, from the daemon's own --config.
func TestTheDaemonRollbackRestoresTheConfig(t *testing.T) {
	r := newRollbackRig(t)
	u := &updateRuntime{
		cfg: r.cfg, configPath: r.cfgPath, store: r.st,
		logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		quiescence: &quiesce.Quiescence{Gate: quiesce.NewGate()},
	}
	out, err := u.rollback(context.Background())
	if err != nil || out.State != update.StateRolledBack || !out.RolledBack {
		t.Fatalf("rollback: %+v %v", out, err)
	}
	if code := r.waitExit(); code != 0 {
		t.Fatalf("exit code %d, want the clean handover", code)
	}
	r.assertRestored()
}

// TestTheDaemonRollbackDryRunChangesNothing (audit SEC-P4 F9): the route's
// {"rollback":true,"dry_run":true} reaches applyLocked, which reports the
// rollback's steps and performs none: the binary, config.toml and the
// ledger are as they were, and nothing hands over.
func TestTheDaemonRollbackDryRunChangesNothing(t *testing.T) {
	r := newRollbackRig(t)
	cfgBefore, _ := os.ReadFile(r.cfgPath)
	u := &updateRuntime{
		cfg: r.cfg, configPath: r.cfgPath, store: r.st,
		logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		quiescence: &quiesce.Quiescence{Gate: quiesce.NewGate()},
	}
	out, err := u.applyLocked(context.Background(), updateApplyRequest{Rollback: true, DryRun: true})
	if err != nil || out.RolledBack || len(out.Steps) == 0 || !strings.Contains(strings.Join(out.Steps, "\n"), "restore the previous binary (v1.2.3)") {
		t.Fatalf("dry-run rollback: %+v %v, want the plan only", out, err)
	}
	if got, _ := os.ReadFile(r.exe); string(got) != "NEW" {
		t.Fatalf("installed binary = %q after a dry run, want it untouched", got)
	}
	if got, _ := os.ReadFile(r.cfgPath); string(got) != string(cfgBefore) {
		t.Fatalf("config.toml changed by a dry run:\n%q", got)
	}
	row, lerr := r.st.LoadUpdateState(context.Background())
	if lerr != nil || row.State != update.StateApplied {
		t.Fatalf("ledger state = %q (%v), want applied, untouched", row.State, lerr)
	}
	select {
	case code := <-r.codes:
		t.Fatalf("a dry run handed over (exit %d)", code)
	case <-time.After(200 * time.Millisecond):
	}
}

// TestTheDaemonRollbackReportsAFailedConfigRestore: a config.toml that
// cannot be put back is a failed rollback that says so, and the process
// still hands over non-zero (the previous binary is already in place).
func TestTheDaemonRollbackReportsAFailedConfigRestore(t *testing.T) {
	r := newRollbackRig(t)
	// A directory where the file must go: the restore cannot succeed.
	if err := os.Remove(r.cfgPath); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(r.cfgPath, 0o700); err != nil {
		t.Fatal(err)
	}
	u := &updateRuntime{
		cfg: r.cfg, configPath: r.cfgPath, store: r.st,
		logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		quiescence: &quiesce.Quiescence{Gate: quiesce.NewGate()},
	}
	out, err := u.rollback(context.Background())
	if err == nil || out.State != update.StateFailed || !out.RolledBack || !strings.Contains(out.Detail, "config.toml could not be restored") {
		t.Fatalf("rollback: %+v %v, want a failed rollback naming config.toml", out, err)
	}
	if code := r.waitExit(); code == 0 {
		t.Fatal("a rollback whose config restore failed must not exit 0")
	}
	if got, _ := os.ReadFile(r.exe); string(got) != "PREVIOUS" {
		t.Fatalf("installed binary = %q, want the previous binary", got)
	}
	row, lerr := r.st.LoadUpdateState(context.Background())
	if lerr != nil || row.State != update.StateFailed {
		t.Fatalf("ledger state = %q (%v), want failed", row.State, lerr)
	}
}

// TestTheCLIRollbackRestoresTheConfigFlagFile drives runLocalRollback with
// --config (merge audit findings 1 and 8): the file named by --config is the
// one restored, never the default path.
func TestTheCLIRollbackRestoresTheConfigFlagFile(t *testing.T) {
	r := newRollbackRig(t)
	ctx := context.Background()
	row, err := r.st.LoadUpdateState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var w strings.Builder
	if err := runLocalRollback(ctx, &w, r.st, row, r.cfg, r.cfgPath); err != nil {
		t.Fatalf("rollback: %v\n%s", err, w.String())
	}
	r.assertRestored()
}

// TestAFailedConfigRestoreStillRestoresTheDatabase (merge audit finding 2):
// a child that migrated the database and left config.toml unrestorable
// still gets the pre-apply database back, and the outcome names both.
func TestAFailedConfigRestoreStillRestoresTheDatabase(t *testing.T) {
	f := newApplyFixture(t)
	cfgPath := filepath.Join(f.dir, "config.toml")
	if err := os.WriteFile(cfgPath, []byte(preApplyConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	f.opts.ConfigPath = cfgPath
	f.opts.TargetSchemaVersion = 105 // the target advances the schema
	f.st.schema, f.st.schemaAt = 104, 105
	f.deps.Supervise = func(context.Context, string, string, time.Duration) (handshakeResult, error) {
		f.st.swapped = true
		if err := os.WriteFile(f.dbPath, []byte("MIGRATED-DB"), 0o600); err != nil {
			t.Fatal(err)
		}
		// The child leaves a directory where config.toml must go back.
		if err := os.Remove(cfgPath); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(cfgPath, 0o700); err != nil {
			t.Fatal(err)
		}
		return handshakeResult{Detail: "self-check failed"}, errors.New("self-check failed")
	}
	out, _ := f.run()
	if got, _ := os.ReadFile(f.dbPath); string(got) != "SNAPSHOT" {
		t.Fatalf("database holds %q, want the pre-apply SNAPSHOT restored despite the config failure", got)
	}
	if got := f.installedBinary(); !strings.Contains(got, "OLD") {
		t.Fatalf("the OLD binary was not restored: %q", got)
	}
	if out.State != update.StateFailed || !out.RolledBack {
		t.Fatalf("outcome = %+v, want a failed rollback with the binary back", out)
	}
	if !strings.Contains(out.Detail, "config.toml could not be restored") || !strings.Contains(out.Detail, "pre-apply snapshot") {
		t.Fatalf("detail must name both outcomes: %q", out.Detail)
	}
}
