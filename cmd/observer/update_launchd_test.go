//go:build !sbo_omit_org_update

package main

import (
	"context"
	"database/sql"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/quiesce"
	"github.com/marmutapp/superbased-observer/internal/service"
	"github.com/marmutapp/superbased-observer/internal/update"
)

// update_launchd_test.go pins the launchd hand-over (SVC-3, option b): the
// parent stops the self-checked child and exits non-zero so the agent starts
// the new binary itself; the restarted binary settles the apply once it has
// stayed up, or restores the previous binary after repeated failed boots.
// The first two tests check code that existed before the hand-over and that
// its boot-time restore reuses.

// TestTheDaemonRollbackExitsSoItsSupervisorRestarts: a rollback ends the
// daemon so the restored binary starts. The unit restarts on failure only
// (Restart=on-failure, SVC-1) and the agent on an unsuccessful exit only, so
// under a supervisor that exit must be non-zero; an exit 0 leaves the node
// down after `observer update rollback`.
func TestTheDaemonRollbackExitsSoItsSupervisorRestarts(t *testing.T) {
	for _, tc := range []struct {
		name           string
		cgroup, notify string
		job, plist     string
		want           int
	}{
		{name: "systemd", cgroup: "0::/system.slice/observer.service\n", notify: "/run/systemd/notify", want: service.SupervisorRestartExitCode},
		{name: "launchd", job: service.LaunchdLabel, plist: restartsPlist, want: service.SupervisorRestartExitCode},
		{name: "unsupervised", cgroup: "0::/user.slice/session-2.scope\n", want: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRollbackRig(t)
			isolateSupervisionEnv(t)
			withHandoverCgroup(t, tc.cgroup)
			t.Setenv("NOTIFY_SOCKET", tc.notify)
			t.Setenv("XPC_SERVICE_NAME", tc.job)
			withLaunchAgentPlist(t, tc.plist)
			u := &updateRuntime{
				cfg: r.cfg, configPath: r.cfgPath, store: r.st,
				logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
				quiescence: &quiesce.Quiescence{Gate: quiesce.NewGate()},
			}
			if out, err := u.rollback(context.Background()); err != nil || !out.RolledBack {
				t.Fatalf("rollback: %+v %v", out, err)
			}
			if code := r.waitExit(); code != tc.want {
				t.Fatalf("exit code %d, want %d", code, tc.want)
			}
		})
	}
}

// TestReopeningARestoredSnapshotDoesNotMigrateIt: after a rollback renames
// the pre-apply snapshot over the live database, the ledger row is written
// through a fresh handle on it. That handle must not run THIS binary's
// migrations: on the daemon-side rollback this binary is the NEWER one, and
// migrating the restored file forward hands the previous binary a newer
// schema, the corruption risk the snapshot exists to avoid.
func TestReopeningARestoredSnapshotDoesNotMigrateIt(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "observer.db")
	plain, err := db.OpenPlain(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	ddl, err := os.ReadFile(filepath.Join("..", "..", "internal", "db", "migrations", "105_update_state.sql"))
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{`CREATE TABLE schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)`, string(ddl)} {
		if _, err := plain.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("seeding an older schema: %v", err)
		}
	}
	tablesBefore := countTables(t, plain)
	_ = plain.Close()

	st, err := reopenUpdateStore(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	row, err := st.LoadUpdateState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	row.State = update.StateRolledBack
	if err := st.SaveUpdateState(ctx, row); err != nil {
		t.Fatalf("recording the rollback on the restored file: %v", err)
	}
	if c, ok := st.(interface{ CloseDatabase() error }); ok {
		_ = c.CloseDatabase()
	}
	check, err := db.OpenPlain(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = check.Close() }()
	if after := countTables(t, check); after != tablesBefore {
		t.Fatalf("the reopen migrated the restored file: %d tables before, %d after", tablesBefore, after)
	}
}

func countTables(t *testing.T, d *sql.DB) int {
	t.Helper()
	var n int
	if err := d.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM sqlite_master WHERE type = 'table'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestApplyHandsALaunchdNodeToItsAgent: the apply leaves the state applying
// with a boot record for the target (the restarted binary settles it), and
// the parent stops the child BEFORE it exits with the restart code.
func TestApplyHandsALaunchdNodeToItsAgent(t *testing.T) {
	f := newApplyFixture(t)
	var order []string
	f.deps.Supervise = func(context.Context, string, string, time.Duration) (handshakeResult, error) {
		return handshakeResult{
			Ready: true, Detail: "self-check passed", ChildPID: 4242, Started: true, RestartBySupervisor: true,
			stopChild: func(time.Duration) error { order = append(order, "stop child"); return nil },
		}, nil
	}
	out, err := f.run()
	if err != nil || !out.Applied || !out.RestartBySupervisor {
		t.Fatalf("apply: %+v, %v", out, err)
	}
	if f.st.row.State != update.StateApplying {
		t.Fatalf("state %s, want applying until the restarted binary settles it", f.st.row.State)
	}
	rec, err := update.DecodeSupervisorRestart(f.st.supervisorRestart)
	if err != nil || !rec.Matches(fixtureTargetVersion) || rec.Attempts != 0 {
		t.Fatalf("boot record %+v, %v", rec, err)
	}
	if last := f.st.events[len(f.st.events)-1]; !strings.Contains(last.Detail, "launchd") {
		t.Fatalf("the ledger does not say launchd starts the new binary: %+v", last)
	}

	codes := make(chan int, 1)
	saved := updateExitFunc
	updateExitFunc = func(code int) { order = append(order, "exit"); codes <- code }
	t.Cleanup(func() { updateExitFunc = saved })
	u := &updateRuntime{logger: discardLogger()}
	if !u.finishApply(out, fixtureTargetVersion) {
		t.Fatal("the parent did not end after a launchd hand-over")
	}
	select {
	case code := <-codes:
		if code != service.SupervisorRestartExitCode {
			t.Fatalf("exit %d, want %d", code, service.SupervisorRestartExitCode)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the parent never exited")
	}
	if strings.Join(order, ",") != "stop child,exit" {
		t.Fatalf("order %v: the child must be stopped (its ports freed) before the parent exits", order)
	}
}

// launchdBootRig is a node database whose state says a launchd hand-over to
// this binary is in progress.
func launchdBootRig(t *testing.T, attempts int) *rollbackRig {
	t.Helper()
	r := newRollbackRig(t)
	ctx := context.Background()
	withVersion(t, "9.9.9")
	t.Setenv(handshakeNonceEnv, "")
	isolateSupervisionEnv(t)
	t.Setenv("XPC_SERVICE_NAME", service.LaunchdLabel)
	withLaunchAgentPlist(t, restartsPlist)
	row, err := r.st.LoadUpdateState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	row.State = update.StateApplying
	row.TargetVersion = "v9.9.9"
	if err := r.st.SaveUpdateState(ctx, row); err != nil {
		t.Fatal(err)
	}
	js, _ := update.EncodeSupervisorRestart(update.SupervisorRestart{Target: "v9.9.9", Attempts: attempts})
	if err := r.st.SaveUpdateSupervisorRestart(ctx, js); err != nil {
		t.Fatal(err)
	}
	saved := supervisorRestartHealthyAfter
	supervisorRestartHealthyAfter = 50 * time.Millisecond
	t.Cleanup(func() { supervisorRestartHealthyAfter = saved })
	return r
}

func TestRecoverAtBootSettlesALaunchdRestartOnceItStaysUp(t *testing.T) {
	r := launchdBootRig(t, 0)
	ctx := context.Background()
	u := &updateRuntime{
		cfg: r.cfg, configPath: r.cfgPath, store: r.st, logger: discardLogger(),
		quiescence: &quiesce.Quiescence{Gate: quiesce.NewGate()},
	}
	u.RecoverAtBoot(ctx)
	rec, _ := r.st.LoadUpdateSupervisorRestart(ctx)
	if got, _ := update.DecodeSupervisorRestart(rec); got.Attempts != 1 {
		t.Fatalf("the boot was not counted: %+v", got)
	}
	if row, _ := r.st.LoadUpdateState(ctx); row.State != update.StateApplying {
		t.Fatalf("settled %s before the boot stayed up", row.State)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		row, _ := r.st.LoadUpdateState(ctx)
		if row.State == update.StateApplied {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("never settled applied: %s", row.State)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if rec, _ := r.st.LoadUpdateSupervisorRestart(ctx); rec != "" {
		t.Fatalf("the boot record was not cleared: %s", rec)
	}
	if got, _ := os.ReadFile(r.exe); string(got) != "NEW" {
		t.Fatalf("a healthy boot touched the binary: %q", got)
	}
}

func TestRecoverAtBootRestoresThePreviousBinaryAfterRepeatedFailedBoots(t *testing.T) {
	r := launchdBootRig(t, update.MaxSupervisorRestartBoots)
	ctx := context.Background()
	u := &updateRuntime{
		cfg: r.cfg, configPath: r.cfgPath, store: r.st, logger: discardLogger(),
		quiescence: &quiesce.Quiescence{Gate: quiesce.NewGate()},
	}
	u.RecoverAtBoot(ctx)
	if code := r.waitExit(); code != service.SupervisorRestartExitCode {
		t.Fatalf("exit %d, want the restart exit so launchd starts the restored binary", code)
	}
	r.assertRestored()
	row, err := r.st.LoadUpdateState(ctx)
	if err != nil || row.State != update.StateRolledBack || row.ErrorClass != update.ErrorHealthcheck {
		t.Fatalf("state %+v, %v", row.NodeState, err)
	}
	if rec, _ := r.st.LoadUpdateSupervisorRestart(ctx); rec != "" {
		t.Fatalf("the boot record was not cleared: %s", rec)
	}
	b, _ := r.st.LoadUpdateApplyBackoff(ctx)
	if got, _ := update.DecodeApplyBackoff(b); got.Failures != 1 || !update.SameVersion(got.Target, "v9.9.9") {
		t.Fatalf("the restored target is not backed off: %+v", got)
	}
}
