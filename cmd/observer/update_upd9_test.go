//go:build !sbo_omit_org_update

package main

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/update"
)

// update_upd9_test.go pins UPD-9 (lane service-units NEW-SU-01): an org
// manifest names a release "v1.42.0", a release build stamps itself
// "1.42.0", and every comparison the updater makes between the two must read
// them as the same version. Before the fix the child's self-check failed with
// "this binary is 1.42.0, the apply targeted v1.42.0", so every in-place
// update to a real release rolled back, and an apply that lost its parent
// settled failed although the running binary was the target.

// upd9Runtime is an update runtime over a real, migrated node database.
func upd9Runtime(t *testing.T) *updateRuntime {
	t.Helper()
	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "observer.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return &updateRuntime{store: store.New(database), logger: discardLogger()}
}

// withVersion stamps this test binary as v for the test.
func withVersion(t *testing.T, v string) {
	t.Helper()
	saved := version
	version = v
	t.Cleanup(func() { version = saved })
}

// heardReport captures what the child self-check tells its parent.
type heardReport struct{ ready, fail []string }

func hearChildReport(t *testing.T) *heardReport {
	t.Helper()
	h := &heardReport{}
	saved := childHandshakeReport
	childHandshakeReport.ready = func(nonce string) error { h.ready = append(h.ready, nonce); return nil }
	childHandshakeReport.fail = func(reason string) error { h.fail = append(h.fail, reason); return nil }
	t.Cleanup(func() { childHandshakeReport = saved })
	return h
}

func TestChildSelfCheckReadsTheManifestSpellingAsItsOwnVersion(t *testing.T) {
	for _, tc := range []struct {
		name, running, target string
		wantReady             bool
	}{
		{"manifest v, release build bare (UPD-9)", "1.42.0", "v1.42.0", true},
		{"both bare", "1.42.0", "1.42.0", true},
		{"both v", "v1.42.0", "v1.42.0", true},
		{"bare manifest, v build", "v1.42.0", "1.42.0", true},
		{"a different version still fails", "1.42.0", "v1.43.0", false},
		{"a pre-release of the target still fails", "1.42.0-rc.1", "v1.42.0", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			u := upd9Runtime(t)
			withVersion(t, tc.running)
			t.Setenv(handshakeNonceEnv, "n0nce")
			isolateSupervisionEnv(t)
			heard := hearChildReport(t)
			row, err := u.store.LoadUpdateState(ctx)
			if err != nil {
				t.Fatal(err)
			}
			row.State = update.StateApplying
			row.TargetVersion = tc.target
			row.PreviousVersion = "1.41.0"
			if err := u.store.SaveUpdateState(ctx, row); err != nil {
				t.Fatal(err)
			}
			u.ReportChildSelfCheck(ctx)
			if gotReady := len(heard.ready) == 1 && len(heard.fail) == 0; gotReady != tc.wantReady {
				t.Fatalf("running %s, target %s: ready=%v fail=%v, want ready=%v", tc.running, tc.target, heard.ready, heard.fail, tc.wantReady)
			}
		})
	}
}

func TestRecoverAtBootSettlesAppliedForTheManifestSpelling(t *testing.T) {
	for _, tc := range []struct {
		name, running, target string
		want                  update.State
	}{
		{"manifest v, release build bare (UPD-9)", "1.42.0", "v1.42.0", update.StateApplied},
		{"both bare", "1.42.0", "1.42.0", update.StateApplied},
		{"not the target", "1.41.0", "v1.42.0", update.StateFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			u := upd9Runtime(t)
			withVersion(t, tc.running)
			t.Setenv(handshakeNonceEnv, "")
			row, err := u.store.LoadUpdateState(ctx)
			if err != nil {
				t.Fatal(err)
			}
			row.State = update.StateApplying
			row.TargetVersion = tc.target
			row.PreviousVersion = "1.41.0"
			// No previous binary on disk: the interrupted-swap repair has
			// nothing to restore, so only the version decision is tested.
			row.PreviousBinaryPath = filepath.Join(t.TempDir(), "absent")
			if err := u.store.SaveUpdateState(ctx, row); err != nil {
				t.Fatal(err)
			}
			u.RecoverAtBoot(ctx)
			got, err := u.store.LoadUpdateState(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if got.State != tc.want {
				t.Fatalf("running %s, target %s: settled %q, want %q", tc.running, tc.target, got.State, tc.want)
			}
		})
	}
}

func TestVersionProbeMatchesEitherSpelling(t *testing.T) {
	for _, tc := range []struct {
		got, target string
		want        bool
	}{
		{"observer version v1.42.0", "1.42.0", true},
		{"observer version 1.42.0", "v1.42.0", true},
		{"v1.42.0", "1.42.0", true},
		{"observer version v1.41.0", "1.42.0", false},
		{"observer v1.41.0 (v1.42.0 available)", "1.42.0", false},
	} {
		if got := versionProbeMatches(tc.got, tc.target); got != tc.want {
			t.Errorf("versionProbeMatches(%q, %q) = %v, want %v", tc.got, tc.target, got, tc.want)
		}
	}
}

// isolateSupervisionEnv clears the supervisor facts the self-check reads
// (the notify socket, the launchd job, the cgroup and the agent plist), so a
// test run under a real unit or agent does not inherit them.
func isolateSupervisionEnv(t *testing.T) {
	t.Helper()
	t.Setenv("NOTIFY_SOCKET", "")
	t.Setenv("XPC_SERVICE_NAME", "")
	withHandoverCgroup(t, "0::/user.slice/user-1000.slice/session-2.scope\n")
	savedPlist := launchAgentPlist
	launchAgentPlist = func() string { return "" }
	t.Cleanup(func() { launchAgentPlist = savedPlist })
}

// withHandoverCgroup makes /proc/self/cgroup read as cg for the test, on
// every platform (the linux-only withUnitCgroup is the same seam).
func withHandoverCgroup(t *testing.T, cg string) {
	t.Helper()
	saved := handoverCgroup
	handoverCgroup = func() (string, error) { return cg, nil }
	t.Cleanup(func() { handoverCgroup = saved })
}
