//go:build !sbo_omit_org_update

package main

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/service"
	"github.com/marmutapp/superbased-observer/internal/update"
)

// update_interlock_test.go pins the update-handover interlock in both places
// it runs (UPD-9 with SVC-1 and SVC-3): the new binary's self-check, which is
// the only code of a new release that runs during an update FROM an older
// one, and the parent's refusal before it drains, so a release with the fix
// never drains a node it cannot hand over.

const (
	unitCgroup    = "0::/user.slice/user-1000.slice/user@1000.service/app.slice/observer.service\n"
	shellCgroup   = "0::/user.slice/user-1000.slice/session-2.scope\n"
	restartsPlist = "<key>KeepAlive</key>\n  <dict>\n    <key>SuccessfulExit</key>\n    <false/>\n  </dict>"
	noKeepAlive   = "<key>RunAtLoad</key><true/>"
)

// withLaunchAgentPlist makes the installed agent plist read as body.
func withLaunchAgentPlist(t *testing.T, body string) {
	t.Helper()
	saved := launchAgentPlist
	launchAgentPlist = func() string { return body }
	t.Cleanup(func() { launchAgentPlist = saved })
}

func TestChildSelfCheckRefusesAHandoverItsSupervisorCannotFollow(t *testing.T) {
	for _, tc := range []struct {
		name           string
		cgroup, notify string
		job, plist     string
		parent         string
		want           service.HandoverRefusal
		wantReady      bool
	}{
		{name: "unsupervised, old parent", cgroup: shellCgroup, parent: "1.42.0", wantReady: true},
		{name: "systemd: new unit, new parent", cgroup: unitCgroup, notify: "/run/user/1000/systemd/notify", parent: update.FirstSupervisedHandoverRelease, wantReady: true},
		{name: "systemd: new unit, newer parent", cgroup: unitCgroup, notify: "@/org/freedesktop/systemd1/notify/1", parent: "v1.50.0", wantReady: true},
		{name: "systemd: pre-fix unit", cgroup: unitCgroup, parent: update.FirstSupervisedHandoverRelease, want: service.RefuseUnitPredatesHandover},
		{name: "systemd: new unit, parent v1.42.0", cgroup: unitCgroup, notify: "/run/user/1000/systemd/notify", parent: "1.42.0", want: service.RefuseParentPredatesMainPID},
		{name: "systemd: new unit, unparseable parent counts as older", cgroup: unitCgroup, notify: "/run/user/1000/systemd/notify", parent: "dev", want: service.RefuseParentPredatesMainPID},
		{name: "launchd: restarting agent, new parent", job: service.LaunchdLabel, plist: restartsPlist, parent: update.FirstSupervisedHandoverRelease, wantReady: true},
		{name: "launchd: parent v1.42.0", job: service.LaunchdLabel, plist: restartsPlist, parent: "v1.42.0", want: service.RefuseParentPredatesLaunchdRestart},
		{name: "launchd: agent without a restart", job: service.LaunchdLabel, plist: noKeepAlive, parent: update.FirstSupervisedHandoverRelease, want: service.RefuseAgentDoesNotRestart},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			u := upd9Runtime(t)
			withVersion(t, "1.50.1")
			t.Setenv(handshakeNonceEnv, "n0nce")
			isolateSupervisionEnv(t)
			t.Setenv("NOTIFY_SOCKET", tc.notify)
			t.Setenv("XPC_SERVICE_NAME", tc.job)
			withHandoverCgroup(t, tc.cgroup)
			withLaunchAgentPlist(t, tc.plist)
			heard := hearChildReport(t)
			row, err := u.store.LoadUpdateState(ctx)
			if err != nil {
				t.Fatal(err)
			}
			row.State = update.StateApplying
			row.TargetVersion = "v1.50.1"
			row.PreviousVersion = tc.parent
			if err := u.store.SaveUpdateState(ctx, row); err != nil {
				t.Fatal(err)
			}
			u.ReportChildSelfCheck(ctx)
			if tc.wantReady {
				if len(heard.ready) != 1 || len(heard.fail) != 0 {
					t.Fatalf("want ready, heard ready=%v fail=%v", heard.ready, heard.fail)
				}
				return
			}
			if len(heard.ready) != 0 || len(heard.fail) != 1 {
				t.Fatalf("want a failed self-check naming %s, heard ready=%v fail=%v", tc.want, heard.ready, heard.fail)
			}
			if got := service.HandoverRefusalIn(heard.fail[0]); got != tc.want {
				t.Fatalf("the failure names %q, want %q: %s", got, tc.want, heard.fail[0])
			}
			if !strings.Contains(heard.fail[0], "observer service upgrade") {
				t.Fatalf("the failure does not name the fix: %s", heard.fail[0])
			}
		})
	}
}

// TestApplyRefusesBeforeTheDrainWhenTheSupervisorCannotFollow: the parent
// checks the same table before a byte is downloaded, so a node it cannot
// hand over is never drained, swapped or restarted.
func TestApplyRefusesBeforeTheDrainWhenTheSupervisorCannotFollow(t *testing.T) {
	for _, refusal := range service.HandoverRefusals() {
		t.Run(string(refusal), func(t *testing.T) {
			f := newApplyFixture(t)
			downloads, supervised := 0, 0
			download := f.deps.Download
			f.deps.Download = func(ctx context.Context, v, name string, dst io.Writer, maxBytes int64) error {
				downloads++
				return download(ctx, v, name, dst, maxBytes)
			}
			f.deps.Supervise = func(context.Context, string, string, time.Duration) (handshakeResult, error) {
				supervised++
				return handshakeResult{Ready: true}, nil
			}
			f.deps.Supervision = func() service.HandoverRefusal { return refusal }
			f.gate.Enter() // a proxied request in flight: a drain would have to wait for it
			defer f.gate.Leave()

			out, err := f.run()
			if err == nil {
				t.Fatal("the apply was not refused")
			}
			if downloads != 0 || supervised != 0 {
				t.Fatalf("refused apply downloaded %d and supervised %d time(s)", downloads, supervised)
			}
			if got := f.installedBinary(); !strings.Contains(got, "OLD") {
				t.Fatal("a refused apply replaced the binary")
			}
			if out.State != update.StateFailed || out.ErrorClass != update.ErrorHealthcheck {
				t.Fatalf("outcome %s/%s, want failed/healthcheck", out.State, out.ErrorClass)
			}
			if service.HandoverRefusalIn(out.Detail) != refusal {
				t.Fatalf("detail does not name %s: %s", refusal, out.Detail)
			}
			if f.st.row.State != update.StateFailed || service.HandoverRefusalIn(f.st.events[len(f.st.events)-1].Detail) != refusal {
				t.Fatalf("ledger: state %s, last event %+v", f.st.row.State, f.st.events[len(f.st.events)-1])
			}
		})
	}
	t.Run("allowed", func(t *testing.T) {
		f := newApplyFixture(t)
		f.deps.Supervision = func() service.HandoverRefusal { return service.HandoverAllowed }
		out, err := f.run()
		if err != nil || !out.Applied {
			t.Fatalf("an allowed handover did not apply: %+v, %v", out, err)
		}
	})
}
