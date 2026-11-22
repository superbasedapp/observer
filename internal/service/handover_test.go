package service

import (
	"strings"
	"testing"
)

// handover_test.go pins the update-handover interlock (UPD-9, SVC-1, SVC-3):
// the one table both the apply's parent (before it drains) and the new
// binary's self-check (before it reports ready) walk, so a node an update
// cannot keep supervised refuses with a reason instead of going down.

const (
	unitCgroupV2   = "0::/user.slice/user-1000.slice/user@1000.service/app.slice/observer.service\n"
	unitCgroupV1   = "12:pids:/user.slice\n1:name=systemd:/system.slice/observer.service\n0::/system.slice/observer.service\n"
	otherCgroup    = "0::/user.slice/user-1000.slice/session-2.scope\n"
	foreignUnitCg  = "0::/system.slice/tmux.service\n"
	renamedUnitCg  = "0::/system.slice/my-observer.service\n"
	launchdJobName = LaunchdLabel
)

func TestDetectSupervisor(t *testing.T) {
	for _, tc := range []struct {
		name, cgroup, job string
		want              Supervisor
	}{
		{"systemd unit, cgroup v2", unitCgroupV2, "", SupervisorSystemd},
		{"systemd unit, cgroup v1", unitCgroupV1, "", SupervisorSystemd},
		{"a login shell", otherCgroup, "", SupervisorNone},
		{"another unit", foreignUnitCg, "", SupervisorNone},
		{"a renamed unit gets no handover", renamedUnitCg, "", SupervisorNone},
		{"the launchd agent", "", launchdJobName, SupervisorLaunchd},
		{"a Terminal-launched process on macOS", "", "0", SupervisorNone},
		{"another launchd job", "", "com.example.other", SupervisorNone},
		{"nothing readable", "", "", SupervisorNone},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := DetectSupervisor(tc.cgroup, tc.job); got != tc.want {
				t.Fatalf("DetectSupervisor = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestDecideHandover is the interlock as a table, one case per row and the
// allowed shapes beside them.
func TestDecideHandover(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   HandoverInput
		want HandoverRefusal
	}{
		{"unsupervised: nothing to hand over", HandoverInput{Supervisor: SupervisorNone}, HandoverAllowed},
		{"unsupervised with an old parent", HandoverInput{Supervisor: SupervisorNone, ParentKeepsSupervision: false}, HandoverAllowed},
		{"systemd: new unit, new parent", HandoverInput{Supervisor: SupervisorSystemd, NotifySocket: true, ParentKeepsSupervision: true}, HandoverAllowed},
		{"systemd: pre-fix unit (no NOTIFY_SOCKET)", HandoverInput{Supervisor: SupervisorSystemd, NotifySocket: false, ParentKeepsSupervision: true}, RefuseUnitPredatesHandover},
		{"systemd: pre-fix unit and old parent names the unit first", HandoverInput{Supervisor: SupervisorSystemd, NotifySocket: false, ParentKeepsSupervision: false}, RefuseUnitPredatesHandover},
		{"systemd: new unit, parent predates MAINPID", HandoverInput{Supervisor: SupervisorSystemd, NotifySocket: true, ParentKeepsSupervision: false}, RefuseParentPredatesMainPID},
		{"launchd: restarting agent, new parent", HandoverInput{Supervisor: SupervisorLaunchd, AgentRestartsOnFailure: true, ParentKeepsSupervision: true}, HandoverAllowed},
		{"launchd: agent that does not restart a failure", HandoverInput{Supervisor: SupervisorLaunchd, AgentRestartsOnFailure: false, ParentKeepsSupervision: true}, RefuseAgentDoesNotRestart},
		{"launchd: parent predates the restart exit", HandoverInput{Supervisor: SupervisorLaunchd, AgentRestartsOnFailure: true, ParentKeepsSupervision: false}, RefuseParentPredatesLaunchdRestart},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := DecideHandover(tc.in); got != tc.want {
				t.Fatalf("DecideHandover(%+v) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestHandoverRefusalNamesTheOneFix: every refusal says what to run, and the
// token survives the trip through the handshake's "fail <reason>" message and
// the ledger detail, so `observer update status` and `observer doctor` can
// name it again from history.
func TestHandoverRefusalNamesTheOneFix(t *testing.T) {
	for _, r := range HandoverRefusals() {
		text := r.Explain()
		for _, want := range []string{string(r), "observer service upgrade"} {
			if !strings.Contains(text, want) {
				t.Errorf("%s: explanation lacks %q:\n%s", r, want, text)
			}
		}
		if r == RefuseUnitPredatesHandover || r == RefuseParentPredatesMainPID || r == RefuseParentPredatesLaunchdRestart || r == RefuseAgentDoesNotRestart {
			if !strings.Contains(text, "restart") {
				t.Errorf("%s: explanation does not say to restart the service:\n%s", r, text)
			}
		}
		detail := "the new binary reported a failed self-check: " + strings.Join(strings.Fields(text), " ") + "; restoring the previous binary"
		if got := HandoverRefusalIn(detail); got != r {
			t.Errorf("HandoverRefusalIn(%q) = %q, want %q", detail, got, r)
		}
	}
	if got := HandoverRefusalIn("the new binary exited before completing its self-check"); got != HandoverAllowed {
		t.Errorf("a detail with no refusal token read as %q", got)
	}
	if HandoverAllowed.Explain() != "" {
		t.Error("an allowed handover must explain nothing")
	}
}

func TestLaunchAgentRestartsOnFailure(t *testing.T) {
	rendered := RenderLaunchAgent(LaunchAgentOptions{ExecPath: "/usr/local/bin/observer", LogPath: "/tmp/o.log"})
	for _, tc := range []struct {
		name, plist string
		want        bool
	}{
		{"the rendered agent (SuccessfulExit=false)", rendered, true},
		{"KeepAlive true", "<dict><key>KeepAlive</key>\n  <true/></dict>", true},
		{"KeepAlive false", "<dict><key>KeepAlive</key><false/></dict>", false},
		{"no KeepAlive", "<dict><key>RunAtLoad</key><true/></dict>", false},
		{"SuccessfulExit true restarts only a clean exit", "<key>KeepAlive</key><dict><key>SuccessfulExit</key><true/></dict>", false},
		{"KeepAlive dict without SuccessfulExit", "<key>KeepAlive</key><dict><key>NetworkState</key><true/></dict>", false},
		{"unreadable", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := LaunchAgentRestartsOnFailure(tc.plist); got != tc.want {
				t.Fatalf("LaunchAgentRestartsOnFailure = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestHandoverEndFor pins SVC-3 option (b): under launchd the hand-over ends
// with the parent stopping the self-checked child and exiting non-zero, so
// the agent's KeepAlive{SuccessfulExit=false} starts the new binary and
// launchd stays the one supervisor. systemd follows MAINPID= and an
// unsupervised node needs nothing, so both end with exit 0.
func TestHandoverEndFor(t *testing.T) {
	for _, tc := range []struct {
		s    Supervisor
		want HandoverEnd
	}{
		{SupervisorNone, EndExitClean},
		{SupervisorSystemd, EndExitClean},
		{SupervisorLaunchd, EndRestartBySupervisor},
		{Supervisor("unknown"), EndExitClean},
	} {
		if got := HandoverEndFor(tc.s); got != tc.want {
			t.Errorf("HandoverEndFor(%q) = %q, want %q", tc.s, got, tc.want)
		}
	}
}

// TestRestartExitCode: a process that ends so its supervisor starts the
// binary now at its path (a launchd hand-over, a rollback) exits with a
// fixed non-zero code under a supervisor, because Restart=on-failure and
// KeepAlive{SuccessfulExit=false} restart only an unsuccessful exit. With no
// supervisor nothing restarts it either way, and the exit is clean.
func TestRestartExitCode(t *testing.T) {
	if SupervisorRestartExitCode == 0 {
		t.Fatal("the restart exit must be non-zero")
	}
	for _, tc := range []struct {
		s    Supervisor
		want int
	}{
		{SupervisorSystemd, SupervisorRestartExitCode},
		{SupervisorLaunchd, SupervisorRestartExitCode},
		{SupervisorNone, 0},
	} {
		if got := RestartExitCode(tc.s); got != tc.want {
			t.Errorf("RestartExitCode(%q) = %d, want %d", tc.s, got, tc.want)
		}
	}
}
