package service

import (
	"regexp"
	"strings"
)

// handover.go is the update-handover INTERLOCK (UPD-9, SVC-1, SVC-3).
//
// An in-place update keeps a supervised daemon up only when two halves agree:
// the supervisor must be able to follow the hand-over, and the daemon that
// runs the apply (the PARENT, the old binary) must perform its half of it.
//
//   - systemd: the unit must carry NotifyAccess=main (supervision.go), which
//     is what puts $NOTIFY_SOCKET in the daemon's environment, and the parent
//     must send MAINPID=<child> before it exits 0. A pre-fix unit, or a
//     daemon still running under one, has no NOTIFY_SOCKET: systemd reads
//     the parent's exit 0 as the service stopping and kills the new daemon.
//   - launchd: there is no MAINPID; the parent stops the self-checked child
//     and exits non-zero so the agent's KeepAlive{SuccessfulExit=false}
//     starts the new binary itself (SVC-3, option b). A parent that predates
//     that exit ends with exit 0, launchd kills the job's process group and
//     does not restart it; an agent that does not restart a failed exit
//     leaves the node down either way.
//
// Both halves are checked twice, from the same table: by the PARENT before it
// drains (a release with this fix never drains a node it cannot hand over),
// and by the NEW binary's self-check before it reports ready. The second
// check is the one that reaches updates FROM an older release, whose parent
// runs none of this code: the child reports a failed self-check, the older
// parent rolls back, and the node stays up on its previous binary.
//
// Everything here is pure: the facts (/proc/self/cgroup, $NOTIFY_SOCKET,
// $XPC_SERVICE_NAME, the agent plist's text, and whether the parent's release
// performs the hand-over) are read and resolved by cmd/observer.

// Supervisor is the closed vocabulary of the supervisors the interlock knows.
type Supervisor string

const (
	// SupervisorNone: not run by this product's unit or agent. Nothing has
	// to follow the hand-over, so nothing is refused: the old daemon exits 0
	// and the new one goes on serving (ruling R14's unsupervised node).
	SupervisorNone Supervisor = "none"
	// SupervisorSystemd: running in observer.service (UnitName), on the
	// hierarchy systemd tracks units on.
	SupervisorSystemd Supervisor = "systemd"
	// SupervisorLaunchd: running as the per-user LaunchAgent (LaunchdLabel).
	SupervisorLaunchd Supervisor = "launchd"
)

// DetectSupervisor resolves the supervisor from what a process can read about
// itself: procSelfCgroup is /proc/self/cgroup ("" off Linux) and launchdJob is
// $XPC_SERVICE_NAME, which launchd sets to the job's label. Only this
// product's own unit and agent count, by exact name: a unit renamed by an
// operator gets no MAINPID hand-over (MainPIDHandover refuses it), and a
// process launched from Terminal.app carries another value.
func DetectSupervisor(procSelfCgroup, launchdJob string) Supervisor {
	switch {
	case inUnitCgroup(procSelfCgroup, UnitName):
		return SupervisorSystemd
	case strings.TrimSpace(launchdJob) == LaunchdLabel:
		return SupervisorLaunchd
	default:
		return SupervisorNone
	}
}

// HandoverRefusal is the closed vocabulary of reasons an update may not hand
// over. The zero value allows it. The values are node-local: they travel in
// the handshake's "fail <reason>" message and the update ledger's detail,
// never on the org wire (the posture carries the healthcheck error class).
type HandoverRefusal string

const (
	// HandoverAllowed: the hand-over keeps the daemon supervised.
	HandoverAllowed HandoverRefusal = ""
	// RefuseUnitPredatesHandover: running as observer.service with no
	// $NOTIFY_SOCKET, so the unit file predates NotifyAccess=main or the
	// daemon was started before the unit was rewritten.
	RefuseUnitPredatesHandover HandoverRefusal = "systemd_unit_predates_handover"
	// RefuseParentPredatesMainPID: under the new unit, but the daemon that
	// runs the apply is a release that does not send MAINPID=.
	RefuseParentPredatesMainPID HandoverRefusal = "parent_predates_mainpid_handover"
	// RefuseAgentDoesNotRestart: the LaunchAgent does not restart a job that
	// exits non-zero (no KeepAlive, or one that restarts clean exits only),
	// so the restart exit would leave the node down.
	RefuseAgentDoesNotRestart HandoverRefusal = "launch_agent_does_not_restart"
	// RefuseParentPredatesLaunchdRestart: under launchd, the daemon that runs
	// the apply is a release that ends a hand-over with exit 0, which ends
	// the job and its process group without a restart.
	RefuseParentPredatesLaunchdRestart HandoverRefusal = "parent_predates_launchd_restart"
)

// HandoverInput is the resolved facts the table reads.
type HandoverInput struct {
	// Supervisor is DetectSupervisor's answer for the process deciding.
	Supervisor Supervisor
	// NotifySocket reports a non-empty $NOTIFY_SOCKET.
	NotifySocket bool
	// ParentKeepsSupervision reports that the daemon running the apply is a
	// release that performs its half of the hand-over (MAINPID= under
	// systemd, the restart exit under launchd). The parent itself always
	// passes true; the new binary resolves it from the parent's version
	// (update.ParentKeepsSupervision).
	ParentKeepsSupervision bool
	// AgentRestartsOnFailure reports that the installed LaunchAgent restarts
	// a non-zero exit (LaunchAgentRestartsOnFailure over its plist).
	AgentRestartsOnFailure bool
}

// handoverRow is one interlock rule: the refusal it yields and when.
type handoverRow struct {
	refusal HandoverRefusal
	applies func(HandoverInput) bool
}

// handoverRows is walked top-down and the first match refuses. The unit row
// comes before the parent row because its fix (a rewritten unit and a
// restart) is needed whatever the parent is; the agent row comes before the
// launchd parent row for the same reason.
var handoverRows = []handoverRow{
	{RefuseUnitPredatesHandover, func(in HandoverInput) bool {
		return in.Supervisor == SupervisorSystemd && !in.NotifySocket
	}},
	{RefuseParentPredatesMainPID, func(in HandoverInput) bool {
		return in.Supervisor == SupervisorSystemd && !in.ParentKeepsSupervision
	}},
	{RefuseAgentDoesNotRestart, func(in HandoverInput) bool {
		return in.Supervisor == SupervisorLaunchd && !in.AgentRestartsOnFailure
	}},
	{RefuseParentPredatesLaunchdRestart, func(in HandoverInput) bool {
		return in.Supervisor == SupervisorLaunchd && !in.ParentKeepsSupervision
	}},
}

// DecideHandover walks the interlock table. HandoverAllowed means the update
// may hand over; anything else names why it may not.
func DecideHandover(in HandoverInput) HandoverRefusal {
	for _, r := range handoverRows {
		if r.applies(in) {
			return r.refusal
		}
	}
	return HandoverAllowed
}

// HandoverRefusals lists every refusal the table can yield, in table order.
func HandoverRefusals() []HandoverRefusal {
	out := make([]HandoverRefusal, 0, len(handoverRows))
	for _, r := range handoverRows {
		out = append(out, r.refusal)
	}
	return out
}

// handoverRefusalPrefix starts every explanation, so the token can be found
// again in a ledger detail (HandoverRefusalIn).
const handoverRefusalPrefix = "supervision "

// handoverExplanations names what is wrong and the one fix, per refusal.
var handoverExplanations = map[HandoverRefusal]string{
	RefuseUnitPredatesHandover: "this daemon runs as observer.service without the update hand-over " +
		"(the unit file predates it, or the daemon was started before the unit was rewritten), " +
		"so systemd would stop the new daemon when the old one exits. " +
		"Fix: run `observer service upgrade`, then restart the service (`observer service restart`) " +
		"when no AI session routes through the proxy; later updates then hand over.",
	RefuseParentPredatesMainPID: "the daemon that ran this apply is a release that does not hand " +
		"systemd the new daemon's PID, so the unit would stop when it exits. " +
		"Fix: install this release once with the installer (it runs `observer service upgrade`), " +
		"or put the binary in place and run `observer service upgrade`, then restart the service " +
		"(`observer service restart`); later updates then go through the org rail.",
	RefuseAgentDoesNotRestart: "the LaunchAgent does not restart a daemon that exits with an error " +
		"(KeepAlive with SuccessfulExit=false), and launchd starts the new binary only through that restart. " +
		"Fix: run `observer service upgrade` to rewrite the agent, then restart the service " +
		"(`observer service restart`).",
	RefuseParentPredatesLaunchdRestart: "the daemon that ran this apply is a release that ends a " +
		"hand-over with exit 0, so launchd would end the agent and the new daemon with it. " +
		"Fix: install this release once with the installer (it runs `observer service upgrade`), " +
		"or put the binary in place and run `observer service upgrade`, then restart the service " +
		"(`observer service restart`); later updates then go through the org rail.",
}

// Explain is the operator-facing reason, starting "supervision <token>: "
// and ending with the one fix. Empty for HandoverAllowed.
func (r HandoverRefusal) Explain() string {
	text, ok := handoverExplanations[r]
	if !ok {
		return ""
	}
	return handoverRefusalPrefix + string(r) + ": " + text
}

// HandoverRefusalIn finds the refusal named in a ledger detail or a
// handshake message (whose whitespace the handshake collapses), or
// HandoverAllowed when it names none. `observer update status` and
// `observer doctor` use it to name the fix again from history, including for
// a refusal an older parent recorded from a newer child's self-check.
func HandoverRefusalIn(detail string) HandoverRefusal {
	for _, r := range HandoverRefusals() {
		if strings.Contains(detail, handoverRefusalPrefix+string(r)+":") {
			return r
		}
	}
	return HandoverAllowed
}

var (
	keepAliveTrueRe = regexp.MustCompile(`<key>KeepAlive</key>\s*<true\s*/>`)
	keepAliveDictRe = regexp.MustCompile(`(?s)<key>KeepAlive</key>\s*<dict>(.*?)</dict>`)
	successFalseRe  = regexp.MustCompile(`<key>SuccessfulExit</key>\s*<false\s*/>`)
)

// LaunchAgentRestartsOnFailure reports whether a LaunchAgent plist restarts a
// job that exits non-zero: KeepAlive true (restart always), or a KeepAlive
// dict with SuccessfulExit false (RenderLaunchAgent's shape: restart only an
// unsuccessful exit). Anything else, an unreadable plist included, is false,
// which refuses the restart exit rather than gambling the node on it.
func LaunchAgentRestartsOnFailure(plist string) bool {
	if keepAliveTrueRe.MatchString(plist) {
		return true
	}
	m := keepAliveDictRe.FindStringSubmatch(plist)
	return m != nil && successFalseRe.MatchString(m[1])
}

// HandoverEnd is how a successful hand-over ends in the old daemon.
type HandoverEnd string

const (
	// EndExitClean: the old daemon exits 0 and the new one goes on serving.
	// Right with no supervisor, and under systemd after MAINPID= made the
	// new daemon the unit's main process.
	EndExitClean HandoverEnd = "exit_clean"
	// EndRestartBySupervisor: the old daemon stops the self-checked new one
	// and exits SupervisorRestartExitCode, so the supervisor starts the new
	// binary itself and keeps tracking it (launchd has no MAINPID; SVC-3
	// option b). The node is down for one process start.
	EndRestartBySupervisor HandoverEnd = "restart_by_supervisor"
)

// handoverEnds is the table from supervisor to how a hand-over ends; a
// supervisor not listed ends clean.
var handoverEnds = map[Supervisor]HandoverEnd{
	SupervisorNone:    EndExitClean,
	SupervisorSystemd: EndExitClean,
	SupervisorLaunchd: EndRestartBySupervisor,
}

// HandoverEndFor returns how a successful hand-over ends under s.
func HandoverEndFor(s Supervisor) HandoverEnd {
	if end, ok := handoverEnds[s]; ok {
		return end
	}
	return EndExitClean
}

// SupervisorRestartExitCode is the exit of a daemon that ends so its
// supervisor starts the binary now at its path (EX_TEMPFAIL): after a launchd
// hand-over, after a rollback, or after RecoverAtBoot restored the previous
// binary. It must be non-zero: the systemd unit restarts on failure only
// (Restart=on-failure) and the agent on an unsuccessful exit only
// (KeepAlive{SuccessfulExit=false}).
const SupervisorRestartExitCode = 75

// RestartExitCode is the exit code for a daemon ending so the binary now at
// its path starts again: SupervisorRestartExitCode under a supervisor, 0 with
// none (nothing restarts it either way, and nothing failed).
func RestartExitCode(s Supervisor) int {
	if s == SupervisorSystemd || s == SupervisorLaunchd {
		return SupervisorRestartExitCode
	}
	return 0
}
