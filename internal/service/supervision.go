package service

import (
	"strconv"
	"strings"
)

// supervision.go is the systemd unit's update-handover table (INFRA-01).
//
// An in-place update (`observer update apply`) spawns the NEW daemon as a
// child of the old one, in the same cgroup, and the old daemon then exits 0
// (cmd/observer/update_handshake.go). With a plain Type=simple unit systemd
// reads that exit as "the service stopped", SIGTERMs the rest of the cgroup
// (the new daemon) and does not restart after a clean exit: the node stays
// down until someone starts it by hand.
//
// The fix has one mechanism that works on every systemd and one extra layer
// where systemd has it, chosen by a drill on systemd 245, 249 and 255 (user
// and system scope, cgroup v1; receipts under drill/ in the lane report):
//
//   - NotifyAccess=main: systemd hands the main process a notify socket and
//     accepts messages from it alone. Just before it exits, the old daemon
//     (the main process) sends MAINPID=<child> (MainPIDHandover), so systemd
//     tracks the child as the unit's main process from then on: the unit
//     stays active, a later crash of the new daemon is a main-process
//     failure that Restart=on-failure restarts, and `systemctl stop` still
//     reaches it (KillMode=control-group) and waits for its drain (the
//     ExecStop below).
//   - ExitType=cgroup (systemd 250+): the unit stays up while any process in
//     its cgroup lives, so a handover whose message never arrived (an old
//     binary without the handover, a send that failed) still leaves the new
//     daemon running. Alone it is not enough: systemd then tracks no main
//     process, so a crash of the new daemon is not a failure and
//     Restart=on-failure does not restart it (drill row "exittype").
//
// Rejected by the same drill: KillMode=process (the unit goes inactive with
// the new daemon left running outside its control, and with Restart=always a
// second daemon starts beside it and fights it for the proxy port) and
// Type=notify (every binary the unit may run, including a rolled-back one
// that predates it, would have to send READY=1 or fail to start).

// MinExitTypeCgroupVersion is the first systemd release that understands
// ExitType= (systemd 250). Older releases log "Unknown key name" and ignore
// the line.
const MinExitTypeCgroupVersion = 250

// supervisionRow is one row of the update-handover table: the systemd
// versions it applies to and the [Service] lines it adds.
type supervisionRow struct {
	name    string
	match   func(version int) bool
	lines   []string
	summary string
}

// gracefulStop is the ExecStop every row writes. systemd before pidfd
// tracking (the drill saw it on 245 and 249, not on 255) calls a main PID it
// did not start "not our child" and does not wait for it at stop: with the
// new daemon the only process in the cgroup it went straight from SIGTERM to
// SIGKILL, so the first stop after an update skipped the daemon's drain.
// This command sends the SIGTERM itself and waits for the main process to
// exit (bounded by TimeoutStopSec, and by the daemon's own shutdown
// watchdog); $$ passes a literal $ to sh, and the leading "-" keeps a
// missing MAINPID (the daemon already exited) from failing the stop.
const gracefulStop = `ExecStop=-/bin/sh -c 'kill -TERM "$$MAINPID" 2>/dev/null; while kill -0 "$$MAINPID" 2>/dev/null; do sleep 0.2; done'`

// handoverLines are the lines every row writes: the main-PID handover, the
// default KillMode spelled out, so a stop reaches the handed-over child, and
// a stop that waits for it.
var handoverLines = []string{"NotifyAccess=main", "KillMode=control-group", gracefulStop}

// supervisionRows is walked top-down; the first match wins and the last row
// matches every version, including unknown (0).
var supervisionRows = []supervisionRow{
	{
		name:    "systemd >= 250",
		match:   func(v int) bool { return v >= MinExitTypeCgroupVersion },
		lines:   append(append([]string{}, handoverLines...), "ExitType=cgroup"),
		summary: "in-place updates hand the main PID to the new daemon (NotifyAccess=main), with ExitType=cgroup as a second guard",
	},
	{
		name:    "systemd < 250",
		match:   func(v int) bool { return v > 0 },
		lines:   handoverLines,
		summary: "in-place updates hand the main PID to the new daemon (NotifyAccess=main); ExitType=cgroup needs systemd 250",
	},
	{
		name:    "systemd version unknown",
		match:   func(int) bool { return true },
		lines:   handoverLines,
		summary: "in-place updates hand the main PID to the new daemon (NotifyAccess=main); the systemd version could not be read, so ExitType=cgroup is left out",
	},
}

// supervisionFor returns the row for a systemd major version (0 = unknown).
func supervisionFor(version int) supervisionRow {
	for _, r := range supervisionRows {
		if r.match(version) {
			return r
		}
	}
	return supervisionRows[len(supervisionRows)-1]
}

// SupervisionSummary is the one line `observer service install` prints about
// how the unit it writes for a systemd major version (0 = unknown) survives
// an in-place update.
func SupervisionSummary(version int) string {
	r := supervisionFor(version)
	if version > 0 {
		return "systemd " + strconv.Itoa(version) + ": " + r.summary
	}
	return r.summary
}

// ParseSystemdVersion reads the major version from `systemctl --version`
// output, whose first line is "systemd 249 (249.11-0ubuntu3)" (the
// parenthesised package version varies by distro). ok is false for output
// that does not start with a positive systemd version.
func ParseSystemdVersion(out string) (int, bool) {
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if fields[0] != "systemd" || len(fields) < 2 {
			return 0, false
		}
		digits := fields[1]
		if i := strings.IndexFunc(digits, func(r rune) bool { return r < '0' || r > '9' }); i >= 0 {
			digits = digits[:i]
		}
		n, err := strconv.Atoi(digits)
		if err != nil || n <= 0 {
			return 0, false
		}
		return n, true
	}
	return 0, false
}

// Notification is one sd_notify datagram: the socket address to send it to
// (an abstract-namespace name already starts with a NUL byte) and the
// message.
type Notification struct {
	Socket  string
	Message string
}

// MainPIDHandover decides the message an observer daemon that is handing
// over to its update child sends its systemd manager, so the child becomes
// the unit's main process (the NotifyAccess=main half of the table above).
//
// notifySocket is $NOTIFY_SOCKET and procSelfCgroup the content of
// /proc/self/cgroup. It answers ok only when both say this process runs in
// this product's own unit (UnitName): a NOTIFY_SOCKET inherited from some
// other unit must never move that unit's main PID. systemd itself accepts
// the message only from the unit's main process and only for a PID inside
// the unit's cgroup.
func MainPIDHandover(notifySocket, procSelfCgroup string, pid int) (Notification, bool) {
	if notifySocket == "" || pid <= 0 || !inUnitCgroup(procSelfCgroup, UnitName) {
		return Notification{}, false
	}
	socket := notifySocket
	if strings.HasPrefix(socket, "@") {
		socket = "\x00" + socket[1:]
	}
	return Notification{Socket: socket, Message: "MAINPID=" + strconv.Itoa(pid) + "\n"}, true
}

// inUnitCgroup reports whether a /proc/<pid>/cgroup listing puts the process
// directly in unit's cgroup, on the hierarchy systemd tracks units on: the
// "name=systemd" line (cgroup v1 and hybrid) or the unified "0::" line
// (cgroup v2).
func inUnitCgroup(listing, unit string) bool {
	for _, line := range strings.Split(listing, "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), ":", 3)
		if len(parts) != 3 {
			continue
		}
		if !(parts[0] == "0" && parts[1] == "") && parts[1] != "name=systemd" {
			continue
		}
		path := strings.TrimRight(parts[2], "/")
		if path[strings.LastIndex(path, "/")+1:] == unit {
			return true
		}
	}
	return false
}
