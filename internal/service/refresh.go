package service

import (
	"fmt"
	"strings"
)

// refresh.go is the decision `observer service install --now` and
// `observer service upgrade` make about an ALREADY RUNNING unit after they
// rewrite it (T-753). The rc.3 roll found that an in-place upgrade (the
// installer, or npm) replaced the binary underneath a running daemon and then
// reported the service as started: the old process kept running the deleted
// executable until someone restarted it by hand.
//
// The daemon IS the proxy, so a restart is only automatic when nothing can be
// routing through it (CLAUDE.md "never stop the daemon while the proxy route
// is active", docs/daemon-restart-runbook.md). Otherwise the caller prints
// the safe order and leaves the old process running. The decision is a data
// table walked top-down; the cmd layer gathers the inputs (systemctl, /proc,
// the route registrars) and performs the action.

// RefreshInputs is what the cmd layer observed about the unit.
type RefreshInputs struct {
	// Active is the unit's ActiveState (active, reloading or activating).
	Active bool
	// StartIfInactive: start a stopped unit (`install --now`); false for
	// `upgrade`, which never starts a unit the operator stopped.
	StartIfInactive bool
	// ExecChanged: the running process's executable is not the binary the
	// unit now names (replaced in place, shown as "(deleted)", or another
	// path). ExecUnknown: it could not be read.
	ExecChanged bool
	ExecUnknown bool
	// ExecStartChanged: the rewrite changed the unit's ExecStart line (new
	// arguments only take effect on a restart).
	ExecStartChanged bool
	// HandoverMissing reports that the running daemon was started without
	// the update hand-over the rewritten unit gives it (no NOTIFY_SOCKET in
	// its environment, while the unit now writes NotifyAccess=main): every
	// in-place update is refused (systemd_unit_predates_handover, UPD-9)
	// until it restarts under the new unit, so the same binary still needs
	// the restart, under the same proxy-safety rows.
	HandoverMissing bool
	// ProxyListening: something listens on the proxy port. When nothing
	// does, no AI session can be routed through this daemon.
	ProxyListening bool
	// Routes are the proxy routes Observer wrote that are present in AI
	// tools' configs ("claude-code (/home/u/.claude/settings.json)").
	Routes []string
	// ProxyClients is the number of open connections to the proxy port.
	ProxyClients int
	// ProbeErr says why routes or connections could not be checked.
	ProbeErr string
}

// RefreshAction is what the caller does.
type RefreshAction string

// The closed RefreshAction vocabulary.
const (
	// RefreshStart: the unit is not running and the caller asked for it to
	// run: enable + start.
	RefreshStart RefreshAction = "start"
	// RefreshLeaveStopped: the unit is not running and the caller did not
	// ask to start it.
	RefreshLeaveStopped RefreshAction = "leave_stopped"
	// RefreshNone: the running process already runs this binary with this
	// ExecStart; the rewritten unit needs no restart.
	RefreshNone RefreshAction = "none"
	// RefreshRestart: try-restart the unit; nothing can be routed through
	// the proxy right now.
	RefreshRestart RefreshAction = "restart"
	// RefreshAdvise: the unit runs an older process, but a proxy route or a
	// proxied connection may be live (or could not be checked): leave it
	// running and print the safe order.
	RefreshAdvise RefreshAction = "advise"
)

// RefreshDecision is the table's answer: the action, the rule that decided
// it and the reasons to print.
type RefreshDecision struct {
	Action  RefreshAction
	Rule    string
	Reasons []string
}

type refreshRule struct {
	name    string
	match   func(RefreshInputs) bool
	action  RefreshAction
	reasons func(RefreshInputs) []string
}

func (in RefreshInputs) stale() bool {
	return in.ExecChanged || in.ExecUnknown || in.ExecStartChanged || in.HandoverMissing
}

// refreshRules is the ordered decision table (CLAUDE.md rule 5).
var refreshRules = []refreshRule{
	{"not running, start", func(in RefreshInputs) bool { return !in.Active && in.StartIfInactive }, RefreshStart, nil},
	{"not running", func(in RefreshInputs) bool { return !in.Active }, RefreshLeaveStopped, nil},
	{"current", func(in RefreshInputs) bool { return !in.stale() }, RefreshNone, nil},
	{
		"no proxy listener", func(in RefreshInputs) bool { return !in.ProxyListening }, RefreshRestart,
		func(RefreshInputs) []string {
			return []string{"the running daemon has no proxy listener, so no AI session is routed through it"}
		},
	},
	{
		"cannot check", func(in RefreshInputs) bool { return in.ProbeErr != "" }, RefreshAdvise,
		func(in RefreshInputs) []string {
			return []string{"the proxy routes and connections could not be checked: " + in.ProbeErr}
		},
	},
	{
		"route or session live", func(in RefreshInputs) bool { return len(in.Routes) > 0 || in.ProxyClients > 0 }, RefreshAdvise,
		func(in RefreshInputs) []string {
			var out []string
			for _, r := range in.Routes {
				out = append(out, "a proxy route is active: "+r)
			}
			if in.ProxyClients > 0 {
				out = append(out, fmt.Sprintf("%d open connection(s) to the proxy", in.ProxyClients))
			}
			return out
		},
	},
	{
		"idle proxy", func(RefreshInputs) bool { return true }, RefreshRestart,
		func(RefreshInputs) []string {
			return []string{"no proxy route is active and no connection to the proxy is open"}
		},
	},
}

// DecideRefresh walks refreshRules top-down and returns the first match.
func DecideRefresh(in RefreshInputs) RefreshDecision {
	for _, r := range refreshRules {
		if r.match(in) {
			d := RefreshDecision{Action: r.action, Rule: r.name}
			if r.reasons != nil {
				d.Reasons = r.reasons(in)
			}
			return d
		}
	}
	return RefreshDecision{Action: RefreshAdvise, Rule: "unreachable"}
}

// ExecStartLine returns the value of a unit's ExecStart= line ("" when the
// unit has none).
func ExecStartLine(unit string) string {
	for _, line := range strings.Split(unit, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "ExecStart="); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// SplitExecStart is shellJoin's inverse for the lines RenderUnit writes:
// whitespace-separated words, a double-quoted word may hold spaces and
// backslash-escaped quotes. It returns the executable, the arguments after
// the `start` verb, and ok=false when the line is empty, unbalanced, or does
// not run `<exe> start` (a unit Observer did not render).
func SplitExecStart(line string) (exe string, args []string, ok bool) {
	var words []string
	var cur strings.Builder
	inWord, quoted := false, false
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case quoted && c == '\\' && i+1 < len(line) && line[i+1] == '"':
			cur.WriteByte('"')
			i++
		case c == '"':
			quoted = !quoted
			inWord = true
		case !quoted && (c == ' ' || c == '\t'):
			if inWord {
				words = append(words, cur.String())
				cur.Reset()
				inWord = false
			}
		default:
			cur.WriteByte(c)
			inWord = true
		}
	}
	if quoted {
		return "", nil, false
	}
	if inWord {
		words = append(words, cur.String())
	}
	if len(words) < 2 || words[1] != "start" {
		return "", nil, false
	}
	return words[0], words[2:], true
}
