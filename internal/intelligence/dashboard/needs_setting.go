package dashboard

import (
	"errors"
	"net/http"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/settingslink"
)

// needs_setting.go is the dashboard's one writer of a refusal whose fix is a
// setting or a component that is off. The body is settingslink.Body:
// {"error": code, "message": sentence, "settings": path, "settings_label":
// name}. The SPA's one renderer (web/src/lib/needsSetting.ts) shows the
// message and a button to the deep link; a client that reads only "error"
// sees exactly what the route answered before. The link comes from the one
// table in internal/settingslink, never from a path built at the call site.
//
// A component_not_installed refusal is the component guard's own
// componentstate.NotActiveBody, which carries the same link fields.

// writeNeedsSetting answers status with a refusal whose fix is at place.
// code is the route's error value (a closed code, or on routes that answered
// a sentence before, that same sentence); message is the plain sentence the
// SPA shows: what is off, why the request needs it, and what to do.
func writeNeedsSetting(w http.ResponseWriter, status int, code, message string, place settingslink.Place) {
	writeJSONStatus(w, status, settingslink.Needs(code, message, place))
}

// writeNeedsComponent answers status with a refusal whose fix is turning one
// component on (Settings > Components with it focused, plus the CLI command).
func writeNeedsComponent(w http.ResponseWriter, status int, code, message, component string) {
	writeJSONStatus(w, status, settingslink.NeedsComponent(code, message, component))
}

// The plain messages of the terminal-stack refusals. errTerminalUnavailable
// and errGuidedInstallOff stay the "error" values (older clients and tests
// read them); these are what a person reads beside the button.
const (
	msgTerminalUnavailable = "The in-dashboard terminal is off on this machine, so there is nowhere to run this. " +
		"Turn on dashboard launch in Settings > Session attach (More settings), then restart the daemon. " +
		"On Windows before 10 version 1809 there is no terminal backend at all."
	msgGuidedInstallOff = "Guided install is off on this machine. Turn on \"Allow guided install and uninstall\" " +
		"in Terminals > Settings > Fresh-agent launch policy. No restart is needed."
)

// writeTerminalUnavailable answers 503 for a route that needs the
// in-dashboard terminal while it is off. prefix names the action ("launch
// unavailable: ") on the routes that always said it; empty elsewhere.
func writeTerminalUnavailable(w http.ResponseWriter, prefix string) {
	writeNeedsSetting(w, http.StatusServiceUnavailable, prefix+errTerminalUnavailable, msgTerminalUnavailable, settingslink.SessionAttach)
}

// writeGuidedInstallOff answers 403 while the guided install and uninstall
// switch is off.
func writeGuidedInstallOff(w http.ResponseWriter) {
	writeNeedsSetting(w, http.StatusForbidden, errGuidedInstallOff, msgGuidedInstallOff, settingslink.TerminalLaunchPolicy)
}

// writeTerminalUnavailableOr is writeTerminalUnavailable for a route whose
// refusal also names a way around it (run a command yourself). code is the
// route's error text as it answered before; alt is the plain alternative,
// one sentence.
func writeTerminalUnavailableOr(w http.ResponseWriter, code, alt string) {
	writeNeedsSetting(w, http.StatusServiceUnavailable, code, msgTerminalUnavailable+" "+alt, settingslink.SessionAttach)
}

// errGuidedUninstallOff is the uninstall route's 403 error text (unchanged
// for older clients); msgGuidedUninstallOff is what a person reads.
const (
	errGuidedUninstallOff = "guided install and uninstall are disabled; turn on \"Allow guided install and uninstall\" in " +
		"Terminals > Settings > Fresh-agent launch policy ([terminal.launch].allow_install)"
	msgGuidedUninstallOff = "Guided uninstall is off on this machine. Turn on \"Allow guided install and uninstall\" " +
		"in Terminals > Settings > Fresh-agent launch policy. No restart is needed."
)

// writeGuidedUninstallOff answers the uninstall route's 403 while the same
// switch is off.
func writeGuidedUninstallOff(w http.ResponseWriter) {
	writeNeedsSetting(w, http.StatusForbidden, errGuidedUninstallOff, msgGuidedUninstallOff, settingslink.TerminalLaunchPolicy)
}

// The plain messages of the other "needs a setting" refusals. Each says what
// is off, why the request needs it, and where to turn it on.
const (
	msgReputationOff = "Reputation lookups are off. A lookup sends one request to the npm registry, so it is opt in. " +
		"Turn on Reputation lookups in Security > MCP > Network features."
	msgRequestsNotEnrolled = "Requests go to your organization, and this machine is not connected to one. " +
		"Connect it in Settings > Account."
	msgMessagesNotEnrolled = "Messages go to your organization, and this machine is not connected to one. " +
		"Connect it in Settings > Account."
	msgAcksNotEnrolled = "Acknowledgements go to your organization, and this machine is not connected to one. " +
		"Connect it in Settings > Account."
	msgCommitScanOff = "Commit scanning is off on this machine, so there is nothing to rescan. " +
		"Turn on commit scanning in Settings > Intelligence, then restart the daemon."
	msgRemoteNotSetUp = "Remote access is not set up on this machine, so there is no remote request to approve. " +
		"Set it up on the Remote page."
	msgRemoteOff = "Remote access is off, so this remote setting has nothing to apply to. " +
		"Turn on remote access on the Remote page first."
	msgRemoteOffTerminal = "Remote access is off, so this remote setting has nothing to apply to. " +
		"Turn on remote access on the Remote page first; its form has the terminal option."
	msgGithooksOff = "Installing the git hooks needs the Local git hooks component (security.githooks), " +
		"which is off on this machine. Turn it on in Settings > Components."
)

// settingRefusals is the table of typed refusals whose fix is one switch on
// this machine (dead-end sweep, 2026-11-18): the sentinel, the place, and the
// sentence a person reads. The "error" value stays err.Error(), exactly what
// the route answered before (lib/LaunchPolicyInline.tsx matches it), so a
// client that reads only the error is unchanged. First match wins.
var settingRefusals = []struct {
	err       error
	place     settingslink.Place
	component string
	message   string
}{
	{
		err: ErrLaunchFreshDisabled, place: settingslink.TerminalLaunchPolicy,
		message: "Fresh-agent launches are off on this machine. Turn on \"Allow fresh-agent launches\" in Terminals > Settings > Fresh-agent launch policy. No restart is needed.",
	},
	{
		err: ErrLaunchShellDisabled, place: settingslink.TerminalLaunchPolicy,
		message: "Plain shell terminals are off on this machine. Turn on \"Allow plain shell terminals\" in Terminals > Settings > Fresh-agent launch policy. No restart is needed.",
	},
	{
		err: ErrLaunchToolNotAllowed, place: settingslink.TerminalLaunchPolicy,
		message: "This tool is not on this machine's fresh-launch list. Add it in Terminals > Settings > Fresh-agent launch policy.",
	},
	{
		err: ErrLaunchSSHDisabled, place: settingslink.TerminalRemoteSystems,
		message: "SSH remote-system terminals are off on this machine. Turn on \"Allow SSH remote-system terminals\" in Terminals > Settings > Remote systems (SSH). No restart is needed.",
	},
	{
		err: ErrInstancesDisabled, place: settingslink.TerminalRemoteSystems,
		message: "Remote systems are off on this machine. Turn on \"Allow SSH remote-system terminals\" in Terminals > Settings > Remote systems (SSH). No restart is needed.",
	},
	{
		err: dashapi.ErrExplainNotSelected, component: "security.feedback",
		message: "Explain needs the security feedback component, which is off on this machine. Turn it on in Settings > Components.",
	},
}

// writeSettingRefusal answers err with its deep link when a settingRefusals
// row matches, and reports whether it did. status is the route's own status
// for that refusal.
func writeSettingRefusal(w http.ResponseWriter, err error, status int) bool {
	for _, r := range settingRefusals {
		if !errors.Is(err, r.err) {
			continue
		}
		if r.component != "" {
			writeNeedsComponent(w, status, err.Error(), r.message, r.component)
		} else {
			writeNeedsSetting(w, status, err.Error(), r.message, r.place)
		}
		return true
	}
	return false
}

// sandboxVerdictFixable lists the sandbox verdicts this machine can lift
// in Terminals > Settings > Sandbox isolation (turn it on, install or
// update the backend). Every other verdict is the platform or the build:
// the refusal stays plain.
var sandboxVerdictFixable = map[string]bool{
	"disabled_by_config": true,
	"backend_missing":    true,
	"backend_too_old":    true,
}

// writeSandboxUnavailable answers a launch whose sandbox cannot start:
// code is the route's error text as before; a fixable verdict adds the
// Sandbox isolation link.
func writeSandboxUnavailable(w http.ResponseWriter, code, verdict, reason string) {
	status := statusForSandboxVerdict(verdict)
	if !sandboxVerdictFixable[verdict] {
		http.Error(w, code, status)
		return
	}
	msg := "The sandbox cannot start on this machine"
	if r := strings.TrimSpace(reason); r != "" {
		msg += ": " + strings.TrimSuffix(r, ".")
	}
	msg += ". Set it up or turn it on in Terminals > Settings > Sandbox isolation."
	writeNeedsSetting(w, status, code, msg, settingslink.TerminalSandbox)
}
