package diag

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/codextrust"
	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/remedy"
)

// codex_trust.go holds the Codex hook-trust family of `observer doctor`:
// checkCodexHookTrust, its cross-mount sibling checkForeignCodexHookTrust,
// the shared trust read (readCodexHookTrust, also behind HookTrustFor) and
// the check builder. Moved out of doctor.go unchanged.

// checkCodexHookTrust reports whether every Codex hook event Observer
// registers will actually run. Codex (0.129.0+, still required on 0.160)
// dispatches a hooks.json entry only after the user trusts it inside
// Codex (`/hooks`); the approval lives in ~/.codex/config.toml
// [hooks.state] as a trusted_hash over the entry's body, so an entry
// whose command changed after it was trusted is untrusted again, and an
// entry the user switched off carries `enabled = false`.
//
// The expected events come from the integration registry (the Registered
// Codex bindings, pinned to the writer's list), so an event a newer
// Observer adds is listed even before hooks.json carries it. The trust
// hash is recomputed by internal/codextrust. This check never writes Codex
// config; the hook writer records trust for Observer's own entries when it
// registers them (live check 2026-10-20), so an entry reported here as
// untrusted is one whose record is missing, changed or switched off.
//
// Outcomes: OK when Codex has no Observer hooks or every expected event
// is trusted; Warn otherwise, with the first detail line naming the
// events that will not run ("untrusted: ...", read by
// CaptureIntegritySignals) and one line per state.
func checkCodexHookTrust(homeDir string) Check {
	st := readCodexHookTrust(homeDir)
	switch {
	case st.noHooksFile:
		return Check{Name: "codex.hook_trust", Status: StatusOK, Message: "no codex hooks registered"}
	case st.err != "":
		return Check{Name: "codex.hook_trust", Status: StatusWarn, Message: st.err}
	case len(st.registered) == 0:
		return Check{Name: "codex.hook_trust", Status: StatusOK, Message: "no observer-owned codex hooks found"}
	}
	return codexHookTrustCheck(st.report, st.hooksPath)
}

// codexTrustState is the parsed Codex hook trust state: the
// observer-owned events in hooks.json and which of them Codex will run.
// Shared by checkCodexHookTrust and the per-binding HookTrustFor read
// (hook-parity Lane G), so the parse exists once; both are built on the
// one internal/codextrust classification (T-039), so an entry changed or
// switched off since it was trusted counts as not trusted in both.
type codexTrustState struct {
	hooksPath   string
	noHooksFile bool
	err         string
	// registered lists the observer-owned events hooks.json carries.
	registered []string
	// trusted marks the registered events Codex will dispatch.
	trusted map[string]bool
	report  codextrust.Report
}

func readCodexHookTrust(homeDir string) codexTrustState {
	hooksPath := filepath.Join(homeDir, ".codex", "hooks.json")
	configPath := filepath.Join(homeDir, ".codex", "config.toml")
	st := codexTrustState{hooksPath: hooksPath, trusted: map[string]bool{}}

	hooksRaw, err := os.ReadFile(hooksPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			st.noHooksFile = true
			return st
		}
		st.err = "read codex hooks.json: " + err.Error()
		return st
	}
	cfgRaw, err := os.ReadFile(configPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		st.err = "read codex config.toml: " + err.Error()
		return st
	}
	rep, err := codextrust.Classify(codextrust.Input{
		HooksPath:     hooksPath,
		HooksJSON:     hooksRaw,
		ConfigTOML:    cfgRaw,
		Expected:      codexExpectedHookEvents(),
		Owned:         isObserverCodexHook,
		NormalizePath: CodexTrustPathKey,
	})
	if err != nil {
		st.err = err.Error()
		return st
	}
	st.report = rep
	for _, e := range rep.Entries {
		if e.State == codextrust.StateMissing {
			continue
		}
		st.registered = append(st.registered, e.Event)
		if e.State == codextrust.StateTrusted {
			st.trusted[e.Event] = true
		}
	}
	sort.Strings(st.registered)
	return st
}

// CodexTrustPathKey is the codextrust NormalizePath every Codex trust read
// uses: the foreign-path translation (a Windows Codex's C:\... or \\?\C:\...
// key becomes /mnt/c/... on a WSL daemon), forward slashes, lower case (NTFS
// and DrvFs are case-insensitive). Applied to both sides of the comparison,
// so a native POSIX path still matches itself.
func CodexTrustPathKey(p string) string {
	return strings.ToLower(filepath.ToSlash(crossmount.TranslateForeignPath(p)))
}

// ForeignCodexHomes returns the cross-mount homes (a WSL daemon's view of
// the Windows user's home, the one the codex-windows hook bridge writes
// into) that carry a .codex directory. A Windows home counts only when it
// is the current Windows user's (the same ownership rule the bridge
// registrar applies). homeOverride is the caller's sandbox home ("" in
// production); a sandboxed caller sees none (crossmount.AutoDetectSuppressed).
func ForeignCodexHomes(homeOverride string) []crossmount.HomeRoot {
	if crossmount.AutoDetectSuppressed(homeOverride, "") {
		return nil
	}
	var out []crossmount.HomeRoot
	for _, h := range crossmount.AllHomes() {
		if h.Origin == "native" {
			continue
		}
		if fi, err := os.Stat(filepath.Join(h.Path, ".codex")); err != nil || !fi.IsDir() {
			continue
		}
		if h.OS == crossmount.OSWindows && !crossmount.HomeOwnedByCurrentWindowsUser(h.Path) {
			continue
		}
		out = append(out, h)
	}
	return out
}

// checkForeignCodexHookTrust is checkCodexHookTrust for every foreign home
// ForeignCodexHomes finds (live check 2026-10-20: on a WSL daemon the only
// check read the WSL ~/.codex, so the Windows Codex's untrusted Observer
// hooks, and with them a gate that never ran, went unreported). A home with
// no Observer hooks yields no check. The check is named
// "codex.hook_trust.<os>" so it sits beside the native one.
func checkForeignCodexHookTrust(homeOverride string) []Check {
	var out []Check
	for _, h := range ForeignCodexHomes(homeOverride) {
		name := "codex.hook_trust." + h.OS
		st := readCodexHookTrust(h.Path)
		switch {
		case st.noHooksFile:
			continue
		case st.err != "":
			out = append(out, Check{Name: name, Status: StatusWarn, Message: st.err})
			continue
		case len(st.registered) == 0:
			continue
		}
		out = append(out, codexHookTrustCheckNamed(name, st.report, st.hooksPath))
	}
	return out
}

// CodexToolGateEvents returns the Codex hooks.json events Observer registers
// as its tool gate (registry bindings with the tool-gate capability). While
// any of them is untrusted, Observer's Codex guard gate does not run at all.
func CodexToolGateEvents() []string {
	c, ok := integration.For(models.ToolCodex)
	if !ok {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for _, b := range c.Hook.Bindings {
		if b.Registered && b.Cap == integration.HookCapToolGate && !seen[b.NativeEvent] {
			seen[b.NativeEvent] = true
			out = append(out, b.NativeEvent)
		}
	}
	return out
}

// codexExpectedHookEvents is every Codex hooks.json event Observer
// registers, from the integration registry.
func codexExpectedHookEvents() []string {
	c, ok := integration.For(models.ToolCodex)
	if !ok {
		return nil
	}
	return c.Hook.RegisteredEvents()
}

// isObserverCodexHook reports an Observer Codex hook command in every shape
// the registrar writes (hook.IsObserverCodexHookCommand, the fail-closed
// hook bridge included).
func isObserverCodexHook(command string) bool {
	return hook.IsObserverCodexHookCommand(command)
}

// codexTrustStateLines is the per-state detail table, in display order.
var codexTrustStateLines = []struct {
	state codextrust.State
	label string
}{
	{codextrust.StateUntrusted, "never trusted"},
	{codextrust.StateModified, "changed since you trusted it (re-trust in /hooks)"},
	{codextrust.StateDisabled, "switched off in /hooks"},
	{codextrust.StateMissing, "not registered yet (run " + remedy.Quote(remedy.Of(remedy.InitTool, models.ToolCodex)) + ", or restart `observer start` to auto-register)"},
	{codextrust.StateTrusted, "trusted"},
}

func codexHookTrustCheck(rep codextrust.Report, hooksPath string) Check {
	return codexHookTrustCheckNamed("codex.hook_trust", rep, hooksPath)
}

// codexHookTrustCheckNamed builds the trust check under name. An untrusted
// tool-gate event (CodexToolGateEvents) is a FAIL, not a warning: Codex runs
// no unapproved hook, so Observer's Codex guard gate is off, not degraded
// (live check 2026-10-20, Codex 0.144.4 `codex exec` ran no hook at all).
func codexHookTrustCheckNamed(name string, rep codextrust.Report, hooksPath string) Check {
	blocked := rep.Events(codextrust.StateUntrusted, codextrust.StateModified, codextrust.StateDisabled)
	missing := rep.Events(codextrust.StateMissing)
	if len(blocked) == 0 && len(missing) == 0 {
		msg := fmt.Sprintf("all %d codex hook(s) are trust-approved", len(rep.Entries))
		if !rep.HashVerified {
			msg += " (recorded approvals; this Codex version's trust hash could not be reproduced)"
		}
		return Check{Name: name, Status: StatusOK, Message: msg}
	}
	gate := map[string]bool{}
	for _, e := range CodexToolGateEvents() {
		gate[e] = true
	}
	var gateOff []string
	for _, e := range blocked {
		if gate[e] {
			gateOff = append(gateOff, e)
		}
	}
	status := StatusWarn
	var details []string
	var msg string
	switch {
	case len(gateOff) > 0:
		status = StatusFail
		msg = fmt.Sprintf("Codex hooks not trusted, so Observer's Codex guard gate is OFF (%s does not run): run `observer init --codex` (it re-registers the hooks and records their trust), or approve each Observer entry in codex /hooks (%d need approval)",
			strings.Join(gateOff, ", "), len(blocked))
		details = append(details, "untrusted: "+strings.Join(blocked, ", "))
	case len(blocked) > 0:
		msg = fmt.Sprintf("%d codex hook(s) need trust approval, so Codex will not run them: run `observer init --codex`, or trust each Observer entry in codex /hooks", len(blocked))
		details = append(details, "untrusted: "+strings.Join(blocked, ", "))
	default:
		msg = fmt.Sprintf("%d codex hook event(s) Observer expects are not registered", len(missing))
		details = append(details, "not registered: "+strings.Join(missing, ", "))
	}
	for _, row := range codexTrustStateLines {
		if evs := rep.Events(row.state); len(evs) > 0 {
			details = append(details, row.label+": "+strings.Join(evs, ", "))
		}
	}
	if !rep.ConfigPresent {
		details = append(details, "config.toml does not exist (codex never opened since the hooks were registered?)")
	}
	if !rep.HashVerified {
		details = append(details, "note: no trust hash in this hooks.json reproduces, so a changed entry cannot be told apart from a trusted one")
	}
	if len(gateOff) > 0 {
		details = append(details, "gate off: guard rules do not apply to Codex tool calls until the tool-gate hook is trusted")
	}
	details = append(details,
		"hooks file: "+hooksPath,
		"why: codex runs a hook only once config.toml [hooks.state] records its trust; Observer records it for its own entries when it registers them, so an entry listed here lacks that record (registered by an older Observer, changed since, or a Codex version that hashes differently). An entry switched off in /hooks stays off until you turn it back on there",
	)
	var rems []remedy.Remediation
	if len(blocked) > 0 || len(missing) > 0 {
		rems = append(rems, remedy.Of(remedy.InitTool, models.ToolCodex))
	}
	if len(blocked) > 0 {
		rems = append(rems, remedy.Of(remedy.CodexTrust, ""))
	}
	return Check{Name: name, Status: status, Message: msg, Details: details, Remediations: rems}
}
