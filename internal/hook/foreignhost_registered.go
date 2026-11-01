package hook

import (
	"encoding/json"
	"errors"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/regularfile"
)

// OwnGateRegistered returns the production ForeignHostEnv.OwnGateRegistered
// (surface-gap Wave 5 audit finding 2, G2): whether Observer's own hook
// registration for tool holds the gate a replayed Claude Code step maps to.
// It reads the registry's own target for tool (for copilot-cli the hooks
// file in the Copilot home the copilot-cli/user-settings artifact
// resolves), so the artifact and its relocation are the writer's, never a
// path built here. An entry counts when it is Observer's whatever binary
// wrote it (an npm shim, the VS Code bundle, a moved install): the question
// is whether Observer sees the call, not whether this binary would rewrite
// the entry. The file is read through regularfile.Read (bounded, a FIFO or
// device refused without blocking), so a planted FIFO cannot hang every
// replay. opts is the registry's: the hook path passes the hook process's
// own home and environment through internal/hookctx (BinaryPath is
// required). Any failure to build or read the registration answers false:
// not known to be registered, so the call is judged. So does a tool whose
// hook writer waits on its live check (HookSpec.LiveGate, FU-141): Observer
// does not rely on a file it would not write, even one already in place.
// Copilot CLI's own
// disableAllHooks is deliberately not read: on Copilot CLI 1.0.105 it did
// not stop ~/.copilot/hooks (FU-159, live 2026-10-29, ~/.copilot/settings.json
// and the repo .github/copilot/settings.json), so the switch being true is
// not "registration absent" and the replay keeps answering neutral.
func OwnGateRegistered(opts Options) func(tool, step string) bool {
	return func(tool, step string) bool {
		if hookLiveGateFor(tool).Waiting() && !runLiveGatedHookWriters {
			return false
		}
		events := ownGateEvents(tool, step)
		if len(events) == 0 {
			return false
		}
		r, err := NewRegistry(opts)
		if err != nil {
			return false
		}
		have, ok := r.observerEntryEvents(tool)
		if !ok {
			return false
		}
		for _, e := range events {
			if !have[e] {
				return false
			}
		}
		return true
	}
}

// ownedEntryReader reads one hook mechanism's registration target: the
// target the registrar writes, and per OS the handler field the host RUNS
// there when that is not the target's commandKey. Copilot CLI on Windows
// runs a handler's "powershell" field, not "bash" (copilot 1.0.80
// hookSelectShellScript), so a bash-only file from before the 2026-10-20
// fix holds Observer's entry but never fires there.
type ownedEntryReader struct {
	target   func(r *Registry) jsonHooksTarget
	runKeyOn map[string]string
}

// ownedEntryReaders reads, per hook mechanism, the events whose entry in
// the tool's own registration target is Observer's (any Observer binary).
// A mechanism with no reader falls back to a dry-run registration
// (probeEntryEvents), which counts an entry only when this binary would
// keep it.
var ownedEntryReaders = map[integration.HookMechanism]ownedEntryReader{
	integration.HookCopilotCLIHooks: {
		target:   (*Registry).copilotCLIHooksTarget,
		runKeyOn: map[string]string{"windows": "powershell"},
	},
	// Cortex Code's own hooks.json (FU-141): only its `observer hook
	// cortex-code <event>` entries count, never a Claude Code command a user
	// copied there (that one reaches the claude-code receiver as a replay).
	integration.HookCortexHooksJSON: {
		target: (*Registry).cortexHooksTarget,
	},
}

// ownedEntryFuncs reads, per hook mechanism whose registration target is
// not a jsonHooksTarget, the events whose entry is Observer's (any Observer
// binary). Checked before ownedEntryReaders.
var ownedEntryFuncs = map[integration.HookMechanism]func(r *Registry) (map[string]bool, bool){
	integration.HookCursor: (*Registry).cursorObserverEvents,
}

// observerEntryEvents is the set of events with an Observer entry in tool's
// own registration target; ok is false when it cannot be read.
func (r *Registry) observerEntryEvents(tool string) (map[string]bool, bool) {
	c, ok := integration.For(tool)
	if !ok {
		return nil, false
	}
	if read, ok := ownedEntryFuncs[c.Hook.Mechanism]; ok {
		return read(r)
	}
	if rd, ok := ownedEntryReaders[c.Hook.Mechanism]; ok {
		return jsonHooksObserverEvents(rd.target(r), rd.runKeyOn[r.hostGOOS()])
	}
	return probeEntryEvents(r.Probe(tool), c.Hook.RegisteredEvents())
}

// jsonHooksObserverEvents reads a JSON hooks target (regularfile.Read,
// capped at the settings-file limit) and reports the events holding an
// entry that is positively Observer's (jsonHooksEntryIsObservers) and, when
// runKey is set, whose runKey field also names an Observer hook invocation.
// A missing file reads as no events; any other read or decode failure is
// unknown.
func jsonHooksObserverEvents(t jsonHooksTarget, runKey string) (map[string]bool, bool) {
	if t.dirErr != nil {
		return nil, false
	}
	path := filepath.Join(t.dir, t.file)
	raw, err := regularfile.Read(path, maxSettingsFileBytes)
	if errors.Is(err, fs.ErrNotExist) {
		return map[string]bool{}, true
	}
	if err != nil {
		return nil, false
	}
	_, _, eventMap, err := decodeJSONHooksFile(t, path, raw)
	if err != nil {
		return nil, false
	}
	out := map[string]bool{}
	for ev, entries := range eventMap {
		for _, e := range entries {
			if jsonHooksEntryIsObservers(t, e) && (runKey == "" || jsonHooksEntryRuns(t, e, runKey)) {
				out[ev] = true
			}
		}
	}
	return out, true
}

// cursorObserverEvents reads Observer's cursor registration (FU-122): the
// events of the user hooks file (cursorHooksPath, regularfile.Read capped at
// the settings-file limit) holding a command that is an Observer hook
// invocation for cursor (observerRunCommand: any Observer binary, the
// wsl.exe bridge included), plus the events the trusted administrator hooks
// file runs Observer's hook for (IDE-5: Cursor merges that layer with the
// user's, so its entry sees the call). A missing file reads as no events;
// any other read or decode failure is unknown.
func (r *Registry) cursorObserverEvents() (map[string]bool, bool) {
	out := map[string]bool{}
	for _, ev := range r.managedHooksPlanFor("cursor", cursorEvents).drop {
		out[ev] = true
	}
	path := r.cursorHooksPath()
	raw, err := regularfile.Read(path, maxSettingsFileBytes)
	if errors.Is(err, fs.ErrNotExist) {
		return out, true
	}
	if err != nil {
		return nil, false
	}
	hooks := map[string][]cursorHookEntry{}
	if len(raw) > 0 {
		settings, err := decodeSettingsObject(path, raw)
		if err != nil {
			return nil, false
		}
		if h, ok := settings["hooks"]; ok && json.Unmarshal(h, &hooks) != nil {
			return nil, false
		}
	}
	for ev, entries := range hooks {
		for _, e := range entries {
			if observerRunCommand(e.Command, "cursor") {
				out[ev] = true
			}
		}
	}
	return out, true
}

// jsonHooksEntryRuns reports whether every handler of a raw entry carries a
// runKey command that is an Observer hook invocation for the target's tool
// (observerRunCommand), and the entry holds at least one handler.
func jsonHooksEntryRuns(t jsonHooksTarget, raw json.RawMessage, runKey string) bool {
	handlers := []json.RawMessage{raw}
	if t.grouped {
		var g struct {
			Hooks []json.RawMessage `json:"hooks"`
		}
		if json.Unmarshal(raw, &g) != nil || len(g.Hooks) == 0 {
			return false
		}
		handlers = g.Hooks
	}
	for _, h := range handlers {
		var m map[string]any
		if json.Unmarshal(h, &m) != nil {
			return false
		}
		cmd, _ := m[runKey].(string)
		if !observerRunCommand(cmd, t.tool) {
			return false
		}
	}
	return true
}

// observerRunCommand recognises the PowerShell command Observer writes for
// a Windows host (copilotPowerShellCommand): an optional call operator
// "&", or the `wsl.exe -d <distro> -e` bridge, then the observer binary,
// "hook" and the tool. Backslashes are read as separators, as
// isObserverAnyHookEntry's retry does.
func observerRunCommand(cmd, tool string) bool {
	toks := splitCommandTokens(strings.ReplaceAll(cmd, `\`, "/"))
	if len(toks) > 0 && toks[0] == "&" {
		toks = toks[1:]
	}
	if len(toks) > 0 && strings.ToLower(strings.TrimSuffix(commandBaseName(toks[0]), ".exe")) == "wsl" {
		rest := []string(nil)
		for i, tok := range toks {
			if tok == "-e" || tok == "--" {
				rest = toks[i+1:]
				break
			}
		}
		toks = rest
	}
	return len(toks) >= 3 && isObserverBinaryToken(toks[0]) && toks[1] == "hook" && toks[2] == tool
}

// ownGateEvents are the events tool's own registration writes for the gate
// a replayed Claude Code step maps to, by the first rule that holds:
//
//  1. the tool's binding reached through claude-code for step names the
//     gate it stands in for (HookBinding.StandsInFor): that event alone;
//  2. a host that replays in its OWN step vocabulary (cursor-agent's
//     preToolUse, beforeSubmitPrompt) names the gate itself: a step that is
//     a registered, wired gate binding of tool maps to that event alone;
//  3. otherwise the registered, wired gate bindings of tool whose
//     capability is that of Claude Code's binding for step. A step Claude
//     Code does not gate (a lifecycle event) maps to every registered gate
//     of tool, so it reads as registered exactly when the tool's gates are.
func ownGateEvents(tool, step string) []string {
	c, ok := integration.For(tool)
	if !ok {
		return nil
	}
	for _, b := range c.Hook.Bindings {
		if b.NativeEvent == step && b.ReplayedVia == models.ToolClaudeCode && b.StandsInFor != "" {
			return []string{b.StandsInFor}
		}
	}
	if b, ok := c.Hook.Binding(step); ok && b.Registered && b.Wired && isGateCap(b.Cap) {
		return []string{step}
	}
	var stepCap integration.HookCap
	if cc, ok := integration.For(models.ToolClaudeCode); ok {
		if b, ok := cc.Hook.Binding(step); ok && isGateCap(b.Cap) {
			stepCap = b.Cap
		}
	}
	var out []string
	for _, b := range c.Hook.Bindings {
		if !b.Registered || !b.Wired || !isGateCap(b.Cap) {
			continue
		}
		if stepCap == "" || b.Cap == stepCap {
			out = append(out, b.NativeEvent)
		}
	}
	return out
}

// isGateCap reports a capability that decides a call (tool or prompt gate).
func isGateCap(c integration.HookCap) bool {
	return c == integration.HookCapToolGate || c == integration.HookCapPromptGate
}

// probeEntryEvents reads a dry-run registration: the events already
// carrying an Observer entry this binary keeps (AlreadySet), held by a
// trusted administrator hooks file (HooksDropped), or an Observer entry
// whose command would be rewritten (Rewrites). A registration that failed
// reads as unknown; one that wrote nothing on purpose reads as no events,
// except a tool covered by its own packaging surface (SkipCovered), whose
// every registered event is covered.
func probeEntryEvents(res RegistrationResult, registered []string) (map[string]bool, bool) {
	if res.Error != nil {
		return nil, false
	}
	out := map[string]bool{}
	if res.Skipped {
		if res.SkipKind == SkipCovered {
			for _, e := range registered {
				out[e] = true
			}
		}
		return out, true
	}
	for _, e := range res.AlreadySet {
		out[e] = true
	}
	for _, e := range res.HooksDropped {
		out[e] = true
	}
	for _, rw := range res.Rewrites {
		out[rw.Event] = true
	}
	return out, true
}
