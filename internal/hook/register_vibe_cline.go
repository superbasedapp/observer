package hook

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

// Two non-JSON tool-gate writers (hook-parity Lane A6):
//
//   - Mistral vibe: ~/.vibe/hooks.toml, an array of [[hooks]] tables
//     ({name, type, match, command, timeout, strict}); pre_tool is the gate.
//   - Cline (SDK hook runtime, extension and CLI): one executable per event
//     in a hooks directory; the file named PreToolUse is the gate.

// observerVibeHookName is the [[hooks]] name Observer owns.
const observerVibeHookName = "superbased-observer"

// vibeHookTimeoutSeconds bounds Observer's pre_tool hook (vibe's default is
// 60 s; strict stays false so a failed hook is a warning, the vendor's own
// fail-open default, and Observer's own fail-closed answer under
// enforcement is a JSON deny written before vibe's timeout).
const vibeHookTimeoutSeconds = 30

// vibeHooksPath is ~/.vibe/hooks.toml, the mistral-code/user-hooks artifact,
// so VIBE_HOME moves it (CLI-4).
func (r *Registry) vibeHooksPath() (dir, path string, err error) {
	path, err = r.artifactPath("mistral-code/user-hooks")
	return filepath.Dir(path), path, err
}

// readVibeHooks reads hooks.toml into its top-level table (a missing file is
// empty) and its [[hooks]] list.
func readVibeHooks(path string) (raw []byte, top map[string]any, hooks []map[string]any, err error) {
	raw, err = readSettingsFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, nil, nil, fmt.Errorf("hook.readVibeHooks: read: %w", err)
	}
	top = map[string]any{}
	if len(bytes.TrimSpace(raw)) > 0 {
		if err := toml.Unmarshal(raw, &top); err != nil {
			return nil, nil, nil, fmt.Errorf("hook.readVibeHooks: parse %s: %w", path, err)
		}
	}
	switch v := top["hooks"].(type) {
	case nil:
	case []map[string]any:
		hooks = v
	case []any:
		for _, e := range v {
			m, ok := e.(map[string]any)
			if !ok {
				return nil, nil, nil, fmt.Errorf("hook.readVibeHooks: %s: hooks holds a non-table entry", path)
			}
			hooks = append(hooks, m)
		}
	default:
		return nil, nil, nil, fmt.Errorf("hook.readVibeHooks: %s: hooks is not an array of tables", path)
	}
	return raw, top, hooks, nil
}

// vibeHookIsObservers reports whether a [[hooks]] table is Observer's.
func vibeHookIsObservers(h map[string]any) bool {
	cmd, _ := h["command"].(string)
	return isObserverAnyHookEntry(cmd, "mistral-code")
}

// writeVibeHooks encodes top back to hooks.toml (comments and key order of a
// user's file are not preserved by the TOML round trip; every value is).
func writeVibeHooks(pinned pinnedTarget, top map[string]any) error {
	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(top); err != nil {
		return fmt.Errorf("hook.writeVibeHooks: encode: %w", err)
	}
	return atomicWriteFile(pinned, buf.Bytes())
}

// registerMistralVibe installs Observer's pre_tool hook into
// ~/.vibe/hooks.toml.
func (r *Registry) registerMistralVibe() RegistrationResult {
	const event = "pre_tool"
	res := RegistrationResult{Tool: "mistral-code", DryRun: r.opts.DryRun}
	dir, path, err := r.vibeHooksPath()
	if err != nil {
		res.Error = fmt.Errorf("hook.registerMistralVibe: %w", err)
		return res
	}
	res.ConfigPath = path
	unlock, err := r.lockSettings(path)
	if err != nil {
		res.Error = fmt.Errorf("hook.registerMistralVibe: %w", err)
		return res
	}
	defer unlock()
	pinned := pinWriteTarget(path)

	raw, top, hooks, err := readVibeHooks(path)
	if err != nil {
		res.Error = err
		return res
	}
	// FU-192: an entry in Observer's shape running another binary is kept.
	if r.refusesForeignBinary(&res, "hook.registerMistralVibe", path, identityContent, shapedHooksInText(raw, "mistral-code")) {
		return res
	}
	cmd := shellQuoteIfNeeded(forwardSlashPath(r.opts.BinaryPath)) + " hook mistral-code " + event + r.configFlagSuffixForwardSlash()
	want := map[string]any{
		"name": observerVibeHookName, "type": event, "match": "*",
		"command": cmd, "timeout": int64(vibeHookTimeoutSeconds),
	}
	kept := make([]map[string]any, 0, len(hooks)+1)
	repair := false
	for _, h := range hooks {
		if vibeHookIsObservers(h) {
			if fmt.Sprint(h) == fmt.Sprint(want) {
				res.AlreadySet = append(res.AlreadySet, event)
				return res
			}
			continue
		}
		// T-872: on a managed repair pass a table under Observer's own
		// [[hooks]] name that no longer runs observer is a neutralised
		// Observer hook (identityOwnedName) and is replaced. Otherwise it
		// is judged like any other table: a pre_tool table that is not
		// Observer's by content is the user's (identityContent).
		if name, _ := h["name"].(string); name == observerVibeHookName &&
			r.resolveConflict(path, identityOwnedName) == conflictRepair {
			repair = true
			continue
		}
		if t, _ := h["type"].(string); t == event && r.refuses(path, identityContent) {
			res.Error = fmt.Errorf("hook.registerMistralVibe: %s already has a non-observer pre_tool hook; pass --force to overwrite", path)
			return res
		}
		kept = append(kept, h)
	}
	top["hooks"] = append(kept, want)
	res.HooksAdded = append(res.HooksAdded, event)
	if r.opts.DryRun {
		return res
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		res.Error = fmt.Errorf("hook.registerMistralVibe: %w", err)
		return res
	}
	if err := pinned.verifyUnmoved(); err != nil {
		res.Error = fmt.Errorf("hook.registerMistralVibe: %w", err)
		return res
	}
	if repair {
		// The TOML round trip drops comments; keep the pre-repair file.
		if err := keepRepairCopyOf(&res, pinned.target); err != nil {
			res.Error = fmt.Errorf("hook.registerMistralVibe: %w", err)
			return res
		}
	}
	if err := writeVibeHooks(pinned, top); err != nil {
		res.Error = err
		return res
	}
	if err := r.recordChecksum(res.Tool, path); err != nil {
		res.Error = err
		return res
	}
	if repair {
		noteOwnedRepair(&res, path, []string{event})
	}
	return res
}

// unregisterMistralVibe removes ONLY Observer's [[hooks]] table.
func (r *Registry) unregisterMistralVibe() UnregistrationResult {
	res := UnregistrationResult{Tool: "mistral-code", DryRun: r.opts.DryRun}
	_, path, err := r.vibeHooksPath()
	if err != nil {
		res.Error = fmt.Errorf("hook.unregisterMistralVibe: %w", err)
		return res
	}
	res.ConfigPath = path
	unlock, err := r.lockSettings(path)
	if err != nil {
		res.Error = fmt.Errorf("hook.unregisterMistralVibe: %w", err)
		return res
	}
	defer unlock()
	pinned := pinWriteTarget(path)
	raw, top, hooks, err := readVibeHooks(path)
	if err != nil {
		res.Error = err
		return res
	}
	kept := make([]map[string]any, 0, len(hooks))
	for _, h := range hooks {
		if vibeHookIsObservers(h) {
			continue
		}
		kept = append(kept, h)
	}
	if len(kept) == len(hooks) {
		return res
	}
	res.HooksRemoved = append(res.HooksRemoved, "pre_tool")
	if r.opts.DryRun {
		return res
	}
	if len(kept) == 0 {
		delete(top, "hooks")
	} else {
		top["hooks"] = kept
	}
	if len(top) == 0 {
		if err := removeEmptyConfigFile(path, raw); err != nil {
			res.Error = fmt.Errorf("hook.unregisterMistralVibe: %w", err)
			return res
		}
	} else if err := writeVibeHooks(pinned, top); err != nil {
		res.Error = err
		return res
	}
	if err := r.removeChecksum(path); err != nil {
		res.Error = err
	}
	return res
}

// clineHookExtensions are the file extensions the Cline SDK maps onto an
// event file (hook-file-config.ts): a PreToolUse under any of them is a hook
// file the runtime runs.
var clineHookExtensions = []string{"", ".sh", ".bash", ".zsh", ".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".py", ".ps1"}

// clineHookMarker is the second line of the PreToolUse GATE script Observer
// writes (`exec <observer> hook cline-cli PreToolUse`): Cline CLI 3.0.3 runs
// hook files named after the event and reads the verdict from the hook's
// stdout, {"cancel":true,...} to stop (MAC-6, 2026-10-30, FU-154); it never
// loads plugins. An earlier version wrote the same script (T-342), so an old
// one is recognized as Observer's and refreshed.
const clineHookMarker = "# superbased-observer: Cline PreToolUse guard (observer init writes this file; observer uninstall removes it)"

// clineKeepAliveMarker is the second line of the no-op PreToolUse script an
// earlier version wrote (2026-10-15 to FU-154): it judged nothing, so on a
// Cline that runs hook files and no plugin nothing blocked. Still recognized
// as Observer's, so a register replaces it with the gate and an unregister
// removes it.
const clineKeepAliveMarker = "# superbased-observer: Cline hooks keep-alive, no verdict (the guard is the Observer plugin in the Cline plugins directory; observer uninstall removes this file)"

// clineHooksDir is the user-level hooks directory the Cline SDK and CLI read
// ($CLINE_DIR/hooks, default ~/.cline/hooks; ~/Documents/Cline/Hooks is the
// other one): resolveHooksConfigSearchPaths in cline/cline
// sdk/packages/shared/src/storage/paths.ts, where resolveClineDir is the
// trimmed CLINE_DIR, else HOME/.cline (S-6). The same root the guard plugin
// goes under (pluginshim's cline-cli host), so the two never split. Which
// directories the VS Code extension itself scans is not grounded here (live
// check 26); Observer registers nothing for the extension.
func (r *Registry) clineHooksDir() string {
	if r.opts.Getenv != nil {
		if dir := strings.TrimSpace(r.opts.Getenv("CLINE_DIR")); dir != "" {
			return filepath.Join(dir, "hooks")
		}
	}
	return filepath.Join(r.opts.HomeDir, ".cline", "hooks")
}

// clineHookTool is the registry row the Cline CLI guard belongs to (T-342:
// the Cline CLI reads ~/.cline, so verdicts are recorded under cline-cli).
// clineHookLegacyTools are the tokens an earlier gate script carried
// (`observer hook cline`): still Observer's script.
const clineHookTool = "cline-cli"

var clineHookLegacyTools = []string{"cline"}

// clineGateScript is Observer's PreToolUse executable (FU-154): it hands
// the payload on stdin to `observer hook cline-cli PreToolUse`, whose
// cline-pretool dialect prints {"cancel":true,"errorMessage":...} to block
// and nothing (the SDK runtime's allow) otherwise. Cline reads the verdict
// from stdout and ignores the exit code. A registered hook file also keeps
// the Cline CLI writing ~/.cline/data/logs/hooks.jsonl, which the clinecli
// adapter tails. A Cline that also loads Observer's plugin judges a call in
// both (its beforeTool denies per call; this file's cancel stops the run).
func (r *Registry) clineGateScript() []byte {
	cmd := shellQuoteIfNeeded(r.opts.BinaryPath) + " hook " + clineHookTool + " PreToolUse" + r.configFlagSuffix()
	return []byte("#!/usr/bin/env bash\n" + clineHookMarker + "\nexec " + cmd + "\n")
}

// clineHooksUnsupportedOS reports whether goos has no grounded Cline guard
// (a Windows host: the SDK runs .ps1 hooks detached and never reads their
// reply, and the plugin sandbox there has not been tested live).
func clineHooksUnsupportedOS(goos string) bool { return goos == "windows" }

// clineHookIsObservers reports whether data is a script Observer wrote: the
// keep-alive, or a gate script of an earlier version.
func clineHookIsObservers(data []byte) bool {
	lines := strings.Split(string(data), "\n")
	if len(lines) < 3 {
		return false
	}
	if lines[1] == clineKeepAliveMarker {
		return true
	}
	if lines[1] != clineHookMarker {
		return false
	}
	cmd, ok := strings.CutPrefix(lines[2], "exec ")
	if !ok {
		return false
	}
	for _, tool := range append([]string{clineHookTool}, clineHookLegacyTools...) {
		if isObserverAnyHookEntry(cmd, tool) {
			return true
		}
	}
	return false
}

// clineHookExecutable reports whether path is a regular file its owner can
// execute. Cline runs the hook file as a program, so the right bytes in a
// file that is not executable (a 0644 copy, a restored backup) are no hook
// at all and must not read as current (review M2-08); the writer below
// rewrites it with 0755.
func clineHookExecutable(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Mode().IsRegular() && fi.Mode().Perm()&0o100 != 0
}

// registerCline installs the Cline CLI guard: first the plugin (the
// internal/hook/pluginshim "cline" shape: the beforeModel prompt gate and the
// beforeTool per-call gate) in the Cline plugins directory, for the hosts
// that load plugins, then the PreToolUse gate file, for the Cline CLI that
// runs hook files and no plugin (FU-154). A plugin that cannot be written
// leaves the hooks directory untouched. macOS / Linux only.
func (r *Registry) registerCline() RegistrationResult {
	res := RegistrationResult{Tool: clineHookTool, DryRun: r.opts.DryRun}
	if clineHooksUnsupportedOS(runtime.GOOS) {
		res.Skipped = true
		res.SkipKind = SkipNotApplicable
		res.SkipReason = "the Cline guard is macOS / Linux only (the SDK's Windows .ps1 hooks are broken, cline/cline #14767, and the plugin sandbox is untested on Windows)"
		return res
	}
	c, ok := integration.For(clineHookTool)
	if !ok {
		res.Error = fmt.Errorf("hook.registerCline: no registry row for %s", clineHookTool)
		return res
	}
	res = r.registerPluginShim(c)
	if res.Error != nil || res.Skipped {
		return res
	}
	// The PreToolUse gate file is a hook Observer serves (FU-154), so its
	// event is reported with the plugin's.
	gate := r.registerClineGateFile()
	if gate.Error != nil {
		res.Error = gate.Error
	}
	res.HooksAdded = append(res.HooksAdded, gate.HooksAdded...)
	res.AlreadySet = append(res.AlreadySet, gate.AlreadySet...)
	// The developer's own PreToolUse holds the slot: the plugin's events
	// are still reported, so say that they do not gate a Cline CLI that
	// loads no plugins (audit-report-arc-w11 row 6).
	if gate.Skipped {
		res.Warnings = append(res.Warnings, gate.SkipReason)
	}
	// The security feedback's PostToolUse file hook (lane sec-h): written
	// only while its component is selected, removed when it is not.
	fb := r.syncClineFeedback()
	if fb.Error != nil && res.Error == nil {
		res.Error = fb.Error
	}
	res.HooksAdded = append(res.HooksAdded, fb.HooksAdded...)
	res.AlreadySet = append(res.AlreadySet, fb.AlreadySet...)
	return res
}

// registerClineGateFile writes the PreToolUse gate file (FU-154). A
// PreToolUse of the developer's own (any extension the SDK reads) occupies
// the event: Observer then writes nothing there and removes a script of its
// own instead of writing beside it (Cline would run both).
func (r *Registry) registerClineGateFile() RegistrationResult {
	const event = "PreToolUse"
	res := RegistrationResult{Tool: clineHookTool, DryRun: r.opts.DryRun}
	dir := r.clineHooksDir()
	path := filepath.Join(dir, event)
	res.ConfigPath = path
	unlock, err := r.lockSettings(path)
	if err != nil {
		res.Error = fmt.Errorf("hook.registerCline: %w", err)
		return res
	}
	defer unlock()
	want := r.clineGateScript()
	var ours []byte
	var foreign []string
	for _, ext := range clineHookExtensions {
		p := path + ext
		have, err := os.ReadFile(p)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			res.Error = fmt.Errorf("hook.registerCline: read %s: %w", p, err)
			return res
		}
		switch {
		case ext == "" && clineHookIsObservers(have):
			ours = have
		case !clineHookIsObservers(have):
			foreign = append(foreign, p)
		}
	}
	if len(foreign) > 0 {
		// Not silent: Observer writes no gate file here, and Cline CLI
		// 3.0.x (which loads no plugins) is then not gated by Observer.
		res.Skipped, res.SkipKind = true, SkipNotApplicable
		res.SkipReason = "cline-cli: the developer's own PreToolUse hook file " + strings.Join(foreign, ", ") +
			" holds the slot, so Observer writes no PreToolUse gate file: a Cline CLI that loads no plugins (3.0.x) is NOT gated by Observer's plugin events; move that hook aside to let Observer gate it"
		if ours != nil && !r.opts.DryRun {
			if err := r.removeClineScript(path, ours); err != nil {
				res.Error = fmt.Errorf("hook.registerCline: %w", err)
			}
		}
		return res
	}
	if bytes.Equal(ours, want) && clineHookExecutable(path) {
		res.AlreadySet = append(res.AlreadySet, event)
		return res
	}
	res.HooksAdded = append(res.HooksAdded, event)
	if r.opts.DryRun {
		return res
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		res.Error = fmt.Errorf("hook.registerCline: %w", err)
		return res
	}
	pinned := pinWriteTarget(path)
	if err := atomicWriteFile(pinned, want); err != nil {
		res.Error = fmt.Errorf("hook.registerCline: write: %w", err)
		return res
	}
	if err := os.Chmod(pinned.target, 0o755); err != nil {
		res.Error = fmt.Errorf("hook.registerCline: chmod: %w", err)
		return res
	}
	if err := r.recordChecksum(res.Tool, path); err != nil {
		res.Error = err
	}
	return res
}

// removeClineScript deletes Observer's script at path (have is its content).
func (r *Registry) removeClineScript(path string, have []byte) error {
	if err := removeEmptyConfigFile(path, have); err != nil {
		return err
	}
	return r.removeChecksum(path)
}

// unregisterCline removes the plugin and Observer's PreToolUse script (the
// keep-alive or an earlier gate script), never a file Observer did not write.
func (r *Registry) unregisterCline() UnregistrationResult {
	res := UnregistrationResult{Tool: clineHookTool, DryRun: r.opts.DryRun}
	if c, ok := integration.For(clineHookTool); ok {
		res = r.unregisterPluginShim(c)
	}
	path := filepath.Join(r.clineHooksDir(), "PreToolUse")
	if res.ConfigPath == "" {
		res.ConfigPath = path
	}
	r.unregisterClineFeedback(&res)
	unlock, err := r.lockSettings(path)
	if err != nil {
		res.Error = fmt.Errorf("hook.unregisterCline: %w", err)
		return res
	}
	defer unlock()
	have, err := os.ReadFile(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) && res.Error == nil {
			res.Error = fmt.Errorf("hook.unregisterCline: %w", err)
		}
		return res
	}
	if !clineHookIsObservers(have) {
		res.HooksKept = append(res.HooksKept, "PreToolUse")
		return res
	}
	// FU-203: Observer's gate file running another binary is kept.
	if r.keepsForeignBinary(shapedHooksInText(have, clineHookTool)) {
		res.HooksKept = append(res.HooksKept, "PreToolUse")
		noteKeptForeign(&res, "PreToolUse")
		return res
	}
	res.HooksRemoved = append(res.HooksRemoved, "PreToolUse")
	if r.opts.DryRun {
		return res
	}
	if err := r.removeClineScript(path, have); err != nil && res.Error == nil {
		res.Error = fmt.Errorf("hook.unregisterCline: %w", err)
	}
	return res
}
