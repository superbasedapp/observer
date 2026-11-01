package hook

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/marmutapp/superbased-observer/internal/credfile"
	"github.com/marmutapp/superbased-observer/internal/integration"
)

// --- Status line for other hosts (`observer init --statusline-tools`, AP-133) ---
//
// The capability-driven sibling of register_statusline.go (Claude Code). A
// registry row whose StatusLine column says Writer with InitFlag
// "--statusline-tools" is written here, and the writer dispatches on the
// row's SHAPE, never its tool name (CLAUDE.md rule 3):
//
//   - StatusLine.Kind picks the config format (statusLineFormats): a
//     top-level "statusLine" member of a JSON settings file, or VT Code's
//     [ui.status_line] table in vtcode.toml.
//   - StatusLine.Exec picks the command: a shell command string
//     `<observer> statusline --host <tool>`, or, for a host that spawns ONE
//     executable path with no arguments (Kimchi) or demands a regular-file
//     script (VT Code), a marker-owned wrapper script under
//     ~/.observer/statusline/ that execs that command.
//
// The contract is the Claude Code writer's: opt-in only (never `observer
// start`), dry run, a foreign status line is refused unless --force, an
// observer-owned one is refreshed, and unregister removes only Observer's.
// Two things are stricter here:
//
//   - The config file is edited, never re-rendered: JSON goes through
//     internal/credfile's member splice (every other member keeps its
//     bytes, so a CodeBuddy settings.json env block holding an API key is
//     never re-encoded) and the TOML table is edited line by line with the
//     decoded result verified. A register then unregister leaves the file
//     byte-identical to before (a file Observer created is removed again).
//   - No checksum entry is recorded or removed for the config file: the
//     same file's entry belongs to the hook writer (CodeBuddy and VT Code
//     hooks live there too), and removing it on unregister would strand
//     that writer's drift guard. Ownership is read from the command itself.
//
// Errors never carry a value read from the file (credentialSafeError).

// statusLineScriptMarkerPrefix opens the marker line of every wrapper script
// Observer writes for a script-path host.
const statusLineScriptMarkerPrefix = "# superbased-observer: status line for "

// statusLineScriptMarker is the marker line of tool's wrapper script.
func statusLineScriptMarker(tool string) string {
	return statusLineScriptMarkerPrefix + tool + " (observer init --statusline-tools writes this file; observer init --statusline-tools " + tool + " --uninstall removes it)"
}

// statusLineScriptDir is where the wrapper scripts live.
func (r *Registry) statusLineScriptDir() string {
	return filepath.Join(r.opts.HomeDir, ".observer", "statusline")
}

// statusLineScript is tool's wrapper script: a POSIX sh file that execs
// `observer statusline --host <tool>` with the payload on its stdin.
func (r *Registry) statusLineScript(tool string) ownedScript {
	return ownedScript{
		event: "script",
		path:  filepath.Join(r.statusLineScriptDir(), tool+".sh"),
		data: []byte("#!/bin/sh\n" + statusLineScriptMarker(tool) + "\nexec " +
			shellQuoteIfNeeded(r.opts.BinaryPath) + " statusline --host " + tool + "\n"),
		mode:      0o755,
		ours:      markerOwned(statusLineScriptMarker(tool)),
		pruneDirs: 1,
	}
}

// isOwnStatusLineScript reports whether cmd names a wrapper script Observer
// wrote: a file in the wrapper directory that carries a wrapper marker line.
// Only files in that directory are ever read.
func (r *Registry) isOwnStatusLineScript(cmd string) bool {
	p := strings.TrimSpace(cmd)
	if p == "" || !filepath.IsAbs(p) || filepath.Clean(filepath.Dir(p)) != filepath.Clean(r.statusLineScriptDir()) {
		return false
	}
	data, err := os.ReadFile(p) // #nosec G304 -- confined to Observer's own wrapper directory
	if err != nil {
		return false
	}
	for _, l := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		if strings.HasPrefix(l, statusLineScriptMarkerPrefix) {
			return true
		}
	}
	return false
}

// statusLineCommand is the command Observer configures for tool.
func (r *Registry) statusLineCommand(tool string, spec integration.StatusLineSpec) string {
	if spec.Exec == integration.StatusLineExecScriptPath {
		return r.statusLineScript(tool).path
	}
	return shellQuoteIfNeeded(forwardSlashPath(r.opts.BinaryPath)) + " statusline --host " + tool
}

// statusLineState is what a config file holds in the status-line slot.
type statusLineState struct {
	present bool   // any status line is configured
	command string // its command ("" when absent or not a string)
	exact   bool   // it is exactly what Observer would write
}

// statusLineFormat is one config format's editor. Every function is pure
// over the file bytes.
type statusLineFormat struct {
	// key is the slot name results report.
	key string
	// path resolves tool's config file; "" = not grounded on this OS, or
	// not nameable (a relative relocation value).
	path func(r *Registry, tool string, spec integration.StatusLineSpec) string
	// state reads the slot against the command Observer would write.
	state func(orig []byte, command string) (statusLineState, error)
	// set returns orig with the slot replaced by Observer's command.
	set func(orig []byte, command string) ([]byte, error)
	// remove returns orig without the slot; empty reports that nothing but
	// whitespace (or an empty JSON object) is left.
	remove func(orig []byte) (out []byte, empty bool, err error)
}

// statusLineFormats maps a StatusLine.Kind to its editor.
var statusLineFormats = map[integration.StatusLineKind]statusLineFormat{
	integration.StatusLineSettingsJSON: {
		key: "statusLine",
		path: func(r *Registry, tool string, spec integration.StatusLineSpec) string {
			return r.statusLineSettingsPath(tool, spec)
		},
		state:  jsonStatusLineState,
		set:    jsonStatusLineSet,
		remove: jsonStatusLineRemove,
	},
	integration.StatusLineVTCodeTOML: {
		key: "ui.status_line",
		path: func(r *Registry, _ string, _ integration.StatusLineSpec) string {
			return r.vtCodeConfigPath()
		},
		state:  vtStatusLineState,
		set:    vtStatusLineSet,
		remove: vtStatusLineRemove,
	},
}

// statusLineTarget resolves tool's writer inputs, or a result to return.
func (r *Registry) statusLineTarget(tool string) (spec integration.StatusLineSpec, f statusLineFormat, path, skip string, err error) {
	spec = integration.StatusLineFor(tool)
	if !spec.Writer || spec.InitFlag != integration.StatusLineInitTools {
		return spec, f, "", "", safeErrorf("hook: %s has no status-line writer for observer init --statusline-tools (writers: %s)",
			tool, strings.Join(integration.StatusLineWriterTools(integration.StatusLineInitTools), ", "))
	}
	f, ok := statusLineFormats[spec.Kind]
	if !ok {
		return spec, f, "", "", safeErrorf("hook: %s status-line shape %q has no writer", tool, spec.Kind)
	}
	if spec.Exec == integration.StatusLineExecScriptPath && r.hostGOOS() == "windows" {
		return spec, f, "", fmt.Sprintf("%s runs its status-line command as a script path, and how it runs a script on Windows is not grounded; nothing written", tool), nil
	}
	path = f.path(r, tool, spec)
	if path == "" {
		return spec, f, "", fmt.Sprintf("%s's config file on %s cannot be named (not grounded, or a relocation variable holds a relative path); nothing written", tool, r.hostGOOS()), nil
	}
	return spec, f, path, "", nil
}

// RegisterStatusLine writes Observer's status line into tool's own config
// (`observer init --statusline-tools <tool>`). Opt-in only: never called by
// `observer start`. tool must be a registry row whose StatusLine column
// names the "--statusline-tools" writer.
func (r *Registry) RegisterStatusLine(tool string) RegistrationResult {
	res := r.registerStatusLine(tool)
	res.Error = credentialSafeError(res.Tool, res.ConfigPath, res.Error)
	return res
}

// UnregisterStatusLine removes Observer's status line from tool's config,
// and its wrapper script; a status line Observer did not write is left.
func (r *Registry) UnregisterStatusLine(tool string) UnregistrationResult {
	res := r.unregisterStatusLine(tool)
	res.Error = credentialSafeError(res.Tool, res.ConfigPath, res.Error)
	return res
}

func (r *Registry) registerStatusLine(tool string) RegistrationResult {
	res := RegistrationResult{Tool: tool + "-statusline", DryRun: r.opts.DryRun}
	spec, f, path, skip, err := r.statusLineTarget(tool)
	if err != nil || skip != "" {
		res.Error, res.Skipped, res.SkipKind, res.SkipReason = err, skip != "", SkipNotApplicable, skip
		return res
	}
	res.ConfigPath = path
	if _, err := os.Stat(filepath.Dir(path)); errors.Is(err, os.ErrNotExist) {
		res.Skipped, res.SkipKind = true, SkipNotApplicable
		res.SkipReason = fmt.Sprintf("%s does not exist (is %s installed and run once?); nothing written", filepath.Dir(path), tool)
		return res
	}

	unlock, err := r.lockSettings(path)
	if err != nil {
		res.Error = fmt.Errorf("hook.RegisterStatusLine: %w", err)
		return res
	}
	defer unlock()
	pinned := pinWriteTarget(path)
	orig, err := readSettingsFile(pinned.target)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		res.Error = fmt.Errorf("hook.RegisterStatusLine: read: %w", err)
		return res
	}
	command := r.statusLineCommand(tool, spec)
	st, err := f.state(orig, command)
	if err != nil {
		res.Error = fmt.Errorf("hook.RegisterStatusLine: %w", err)
		return res
	}
	if st.present && !st.exact && !isObserverStatuslineEntry(st.command) && !r.isOwnStatusLineScript(st.command) && !r.opts.Force {
		// The foreign command is a value read from the file: not echoed.
		res.Error = safeErrorf("hook.RegisterStatusLine: %s already has a non-observer %s; pass --force to overwrite", path, f.key)
		return res
	}

	// The wrapper script first, so the config never points at a script that
	// is not there yet.
	if spec.Exec == integration.StatusLineExecScriptPath {
		var sres RegistrationResult
		sres.Tool = res.Tool
		if err := r.registerOwnedScript(&sres, "hook.RegisterStatusLine", tool, r.statusLineScript(tool)); err != nil {
			res.Error = err
			return res
		}
		if len(sres.HooksAdded) > 0 {
			res.HooksAdded = append(res.HooksAdded, "wrapper script")
		}
	}

	if st.exact {
		if len(res.HooksAdded) == 0 {
			res.AlreadySet = append(res.AlreadySet, f.key)
		}
		return res
	}
	out, err := f.set(orig, command)
	if err != nil {
		res.Error = fmt.Errorf("hook.RegisterStatusLine: %w", err)
		return res
	}
	res.HooksAdded = append(res.HooksAdded, f.key)
	if r.opts.DryRun {
		return res
	}
	if err := pinned.verifyUnmoved(); err != nil {
		res.Error = fmt.Errorf("hook.RegisterStatusLine: %w", err)
		return res
	}
	if err := atomicWriteFileMode(pinned, out, fileModeOr(pinned.target, 0o644)); err != nil {
		res.Error = fmt.Errorf("hook.RegisterStatusLine: write: %w", err)
	}
	return res
}

func (r *Registry) unregisterStatusLine(tool string) UnregistrationResult {
	res := UnregistrationResult{Tool: tool + "-statusline", DryRun: r.opts.DryRun}
	spec, f, path, skip, err := r.statusLineTarget(tool)
	if err != nil || skip != "" {
		res.Error, res.Skipped = err, skip != ""
		return res
	}
	res.ConfigPath = path
	// The wrapper script goes last, whatever the config held: nothing that
	// is left points at it (a crash between the two writes leaves at most an
	// unreferenced script, never a command naming a missing one).
	defer func() {
		if res.Error != nil || spec.Exec != integration.StatusLineExecScriptPath {
			return
		}
		sres := r.unregisterOwnedScripts(res.Tool, "hook.UnregisterStatusLine", []ownedScript{r.statusLineScript(tool)})
		if sres.Error != nil {
			res.Error = sres.Error
			return
		}
		if len(sres.HooksRemoved) > 0 {
			res.HooksRemoved = append(res.HooksRemoved, "wrapper script")
			res.Skipped = false
		}
	}()

	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		res.Skipped = true
		return res
	}
	unlock, err := r.lockSettings(path)
	if err != nil {
		res.Error = fmt.Errorf("hook.UnregisterStatusLine: %w", err)
		return res
	}
	defer unlock()
	pinned := pinWriteTarget(path)
	orig, err := readSettingsFile(pinned.target)
	if errors.Is(err, os.ErrNotExist) {
		res.Skipped = true
		return res
	}
	if err != nil {
		res.Error = fmt.Errorf("hook.UnregisterStatusLine: read: %w", err)
		return res
	}
	st, err := f.state(orig, r.statusLineCommand(tool, spec))
	if err != nil {
		res.Error = fmt.Errorf("hook.UnregisterStatusLine: %w", err)
		return res
	}
	if !st.present {
		res.Skipped = true
		return res
	}
	if !st.exact && !isObserverStatuslineEntry(st.command) && !r.isOwnStatusLineScript(st.command) {
		res.HooksKept = append(res.HooksKept, f.key)
		res.Skipped = true
		return res
	}
	out, empty, err := f.remove(orig)
	if err != nil {
		res.Error = fmt.Errorf("hook.UnregisterStatusLine: %w", err)
		return res
	}
	res.HooksRemoved = append(res.HooksRemoved, f.key)
	if r.opts.DryRun {
		return res
	}
	if empty {
		err = removeEmptyConfigFile(pinned.target, orig)
	} else if err = pinned.verifyUnmoved(); err == nil {
		err = atomicWriteFileMode(pinned, out, fileModeOr(pinned.target, 0o644))
	}
	if err != nil {
		res.Error = fmt.Errorf("hook.UnregisterStatusLine: %w", err)
	}
	return res
}

// --- JSON settings: the top-level "statusLine" member ---------------------

func jsonStatusLineEntry(command string) json.RawMessage {
	b, _ := json.Marshal(claudeStatuslineEntry{Type: "command", Command: command, Padding: 0})
	return b
}

func jsonStatusLineState(orig []byte, command string) (statusLineState, error) {
	if len(bytes.TrimSpace(orig)) == 0 {
		return statusLineState{}, nil
	}
	settings, err := decodeSettingsObject("settings file", orig)
	if err != nil {
		return statusLineState{}, err
	}
	raw, ok := settings["statusLine"]
	if !ok {
		return statusLineState{}, nil
	}
	st := statusLineState{present: true}
	var cur claudeStatuslineEntry
	if json.Unmarshal(raw, &cur) == nil {
		st.command = cur.Command
		st.exact = credfile.JSONEqual(raw, jsonStatusLineEntry(command))
	}
	return st, nil
}

func jsonStatusLineSet(orig []byte, command string) ([]byte, error) {
	return credfile.SetObjectMember(orig, "statusLine", jsonStatusLineEntry(command), true)
}

func jsonStatusLineRemove(orig []byte) ([]byte, bool, error) {
	out, err := credfile.SetObjectMember(orig, "statusLine", nil, false)
	if err != nil {
		return nil, false, err
	}
	var left map[string]json.RawMessage
	if json.Unmarshal(out, &left) != nil {
		return nil, false, errCredentialPatch
	}
	return out, len(left) == 0, nil
}

// --- VT Code: the [ui.status_line] table ----------------------------------

// vtStatusLineMarkerPrefix opens the comment line Observer writes above its
// [ui.status_line] table. The table is Observer's only when the marker sits
// directly above the header.
const vtStatusLineMarkerPrefix = "# superbased-observer: VT Code status line"

// vtStatusLineNoEOL tags a marker whose file had no final newline before
// Observer appended its table, so the removal restores that exactly.
const vtStatusLineNoEOL = " [no-eol]"

func vtStatusLineMarker(noEOL bool) string {
	m := vtStatusLineMarkerPrefix + " (observer init --statusline-tools writes this table; observer init --statusline-tools vtcode --uninstall removes it)"
	if noEOL {
		m += vtStatusLineNoEOL
	}
	return m
}

var vtStatusLineHeader = regexp.MustCompile(`^\s*\[\s*ui\s*\.\s*status_line\s*\]\s*(#.*)?$`)

// errVTStatusLineShape refuses a [ui.status_line] the line editor cannot
// follow (an inline table or dotted keys).
var errVTStatusLineShape = safeErrorf("hook: vtcode.toml sets ui.status_line in a shape other than one [ui.status_line] table; edit it by hand")

// vtStatusLineTimeoutKey is VT Code's per-run limit on the status-line
// command, a member of the same [ui.status_line] table as mode and command
// (grounded: vtcode 0.180.2's StatusLineConfig serde fields mode, command,
// refresh_interval_ms, command_timeout_ms, show_clock; vtcode
// CONFIG_FIELD_REFERENCE). VT Code's default is 200 ms, tight for
// `observer statusline`, so Observer writes vtStatusLineTimeoutMS unless
// the table it replaces already set its own value.
const vtStatusLineTimeoutKey = "command_timeout_ms"

// vtStatusLineTimeoutMS is the command_timeout_ms Observer writes.
const vtStatusLineTimeoutMS int64 = 1000

// vtStatusLineTimeout is the command_timeout_ms Observer's table carries
// given the [ui.status_line] table it replaces (nil when there is none):
// the value already set there, kept as is (Observer never lowers or
// otherwise changes a value the user set), else vtStatusLineTimeoutMS.
func vtStatusLineTimeout(existing map[string]any) any {
	if v, ok := existing[vtStatusLineTimeoutKey]; ok {
		return v
	}
	return vtStatusLineTimeoutMS
}

// vtStatusLineTable is the table Observer writes.
func vtStatusLineTable(command string, timeout any) map[string]any {
	return map[string]any{"mode": "command", "command": command, vtStatusLineTimeoutKey: timeout}
}

// vtTOMLValue renders v as a TOML value (the right-hand side of `k = v`).
func vtTOMLValue(v any) (string, error) {
	if n, ok := v.(int64); ok {
		return strconv.FormatInt(n, 10), nil
	}
	var b bytes.Buffer
	if err := toml.NewEncoder(&b).Encode(map[string]any{"v": v}); err != nil {
		return "", errCredentialPatch
	}
	s := strings.TrimSpace(b.String())
	if !strings.HasPrefix(s, "v = ") || strings.Contains(s, "\n") {
		return "", errCredentialPatch
	}
	return strings.TrimPrefix(s, "v = "), nil
}

// vtDecode decodes orig and returns its ui.status_line value.
func vtDecode(orig []byte) (top map[string]any, sl map[string]any, present bool, err error) {
	top = map[string]any{}
	if len(bytes.TrimSpace(orig)) > 0 {
		if _, derr := toml.Decode(string(orig), &top); derr != nil {
			return nil, nil, false, errCredentialPatch
		}
	}
	ui, _ := top["ui"].(map[string]any)
	v, ok := ui["status_line"]
	if !ok {
		return top, nil, false, nil
	}
	sl, _ = v.(map[string]any)
	return top, sl, true, nil
}

func vtStatusLineState(orig []byte, command string) (statusLineState, error) {
	_, sl, present, err := vtDecode(orig)
	if err != nil || !present {
		return statusLineState{}, err
	}
	st := statusLineState{present: true}
	st.command, _ = sl["command"].(string)
	if _, region, ok := vtStatusLineRegion(orig); ok && region.ours {
		st.exact = tomlJSONEqual(sl, vtStatusLineTable(command, vtStatusLineTimeout(sl)))
	}
	return st, nil
}

// vtRegion is the line span of the [ui.status_line] table: start..end
// (exclusive), including Observer's marker and the blank separator line
// Observer added before it when ours.
type vtRegion struct {
	start, end int
	ours       bool
	noEOL      bool
}

// vtStatusLineRegion finds the one [ui.status_line] header table in orig.
// ok is false when there is none.
func vtStatusLineRegion(orig []byte) (lines []string, reg vtRegion, ok bool) {
	lines = strings.SplitAfter(string(orig), "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	header := -1
	for i, l := range lines {
		if vtStatusLineHeader.MatchString(strings.TrimRight(l, "\r\n")) {
			if header >= 0 {
				return lines, reg, false
			}
			header = i
		}
	}
	if header < 0 {
		return lines, reg, false
	}
	reg = vtRegion{start: header, end: vtCodeTableEnd(lines, header)}
	if header > 0 {
		if m := strings.TrimRight(lines[header-1], "\r\n"); strings.HasPrefix(m, vtStatusLineMarkerPrefix) {
			reg.ours = true
			reg.noEOL = strings.HasSuffix(m, vtStatusLineNoEOL)
			reg.start = header - 1
			if reg.start > 0 && strings.TrimSpace(lines[reg.start-1]) == "" {
				reg.start--
			}
		}
	}
	return lines, reg, true
}

// vtCut removes the [ui.status_line] table from orig (verified against the
// decoded document by the caller).
func vtCut(orig []byte, present bool) (string, error) {
	if !present {
		return string(orig), nil
	}
	lines, reg, ok := vtStatusLineRegion(orig)
	if !ok {
		return "", errVTStatusLineShape
	}
	atEnd := reg.end == len(lines)
	body := strings.Join(append(append([]string{}, lines[:reg.start]...), lines[reg.end:]...), "")
	if reg.noEOL && atEnd {
		body = strings.TrimSuffix(strings.TrimSuffix(body, "\n"), "\r")
	}
	return body, nil
}

func vtStatusLineSet(orig []byte, command string) ([]byte, error) {
	before, sl, present, err := vtDecode(orig)
	if err != nil {
		return nil, err
	}
	body, err := vtCut(orig, present)
	if err != nil {
		return nil, err
	}
	timeout := vtStatusLineTimeout(sl)
	timeoutTOML, err := vtTOMLValue(timeout)
	if err != nil {
		return nil, err
	}
	nl := credfile.LineEnding(orig)
	noEOL := body != "" && !strings.HasSuffix(body, "\n")
	if noEOL {
		body += nl
	}
	if body != "" {
		body += nl
	}
	var q bytes.Buffer
	enc := json.NewEncoder(&q)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(command); err != nil {
		return nil, errCredentialPatch
	}
	body += vtStatusLineMarker(noEOL) + nl + "[ui.status_line]" + nl +
		`mode = "command"` + nl + "command = " + strings.TrimSpace(q.String()) + nl +
		vtStatusLineTimeoutKey + " = " + timeoutTOML + nl
	if err := vtVerify(body, before, vtStatusLineTable(command, timeout)); err != nil {
		return nil, err
	}
	return []byte(body), nil
}

func vtStatusLineRemove(orig []byte) ([]byte, bool, error) {
	before, _, present, err := vtDecode(orig)
	if err != nil {
		return nil, false, err
	}
	body, err := vtCut(orig, present)
	if err != nil {
		return nil, false, err
	}
	if err := vtVerify(body, before, nil); err != nil {
		return nil, false, err
	}
	return []byte(body), strings.TrimSpace(body) == "", nil
}

// vtVerify checks body decodes to before with ui.status_line set to table
// (removed when nil), empty tables ignored on both sides.
func vtVerify(body string, before map[string]any, table map[string]any) error {
	after := map[string]any{}
	if _, err := toml.Decode(body, &after); err != nil {
		return errCredentialPatch
	}
	expect := map[string]any{}
	for k, v := range before {
		expect[k] = v
	}
	ui := map[string]any{}
	if u, ok := before["ui"].(map[string]any); ok {
		for k, v := range u {
			ui[k] = v
		}
	}
	if table == nil {
		delete(ui, "status_line")
	} else {
		ui["status_line"] = table
	}
	expect["ui"] = ui
	if !tomlJSONEqual(dropEmptyTOML(after), dropEmptyTOML(expect)) {
		return errCredentialPatch
	}
	return nil
}

// dropEmptyTOML returns m without tables that hold nothing (recursively).
func dropEmptyTOML(m map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range m {
		if sub, ok := v.(map[string]any); ok {
			sub = dropEmptyTOML(sub)
			if len(sub) == 0 {
				continue
			}
			v = sub
		}
		out[k] = v
	}
	return out
}

// tomlJSONEqual compares two decoded TOML values by their JSON encoding.
func tomlJSONEqual(a, b any) bool {
	x, err1 := json.Marshal(a)
	y, err2 := json.Marshal(b)
	return err1 == nil && err2 == nil && bytes.Equal(x, y)
}
