package hook

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/marmutapp/superbased-observer/internal/credfile"
	"github.com/marmutapp/superbased-observer/internal/regularfile"
)

// --- Autohand -----------------------------------------------------------

// Autohand keeps its hooks as an ARRAY, hooks.hooks[] of {event, command,
// description, enabled, async, matcher, filter, timeout}, inside the user's
// config.json, a file that also holds provider keys and the auth token. The
// writer touches only the top-level "hooks" member (credential-file splice,
// integration.HookSpec.HooksShareCredentialFile) and, inside it, only the
// entries it owns; it never reads any other member. The entry Observer owns
// is the one whose command runs `observer hook autohand`.
//
// Device sync mirrors the hooks member between a user's devices, and a
// pre-tool hook that fails BLOCKS the call, so a hook written on one OS
// would block every tool on another. The mechanism therefore stays
// `observer init`-only (no auto-register on `observer start`) and has no
// cross-OS bridge target.

// autohandConfigPath is the config.json Autohand reads: the
// autohand/user-config artifact, so $AUTOHAND_CONFIG (the file) wins, then
// $AUTOHAND_HOME (the home, FU-50: the old writer ignored it while the
// adapter honoured it), else ~/.autohand/config.json.
func (r *Registry) autohandConfigPath() (string, error) {
	return r.artifactPath("autohand/user-config")
}

// autohandSiblingConfig names a config.{toml,yaml,yml} beside path: Autohand
// treats two config files as an error, and Observer edits only JSON.
func autohandSiblingConfig(path string) string {
	if !strings.EqualFold(filepath.Ext(path), ".json") {
		return path
	}
	base := strings.TrimSuffix(path, filepath.Ext(path))
	for _, ext := range []string{".toml", ".yaml", ".yml"} {
		if _, err := os.Stat(base + ext); err == nil { //nolint:gosec // G703: stat of a sibling of Autohand's own config path, read only
			return base + ext
		}
	}
	return ""
}

// autohandHooks is the "hooks" member: the global switch, the entries, and
// every other key kept as raw bytes.
type autohandHooks struct {
	other   map[string]json.RawMessage
	enabled *bool
	entries []json.RawMessage
}

// decodeAutohandHooks reads the "hooks" member (absent: empty).
func decodeAutohandHooks(raw json.RawMessage) (autohandHooks, error) {
	h := autohandHooks{other: map[string]json.RawMessage{}}
	if len(bytes.TrimSpace(raw)) == 0 {
		return h, nil
	}
	if err := json.Unmarshal(raw, &h.other); err != nil || h.other == nil {
		return h, safeErrorf("hook.registerAutohand: the hooks member of config.json is not an object; Observer edits only an object of the form {enabled, hooks: [...]}")
	}
	if e, ok := h.other["enabled"]; ok {
		var b bool
		if json.Unmarshal(e, &b) == nil {
			h.enabled = &b
		}
		delete(h.other, "enabled")
	}
	if list, ok := h.other["hooks"]; ok {
		if json.Unmarshal(list, &h.entries) != nil {
			return h, safeErrorf("hook.registerAutohand: hooks.hooks in config.json is not an array; Observer edits only an array of hook entries")
		}
		delete(h.other, "hooks")
	}
	return h, nil
}

// encode renders the member back in key order enabled, hooks, then the rest.
func (h autohandHooks) encode() (json.RawMessage, error) {
	var buf bytes.Buffer
	buf.WriteByte('{')
	n := 0
	put := func(k string, v []byte) {
		if n > 0 {
			buf.WriteByte(',')
		}
		kb, _ := json.Marshal(k)
		buf.Write(kb)
		buf.WriteByte(':')
		buf.Write(v)
		n++
	}
	if h.enabled != nil {
		put("enabled", []byte(fmt.Sprint(*h.enabled)))
	}
	entries := h.entries
	if entries == nil {
		entries = []json.RawMessage{}
	}
	list, err := json.Marshal(entries)
	if err != nil {
		return nil, err
	}
	put("hooks", list)
	keys := make([]string, 0, len(h.other))
	for k := range h.other {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		put(k, h.other[k])
	}
	buf.WriteByte('}')
	var out bytes.Buffer
	if err := json.Indent(&out, buf.Bytes(), "  ", "  "); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// autohandEntryEvent returns an entry's event and whether Observer owns it.
func autohandEntryEvent(e json.RawMessage) (event string, ours bool) {
	var v struct {
		Event   string `json:"event"`
		Command string `json:"command"`
	}
	if json.Unmarshal(e, &v) != nil {
		return "", false
	}
	return v.Event, isObserverAnyHookEntry(v.Command, "autohand")
}

// autohandWanted is Observer's entry for event.
func (r *Registry) autohandWanted(event string) (json.RawMessage, error) {
	return json.Marshal(struct {
		Event       string `json:"event"`
		Command     string `json:"command"`
		Description string `json:"description"`
		Enabled     bool   `json:"enabled"`
		Timeout     int    `json:"timeout"`
	}{
		Enabled:     true,
		Event:       event,
		Command:     codexCmdQuoteIfNeeded(r.opts.BinaryPath) + " hook autohand " + event + r.configFlagSuffixWith(codexCmdQuoteIfNeeded),
		Description: "superbased-observer " + event,
		Timeout:     autohandHookTimeoutMs,
	})
}

// readAutohandConfig reads config.json and decodes ONLY its hooks member
// (decision D16, FU-45): the file holds provider API keys, auth.token and
// api.companySecret, so no other member is decoded, kept in memory as a
// value or surfaced. The read is the capped, FIFO-safe regularfile.Read; the
// other members are scanned for their extent only (credfile.ObjectMembers),
// and a duplicate top-level key is refused because a splice could not keep
// both. A missing file is an empty one.
func readAutohandConfig(path string) (raw []byte, h autohandHooks, err error) {
	raw, err = regularfile.Read(path, maxSettingsFileBytes)
	switch {
	case errors.Is(err, os.ErrNotExist):
		raw = nil
	case err != nil:
		return nil, h, safeErrorf("hook.registerAutohand: %s is not a regular settings file within %d bytes Observer can read; nothing was written", path, maxSettingsFileBytes)
	}
	var member json.RawMessage
	if len(bytes.TrimSpace(raw)) > 0 {
		if !credfile.IsObject(raw) {
			return nil, h, safeErrorf("hook.registerAutohand: %s is not a JSON object; Observer edits only the hooks member of an object", path)
		}
		if key, dup := duplicateTopLevelKey(raw); dup {
			return nil, h, safeErrorf("hook.registerAutohand: %s has a duplicate top-level %q key; refusing to modify it (de-duplicate the file by hand first)", path, key)
		}
		members, merr := credfile.ObjectMembers(raw, "hooks")
		if merr != nil {
			return nil, h, credentialSafeError("hook.registerAutohand", path, merr)
		}
		member = members["hooks"]
	}
	h, err = decodeAutohandHooks(member)
	return raw, h, err
}

// registerAutohand writes Observer's entries into hooks.hooks[].
func (r *Registry) registerAutohand() RegistrationResult {
	res := RegistrationResult{Tool: "autohand", DryRun: r.opts.DryRun}
	path, err := r.autohandConfigPath()
	if err != nil {
		res.Error = fmt.Errorf("hook.registerAutohand: %w", err)
		return res
	}
	res.ConfigPath = path
	if sib := autohandSiblingConfig(path); sib != "" {
		res.Skipped, res.SkipKind = true, SkipNotApplicable
		res.SkipReason = "Autohand reads " + filepath.Base(sib) + " here, which Observer does not edit; add the hook entries by hand (docs/guard.md)"
		return res
	}
	unlock, err := r.lockSettings(path)
	if err != nil {
		res.Error = fmt.Errorf("hook.registerAutohand: %w", err)
		return res
	}
	defer unlock()
	pinned := pinWriteTarget(path)
	raw, h, err := readAutohandConfig(pinned.target)
	if err != nil {
		res.Error = err
		return res
	}
	if h.enabled != nil && !*h.enabled {
		res.Skipped, res.SkipKind = true, SkipNotApplicable
		res.SkipReason = "Autohand's config.json sets hooks.enabled: false, so Autohand runs no hook; Observer leaves the switch as you set it and writes nothing"
		return res
	}
	// FU-192: an entry in Observer's shape running another binary is kept.
	if r.refusesForeignBinary(&res, "hook.registerAutohand", path, identityContent, shapedHooksInText(raw, "autohand")) {
		return res
	}
	changed := false
	for _, event := range eventsOr("autohand", "pre-tool", "pre-prompt") {
		if r.skipEvent("autohand", event) {
			continue
		}
		want, err := r.autohandWanted(event)
		if err != nil {
			res.Error = fmt.Errorf("hook.registerAutohand: %w", err)
			return res
		}
		idx := -1
		for i, e := range h.entries {
			if ev, ours := autohandEntryEvent(e); ours && ev == event {
				idx = i
			}
		}
		if idx >= 0 && jsonEqual(h.entries[idx], want) {
			res.AlreadySet = append(res.AlreadySet, event)
			continue
		}
		if idx >= 0 {
			h.entries = append(h.entries[:idx:idx], h.entries[idx+1:]...)
		}
		h.entries = append(h.entries, want)
		res.HooksAdded = append(res.HooksAdded, event)
		changed = true
	}
	if !changed || r.opts.DryRun {
		return res
	}
	if h.enabled == nil {
		// The global switch is written on, as Autohand's own examples do;
		// an explicit false was refused above.
		on := true
		h.enabled = &on
	}
	if err := r.writeAutohandHooks(pinned, path, raw, h); err != nil {
		res.Error = err
	}
	return res
}

// writeAutohandHooks splices the hooks member into config.json (keeping
// every other member's bytes, credfile.SetObjectMember) and records the
// hooks-subtree checksum.
func (r *Registry) writeAutohandHooks(pinned pinnedTarget, path string, raw []byte, h autohandHooks) error {
	var body []byte
	var err error
	if len(h.entries) == 0 && len(h.other) == 0 && (h.enabled == nil || *h.enabled) {
		// Nothing but Observer's own scaffolding is left: the member goes,
		// as it was before Observer wrote it.
		body, err = credfile.SetObjectMember(raw, "hooks", nil, false)
	} else {
		member, eerr := h.encode()
		if eerr != nil {
			return fmt.Errorf("hook.registerAutohand: %w", eerr)
		}
		body, err = credfile.SetObjectMember(raw, "hooks", member, true)
	}
	if err != nil {
		return credentialSafeError("hook.registerAutohand", path, err)
	}
	if len(raw) > 0 && bytes.Equal(body, raw) {
		return nil
	}
	if err := pinned.verifyUnmoved(); err != nil {
		return fmt.Errorf("hook.registerAutohand: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("hook.registerAutohand: mkdir: %w", err)
	}
	if err := atomicWriteFileMode(pinned, body, fileModeOr(pinned.target, 0o600)); err != nil {
		return credentialSafeError("hook.registerAutohand", path, err)
	}
	return r.recordHookChecksum("autohand", path)
}

// unregisterAutohand removes ONLY Observer's entries. The hooks member stays
// (with whatever else it holds), even when its array ends up empty.
func (r *Registry) unregisterAutohand() UnregistrationResult {
	res := UnregistrationResult{Tool: "autohand", DryRun: r.opts.DryRun}
	path, err := r.autohandConfigPath()
	if err != nil {
		res.Error = fmt.Errorf("hook.unregisterAutohand: %w", err)
		return res
	}
	res.ConfigPath = path
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return res
	}
	unlock, err := r.lockSettings(path)
	if err != nil {
		res.Error = fmt.Errorf("hook.unregisterAutohand: %w", err)
		return res
	}
	defer unlock()
	pinned := pinWriteTarget(path)
	raw, h, err := readAutohandConfig(pinned.target)
	if err != nil {
		res.Error = err
		return res
	}
	kept := h.entries[:0:0]
	for _, e := range h.entries {
		if ev, ours := autohandEntryEvent(e); ours {
			res.HooksRemoved = append(res.HooksRemoved, ev)
			continue
		}
		kept = append(kept, e)
	}
	if len(res.HooksRemoved) == 0 || r.opts.DryRun {
		return res
	}
	h.entries = kept
	if err := r.writeAutohandHooks(pinned, path, raw, h); err != nil {
		res.Error = err
		return res
	}
	if err := r.removeChecksum(path); err != nil {
		res.Error = err
	}
	return res
}

// --- VT Code -------------------------------------------------------------

// VT Code reads lifecycle hooks from the user-level vtcode.toml as arrays
// of tables keyed by the snake_case event name:
//
//	[[hooks.lifecycle.pre_tool_use]]
//	hooks = [{ type = "command", command = "...", timeout_seconds = 30 }]
//
// The file is the user's VT Code configuration, so the writer edits it line
// by line: it removes the groups it owns, appends its own at the end, and
// refuses any edit whose decoded result differs from the original in
// anything but those groups. Only the user-level file is written: a
// workspace vtcode.toml needs VT Code's interactive approval.

// vtCodeConfigPath is the user-level vtcode.toml, the vtcode/user-config
// artifact: %APPDATA%\vinhnx\vtcode\config on Windows,
// $XDG_CONFIG_HOME/vtcode on Linux and ~/Library/Application
// Support/com.vinhnx.vtcode on macOS (source-grounded, vtcode_paths.rs),
// with an absolute VTCODE_CONFIG directory beating each (FU-50, S-21: the old
// writer hard-coded ~/.config on Linux and skipped macOS). "" when it cannot
// be named (a relative VTCODE_CONFIG).
func (r *Registry) vtCodeConfigPath() string {
	p, err := r.artifactPath("vtcode/user-config")
	if err != nil {
		return ""
	}
	return p
}

// vtCodeEventKey maps a payload event name (PreToolUse) to its config key
// (pre_tool_use).
func vtCodeEventKey(event string) string {
	var b strings.Builder
	for i, c := range event {
		if c >= 'A' && c <= 'Z' {
			if i > 0 {
				b.WriteByte('_')
			}
			c += 'a' - 'A'
		}
		b.WriteRune(c)
	}
	return b.String()
}

var (
	vtCodeGroupHeader = regexp.MustCompile(`^\s*\[\[\s*hooks\s*\.\s*lifecycle\s*\.\s*([A-Za-z0-9_]+)\s*\]\]\s*(#.*)?$`)
	vtCodeAnyHeader   = regexp.MustCompile(`^\s*\[`)
)

// vtCodeGroupIsObservers reports whether a decoded group is Observer's: it
// has hooks and every one runs `observer hook vtcode`.
func vtCodeGroupIsObservers(g map[string]any) bool {
	hooks, ok := tomlHookTables(g["hooks"])
	if !ok || len(hooks) == 0 {
		return false
	}
	for _, h := range hooks {
		cmd, _ := h["command"].(string)
		if !isObserverAnyHookEntry(cmd, "vtcode") {
			return false
		}
	}
	return true
}

// vtCodeGroupBlock renders Observer's group for event. bridgeDistro is the
// WSL distro of a "-windows" bridge target ("" for a native one), whose
// command is the portable bridge form (portableBridgeCommand, AP-119).
func (r *Registry) vtCodeGroupBlock(event, bridgeDistro, nl string) string {
	var cmd string
	if bridgeDistro != "" {
		cmd = portableBridgeCommand(bridgeDistro, r.opts.BinaryPath, "vtcode", event, r.opts.ConfigPath)
	} else {
		cmd = shellQuoteIfNeeded(forwardSlashPath(r.opts.BinaryPath)) + " hook vtcode " + event + r.configFlagSuffixForwardSlash()
	}
	var q bytes.Buffer
	enc := json.NewEncoder(&q)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(cmd)
	return "[[hooks.lifecycle." + vtCodeEventKey(event) + "]]" + nl +
		`hooks = [{ type = "command", command = ` + strings.TrimSpace(q.String()) +
		fmt.Sprintf(", timeout_seconds = %d }]", waveHookTimeoutSeconds) + nl
}

// vtCodeLifecycle returns the decoded groups of every lifecycle event key.
func vtCodeLifecycle(top map[string]any) (map[string][]map[string]any, error) {
	out := map[string][]map[string]any{}
	hooks, _ := top["hooks"].(map[string]any)
	life, _ := hooks["lifecycle"].(map[string]any)
	for k, v := range life {
		if _, isBool := v.(bool); isBool {
			continue
		}
		groups, ok := tomlHookTables(v)
		if !ok {
			return nil, errVTCodeShape
		}
		out[k] = groups
	}
	return out, nil
}

var errVTCodeShape = safeErrorf("hook: vtcode.toml defines lifecycle hooks in a shape other than [[hooks.lifecycle.<event>]] tables; Observer edits only those tables, so add or remove its entries by hand")

// setVTCodeGroups returns orig with every Observer group removed and the
// want blocks appended; changed is false when the owned groups already
// render as want.
func setVTCodeGroups(orig []byte, want []string) (out []byte, changed bool, err error) {
	before := map[string]any{}
	if len(bytes.TrimSpace(orig)) > 0 {
		if _, derr := toml.Decode(string(orig), &before); derr != nil {
			return nil, false, errCredentialPatch
		}
	}
	groups, err := vtCodeLifecycle(before)
	if err != nil {
		return nil, false, err
	}
	text := string(orig)
	nl := "\n"
	if strings.Contains(text, "\r\n") {
		nl = "\r\n"
	}
	lines := strings.SplitAfter(text, "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	// Index each [[hooks.lifecycle.<key>]] header in file order per key; a
	// key whose header count differs from its decoded group count is in a
	// shape the line editor cannot follow (inline arrays, dotted keys).
	seen := map[string]int{}
	type hdr struct {
		line int
		ours bool
	}
	var headers []hdr
	for i, l := range lines {
		m := vtCodeGroupHeader.FindStringSubmatch(strings.TrimRight(l, "\r\n"))
		if m == nil {
			continue
		}
		k := m[1]
		if seen[k] >= len(groups[k]) {
			return nil, false, errVTCodeShape
		}
		headers = append(headers, hdr{line: i, ours: vtCodeGroupIsObservers(groups[k][seen[k]])})
		seen[k]++
	}
	for k, g := range groups {
		if seen[k] != len(g) {
			return nil, false, errVTCodeShape
		}
	}
	var mine strings.Builder
	for _, h := range headers {
		if h.ours {
			mine.WriteString(strings.Join(lines[h.line:vtCodeTableEnd(lines, h.line)], ""))
		}
	}
	wantText := strings.Join(want, "")
	if normalizeNL(mine.String()) == normalizeNL(wantText) {
		return orig, false, nil
	}
	for k := len(headers) - 1; k >= 0; k-- {
		if !headers[k].ours {
			continue
		}
		start, end := headers[k].line, vtCodeTableEnd(lines, headers[k].line)
		lines = append(lines[:start], lines[end:]...)
	}
	for len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == "" {
		lines = lines[:len(lines)-1]
	}
	body := strings.Join(lines, "")
	if body != "" && !strings.HasSuffix(body, "\n") {
		body += nl
	}
	if wantText != "" {
		if body != "" {
			body += nl
		}
		body += strings.ReplaceAll(normalizeNL(wantText), "\n", nl)
	}
	if err := verifyVTCodeEdit(body, before, groups, wantText); err != nil {
		return nil, false, err
	}
	return []byte(body), true, nil
}

// vtCodeTableEnd is the line index one past the table that starts at start
// (the next table header, trailing blank/comment lines left to what follows).
func vtCodeTableEnd(lines []string, start int) int {
	end := len(lines)
	for i := start + 1; i < len(lines); i++ {
		if vtCodeAnyHeader.MatchString(lines[i]) {
			end = i
			break
		}
	}
	for end > start+1 && tomlBlankOrComment.MatchString(strings.TrimRight(lines[end-1], "\r\n")) {
		end--
	}
	return end
}

func normalizeNL(s string) string { return strings.ReplaceAll(s, "\r\n", "\n") }

// verifyVTCodeEdit checks body decodes to before with each lifecycle key's
// groups replaced by its foreign groups followed by Observer's.
func verifyVTCodeEdit(body string, before map[string]any, groups map[string][]map[string]any, wantText string) error {
	after := map[string]any{}
	if _, err := toml.Decode(body, &after); err != nil {
		return errCredentialPatch
	}
	wantTop := map[string]any{}
	if _, err := toml.Decode(wantText, &wantTop); err != nil {
		return errCredentialPatch
	}
	wantGroups, err := vtCodeLifecycle(wantTop)
	if err != nil {
		return errCredentialPatch
	}
	expect := map[string]any{}
	for k, v := range before {
		expect[k] = v
	}
	expHooks := map[string]any{}
	if h, ok := before["hooks"].(map[string]any); ok {
		for k, v := range h {
			expHooks[k] = v
		}
	}
	expLife := map[string]any{}
	if l, ok := expHooks["lifecycle"].(map[string]any); ok {
		for k, v := range l {
			expLife[k] = v
		}
	}
	keys := map[string]bool{}
	for k := range groups {
		keys[k] = true
	}
	for k := range wantGroups {
		keys[k] = true
	}
	for k := range keys {
		var list []map[string]any
		for _, g := range groups[k] {
			if !vtCodeGroupIsObservers(g) {
				list = append(list, g)
			}
		}
		list = append(list, wantGroups[k]...)
		if len(list) == 0 {
			delete(expLife, k)
		} else {
			expLife[k] = list
		}
	}
	if len(expLife) > 0 {
		expHooks["lifecycle"] = expLife
	} else {
		delete(expHooks, "lifecycle")
	}
	if len(expHooks) > 0 {
		expect["hooks"] = expHooks
	} else {
		delete(expect, "hooks")
	}
	a, err1 := json.Marshal(after)
	e, err2 := json.Marshal(expect)
	if err1 != nil || err2 != nil || !bytes.Equal(a, e) {
		return errCredentialPatch
	}
	return nil
}

// registerVTCodeAt writes Observer's groups into the vtcode.toml at path.
// bridgeDistro is the WSL distro of a "-windows" bridge target, "" for a
// native one.
func (r *Registry) registerVTCodeAt(label, path, bridgeDistro string) RegistrationResult {
	res := RegistrationResult{Tool: label, DryRun: r.opts.DryRun, ConfigPath: path}
	if bridgeDistro != "" {
		if err := portableBridgePathError("hook.registerVTCode", r.opts.BinaryPath, r.opts.ConfigPath); err != nil {
			res.Error = err
			return res
		}
	}
	unlock, err := r.lockSettings(path)
	if err != nil {
		res.Error = fmt.Errorf("hook.registerVTCode: %w", err)
		return res
	}
	defer unlock()
	pinned := pinWriteTarget(path)
	orig, err := readSettingsFile(pinned.target)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		res.Error = fmt.Errorf("hook.registerVTCode: read: %w", err)
		return res
	}
	// FU-192: an entry in Observer's shape running another binary is kept.
	if r.refusesForeignBinary(&res, "hook.registerVTCode", path, identityContent, shapedHooksInText(orig, "vtcode")) {
		return res
	}
	nl := "\n"
	if bytes.Contains(orig, []byte("\r\n")) {
		nl = "\r\n"
	}
	var blocks, events []string
	for _, event := range eventsOr("vtcode", "PreToolUse", "UserPromptSubmit") {
		if r.skipEvent("vtcode", event) {
			continue
		}
		blocks = append(blocks, r.vtCodeGroupBlock(event, bridgeDistro, nl))
		events = append(events, event)
	}
	body, changed, err := setVTCodeGroups(orig, blocks)
	if err != nil {
		res.Error = fmt.Errorf("hook.registerVTCode: %w", err)
		return res
	}
	if !changed {
		res.AlreadySet = append(res.AlreadySet, events...)
		return res
	}
	res.HooksAdded = append(res.HooksAdded, events...)
	if r.opts.DryRun {
		return res
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		res.Error = fmt.Errorf("hook.registerVTCode: %w", err)
		return res
	}
	if err := pinned.verifyUnmoved(); err != nil {
		res.Error = fmt.Errorf("hook.registerVTCode: %w", err)
		return res
	}
	if err := atomicWriteFileMode(pinned, body, fileModeOr(pinned.target, 0o644)); err != nil {
		res.Error = fmt.Errorf("hook.registerVTCode: write: %w", err)
		return res
	}
	if err := r.recordHookChecksum("vtcode", path); err != nil {
		res.Error = err
	}
	return res
}

// unregisterVTCodeAt removes ONLY Observer's groups from the vtcode.toml at
// path; a file left holding nothing is removed.
func (r *Registry) unregisterVTCodeAt(label, path string) UnregistrationResult {
	res := UnregistrationResult{Tool: label, DryRun: r.opts.DryRun, ConfigPath: path}
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return res
	}
	unlock, err := r.lockSettings(path)
	if err != nil {
		res.Error = fmt.Errorf("hook.unregisterVTCode: %w", err)
		return res
	}
	defer unlock()
	pinned := pinWriteTarget(path)
	orig, err := readSettingsFile(pinned.target)
	if err != nil {
		res.Error = fmt.Errorf("hook.unregisterVTCode: read: %w", err)
		return res
	}
	before := map[string]any{}
	if _, derr := toml.Decode(string(orig), &before); derr != nil {
		res.Error = fmt.Errorf("hook.unregisterVTCode: %w", errCredentialPatch)
		return res
	}
	groups, err := vtCodeLifecycle(before)
	if err != nil {
		res.Error = fmt.Errorf("hook.unregisterVTCode: %w", err)
		return res
	}
	for k, gs := range groups {
		for _, g := range gs {
			if vtCodeGroupIsObservers(g) {
				res.HooksRemoved = append(res.HooksRemoved, vtCodePayloadEvent(k))
			}
		}
	}
	if len(res.HooksRemoved) == 0 {
		return res
	}
	sort.Strings(res.HooksRemoved)
	if r.opts.DryRun {
		return res
	}
	body, _, err := setVTCodeGroups(orig, nil)
	if err != nil {
		res.Error = fmt.Errorf("hook.unregisterVTCode: %w", err)
		return res
	}
	if strings.TrimSpace(string(body)) == "" {
		err = removeEmptyConfigFile(pinned.target, orig)
	} else if err = pinned.verifyUnmoved(); err == nil {
		err = atomicWriteFileMode(pinned, body, fileModeOr(pinned.target, 0o644))
	}
	if err != nil {
		res.Error = fmt.Errorf("hook.unregisterVTCode: %w", err)
		return res
	}
	if err := r.removeChecksum(path); err != nil {
		res.Error = err
	}
	return res
}

// vtCodePayloadEvent maps a config key (pre_tool_use) back to the payload
// spelling (PreToolUse).
func vtCodePayloadEvent(key string) string {
	var b strings.Builder
	for _, part := range strings.Split(key, "_") {
		if part == "" {
			continue
		}
		b.WriteString(strings.ToUpper(part[:1]) + part[1:])
	}
	return b.String()
}

func (r *Registry) registerVTCode() RegistrationResult {
	path := r.vtCodeConfigPath()
	if path == "" {
		return RegistrationResult{
			Tool: "vtcode", DryRun: r.opts.DryRun, Skipped: true, SkipKind: SkipNotApplicable,
			SkipReason: "VT Code's user config file cannot be named (VTCODE_CONFIG is a relative path); set an absolute path, or add the [[hooks.lifecycle.pre_tool_use]] group by hand (docs/guard.md)",
		}
	}
	return r.registerVTCodeAt("vtcode", path, "")
}

func (r *Registry) unregisterVTCode() UnregistrationResult {
	path := r.vtCodeConfigPath()
	if path == "" {
		return UnregistrationResult{Tool: "vtcode", DryRun: r.opts.DryRun, Skipped: true}
	}
	return r.unregisterVTCodeAt("vtcode", path)
}
