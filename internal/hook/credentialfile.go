package hook

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"gopkg.in/yaml.v3"

	"github.com/marmutapp/superbased-observer/internal/credfile"
	"github.com/marmutapp/superbased-observer/internal/hookdigest"
	"github.com/marmutapp/superbased-observer/internal/integration"
)

// The D-268 credential-file exception. Some vendors keep their hook config
// in a file that also holds plaintext credentials (Claude Code's
// settings.json env block, Codex's config.toml, Qwen Code's settings.json,
// Crush's crush.json, Junie's config.json, Poolside's settings.yaml, ZCode's
// config.json). A registry row declares that with
// integration.HookSpec.HooksShareCredentialFile, and only a flagged row's
// writer may read-modify-write such a file. A flagged writer here:
//
//   - changes only the hooks subtree: every other top-level member keeps its
//     exact bytes (JSON is spliced, not re-rendered; YAML is edited as a node
//     tree; TOML is edited line by line), and the result is re-parsed and
//     compared value for value against the intended document before it is
//     written, or the write is refused;
//   - keeps the file's permission bits and writes atomically (unique temp
//     file plus rename);
//   - refuses a file it cannot parse, and never puts a decoder's message in
//     an error, because decoders quote file contents (credentialSafeError);
//   - records in hook_checksums.json only a digest of the hooks subtree
//     (internal/hookdigest), never a whole-file hash, and converts a
//     whole-file entry an older build left behind;
//   - makes no backup, never logs, and returns nothing read from the file.

// hooksShareCredentialFile reports whether tool (a Registry target, a
// "-windows" bridge included) writes under the exception. It asks the
// registry row: a capability, not a tool-name list.
//
// A host-home target (claude-code-xcode, codex-xcode, gemini-cli-xcode)
// writes its base tool's file shape in another home, so it answers for its
// base tool, as a WSL twin does (lane w8-writers audit item 2); one whose
// file is the host's own (hostOwnedFile: gemini-cli-xcode) is under the
// rules whatever the base row declares.
func hooksShareCredentialFile(tool string) bool {
	if t, ok := xcodeTargetFor(tool); ok {
		return t.hostOwnedFile || integration.HooksShareCredentialFile(t.tool)
	}
	return integration.HooksShareCredentialFile(tool)
}

// ErrCredentialDetailWithheld is wrapped by every error a credential-file
// writer returns in place of a message that could quote the file. It is the
// shared internal/credfile sentinel, so a hook writer and an MCP writer
// (T-384) withhold the same way.
var ErrCredentialDetailWithheld = credfile.ErrDetailWithheld

// safeMsgError is an error whose message Observer composed only from paths,
// event names and key names, never from file contents: a hook conflict, a
// checksum drift refusal, a settings-shape refusal. credentialSafeError
// passes it through.
type safeMsgError struct{ msg string }

func (e *safeMsgError) Error() string { return e.msg }

// safeErrorf builds a safeMsgError. Arguments must be paths, event names,
// key names or sizes: never a value read from a file.
func safeErrorf(format string, args ...any) error {
	return &safeMsgError{msg: fmt.Sprintf(format, args...)}
}

// hookConflictError is the --force conflict refusal every writer shares.
func hookConflictError(prefix, event string) error {
	return safeErrorf("%s: event %s already has a non-observer hook; pass --force to overwrite", prefix, event)
}

// credentialSafeError returns err unchanged when its message cannot carry
// file contents (a safeMsgError, an fs.PathError), and otherwise a fixed
// message naming only the target and the path. Applied to every result of a
// flagged target (Register / Unregister), so the error persisted to
// hook_checksums.json by RecordAutoRegisterResult, shown by the dashboard
// probe and printed by `observer start` is safe too.
func credentialSafeError(label, path string, err error) error {
	if err == nil {
		return nil
	}
	var safe *safeMsgError
	var shared *credfile.SafeError
	var pathErr *fs.PathError
	if errors.As(err, &safe) || errors.As(err, &shared) || errors.As(err, &pathErr) {
		return err
	}
	return fmt.Errorf("hook %s: %s was left unchanged (check that it parses and is writable): %w", label, path, ErrCredentialDetailWithheld)
}

// guardCredentialRegistration applies the credential-file rules to a
// finished registration result: the error is made safe, and a whole-file
// checksum entry an older build recorded for the file is converted to a
// hooks-subtree digest.
func (r *Registry) guardCredentialRegistration(tool string, res RegistrationResult) RegistrationResult {
	if !hooksShareCredentialFile(tool) {
		return res
	}
	res.Error = credentialSafeError(res.Tool, res.ConfigPath, res.Error)
	if res.Error == nil && !r.opts.DryRun && res.ConfigPath != "" {
		_ = r.scrubWholeFileChecksum(res.ConfigPath)
	}
	return res
}

// guardCredentialUnregistration is guardCredentialRegistration's removal
// counterpart (an unregister removes the checksum entry itself).
func (r *Registry) guardCredentialUnregistration(tool string, res UnregistrationResult) UnregistrationResult {
	if !hooksShareCredentialFile(tool) {
		return res
	}
	res.Error = credentialSafeError(res.Tool, res.ConfigPath, res.Error)
	return res
}

// fileModeOr returns the permission bits of path, or def when it does not
// exist.
func fileModeOr(path string, def os.FileMode) os.FileMode {
	fi, err := os.Stat(path)
	if err != nil {
		return def
	}
	return fi.Mode().Perm()
}

// writeHookSettingsJSON is the JSON settings write every Claude-shaped and
// table-driven writer calls. For a flagged tool it splices only the changed
// top-level members into orig (credential rules); otherwise it is
// writeJSONIndented.
//
// Idempotent byte for byte (T-407): when the splice leaves orig unchanged
// (every hook already current, as on every `observer start` after the
// first), nothing is written, so the file's bytes, line endings and mtime
// stay the user's.
func (r *Registry) writeHookSettingsJSON(tool, dir string, pinned pinnedTarget, orig []byte, settings map[string]json.RawMessage) error {
	if !hooksShareCredentialFile(tool) {
		return writeJSONIndented(dir, pinned, settings)
	}
	body, err := spliceTopLevelJSON(orig, settings)
	if err != nil {
		return err
	}
	if len(orig) > 0 && bytes.Equal(body, orig) {
		return nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("hook.write: mkdir: %w", err)
	}
	return atomicWriteFileMode(pinned, body, fileModeOr(pinned.target, 0o600))
}

// errCredentialPatch is returned when a credential-file patch cannot be
// built or does not verify; it never carries file contents.
var errCredentialPatch = credfile.ErrPatch

// spliceTopLevelJSON rewrites orig so its top-level members equal next,
// keeping every unchanged member's bytes (internal/credfile.SpliceObject,
// the seam the MCP registrars share, T-384).
func spliceTopLevelJSON(orig []byte, next map[string]json.RawMessage) ([]byte, error) {
	return credfile.SpliceObject(orig, next)
}

// writeHookSettingsYAML is the settings.yaml write (Poolside). For a
// flagged tool it edits only the top-level "hooks" node of the existing
// document, keeping comments, key order and every other value, verifies
// the result, keeps the mode and makes no backup; otherwise it is
// writeYAMLMap.
func (r *Registry) writeHookSettingsYAML(tool string, pinned pinnedTarget, doc map[string]any) error {
	if !hooksShareCredentialFile(tool) {
		if err := pinned.verifyUnmoved(); err != nil {
			return err
		}
		return writeYAMLMap(pinned.target, doc)
	}
	return writeCredentialYAMLKey(pinned, "hooks", doc)
}

// writeCredentialYAMLKey writes doc to the credential-bearing YAML file at
// pinned by editing only its top-level key node (set from doc[key], or
// removed when doc has no key): comments, key order and every other value
// stay, the result must decode to exactly doc, the mode is kept, the write
// is atomic and no backup is made.
func writeCredentialYAMLKey(pinned pinnedTarget, key string, doc map[string]any) error {
	orig, err := os.ReadFile(pinned.target)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("hook.writeCredentialYAMLKey: read: %w", err)
	}
	body, err := setYAMLTopLevel(orig, key, doc[key], hasKey(doc, key))
	if err != nil {
		return err
	}
	if !yamlDocsEqual(body, doc) {
		return errCredentialPatch
	}
	if err := os.MkdirAll(filepath.Dir(pinned.target), 0o755); err != nil {
		return fmt.Errorf("hook.writeCredentialYAMLKey: mkdir: %w", err)
	}
	return atomicWriteFileMode(pinned, body, fileModeOr(pinned.target, 0o600))
}

func hasKey(m map[string]any, k string) bool {
	_, ok := m[k]
	return ok
}

// setYAMLTopLevel sets (present) or removes (!present) one top-level key of
// the YAML mapping document orig, as a node edit.
func setYAMLTopLevel(orig []byte, key string, value any, present bool) ([]byte, error) {
	var root yaml.Node
	if len(bytes.TrimSpace(orig)) > 0 {
		if yaml.Unmarshal(orig, &root) != nil {
			return nil, errCredentialPatch
		}
	}
	if root.Kind == 0 {
		root = yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{{Kind: yaml.MappingNode, Tag: "!!map"}}}
	}
	if root.Kind != yaml.DocumentNode || len(root.Content) != 1 || root.Content[0].Kind != yaml.MappingNode {
		return nil, errCredentialPatch
	}
	m := root.Content[0]
	idx := -1
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			idx = i
		}
	}
	switch {
	case !present && idx >= 0:
		m.Content = append(m.Content[:idx], m.Content[idx+2:]...)
	case present:
		var v yaml.Node
		if v.Encode(value) != nil {
			return nil, errCredentialPatch
		}
		if idx >= 0 {
			m.Content[idx+1] = &v
		} else {
			m.Content = append(m.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, &v)
		}
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if enc.Encode(&root) != nil || enc.Close() != nil {
		return nil, errCredentialPatch
	}
	return buf.Bytes(), nil
}

// yamlDocsEqual reports whether body decodes to the same generic document
// as want (both normalized through one YAML encode/decode).
func yamlDocsEqual(body []byte, want map[string]any) bool {
	var got map[string]any
	if yaml.Unmarshal(body, &got) != nil {
		return false
	}
	wb, err := yaml.Marshal(want)
	if err != nil {
		return false
	}
	var w map[string]any
	if yaml.Unmarshal(wb, &w) != nil {
		return false
	}
	if got == nil {
		got = map[string]any{}
	}
	if w == nil {
		w = map[string]any{}
	}
	return reflect.DeepEqual(got, w)
}

// tomlTableHeader matches a TOML table or array-of-tables header line.
var tomlTableHeader = regexp.MustCompile(`^\s*\[`)

// tomlFeaturesHeader matches the [features] table header.
var tomlFeaturesHeader = regexp.MustCompile(`^\s*\[\s*features\s*\]\s*(#.*)?$`)

// tomlFeaturesKeyLine matches a key line that defines features by a dotted
// key or an inline table (`features.x = ...`, `features = {...}`).
var tomlFeaturesKeyLine = regexp.MustCompile(`^\s*features\s*[.=]`)

// tomlHooksKey matches a `hooks = ...` key line inside a table.
var tomlHooksKey = regexp.MustCompile(`^(\s*)hooks\s*=`)

// setTOMLFeaturesHooks returns orig with [features] hooks = true, edited
// line by line so every other line keeps its bytes, and verifies that the
// result parses to orig's values plus features.hooks = true. A features
// defined some other way (dotted keys, an inline table) fails that check
// and is refused rather than guessed at.
func setTOMLFeaturesHooks(orig []byte, before map[string]any) ([]byte, error) {
	text := string(orig)
	lines := strings.SplitAfter(text, "\n")
	header := -1
	for i, l := range lines {
		if tomlFeaturesHeader.MatchString(strings.TrimRight(l, "\r\n")) {
			header = i
			break
		}
	}
	var out string
	switch {
	case header >= 0:
		done := false
		for i := header + 1; i < len(lines); i++ {
			l := strings.TrimRight(lines[i], "\r\n")
			if tomlTableHeader.MatchString(l) {
				break
			}
			if m := tomlHooksKey.FindStringSubmatch(l); m != nil {
				lines[i] = m[1] + "hooks = true" + lines[i][len(l):]
				done = true
				break
			}
		}
		if !done {
			nl := "\n"
			if strings.HasSuffix(lines[header], "\r\n") {
				nl = "\r\n"
			}
			if !strings.HasSuffix(lines[header], "\n") {
				lines[header] += nl
			}
			lines = append(lines[:header+1], append([]string{"hooks = true" + nl}, lines[header+1:]...)...)
		}
		out = strings.Join(lines, "")
	default:
		// No [features] header: append one. TOML allows the table after
		// its own sub-tables ([features.x]), but not after features was
		// defined by a dotted key or an inline table (a parser may accept
		// it; Codex's need not), so a key line naming features is refused.
		if _, defined := before["features"]; defined {
			for _, l := range lines {
				if tomlFeaturesKeyLine.MatchString(l) {
					return nil, safeErrorf("hook.ensureCodexHooksFeatureFlag: config.toml defines features without a [features] table Observer can edit; add hooks = true under [features] by hand")
				}
			}
		}
		out = text
		if out != "" && !strings.HasSuffix(out, "\n") {
			out += "\n"
		}
		if out != "" {
			out += "\n"
		}
		out += "[features]\nhooks = true\n"
	}
	refuse := errCredentialPatch
	if _, defined := before["features"]; defined && header < 0 {
		refuse = safeErrorf("hook.ensureCodexHooksFeatureFlag: config.toml defines features without a [features] table Observer can edit; add hooks = true under [features] by hand")
	}
	after := map[string]any{}
	if _, err := toml.Decode(out, &after); err != nil {
		return nil, refuse
	}
	want := map[string]any{}
	for k, v := range before {
		want[k] = v
	}
	features := map[string]any{}
	if f, ok := want["features"].(map[string]any); ok {
		for k, v := range f {
			features[k] = v
		}
	}
	features["hooks"] = true
	want["features"] = features
	if !reflect.DeepEqual(after, want) {
		return nil, refuse
	}
	return []byte(out), nil
}

// tomlHooksArrayHeader matches a [[hooks]] array-of-tables header line.
var tomlHooksArrayHeader = regexp.MustCompile(`^\s*\[\[\s*hooks\s*\]\]\s*(#.*)?$`)

// tomlHooksSubtable matches a header of a table nested under hooks
// ([hooks.x], [[hooks.x]]), a shape the [[hooks]] line editor cannot own.
var tomlHooksSubtable = regexp.MustCompile(`^\s*\[\[?\s*hooks\s*\.`)

// tomlBlankOrComment matches a line holding nothing but whitespace or a
// comment.
var tomlBlankOrComment = regexp.MustCompile(`^\s*(#.*)?$`)

// errTOMLHooksShape refuses a file whose hooks key is not a plain list of
// [[hooks]] tables the line editor can own. It names only the key.
var errTOMLHooksShape = safeErrorf("hook: config.toml defines hooks in a shape other than [[hooks]] tables; Observer edits only [[hooks]] tables, so add or remove its entries by hand")

// tomlHookTables reads a decoded top-level hooks value as a list of tables.
// ok is false for any other shape.
func tomlHookTables(v any) (tables []map[string]any, ok bool) {
	switch t := v.(type) {
	case nil:
		return nil, true
	case []map[string]any:
		return t, true
	case []any:
		for _, e := range t {
			m, isMap := e.(map[string]any)
			if !isMap {
				return nil, false
			}
			tables = append(tables, m)
		}
		return tables, true
	}
	return nil, false
}

// setTOMLHookTables is the credential-file editor for a TOML file whose hooks
// live in a top-level [[hooks]] array of tables (Kimi Code's config.toml,
// T-378). It returns orig with every table ours reports removed and want
// appended as new [[hooks]] tables, edited line by line so every other line
// keeps its bytes (comments, key order, the provider keys). changed is false,
// and orig is returned untouched, when the tables ours reports already equal
// want in order. The result must decode to orig's values with hooks set to
// the other tables (in their order) followed by want, or the edit is refused
// with errCredentialPatch; a hooks key in any other shape is refused with
// errTOMLHooksShape. Neither error carries file contents.
func setTOMLHookTables(orig []byte, ours func(map[string]any) bool, want []map[string]any) (out []byte, changed bool, err error) {
	before := map[string]any{}
	if len(bytes.TrimSpace(orig)) > 0 {
		if _, derr := toml.Decode(string(orig), &before); derr != nil {
			return nil, false, errCredentialPatch
		}
	}
	existing, ok := tomlHookTables(before["hooks"])
	if !ok {
		return nil, false, errTOMLHooksShape
	}
	var theirs, mine []map[string]any
	var mineIdx []int
	for i, t := range existing {
		if ours(t) {
			mine = append(mine, t)
			mineIdx = append(mineIdx, i)
			continue
		}
		theirs = append(theirs, t)
	}
	if len(mine) == len(want) && (len(want) == 0 || reflect.DeepEqual(mine, want)) {
		return orig, false, nil
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
	headers, err := tomlHooksHeaderLines(lines)
	if err != nil {
		return nil, false, err
	}
	if len(headers) != len(existing) {
		return nil, false, errTOMLHooksShape
	}
	lines = removeTOMLTables(lines, headers, mineIdx)
	body, err := appendTOMLHookTables(strings.Join(lines, ""), nl, want)
	if err != nil {
		return nil, false, err
	}
	if err := verifyTOMLHookEdit(body, before, append(append([]map[string]any{}, theirs...), want...)); err != nil {
		return nil, false, err
	}
	return []byte(body), true, nil
}

// tomlHooksHeaderLines returns the indexes of the [[hooks]] header lines,
// refusing a table nested under hooks.
func tomlHooksHeaderLines(lines []string) ([]int, error) {
	var headers []int
	for i, l := range lines {
		bare := strings.TrimRight(l, "\r\n")
		if tomlHooksSubtable.MatchString(bare) {
			return nil, errTOMLHooksShape
		}
		if tomlHooksArrayHeader.MatchString(bare) {
			headers = append(headers, i)
		}
	}
	return headers, nil
}

// removeTOMLTables deletes the [[hooks]] tables whose positions (indexes into
// headers) are drop, last to first so earlier indexes stay valid. A table
// ends at the next table header; trailing blank and comment lines stay, since
// they usually introduce whatever follows. When a table was removed, blank
// lines left at the end of the file go too (the writer puts one blank line
// before the tables it appends).
func removeTOMLTables(lines []string, headers, drop []int) []string {
	for k := len(drop) - 1; k >= 0; k-- {
		start := headers[drop[k]]
		end := len(lines)
		for i := start + 1; i < len(lines); i++ {
			if tomlTableHeader.MatchString(strings.TrimRight(lines[i], "\r\n")) {
				end = i
				break
			}
		}
		for end > start+1 && tomlBlankOrComment.MatchString(strings.TrimRight(lines[end-1], "\r\n")) {
			end--
		}
		lines = append(lines[:start], lines[end:]...)
	}
	for len(drop) > 0 && len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

// appendTOMLHookTables appends want to body as [[hooks]] tables after one
// blank line, in the file's line ending nl.
func appendTOMLHookTables(body, nl string, want []map[string]any) (string, error) {
	if body != "" && !strings.HasSuffix(body, "\n") {
		body += nl
	}
	if len(want) == 0 {
		return body, nil
	}
	var buf bytes.Buffer
	enc := toml.NewEncoder(&buf)
	enc.Indent = ""
	if enc.Encode(map[string]any{"hooks": want}) != nil {
		return "", errCredentialPatch
	}
	block := strings.TrimLeft(buf.String(), "\n")
	if nl != "\n" {
		block = strings.ReplaceAll(block, "\n", nl)
	}
	if body != "" {
		body += nl
	}
	return body + block, nil
}

// verifyTOMLHookEdit checks body decodes to before with its hooks value
// replaced by hooks (removed when hooks is empty).
func verifyTOMLHookEdit(body string, before map[string]any, hooks []map[string]any) error {
	after := map[string]any{}
	if _, err := toml.Decode(body, &after); err != nil {
		return errCredentialPatch
	}
	expect := map[string]any{}
	for k, v := range before {
		expect[k] = v
	}
	if len(hooks) == 0 {
		delete(expect, "hooks")
	} else {
		expect["hooks"] = hooks
	}
	if !reflect.DeepEqual(after, expect) {
		return errCredentialPatch
	}
	return nil
}

// recordHookChecksum records the checksum entry for a hook config file
// written for tool: a hooks-subtree digest for a credential-bearing file,
// the whole-file hash (recordChecksum) otherwise.
func (r *Registry) recordHookChecksum(tool, path string) error {
	if !hooksShareCredentialFile(tool) {
		return r.recordChecksum(tool, path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("hook.recordChecksum: %w", err)
	}
	digest, err := hookdigest.HooksSubtree(path, data)
	if err != nil {
		return fmt.Errorf("hook.recordChecksum: %s: %w", path, err)
	}
	return r.updateChecksumEntry(path, func(entry map[string]any) {
		delete(entry, "sha256")
		entry[hookdigest.KeyScope] = hookdigest.Scope
		entry[hookdigest.KeyDigest] = digest
		entry["registered"] = time.Now().UTC().Format(time.RFC3339)
		entry["binary_path"] = r.opts.BinaryPath
		if tool != "" {
			entry["tool"] = tool
		}
	})
}

// scrubWholeFileChecksum converts a whole-file "sha256" entry for path (left
// by a build before the credential-file rules) into a hooks-subtree digest.
// A missing entry or registry is left alone.
func (r *Registry) scrubWholeFileChecksum(path string) error {
	csPath := r.checksumsPath()
	raw, err := os.ReadFile(csPath)
	if err != nil {
		return nil
	}
	current := map[string]map[string]any{}
	if json.Unmarshal(raw, &current) != nil {
		return nil
	}
	if _, has := current[path]["sha256"]; !has {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	digest, err := hookdigest.HooksSubtree(path, data)
	return r.updateChecksumEntry(path, func(entry map[string]any) {
		delete(entry, "sha256")
		if err == nil {
			entry[hookdigest.KeyScope] = hookdigest.Scope
			entry[hookdigest.KeyDigest] = digest
		}
	})
}

// checksumsPath is the hook_checksums.json location.
func (r *Registry) checksumsPath() string {
	if r.opts.ChecksumsPath != "" {
		return r.opts.ChecksumsPath
	}
	return filepath.Join(r.opts.HomeDir, ".observer", "hook_checksums.json")
}

// updateChecksumEntry applies fn to path's entry in hook_checksums.json
// under the registry's lock, keeping every other entry and key.
func (r *Registry) updateChecksumEntry(path string, fn func(entry map[string]any)) error {
	csPath := r.checksumsPath()
	unlock, err := r.lockSettings(csPath)
	if err != nil {
		return fmt.Errorf("hook.updateChecksumEntry: %w", err)
	}
	defer unlock()
	pinned := pinWriteTarget(csPath)
	current := map[string]map[string]any{}
	if raw, err := os.ReadFile(csPath); err == nil {
		_ = json.Unmarshal(raw, &current)
	}
	entry := current[path]
	if entry == nil {
		entry = map[string]any{}
	}
	fn(entry)
	current[path] = entry
	body, err := json.MarshalIndent(current, "", "  ")
	if err != nil {
		return fmt.Errorf("hook.updateChecksumEntry: marshal: %w", err)
	}
	return atomicWriteFile(pinned, body)
}

// scopedChecksumMatches compares a hooks-subtree entry against data. ok is
// false when the entry is not scoped.
func scopedChecksumMatches(path string, entry map[string]any, data []byte) (match, ok bool) {
	if scope, _ := entry[hookdigest.KeyScope].(string); scope != hookdigest.Scope {
		return false, false
	}
	stored, _ := entry[hookdigest.KeyDigest].(string)
	digest, err := hookdigest.HooksSubtree(path, data)
	return err == nil && stored != "" && stored == digest, true
}
