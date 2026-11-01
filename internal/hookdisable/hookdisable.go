package hookdisable

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
)

// Scope says whose file a switch lives in.
type Scope string

const (
	// ScopeUser is a file under the developer's home directory.
	ScopeUser Scope = "user"
	// ScopeManaged is an administrator-managed system file (MDM or
	// policy); a developer cannot override it.
	ScopeManaged Scope = "managed"
	// ScopeProject is a file inside a project directory
	// (<project>/.claude/settings.local.json and the like). An agent can
	// write one and a cloned repository can ship one, and the vendor reads
	// it whenever it runs in that project (T-910).
	ScopeProject Scope = "project"
	// ScopeEnv is an environment variable of the process that starts the
	// vendor's tool. Detect reads it from Options.Getenv: the doctor's own
	// environment, which is the developer's shell for `observer doctor` and
	// the daemon's for the daemon's watch, so a variable set only in another
	// shell is not seen.
	ScopeEnv Scope = "env"
)

// EnvPath is the Finding.Path of an environment-variable switch.
const EnvPath = "environment"

// MaxProjectRoots bounds the project directories one Detect scans: at most
// this many roots times the project-scope rows, each one small file read.
const MaxProjectRoots = 64

// Switch is one row of the table: a JSON file, the key path inside it, and
// the value that means "hooks are off".
type Switch struct {
	// ID is a stable identifier, e.g. "claude.disableAllHooks".
	ID string
	// Scope is user, managed, project or env.
	Scope Scope
	// HomeRel is the file path relative to the home directory (user
	// scope); HomeRelOS replaces it on the GOOS it names (Devin's Windows
	// file sits under %APPDATA%). ManagedFile is the internal/agentconfig
	// FileRow id of a managed-scope file: the caller resolves it
	// (Options.ManagedFiles), so the path has one owner. ProjectRel is the
	// file path relative to a project directory (project scope).
	HomeRel     string
	HomeRelOS   map[string]string
	ManagedFile string
	ProjectRel  string
	// File is the internal/agentconfig FileRow id of a user-scope row's
	// file, when the catalogue has one: the caller resolves it with the
	// row's relocation rules (Options.UserFiles), so a relocated home
	// (CODEBUDDY_CONFIG_DIR, SNOWFLAKE_HOME, AUTOHAND_HOME, ...) is read
	// where the vendor reads it (FU-38). HomeRel stays the fallback for a
	// caller with no resolver.
	File string
	// Key is the dotted JSON key path; for an env-scope row it is the
	// variable's name.
	Key string
	// KeyPath, when set, replaces Key's dotted split for a key whose
	// segment holds a dot (Kimchi's resources["hooks.bash"]). Key stays the
	// display form.
	KeyPath []string
	// Format is the file's syntax: "" (JSON, or JSON with comments) or
	// FormatTOML.
	Format string
	// Off is the value of Key that switches the hooks off (a key switch).
	Off bool
	// EnvOff is the value of the variable that switches the hooks off (env
	// scope), compared trimmed and case-insensitively.
	EnvOff string
	// EnvTruthy, for an env-scope row, makes any of the common true
	// spellings (1, true, yes, on) the off value instead of EnvOff.
	EnvTruthy bool
	// Contains, when set, makes the row a list-membership switch: Key names
	// a JSON array and an entry equal to Contains is the off state.
	Contains string
	// DenyList, when set, names the deny-list dialect of the file
	// (denyListDialects): the file lists hook-entry hashes, and the row is
	// set when it holds the hash of one of Observer's own entries in
	// DenyHooksRel (relative to the home directory). The deny list is read
	// for membership only (surface-gap decision D5).
	DenyList     string
	DenyHooksRel string
	// DenyHooksFile is the agentconfig FileRow id of the hooks file
	// DenyHooksRel names, resolved like File (relocation applied).
	DenyHooksFile string
	// ReplayOnly marks a switch that stops a host replaying another tool's
	// hook settings (Devin's read_config_from.claude), not the host's own
	// hooks: Observer's own hooks for that tool keep running, so such a row
	// is reported only when Options.IncludeReplayOnly is set (the doctor),
	// never to a gate that asks whether the tool's hooks are off.
	ReplayOnly bool
	// WriteGuardOnly marks a key the vendor documents as a hook-off switch
	// that a live run showed it does not honour (FU-159: Copilot CLI
	// 1.0.105's disableAllHooks). The guard still refuses an agent write
	// that sets it (R-162 / R-163, a precaution that costs nothing should a
	// later version honour it), but no reader claims the effect: Detect
	// never reports the row (so neither the doctor, the launch gate nor
	// managed integrity does) and repository trust does not flag it. Tools
	// then names who would go silent if the vendor honoured it.
	WriteGuardOnly bool
	// Tools are the tool ids Observer goes silent on when the switch is set.
	Tools []string
	// Effect is the one-line consequence, for doctor and the guard event.
	Effect string
	// Grounding names where the switch is documented.
	Grounding string
}

// FormatTOML is Switch.Format for a TOML file.
const FormatTOML = "toml"

// KeySwitch reports a plain key switch: a JSON boolean Key equal to Off in
// one file, the shape the guard's R-162 rows project. Env, list-membership
// and deny-list rows are not key switches, and neither is a TOML row or a
// row whose key segment holds a dot (the R-162 rows judge a dotted JSON
// key).
func (s Switch) KeySwitch() bool {
	return s.Scope != ScopeEnv && s.Contains == "" && s.DenyList == "" && s.Format == "" && len(s.KeyPath) == 0
}

// keyPath is the row's key as path segments.
func (s Switch) keyPath() []string {
	if len(s.KeyPath) > 0 {
		return s.KeyPath
	}
	return strings.Split(s.Key, ".")
}

// Finding is one switch found set.
type Finding struct {
	SwitchID string
	Scope    Scope
	// Path is the file that holds the switch (EnvPath for an env-scope
	// row).
	Path   string
	Key    string
	Tools  []string
	Effect string
	// ReplayOnly copies the row's ReplayOnly: the switch stops a replay,
	// not the tool's own hooks.
	ReplayOnly bool
	// ProjectRoot is the project directory a project-scope finding sits
	// in ("" for user, managed and env scope).
	ProjectRoot string
}

// Options are the injected inputs.
type Options struct {
	// Home is the home directory user-scope paths resolve against ("" skips
	// every user-scope row).
	Home string
	// GOOS selects the managed path and a row's HomeRelOS ("" skips every
	// managed-scope row, as a sandboxed doctor run does).
	GOOS string
	// ManagedFiles resolves a managed row's ManagedFile id on goos to the
	// files the vendor reads for it, in merge order: a later file's value
	// replaces an earlier one's (Claude Code's managed-settings.json, then
	// its managed-settings.d drop-ins in name order). Nil skips every
	// managed-scope row.
	ManagedFiles func(fileID, goos string) []string
	// UserFiles resolves a user-scope row's File (an agentconfig FileRow
	// id) to the path the vendor reads, its relocation rules applied
	// (internal/diag.HookSwitchInputs). ok=false, or a nil resolver, falls
	// back to Home plus HomeRel.
	UserFiles func(fileID string) (path string, ok bool)
	// ProjectRoots are the project directories project-scope rows resolve
	// against, most recently active first. Empty entries are skipped and a
	// repeated directory is read once; only the first MaxProjectRoots
	// distinct directories are scanned. Nil skips every project-scope row.
	ProjectRoots []string
	// Getenv reads one environment variable (os.Getenv in production). Nil
	// skips every env-scope row.
	Getenv func(name string) string
	// OwnHookCommand reports whether a hook command is one Observer
	// registers (internal/hook.IsObserverHookCommand in production). Nil
	// skips every deny-list row.
	OwnHookCommand func(command string) bool
	// IncludeReplayOnly reports ReplayOnly rows too.
	IncludeReplayOnly bool
	// ReadFile reads one file (os.ReadFile in production). An error means
	// the file is absent or unreadable, which is never a finding.
	ReadFile func(path string) ([]byte, error)
}

// Detect walks the table and returns every switch currently set, in table
// order (a project-scope row once per project, in ProjectRoots order). An
// absent, unreadable or malformed file is not a finding: unknown is never
// reported as off.
//
// A file is read whole into memory, but only the top-level member a row's
// key names is decoded (memberValue): many of these files also hold
// provider keys, which are never parsed, kept or reported. A deny list is
// decoded for its hash keys only.
func Detect(o Options) []Finding {
	if o.ReadFile == nil {
		return nil
	}
	roots := boundedRoots(o.ProjectRoots)
	r := &fileReader{read: o.ReadFile, raw: map[string][]byte{}, members: map[string]any{}}
	var out []Finding
	for _, s := range Switches {
		if s.ReplayOnly && !o.IncludeReplayOnly {
			continue
		}
		if s.WriteGuardOnly {
			continue // guarded at the agent boundary only; the effect is not claimed
		}
		for _, t := range s.targets(o, roots) {
			path, ok := s.evaluate(o, r, t.files)
			if !ok {
				continue
			}
			out = append(out, Finding{
				SwitchID: s.ID, Scope: s.Scope, Path: path, Key: s.Key,
				Tools: s.Tools, Effect: s.Effect, ReplayOnly: s.ReplayOnly, ProjectRoot: t.root,
			})
		}
	}
	return out
}

// target is the files one row resolves to at one place (one file, or a
// managed file and its drop-ins in merge order), with the project it
// belongs to.
type target struct {
	files []string
	root  string
}

func (s Switch) targets(o Options, roots []string) []target {
	switch s.Scope {
	case ScopeUser:
		if o.Home == "" {
			return nil
		}
		if s.File != "" && o.UserFiles != nil {
			if p, ok := o.UserFiles(s.File); ok && p != "" {
				return []target{{files: []string{p}}}
			}
		}
		rel := s.HomeRel
		if r, ok := s.HomeRelOS[o.GOOS]; ok && o.GOOS != "" {
			rel = r
		}
		if o.Home == "" || rel == "" {
			return nil
		}
		return []target{{files: []string{filepath.Join(o.Home, filepath.FromSlash(rel))}}}
	case ScopeManaged:
		if o.GOOS == "" || o.ManagedFiles == nil || s.ManagedFile == "" {
			return nil
		}
		if files := o.ManagedFiles(s.ManagedFile, o.GOOS); len(files) > 0 {
			return []target{{files: files}}
		}
		return nil
	case ScopeProject:
		if s.ProjectRel == "" {
			return nil
		}
		out := make([]target, 0, len(roots))
		for _, r := range roots {
			out = append(out, target{files: []string{filepath.Join(r, filepath.FromSlash(s.ProjectRel))}, root: r})
		}
		return out
	case ScopeEnv:
		if o.Getenv == nil || s.Key == "" {
			return nil
		}
		return []target{{files: []string{EnvPath}}}
	}
	return nil
}

// evaluate reports whether the row is set at one target and the path that
// sets it.
func (s Switch) evaluate(o Options, r *fileReader, files []string) (string, bool) {
	switch {
	case s.Scope == ScopeEnv:
		v := strings.TrimSpace(o.Getenv(s.Key))
		if s.EnvTruthy {
			return EnvPath, envTruthy(v)
		}
		return EnvPath, v != "" && strings.EqualFold(v, s.EnvOff)
	case s.DenyList != "":
		denied := denyListDialects[s.DenyList]
		if denied == nil || o.OwnHookCommand == nil || o.Home == "" || s.DenyHooksRel == "" {
			return "", false
		}
		deny, ok := r.file(files[0])
		if !ok {
			return "", false
		}
		hooksPath := filepath.Join(o.Home, filepath.FromSlash(s.DenyHooksRel))
		if s.DenyHooksFile != "" && o.UserFiles != nil {
			if p, ok := o.UserFiles(s.DenyHooksFile); ok && p != "" {
				hooksPath = p
			}
		}
		hooks, ok := r.file(hooksPath)
		if !ok {
			return "", false
		}
		return files[0], denied(deny, hooks, o.OwnHookCommand)
	case s.Contains != "":
		for _, f := range files {
			if list, ok := r.lookup(f, s.keyPath(), s.Format).([]any); ok && slices.Contains(list, any(s.Contains)) {
				return f, true
			}
		}
		return "", false
	}
	// A key switch: the last file that sets the key as a boolean decides.
	at, set := "", false
	for _, f := range files {
		if v, ok := r.lookup(f, s.keyPath(), s.Format).(bool); ok {
			at, set = f, v == s.Off
		}
	}
	return at, set
}

// fileReader caches one Detect call's reads: each file once, each top-level
// member once.
type fileReader struct {
	read    func(string) ([]byte, error)
	raw     map[string][]byte
	members map[string]any
}

// file returns a file's bytes (ok=false when absent or unreadable).
func (r *fileReader) file(path string) ([]byte, bool) {
	b, seen := r.raw[path]
	if !seen {
		var err error
		if b, err = r.read(path); err != nil {
			b = nil
		} else if b == nil {
			b = []byte{}
		}
		r.raw[path] = b
	}
	return b, b != nil
}

// lookup resolves a key path in one file (nil when any segment is absent
// or the file is unreadable or malformed).
func (r *fileReader) lookup(path string, segs []string, format string) any {
	if len(segs) == 0 {
		return nil
	}
	ck := path + "\x00" + format + "\x00" + segs[0]
	v, seen := r.members[ck]
	if !seen {
		if b, ok := r.file(path); ok {
			if format == FormatTOML {
				v = tomlMemberValue(b, segs[0])
			} else {
				v = memberValue(b, segs[0])
			}
		}
		r.members[ck] = v
	}
	for _, seg := range segs[1:] {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = m[seg]
	}
	return v
}

// memberValue decodes the one top-level member of a JSON (or JSON with
// comments) object, leaving every other member unparsed. A file that is
// not an object, or is malformed, yields nil. encoding/json matches the
// member name case-insensitively when no exact match exists; the vendors
// read it case-sensitively, so a differently cased key could in principle
// be read here and not by the vendor.
func memberValue(b []byte, member string) any {
	b = bytes.TrimPrefix(b, []byte("\ufeff"))
	t := reflect.StructOf([]reflect.StructField{{
		Name: "M", Type: reflect.TypeOf(json.RawMessage(nil)),
		Tag: reflect.StructTag(`json:"` + member + `"`),
	}})
	holder := reflect.New(t)
	if json.Unmarshal(b, holder.Interface()) != nil {
		// Copilot CLI, Qwen Code and Gemini CLI settings are JSON with
		// comments: a comment must not hide a switch.
		holder = reflect.New(t)
		if json.Unmarshal(sanitizeJSONC(b), holder.Interface()) != nil {
			return nil
		}
	}
	raw, _ := holder.Elem().Field(0).Interface().(json.RawMessage)
	if raw == nil {
		return nil
	}
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return nil
	}
	return v
}

// tomlMemberValue decodes the one top-level table or key of a TOML file,
// leaving every other member undecoded (VT Code's vtcode.toml can hold
// provider key material beside the workspace table). Malformed TOML yields
// nil.
func tomlMemberValue(b []byte, member string) any {
	b = bytes.TrimPrefix(b, []byte("\xef\xbb\xbf"))
	t := reflect.StructOf([]reflect.StructField{{
		Name: "M", Type: reflect.TypeOf(toml.Primitive{}),
		Tag: reflect.StructTag(`toml:"` + member + `"`),
	}})
	holder := reflect.New(t)
	md, err := toml.Decode(string(b), holder.Interface())
	if err != nil || !md.IsDefined(member) {
		return nil
	}
	prim, _ := holder.Elem().Field(0).Interface().(toml.Primitive)
	var v any
	if md.PrimitiveDecode(prim, &v) != nil {
		return nil
	}
	return v
}

// envTruthy reports the common true spellings of an environment flag.
func envTruthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// boundedRoots keeps the first MaxProjectRoots distinct non-empty roots.
func boundedRoots(roots []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range roots {
		if r == "" {
			continue
		}
		c := filepath.Clean(r)
		if seen[c] {
			continue
		}
		seen[c] = true
		out = append(out, c)
		if len(out) == MaxProjectRoots {
			break
		}
	}
	return out
}

// sanitizeJSONC removes // and /* */ comments and trailing commas outside
// strings, so a JSON-with-comments file decodes as JSON.
func sanitizeJSONC(b []byte) []byte {
	out := make([]byte, 0, len(b))
	inStr, esc := false, false
	for i := 0; i < len(b); i++ {
		c := b[i]
		if inStr {
			out = append(out, c)
			switch {
			case esc:
				esc = false
			case c == '\\':
				esc = true
			case c == '"':
				inStr = false
			}
			continue
		}
		switch {
		case c == '"':
			inStr = true
			out = append(out, c)
		case c == '/' && i+1 < len(b) && b[i+1] == '/':
			for i < len(b) && b[i] != '\n' {
				i++
			}
			if i < len(b) {
				out = append(out, '\n')
			}
		case c == '/' && i+1 < len(b) && b[i+1] == '*':
			i += 2
			for i+1 < len(b) && (b[i] != '*' || b[i+1] != '/') {
				i++
			}
			i++
		case c == ']' || c == '}':
			j := len(out) - 1
			for j >= 0 && strings.IndexByte(" \t\r\n", out[j]) >= 0 {
				j--
			}
			if j >= 0 && out[j] == ',' {
				out = append(out[:j], out[j+1:]...)
			}
			out = append(out, c)
		default:
			out = append(out, c)
		}
	}
	return out
}

// AffectedTools is the sorted union of the tools every finding silences.
func AffectedTools(fs []Finding) []string {
	seen := map[string]bool{}
	var out []string
	for _, f := range fs {
		for _, t := range f.Tools {
			if !seen[t] {
				seen[t] = true
				out = append(out, t)
			}
		}
	}
	sort.Strings(out)
	return out
}

// Tracker turns successive Detect results into transitions: a switch is
// reported once when it is first seen set and again only after it was seen
// clear in between. One Tracker per daemon process (the daemon's hook loop
// owns it).
type Tracker struct {
	on map[string]bool
}

// Turned returns the findings that switched on since the previous call.
func (t *Tracker) Turned(fs []Finding) []Finding {
	if t.on == nil {
		t.on = map[string]bool{}
	}
	now := map[string]bool{}
	var out []Finding
	for _, f := range fs {
		k := f.SwitchID + "\x00" + f.Path
		now[k] = true
		if !t.on[k] {
			out = append(out, f)
		}
	}
	t.on = now
	return out
}
