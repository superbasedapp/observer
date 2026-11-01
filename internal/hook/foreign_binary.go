package hook

import (
	"errors"
	"regexp"
	"sort"
	"strings"
)

// foreign_binary.go - FU-192 (arc lead ruling AW-117): one rule for every
// hook writer and every caller (`observer start` auto-registration,
// `observer init`, the dashboard wiring).
//
// An existing entry with Observer's `<bin> hook <tool> <event>` command
// shape whose binary hook_equivalence does not judge an Observer binary
// (observerBinaryJudged) is not Observer's entry. Without --force the writer
// keeps it byte for byte and reports the registration as refused with
// foreignBinaryReason; the file is not written. It is rewritten only when
// its binary IS judged an Observer binary (a moved or renamed Observer, the
// stale-path repair the equivalence table exists for). --force keeps its
// meaning: each writer proceeds as it did before this rule.
//
// Before the rule the Claude Code, Cursor and Codex writers recognised their
// own entries by a ` hook <tool> ` substring and replaced the entry, and
// several writers that keep foreign hooks beside their own appended
// Observer's entry next to it, while the gemini-cli, poolside, devin,
// copilot-cli and ibm-bob writers refused (MAC-6, 2026-10-30: the stand-in
// `lc-hook.sh hook claude-code <event>` entries were rewritten by
// `observer start`).

// foreignBinaryRule / foreignBinaryReason name the rule.
const (
	foreignBinaryRule   = "binary-not-observer"
	foreignBinaryReason = "the entry runs a binary that is not an observer binary"
)

// ForeignBinaryReason is foreignBinaryReason for a caller that reports an
// UnregistrationResult's HooksKeptForeign (`observer uninstall`).
const ForeignBinaryReason = foreignBinaryReason

// observerBinaryJudged reports whether hook_equivalence judges have, the
// binary an existing entry runs, an Observer binary: its base name names one
// (isObserverBinaryToken), or it is the base name of want, the binary this
// registry writes.
func observerBinaryJudged(have, want string) bool {
	if have == "" {
		return false
	}
	if isObserverBinaryToken(have) {
		return true
	}
	return strings.EqualFold(commandBaseName(have), commandBaseName(want))
}

// foreignBinaryError is the refusal of an entry in Observer's command shape
// that runs another binary. A plugin shim has no event of its own, so its
// refusal names the file. It is a foreignBinaryRefusal around the safe
// message, so a caller can tell this refusal from any other
// (isForeignBinaryRefusal, FU-208).
func foreignBinaryError(prefix, event, path string) error {
	if event == "" {
		return &foreignBinaryRefusal{safeErrorf("%s: %s already has a non-observer hook (%s); pass --force to overwrite", prefix, path, foreignBinaryReason)}
	}
	return &foreignBinaryRefusal{safeErrorf("%s: event %s already has a non-observer hook (%s); pass --force to overwrite", prefix, event, foreignBinaryReason)}
}

// foreignBinaryRefusal marks a foreignBinaryError. It unwraps to the
// safeMsgError, so the credential-safe error rules still recognise it.
type foreignBinaryRefusal struct{ err error }

func (e *foreignBinaryRefusal) Error() string { return e.err.Error() }
func (e *foreignBinaryRefusal) Unwrap() error { return e.err }

// isForeignBinaryRefusal reports whether err is (or wraps) a FU-192 refusal.
func isForeignBinaryRefusal(err error) bool {
	var f *foreignBinaryRefusal
	return errors.As(err, &f)
}

// shapedHook is one `<bin> hook <tool> <event>` occurrence found in an
// existing artifact.
type shapedHook struct {
	binary string
	event  string
}

// shapedHooksInText finds every `<bin> hook <tool> <event>` occurrence in
// data: a command line in a hook script, a command string in a JSON or TOML
// settings file (escaped or not), a wsl.exe bridge argument list. The binary
// is the token before ` hook `, with surrounding quotes and escape
// backslashes trimmed; only its base name is judged, so a quoted path with a
// space still yields the right base name.
func shapedHooksInText(data []byte, tool string) []shapedHook {
	text := string(data)
	needle := " hook " + tool + " "
	var out []shapedHook
	for from := 0; ; {
		i := strings.Index(text[from:], needle)
		if i < 0 {
			return out
		}
		at := from + i
		from = at + len(needle)
		start := at
		for start > 0 && !isShapeSpace(text[start-1]) {
			start--
		}
		// Trim the closing quote (and its escape), then keep what follows
		// the opening one: in compact JSON the token runs back to `{"k":"`.
		bin := strings.TrimRight(text[start:at], `"'\`+"`")
		if q := strings.LastIndexAny(bin, `"'`+"`"); q >= 0 {
			bin = bin[q+1:]
		}
		if bin == "" {
			continue
		}
		end := from
		for end < len(text) && !isShapeSpace(text[end]) && !strings.ContainsRune(`"'\;,`+"`", rune(text[end])) {
			end++
		}
		out = append(out, shapedHook{binary: bin, event: text[from:end]})
	}
}

func isShapeSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }

// pluginProfileBin matches the `"bin":"<path>"` member of a rendered plugin
// shim's PROFILE (pluginshim.Render): the binary the shim runs as
// `<bin> hook <tool> <event>`, or, for a wsl.exe bridge shim, its
// `"wsl_bin"` (the binary run inside WSL).
var pluginProfileBin = regexp.MustCompile(`"(?:wsl_)?bin":"((?:[^"\\]|\\.)*)"`)

// shapedHooksInPluginProfile is shapedHooksInText for a plugin shim, whose
// command line is assembled at run time from its PROFILE's bin.
func shapedHooksInPluginProfile(data []byte) []shapedHook {
	var out []shapedHook
	for _, m := range pluginProfileBin.FindAllSubmatch(data, -1) {
		if bin := strings.ReplaceAll(string(m[1]), `\\`, `\`); bin != "" {
			out = append(out, shapedHook{binary: bin})
		}
	}
	return out
}

// removableEntry wraps recognise, an uninstall path's own test for its
// entries, with the FU-192 judgement (FU-203): a command in Observer's
// `<bin> hook <tool> <event>` shape whose binary is not judged an Observer
// binary is not Observer's to remove, whatever recognise says, and *foreign
// is set. A moved or renamed Observer (its binary judged Observer's) is
// still recognise's to decide.
func (r *Registry) removableEntry(tool string, recognise func(string) bool, foreign *bool) func(string) bool {
	return func(cmd string) bool {
		if r.keepsForeignBinary(shapedHooksInText([]byte(cmd), tool)) {
			*foreign = true
			return false
		}
		return recognise(cmd)
	}
}

// keepsForeignBinary reports whether an uninstall keeps an artifact holding
// hooks: one runs a binary not judged an Observer binary (FU-203).
func (r *Registry) keepsForeignBinary(hooks []shapedHook) bool {
	_, found := r.foreignShapedHook(hooks)
	return found
}

// noteKeptForeign records event on res as kept for ForeignBinaryReason.
func noteKeptForeign(res *UnregistrationResult, events ...string) {
	for _, e := range events {
		res.HooksKeptForeign = appendNew(res.HooksKeptForeign, e)
	}
	sort.Strings(res.HooksKeptForeign)
}

// foreignShapedHook returns the first of hooks whose binary is not judged an
// Observer binary.
func (r *Registry) foreignShapedHook(hooks []shapedHook) (shapedHook, bool) {
	for _, h := range hooks {
		if !observerBinaryJudged(h.binary, r.opts.BinaryPath) {
			return h, true
		}
	}
	return shapedHook{}, false
}

// refusesForeignBinaryInFile is refusesForeignBinary for a writer that keeps
// no copy of the bytes it decoded: it reads path again under the writer's
// lock. A file it cannot read refuses nothing here (the writer's own read
// reported it).
func (r *Registry) refusesForeignBinaryInFile(res *RegistrationResult, prefix, path, tool string, id artifactIdentity) bool {
	raw, err := readSettingsFile(path)
	if err != nil {
		return false
	}
	return r.refusesForeignBinary(res, prefix, path, id, shapedHooksInText(raw, tool))
}

// refusesForeignBinary is the one FU-192 test a writer makes once it has
// read the artifact at path: hooks are the Observer-shaped entries found in
// it, id how the writer recognises the artifact (ownership.go). It returns
// true, with res.Error set and nothing written, when an entry runs a binary
// not judged an Observer binary and resolveConflict refuses the slot. With
// --force (or a managed repair of an artifact Observer owns by name and has
// installed) it returns false and the writer proceeds as before.
func (r *Registry) refusesForeignBinary(res *RegistrationResult, prefix, path string, id artifactIdentity, hooks []shapedHook) bool {
	h, found := r.foreignShapedHook(hooks)
	if !found || !r.refuses(path, id) {
		return false
	}
	res.Error = foreignBinaryError(prefix, h.event, path)
	return true
}
