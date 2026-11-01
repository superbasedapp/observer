package policy

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
)

// R-162 (T-910, D-761): an agent turning a coding agent's hooks off.
//
// One setting such as `"disableAllHooks": true` in a project's
// .claude/settings.local.json switches off every hook the host runs,
// Observer's guard hooks included, and nothing Observer wrote changes.
// R-160 cannot cover that file by path: the host itself writes it on every
// permission grant, so a path rule would flag or refuse ordinary work. R-162
// judges the CONTENT instead. A write or edit to a hook-bearing settings
// file is refused only when it turns a hook switch on (the value after the
// write switches hooks off and the value before did not), so a permission
// grant, or any other edit of the same file, passes.
//
// The table of switches is injected (Config.HookSwitches, owned by
// internal/hookdisable). Detection of a switch already set is that
// package's job; this rule is the prevention half at the agent boundary.
// R-163 is its record-only sibling for a shell write whose new content the
// guard cannot see.

// HookSwitch is one vendor setting that turns a coding agent's hooks off,
// as the R-162 rows judge it.
type HookSwitch struct {
	// Glob is a settings file the switch lives in, in this package's path
	// glob dialect ("~/.claude/settings.json", "**/.claude/settings.local.json").
	Glob string
	// Key is the dotted JSON key path ("disableAllHooks", "hooksConfig.enabled").
	Key string
	// Off is the value of Key that switches the hooks off.
	Off bool
	// Desc names the switch in a verdict reason.
	Desc string
}

// maxSwitchDoc bounds the text one switch judgement parses or scans.
const maxSwitchDoc = 1 << 20

// hookSwitchesAt returns every injected switch whose file is path.
func hookSwitchesAt(ctx *MatchContext, path string) []HookSwitch {
	if path == "" || len(ctx.Cfg.HookSwitches) == 0 {
		return nil
	}
	var out []HookSwitch
	for _, sw := range ctx.Cfg.HookSwitches {
		if _, ok := pathPatternMatch(path, ctx.Cfg.Home, []pathPattern{{glob: sw.Glob, desc: sw.Desc}}); ok {
			out = append(out, sw)
		}
	}
	return out
}

// matchHookSwitchWrite is the R-162 file-access row: a write or edit of a
// hook-bearing settings file whose proposed content turns a switch on.
func matchHookSwitchWrite(ctx *MatchContext) (bool, string) {
	ev := ctx.Event
	if !isWriteEvent(ev) || len(ev.Edits) == 0 {
		return false, ""
	}
	sws := hookSwitchesAt(ctx, ctx.Path)
	if len(sws) == 0 {
		return false, ""
	}
	var current []byte
	have := false
	if ctx.Cfg.ReadFile != nil {
		current, have = ctx.Cfg.ReadFile(ctx.Path)
	}
	for _, sw := range sws {
		if editsTurnOn(ev.Edits, current, have, sw) {
			return true, switchDetail(sw) + " (" + ev.Target + ")"
		}
	}
	return false, ""
}

// switchDetail is the verdict detail naming the switch and its value.
func switchDetail(sw HookSwitch) string {
	return sw.Desc + ": " + sw.Key + " set to " + strconv.FormatBool(sw.Off)
}

// editsTurnOn reports whether applying edits turns sw on. When the edits
// can be replayed onto the file (a whole-file write, or replacements whose
// old text the current file holds), the file before and after is judged.
// Otherwise each edit's own text is judged: its new text sets the switch
// and its old text did not.
func editsTurnOn(edits []ProposedEdit, current []byte, have bool, sw HookSwitch) bool {
	if after, ok := replayEdits(edits, string(current), have); ok {
		before := have && docSetsSwitch(string(current), sw)
		return docSetsSwitch(after, sw) && !before
	}
	for _, e := range edits {
		if textSetsSwitch(e.New, sw) && !textSetsSwitch(e.Old, sw) {
			return true
		}
	}
	return false
}

// replayEdits applies edits to current, the way the host tool does. ok is
// false when an edit cannot be replayed (a fragment, or old text the
// current file does not hold).
func replayEdits(edits []ProposedEdit, current string, have bool) (string, bool) {
	content := current
	known := have
	for _, e := range edits {
		switch e.Kind {
		case EditWhole:
			content, known = e.New, true
		case EditReplace:
			if !known || e.Old == "" || !strings.Contains(content, e.Old) {
				return "", false
			}
			if e.All {
				content = strings.ReplaceAll(content, e.Old, e.New)
			} else {
				content = strings.Replace(content, e.Old, e.New, 1)
			}
		default:
			return "", false
		}
	}
	return content, known
}

// docSetsSwitch judges a whole settings document: decoded as JSON (with
// comments and trailing commas tolerated) the key holds the off value. A
// document that does not decode is judged by its text.
func docSetsSwitch(doc string, sw HookSwitch) bool {
	if len(doc) > maxSwitchDoc {
		doc = doc[:maxSwitchDoc]
	}
	b := []byte(strings.TrimPrefix(doc, "\ufeff"))
	var m map[string]any
	if json.Unmarshal(b, &m) != nil {
		m = nil
		if json.Unmarshal(stripJSONC(b), &m) != nil {
			return textSetsSwitch(doc, sw)
		}
	}
	v, ok := jsonBoolAt(m, sw.Key)
	return ok && v == sw.Off
}

// jsonBoolAt resolves a dotted key to a JSON boolean.
func jsonBoolAt(doc map[string]any, key string) (bool, bool) {
	cur := any(doc)
	for _, seg := range strings.Split(key, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return false, false
		}
		if cur, ok = m[seg]; !ok {
			return false, false
		}
	}
	v, ok := cur.(bool)
	return v, ok
}

// switchQuote is the run of quoting a key or value can carry in JSON, in a
// jq or PowerShell path, in a Python subscript, or escaped inside a shell
// string: quotes, backslashes, backticks and brackets.
const switchQuote = "[\\\\\"'`\\[\\]]*"

// switchPattern builds the text pattern for a switch key followed by a
// boolean literal. Segments of a dotted key may be joined as a JSON nesting
// (`"hooksConfig": { ... "enabled"`), a path (`.hooksConfig.enabled`) or a
// subscript (`['hooksConfig']['enabled']`). The literal is captured, so the
// caller compares it against the off value ("true", "True", "$true").
func switchPattern(key string) *regexp.Regexp {
	segs := strings.Split(key, ".")
	sep := `(?:` + switchQuote + `\s*(?:\.|\]\s*\[|:\s*\{[^{}]*?)\s*` + switchQuote + `)`
	var b strings.Builder
	b.WriteString(`(?:^|[^A-Za-z0-9_$])` + switchQuote)
	for i, s := range segs {
		if i > 0 {
			b.WriteString(sep)
		}
		b.WriteString(regexp.QuoteMeta(s))
	}
	b.WriteString(switchQuote + `\s*(?::|\|?=)\s*\$?((?i:true|false))\b`)
	return regexp.MustCompile(b.String())
}

// keyPattern builds the text pattern for a switch key alone (any value).
func keyPattern(key string) *regexp.Regexp {
	segs := strings.Split(key, ".")
	for i, s := range segs {
		segs[i] = regexp.QuoteMeta(s)
	}
	return regexp.MustCompile(`(?:^|[^A-Za-z0-9_$])` + strings.Join(segs, `[^A-Za-z0-9_$]+`) + `(?:[^A-Za-z0-9_$]|$)`)
}

// textSetsSwitch reports whether text names the switch key with its off
// value anywhere. It is the judgement for a fragment and for a shell
// command line, where the content is not a whole document. Comments are
// deliberately NOT removed here: a fragment can start inside a string, so
// what looks like a comment may be data in the real file, and removing it
// could hide a switch. A commented-out switch therefore also matches (the
// safe direction).
func textSetsSwitch(text string, sw HookSwitch) bool {
	if text == "" || !strings.Contains(text, lastSegment(sw.Key)) {
		return false
	}
	if len(text) > maxSwitchDoc {
		text = text[:maxSwitchDoc]
	}
	want := strconv.FormatBool(sw.Off)
	for _, m := range switchPattern(sw.Key).FindAllStringSubmatch(text, -1) {
		if strings.EqualFold(m[1], want) {
			return true
		}
	}
	return false
}

// textNamesSwitch reports whether text names the switch key at all.
func textNamesSwitch(text string, sw HookSwitch) bool {
	return strings.Contains(text, lastSegment(sw.Key)) && keyPattern(sw.Key).MatchString(text)
}

func lastSegment(key string) string {
	if i := strings.LastIndexByte(key, '.'); i >= 0 {
		return key[i+1:]
	}
	return key
}

// stripJSONC removes // and /* */ comments and trailing commas outside
// double-quoted strings, for decoding a WHOLE settings document (where the
// string tracking is reliable). Never used on fragments or command lines.
func stripJSONC(b []byte) []byte {
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

// shellLine is the whole command line a shell event carries: the content a
// unit writes may come from an earlier unit (`jq ... > t && mv t file`).
func shellLine(ev *Event) string {
	if len(ev.Args) > 0 {
		return ev.Target + " " + strings.Join(ev.Args, " ")
	}
	return ev.Target
}

// switchWrite is one hook-bearing settings file a command unit writes.
type switchWrite struct {
	sw    HookSwitch
	token string
	moved bool
	// inline is true when the file is named inside interpreter program
	// text, where the direction (read or write) cannot be told.
	inline bool
}

// hookSwitchWrites lists the hook switches whose file the unit writes: a
// positional or redirect operand classified as a write (classifyWrite),
// or, with inline set, a file named in interpreter program text.
func hookSwitchWrites(ctx *MatchContext, cmd *Command, withInline bool) []switchWrite {
	if len(ctx.Cfg.HookSwitches) == 0 {
		return nil
	}
	var out []switchWrite
	anchors := unitAnchors(ctx, cmd)
	for _, t := range sensitivePathTokens(cmd) {
		if !classifyWrite(cmd, t.text) {
			continue
		}
		for _, c := range unitPathCandidates(ctx, anchors, t.text) {
			for _, sw := range hookSwitchesAt(ctx, c.path) {
				out = append(out, switchWrite{sw: sw, token: t.text, moved: c.moved})
			}
		}
	}
	if !withInline {
		return out
	}
	for _, op := range inlineOperands(ctx, cmd) {
		for _, c := range unitPathCandidates(ctx, anchors, op.text) {
			for _, sw := range hookSwitchesAt(ctx, c.path) {
				out = append(out, switchWrite{sw: sw, token: op.text + ", named in a " + op.kind + " inline script", moved: c.moved, inline: true})
			}
		}
	}
	return out
}

// matchHookSwitchShell is the R-162 shell row: a unit writes a hook-bearing
// settings file (or interpreter program text names one) and the command
// line sets that file's switch to its off value (`jq '.disableAllHooks =
// true'`, `sed -i 's/.../"disableAllHooks": true/'`, an echo or a Python
// assignment). The value can still be computed out of sight; the opaque
// row below records such a write.
func matchHookSwitchShell(ctx *MatchContext, cmd *Command) (bool, string) {
	ws := hookSwitchWrites(ctx, cmd, true)
	if len(ws) == 0 {
		return false, ""
	}
	line := shellLine(ctx.Event)
	for _, w := range ws {
		if textSetsSwitch(line, w.sw) {
			return true, movedReason(switchDetail(w.sw)+" ("+w.token+")", w.moved)
		}
	}
	return false, ""
}

// matchHookSwitchShellUnseen is the R-163 record-only row: a unit writes a
// hook-bearing settings file and the command line does not name that
// file's switch at all, so the guard cannot see whether the new content
// turns hooks off (`cp /tmp/x .claude/settings.local.json`, `jq ... > t
// && mv t ...`). The daemon's hook-disable watch reports the file if a
// switch did turn on.
func matchHookSwitchShellUnseen(ctx *MatchContext, cmd *Command) (bool, string) {
	ws := hookSwitchWrites(ctx, cmd, false)
	if len(ws) == 0 {
		return false, ""
	}
	line := shellLine(ctx.Event)
	for _, w := range ws {
		if !textNamesSwitch(line, w.sw) {
			return true, movedReason(w.sw.Desc+" file written with content the guard cannot see ("+w.token+")", w.moved)
		}
	}
	return false, ""
}

// hookSwitchRules returns the R-162 and R-163 rows (appended to the
// boundary table).
func hookSwitchRules() []Rule {
	faCfg := []EventKind{KindFileAccess, KindConfigChange}
	shell := []EventKind{KindShellExec}
	const advice = "Hook switches are operator-owned: with one on, Observer's guard hooks stop running. Ask the operator to change it; permission grants and other settings edits are not affected."
	return []Rule{
		{
			ID: "R-162", Category: CategoryBoundary, Severity: SeverityCritical,
			AppliesTo: faCfg, Match: matchHookSwitchWrite,
			Observe: DecisionFlag, Enforce: DecisionDeny,
			Doc:    "agent write or edit that turns a coding agent's hooks off (disableAllHooks and its siblings) in a hook-bearing settings file",
			Advice: advice,
		},
		{
			ID: "R-162", Category: CategoryBoundary, Severity: SeverityCritical,
			AppliesTo: shell, MatchCmd: matchHookSwitchShell,
			Observe: DecisionFlag, Enforce: DecisionDeny,
			Doc:    "shell command or inline script that turns a coding agent's hooks off in a hook-bearing settings file",
			Advice: advice,
		},
		{
			// Its own ID: one ID's rows share a severity, and a write
			// whose content is unseen is graded below one that visibly
			// turns hooks off.
			ID: "R-163", Category: CategoryBoundary, Severity: SeverityHigh,
			AppliesTo: shell, MatchCmd: matchHookSwitchShellUnseen,
			Observe: DecisionFlag, Enforce: DecisionFlag,
			Doc:    "shell command writing a hook-bearing settings file with content the guard cannot see (recorded; the hook-disable watch reports a switch that turns on)",
			Advice: "Edit settings files with the file tools so the guard can see the change.",
		},
	}
}
