package secassess

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// Reference checking (validator row V8). The pure side decides what a
// reference earns; the service supplies the lines through a RefChecker that
// opens files safely and keeps a read budget.

// LookupStatus is the answer of a RefChecker.
type LookupStatus int

// The lookup statuses.
const (
	// LookupOK: the file was read.
	LookupOK LookupStatus = iota
	// LookupMissing: there is no such regular file inside the project (a
	// missing path, a directory, a symlink, a device, a path that leaves the
	// project).
	LookupMissing
	// LookupBudget: the checker's read budget is used up; nothing was read.
	LookupBudget
)

// RefChecker looks up project files. Implementations live outside this pure
// package.
type RefChecker interface {
	// Lines returns lines first..last (1-based, inclusive, clipped to the
	// file) of the project-relative, slash-separated file rel, and the
	// file's total number of lines.
	Lines(rel string, first, last int) (lines []string, total int, st LookupStatus)
}

// maxMatchRunes caps a line, or a needle, compared by the needle rule. Both
// sides go through clean first, so a needle with a backtick or a dash run still
// matches the code it was copied from.
const maxMatchRunes = 8192

// commentStyle says how a language marks comments, for the one question the
// needle rule asks: is this text on a code line.
type commentStyle struct {
	// line are the markers that start a comment running to the end of the line.
	line []string
	// block is true when "/*" starts a block comment.
	block bool
}

var (
	hashStyle  = commentStyle{line: []string{"#"}}
	slashStyle = commentStyle{line: []string{"//"}, block: true}
	dashStyle  = commentStyle{line: []string{"--"}}
)

// commentStyles maps a lower-case file extension to its comment style, one
// row per extension. An extension not listed gets no comment exclusion: a
// needle on any line of the range can be found (the rule is a heuristic over
// lines, not a parser, and says so).
var commentStyles = map[string]commentStyle{
	".py": hashStyle, ".sh": hashStyle, ".bash": hashStyle, ".zsh": hashStyle, ".rb": hashStyle,
	".yaml": hashStyle, ".yml": hashStyle, ".toml": hashStyle, ".pl": hashStyle, ".ps1": hashStyle,
	".r": hashStyle, ".tf": hashStyle, ".dockerfile": hashStyle, ".mk": hashStyle,
	".c": slashStyle, ".h": slashStyle, ".cc": slashStyle, ".cpp": slashStyle, ".hpp": slashStyle,
	".cs": slashStyle, ".go": slashStyle, ".rs": slashStyle, ".java": slashStyle, ".kt": slashStyle,
	".swift": slashStyle, ".scala": slashStyle, ".js": slashStyle, ".jsx": slashStyle, ".mjs": slashStyle,
	".cjs": slashStyle, ".ts": slashStyle, ".tsx": slashStyle, ".dart": slashStyle,
	".php": {line: []string{"//", "#"}, block: true},
	".sql": dashStyle,
	".lua": dashStyle,
	".hs":  dashStyle,
}

// commentStyleOf returns the style for a project-relative path.
func commentStyleOf(rel string) (commentStyle, bool) {
	base := rel
	if i := strings.LastIndexByte(base, '/'); i >= 0 {
		base = base[i+1:]
	}
	base = strings.ToLower(base)
	switch base {
	case "dockerfile", "makefile":
		return hashStyle, true
	}
	if i := strings.LastIndexByte(base, '.'); i >= 0 {
		st, ok := commentStyles[base[i:]]
		return st, ok
	}
	return commentStyle{}, false
}

// codePart returns the code on a line, or "" when the whole line is a
// comment. A trailing comment is cut at its marker unless the marker is inside
// a quoted string. This is a line heuristic: a needle inside a string literal
// on a code line still counts as code, and the credit rule says so.
func (c commentStyle) codePart(line string) string {
	t := strings.TrimSpace(line)
	if t == "" {
		return ""
	}
	for _, m := range c.line {
		if strings.HasPrefix(t, m) {
			return ""
		}
	}
	if c.block {
		if strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*/") ||
			(strings.HasPrefix(t, "*") && (len(t) == 1 || t[1] == ' ' || t[1] == '/' || t[1] == '\t')) {
			return ""
		}
	}
	return strings.TrimSpace(c.stripTrailing(t))
}

// stripTrailing cuts a trailing comment that starts outside a quoted string.
func (c commentStyle) stripTrailing(t string) string {
	var quote byte
	for i := 0; i < len(t); i++ {
		ch := t[i]
		if quote != 0 {
			switch {
			case ch == '\\':
				i++
			case ch == quote:
				quote = 0
			}
			continue
		}
		switch ch {
		case '"', '\'', '`':
			quote = ch
			continue
		}
		rest := t[i:]
		for _, m := range c.line {
			if strings.HasPrefix(rest, m) {
				return t[:i]
			}
		}
		if c.block && strings.HasPrefix(rest, "/*") {
			return t[:i]
		}
	}
	return t
}

// needleUsable reports whether needle can earn RefFound: at least
// minNeedleRunes characters and one identifier token (a letter or underscore
// followed by at least two letters, digits or underscores). A needle made of
// punctuation or a couple of letters matches nearly any line and proves
// nothing.
func needleUsable(needle string) bool {
	if utf8.RuneCountInString(needle) < minNeedleRunes {
		return false
	}
	run, first := 0, false
	for _, r := range needle {
		switch {
		case r == '_' || unicode.IsLetter(r):
			if run == 0 {
				first = true
			}
			run++
		case unicode.IsDigit(r):
			if run > 0 {
				run++
			}
		default:
			run, first = 0, false
		}
		if first && run >= 3 {
			return true
		}
	}
	return false
}

// RefOutcome is the result of classifying one reference.
type RefOutcome struct {
	State RefState
	// Code is a closed reason code for a state that needs one ("" when the
	// state says it all): ref_path_refused, ref_range_invalid, ref_range_long,
	// ref_line_past_end, ref_file_missing, ref_budget, ref_no_checker,
	// ref_needle_weak, ref_needle_needs_line, ref_needle_far.
	Code string
	// Line is the line the needle was found on (RefFound only).
	Line int
}

// The window a reference's text must sit in to count as found (setting
// ref_match_window_lines). The window is counted in lines from the first cited
// line: 1 is the cited line only, 5 the cited line and the four after it.
const (
	// DefaultRefWindow is the window when none is given.
	DefaultRefWindow = 5
	// MaxRefWindow is the widest window the setting allows.
	MaxRefWindow = 50
)

// ClassifyRef decides what a reference earns. needle is the agent's needle as
// written (whitespace is squashed here); the checker may be nil.
//
// found means the needle is on a code line within window lines of the first
// cited line (window 0 reads as DefaultRefWindow): credit is local. A needle
// that is in a longer cited range but only past that window earns "exists",
// the location with nothing matched near it, and the line it was found on is
// returned in RefOutcome.Line.
func ClassifyRef(r Ref, ch RefChecker, window int) RefOutcome {
	if window <= 0 {
		window = DefaultRefWindow
	}
	rel, why := relPath(r.Path)
	if why != "" {
		return RefOutcome{State: RefInvalid, Code: "ref_path_refused"}
	}
	end := r.EndLine
	switch {
	case r.Line < 0 || end < 0 || (end != 0 && r.Line == 0):
		return RefOutcome{State: RefInvalid, Code: "ref_range_invalid"}
	case end != 0 && end < r.Line:
		return RefOutcome{State: RefInvalid, Code: "ref_range_invalid"}
	case end != 0 && end-r.Line > maxRefSpan:
		return RefOutcome{State: RefInvalid, Code: "ref_range_long"}
	}
	if end == 0 {
		end = r.Line
	}
	if ch == nil {
		return RefOutcome{State: RefUnchecked, Code: "ref_no_checker"}
	}
	first, last := r.Line, end
	if first == 0 { // a file-level reference: existence only
		first, last = 1, 1
	}
	lines, total, st := ch.Lines(rel, first, last)
	if n := last - first + 1; len(lines) > n {
		lines = lines[:n]
	}
	switch st {
	case LookupBudget:
		return RefOutcome{State: RefUnchecked, Code: "ref_budget"}
	case LookupMissing:
		return RefOutcome{State: RefMissing, Code: "ref_file_missing"}
	}
	if r.Line > 0 && (r.Line > total || end > total) {
		return RefOutcome{State: RefMissing, Code: "ref_line_past_end"}
	}
	needle := clean(r.Needle, maxMatchRunes)
	if needle == "" {
		return RefOutcome{State: RefExists}
	}
	if r.Line == 0 {
		return RefOutcome{State: RefExists, Code: "ref_needle_needs_line"}
	}
	if !needleUsable(needle) {
		return RefOutcome{State: RefExists, Code: "ref_needle_weak"}
	}
	style, _ := commentStyleOf(rel)
	far := false
	for i, ln := range lines {
		code := ln
		if style.line != nil || style.block {
			code = style.codePart(ln)
		}
		if !strings.Contains(clean(code, maxMatchRunes), needle) {
			continue
		}
		if i < window {
			return RefOutcome{State: RefFound, Line: first + i}
		}
		far = true
		break
	}
	if far {
		return RefOutcome{State: RefExists, Code: "ref_needle_far"}
	}
	return RefOutcome{State: RefClaimedNotFound}
}
