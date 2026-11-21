package secassess

import (
	"strings"
	"unicode"
)

// The file names a fix task prints (review W6b-M1; decision D24).
//
// A located place is Observer's own finding, but its path is a name the
// assessing agent chose in its model file, and a project file of that name can
// be created by the agent (a run writes into its own folder, and a pen test
// has the live tree). A file name is therefore a free-text channel into a
// write-capable agent unless it is held to a narrow shape. A path is printed
// only when it passes every row of fixPathRules; a place that fails is counted
// ("N more places are not listed"), never printed, never dropped silently.

// Bounds of a printed path.
const (
	// FixPathMaxBytes is the longest path a fix task prints. Real project paths
	// are well under it; a sentence is not.
	FixPathMaxBytes = 160
	// fixSegmentMaxBytes is the longest single name in a path.
	fixSegmentMaxBytes = 80
)

// Closed ids of the rules that keep a path out of a fix task.
const (
	fixPathEmpty      = "empty"
	fixPathTooLong    = "too_long"
	fixPathAlphabet   = "alphabet"
	fixPathSegment    = "segment"
	fixPathSegmentLen = "segment_too_long"
	fixPathToolFolder = "tool_folder"
)

// fixPathRule is one row of the filter: refuses reports whether the path
// fails it.
type fixPathRule struct {
	id      string
	refuses func(path string) bool
}

// fixPathRules are the rows, in the order they run; the first that refuses
// names the reason. Every row has a test row on each side.
var fixPathRules = []fixPathRule{
	{fixPathEmpty, func(p string) bool { return p == "" }},
	{fixPathTooLong, func(p string) bool { return len(p) > FixPathMaxBytes }},
	{fixPathAlphabet, func(p string) bool { return strings.IndexFunc(p, func(r rune) bool { return !fixPathRune(r) }) >= 0 }},
	{fixPathSegment, func(p string) bool {
		for _, seg := range strings.Split(p, "/") {
			if seg == "" || seg == "." || seg == ".." {
				return true
			}
		}
		return false
	}},
	{fixPathSegmentLen, func(p string) bool {
		for _, seg := range strings.Split(p, "/") {
			if len(seg) > fixSegmentMaxBytes {
				return true
			}
		}
		return false
	}},
	{fixPathToolFolder, func(p string) bool {
		for _, seg := range strings.Split(p, "/") {
			if _, ok := fixToolFolders[strings.ToLower(seg)]; ok {
				return true
			}
		}
		return false
	}},
}

// fixToolFolders are names no fix task points at, whatever their depth: the
// folder of Observer's own run files (the agent wrote there, and the prompt
// already tells the agent not to touch it) and the repository's own store.
var fixToolFolders = map[string]struct{}{
	".observer": {},
	".git":      {},
}

// fixPathPunct is the punctuation a path may carry: what ordinary project trees
// use (extensions, scopes, framework route folders such as (group), [id] and
// $param) and nothing that forms a sentence. There is no space.
const fixPathPunct = "._-/@+~=,[]()$"

// fixPathRune reports whether r may appear in a printed path: an ASCII letter
// or digit, the punctuation above, or a letter, digit or combining mark of any
// script (a project with non-Latin file names keeps its places). A space, a
// control, format or separator character, a symbol and an emoji do not.
func fixPathRune(r rune) bool {
	switch {
	case r < unicode.MaxASCII:
		return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune(fixPathPunct, r)
	default:
		return unicode.IsLetter(r) || unicode.IsDigit(r) || unicode.In(r, unicode.Mn, unicode.Mc)
	}
}

// FixPathRefusal returns the closed id of the first rule that keeps path out of
// a fix task, "" when the path may be printed.
func FixPathRefusal(path string) string {
	for _, rule := range fixPathRules {
		if rule.refuses(path) {
			return rule.id
		}
	}
	return ""
}

// FixPathOK reports whether a fix task may print path. The Findings tab's task
// and the derived findings place the same names; whatever selects them can ask
// the same question.
func FixPathOK(path string) bool { return FixPathRefusal(path) == "" }
