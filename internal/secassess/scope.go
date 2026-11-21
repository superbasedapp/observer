package secassess

import (
	"fmt"
	"slices"
	"strings"
)

// The scope of a threat model run (depth plan W3.3): the developer may limit
// the model to a few folders or files of the project. The paths are the
// developer's own choice, validated the way a reference is (project-relative,
// forward slashes, no parent segment), and the note is their own words, cleaned.
// A scope narrows what the agent is ASKED to model; it is not a barrier, and
// the check afterwards (V9) only warns when the model's own scope names a place
// outside it.

// Caps of a scope.
const (
	// MaxScopeChoices is the most paths one run's scope names.
	MaxScopeChoices = 8
	// MaxScopeNote is the longest scope note, in characters.
	MaxScopeNote = 200
	// maxScopePath is the longest single scope path, in characters.
	maxScopePath = 120
)

// The refusal codes of a scope path.
const (
	ScopeTooMany  = "too_many"
	ScopeUnsafe   = "unsafe_characters"
	ScopeTooLong  = "path_too_long"
	ScopeInternal = "internal_folder"
)

// scopeReasons are the words of each refusal code: the codes relPath returns
// (the same closed set a reference is held to) and the scope's own.
var scopeReasons = map[string]string{
	"empty_uri":          "The path is empty.",
	"uri_too_long":       "The path is too long.",
	"control_character":  "The path holds a control or invisible character.",
	"query_or_fragment":  "A path cannot hold ? or #.",
	"absolute_or_remote": "Write the path relative to the project folder, without a drive, a leading slash or a web address.",
	"parent_segment":     "A path cannot go up with .. (it must stay inside the project).",
	ScopeTooMany:         fmt.Sprintf("A run's scope names at most %d paths.", MaxScopeChoices),
	ScopeUnsafe:          "The path holds a character that is not allowed in the task. Choose a folder with a plain name.",
	ScopeTooLong:         fmt.Sprintf("The path is over %d characters.", maxScopePath),
	ScopeInternal:        "Observer's own run folders and git's folder are not part of the project's code.",
}

// ScopeRefusal is a scope path that was not accepted, with the closed code and
// the sentence the dialog shows.
type ScopeRefusal struct {
	Path   string `json:"path"`
	Code   string `json:"code"`
	Reason string `json:"reason"`
}

// ScopeReason returns the sentence for a refusal code.
func ScopeReason(code string) string {
	if s, ok := scopeReasons[code]; ok {
		return s
	}
	return "The path was not accepted."
}

// NormalizeScope validates the scope paths a plan or launch names, in order. An
// accepted path is project-relative with forward slashes; a path already
// covered by another, broader one is dropped silently (whichever comes first) and
// one that repeats another is kept once. Everything refused comes back with its
// code, so the dialog says why; a place past the eighth, counted after the nested
// and repeated paths are collapsed, is refused too_many, never dropped without a
// word.
func NormalizeScope(paths []string) (ok []string, refused []ScopeRefusal) {
	for _, raw := range paths {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		rel, code := relPath(strings.TrimSpace(raw))
		switch {
		case code != "":
		case len(rel) > maxScopePath:
			code = ScopeTooLong
		case scopeInternal(rel):
			code = ScopeInternal
		case clean(rel, maxScopePath+1) != rel || strings.ContainsAny(rel, "\"'<>"):
			code = ScopeUnsafe
		}
		if code != "" {
			refused = append(refused, ScopeRefusal{Path: clean(raw, 80), Code: code, Reason: ScopeReason(code)})
			continue
		}
		ok = append(ok, rel)
	}
	// Collapse first, then count: nine nested paths are one place, not nine.
	ok = collapseScope(ok)
	if len(ok) > MaxScopeChoices {
		for _, rel := range ok[MaxScopeChoices:] {
			refused = append(refused, ScopeRefusal{Path: rel, Code: ScopeTooMany, Reason: ScopeReason(ScopeTooMany)})
		}
		ok = ok[:MaxScopeChoices]
	}
	return ok, refused
}

// scopeInternalRoots are the folders a scope never names: Observer's own run
// folders, its parent and git's folder. They are compared in lower case, so a
// case-insensitive disk (Windows, macOS) cannot spell its way around the rule
// (.GIT/config, .Observer/x).
var scopeInternalRoots = []string{ResultRoot, ".observer", ".git"}

// scopeInternal reports whether a project-relative path is, or lies inside, one
// of scopeInternalRoots.
func scopeInternal(rel string) bool {
	lower := strings.ToLower(rel)
	for _, root := range scopeInternalRoots {
		if lower == root || strings.HasPrefix(lower, root+"/") {
			return true
		}
	}
	return false
}

// collapseScope drops repeats and any path that lies inside another accepted
// path, keeping the first-seen order of what is left.
func collapseScope(paths []string) []string {
	var out []string
	for i, p := range paths {
		covered := false
		for j, q := range paths {
			if i == j {
				continue
			}
			if q == p && j < i {
				covered = true
			}
			if q != p && strings.HasPrefix(p, q+"/") {
				covered = true
			}
		}
		if !covered {
			out = append(out, p)
		}
	}
	return out
}

// CleanScopeNote cleans the developer's scope note for the task: one line, no
// backticks or invisible characters, dash runs shortened, at most MaxScopeNote
// characters.
func CleanScopeNote(s string) string { return clean(s, MaxScopeNote) }

// SameScope reports whether two scopes name the same paths, whatever the order.
func SameScope(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x, y := slices.Clone(a), slices.Clone(b)
	slices.Sort(x)
	slices.Sort(y)
	return slices.Equal(x, y)
}
