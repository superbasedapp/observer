package commitlog

import "strings"

// StatusArgs builds the argv to pass to git (after "git" itself, e.g.
// via gitview.RunReadOnly) for a working-tree status snapshot.
//
//   - "--porcelain=v2" is the stable, script-friendly status format;
//     "-z" NUL-terminates records instead of newlines, matching
//     ParseStatus (and internal/gitview's own status parsing).
//   - "--untracked-files=all" reports every untracked file individually
//     rather than collapsing an untracked directory into one entry.
//   - "--ignored=matching" reports ignored paths too (git's default is
//     to omit them entirely), so a caller that wants to distinguish
//     "not tracked" from "tracked-but-ignored" can.
//   - pathspec, when non-empty, is appended after the "--" separator to
//     scope the status to a subtree; pathspec == "" reports the whole
//     work tree.
func StatusArgs(pathspec string) []string {
	args := []string{"status", "--porcelain=v2", "-z", "--untracked-files=all", "--ignored=matching", "--"}
	if pathspec != "" {
		args = append(args, pathspec)
	}
	return args
}

// PathState.State values. See ParseStatus for how each is derived.
const (
	StatusModified  = "modified"
	StatusAdded     = "added"
	StatusDeleted   = "deleted"
	StatusUntracked = "untracked"
	StatusIgnored   = "ignored"
	StatusRenamed   = "renamed"
	StatusUnmerged  = "unmerged"
	// StatusRenamedAway is a staged rename's ORIGIN path: it is in HEAD
	// and staged for removal (a copy's origin is untouched and not
	// reported).
	StatusRenamedAway = "renamed_away"
)

// PathState is one path's working-tree state, as decoded by ParseStatus.
type PathState struct {
	// RelPath is REPOSITORY-ROOT relative — porcelain-v2 always reports
	// paths this way, regardless of the invocation's working directory
	// or any pathspec passed to StatusArgs. A caller scoping to a
	// project rooted in a subdirectory of the repository is responsible
	// for stripping that subdirectory's prefix itself; this package
	// does not attempt it, since it has no notion of the project root.
	RelPath string
	// State is one of the Status* constants above.
	State string
}

// ParseStatus decodes the output of a `git status` invocation built with
// StatusArgs into a slice of PathState.
//
// Record shapes (see git-status(1) "Porcelain Format Version 2"):
//
//   - "1 <XY> <sub> <mH> <mI> <mW> <hH> <hI> <path>" — an ordinary
//     changed entry; path is field 8 (0-based, space-split).
//   - "2 <XY> <sub> <mH> <mI> <mW> <hH> <hI> <X><score> <path>" — a
//     rename/copy; path is field 9, followed by a NUL-separated origin
//     path token. For a RENAME the origin is reported too, as
//     StatusRenamedAway (it was committed and is staged away); a copy's
//     origin is untouched and dropped.
//   - "u <XY> <sub> <m1> <m2> <m3> <mW> <h1> <h2> <h3> <path>" — an
//     unmerged entry; path is field 10, State is always StatusUnmerged.
//   - "? <path>" — untracked.
//   - "! <path>" — ignored (only present with --ignored=matching).
//   - "# ..." — a header line (branch info); skipped.
//
// For "1"/"2" records, State is derived from the two-character XY code
// by an ORDERED rule (CLAUDE.md module-boundary rule #5), see classifyXY:
// an 'A' in X (staged add, whatever the work tree did since) means
// added; a "2" record with 'R'/'C' in X means renamed; a 'D' in either
// position means deleted; an 'A' in Y (intent-to-add) means added; else
// modified.
func ParseStatus(data []byte) []PathState {
	tokens := strings.Split(string(data), "\x00")
	var states []PathState
	for i := 0; i < len(tokens); i++ {
		tok := tokens[i]
		switch {
		case tok == "" || strings.HasPrefix(tok, "# "):
			// Empty split artifact (trailing NUL) or a header line.
		case strings.HasPrefix(tok, "1 "):
			if ps, ok := parseOrdinaryEntry(tok, 8, '1'); ok {
				states = append(states, ps)
			}
		case strings.HasPrefix(tok, "2 "):
			if ps, ok := parseOrdinaryEntry(tok, 9, '2'); ok {
				states = append(states, ps)
				// Consume the rename/copy origin-path token that
				// follows: it is a separate NUL-delimited token, not
				// part of this record, and must not be misread as its
				// own status line on the next loop iteration.
				if i+1 < len(tokens) {
					i++
					if xy := strings.SplitN(tok, " ", 3)[1]; xy[0] == 'R' && tokens[i] != "" {
						states = append(states, PathState{RelPath: tokens[i], State: StatusRenamedAway})
					}
				}
			}
		case strings.HasPrefix(tok, "u "):
			if ps, ok := parseUnmergedEntry(tok); ok {
				states = append(states, ps)
			}
		case strings.HasPrefix(tok, "? "):
			states = append(states, PathState{RelPath: strings.TrimPrefix(tok, "? "), State: StatusUntracked})
		case strings.HasPrefix(tok, "! "):
			states = append(states, PathState{RelPath: strings.TrimPrefix(tok, "! "), State: StatusIgnored})
		}
	}
	return states
}

// parseOrdinaryEntry extracts the XY code and the path (at 0-based field
// index pathField, space-delimited) from a porcelain-v2 "1" or "2"
// record and classifies it via classifyXY.
func parseOrdinaryEntry(tok string, pathField int, recordType byte) (PathState, bool) {
	fields := strings.SplitN(tok, " ", pathField+1)
	if len(fields) <= pathField {
		return PathState{}, false
	}
	xy := fields[1]
	if len(xy) < 2 {
		return PathState{}, false
	}
	return PathState{RelPath: fields[pathField], State: classifyXY(recordType, xy)}, true
}

// parseUnmergedEntry extracts the path (field 10) from a porcelain-v2
// "u" record. Its State is always StatusUnmerged — the three-way XY
// code on an unmerged entry describes the conflict shape, not a
// modified/added/deleted axis, so it is not run through classifyXY.
func parseUnmergedEntry(tok string) (PathState, bool) {
	const pathField = 10
	fields := strings.SplitN(tok, " ", pathField+1)
	if len(fields) <= pathField {
		return PathState{}, false
	}
	return PathState{RelPath: fields[pathField], State: StatusUnmerged}, true
}

// classifyXY derives a PathState.State from a porcelain-v2 two-character
// XY status code. recordType is '1' or '2' (a "2" record's X position
// may additionally carry 'R'/'C' for rename/copy).
func classifyXY(recordType byte, xy string) string {
	for _, r := range xyRules {
		if r.match(recordType, xy) {
			return r.state
		}
	}
	return StatusModified
}

// xyRules is walked top-down; the first match decides. X is the index
// (staged) side, Y the work tree. The order matters: "AD" (staged add,
// then deleted from the work tree) was never committed, so the staged
// add wins over the 'D'; a rename's new path was never committed either.
var xyRules = []struct {
	state string
	match func(recordType byte, xy string) bool
}{
	{StatusAdded, func(_ byte, xy string) bool { return xy[0] == 'A' }},
	{StatusRenamed, func(rt byte, xy string) bool { return rt == '2' && (xy[0] == 'R' || xy[0] == 'C') }},
	{StatusDeleted, func(_ byte, xy string) bool { return strings.Contains(xy, "D") }},
	{StatusAdded, func(_ byte, xy string) bool { return xy[1] == 'A' }},
}
