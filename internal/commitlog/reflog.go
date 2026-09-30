package commitlog

import (
	"bytes"
	"strconv"
	"strings"
	"time"
)

// reflogRecordSep mirrors recordSep (parse.go) for the reflog stream: it
// prefixes each record, letting splitRecords-style trimming work the
// same way it does for `git log`.
const reflogRecordSep = 0x1e

// reflogFormat is the --format argument's payload for ReflogArgs: a
// leading record separator (%x1e, so records can be split exactly like
// logFormat's), then three NUL-separated (%x00) fields — the full SHA
// (%H), the reflog selector (%gd), and the reflog subject (%gs).
const reflogFormat = `%x1e%H%x00%gd%x00%gs`

// ReflogArgs builds the argv to pass to git (after "git" itself, e.g.
// via gitview.RunReadOnly) for a HEAD-only reflog scan.
//
//   - "--date=unix" makes %gd render as "HEAD@{<epoch-seconds>}" instead
//     of a relative or ISO string, so ParseReflog can recover an exact
//     MovedAt without a second, format-guessing date parser.
//   - "--format=tformat:<reflogFormat>" is the ONE output shape
//     ParseReflog understands; "tformat:" (not "format:") terminates
//     every record with a newline, including the last, the same
//     ParseLog precedent (args.go).
//   - max, when > 0, becomes "-n <max>" (bound the number of entries
//     read); max <= 0 omits it (unbounded).
//   - skip, when > 0, becomes "--skip=<skip>" (page past entries already
//     read); skip <= 0 omits it.
//   - "HEAD --" pins the walk to HEAD's own reflog and stops git from
//     treating any trailing token as a pathspec (there is none here, but
//     the same defensive "--" as Args/PageArgsRev).
//
// The reflog subject (%gs) is free text (a commit message summary, a
// checkout target, a rebase step) — ParseReflog classifies it into a
// closed ReflogEntry.Kind vocabulary via ReflogKind and DISCARDS the raw
// subject; it never appears in ReflogEntry.
func ReflogArgs(max, skip int) []string {
	args := []string{"reflog", "show", "--no-color", "--date=unix", "--format=tformat:" + reflogFormat}
	if max > 0 {
		args = append(args, "-n", strconv.Itoa(max))
	}
	if skip > 0 {
		args = append(args, "--skip="+strconv.Itoa(skip))
	}
	args = append(args, "HEAD", "--")
	return args
}

// ReflogEntry is one HEAD reflog entry as decoded by ParseReflog.
type ReflogEntry struct {
	// SHA is the full commit object id the reflog entry points at.
	SHA string
	// MovedAt is when HEAD moved to SHA, in UTC.
	MovedAt time.Time
	// Kind is the closed classification of the entry (ReflogKind), never
	// the raw git subject.
	Kind string
}

// reflogKinds classifies a reflog subject (%gs) into ReflogEntry.Kind. It
// is an ORDERED table (CLAUDE.md module-boundary rule #5) walked
// top-down by ReflogKind — order matters, since several prefixes share a
// common stem ("commit (amend)" must be checked before the bare
// "commit", or every amend would be misclassified as a plain commit).
var reflogKinds = []struct{ prefix, kind string }{
	{"commit (amend)", "amend"},
	{"commit (merge)", "merge"},
	{"commit (initial)", "commit"},
	{"commit", "commit"},
	{"checkout", "checkout"},
	{"merge", "merge"},
	{"rebase", "rebase"},
	{"reset", "reset"},
	{"pull", "pull"},
	{"cherry-pick", "cherry-pick"},
	{"revert", "commit"},
	{"clone", "clone"},
	{"am", "commit"},
}

// ReflogKind classifies a raw reflog subject (git's %gs) into a closed
// vocabulary using the reflogKinds table, falling back to "other" when
// no row matches.
//
// A prefix only matches at a WORD boundary — the prefix itself, followed
// by ':', ' ', '(' or end-of-string — never as a plain byte-prefix. This
// is what stops the "am" row (git's `git am` reflog subjects all start
// "am:" or "am ") from matching a subject that merely starts with the
// letters "am", most notably "amend..." — which must fall through to the
// "commit (amend)" row above it instead.
func ReflogKind(subject string) string {
	for _, k := range reflogKinds {
		if hasWordPrefix(subject, k.prefix) {
			return k.kind
		}
	}
	return "other"
}

// hasWordPrefix reports whether s starts with prefix AND prefix ends
// there at a word boundary (s is exactly prefix, or the next byte is
// ':', ' ' or '(').
func hasWordPrefix(s, prefix string) bool {
	if !strings.HasPrefix(s, prefix) {
		return false
	}
	if len(s) == len(prefix) {
		return true
	}
	switch s[len(prefix)] {
	case ':', ' ', '(':
		return true
	default:
		return false
	}
}

// ParseReflog decodes the output of a `git reflog` invocation built with
// ReflogArgs into a slice of ReflogEntry, newest first (git's own
// emission order, preserved as-is).
//
// Each record is 3 NUL-separated fields (SHA, %gd, %gs); a record with
// fewer than 3 fields — including a trailing record cut short by an
// upstream byte cap — is silently dropped rather than guessed at. A
// malformed SHA (not 40 or 64 lowercase hex characters) or an
// unparsable %gd ("<selector>@{<unix-seconds>}") also drops just that
// one record; ParseReflog never fails the whole scan over one bad entry.
func ParseReflog(data []byte) []ReflogEntry {
	var entries []ReflogEntry
	for _, chunk := range bytes.Split(data, []byte{reflogRecordSep}) {
		if len(bytes.TrimSpace(chunk)) == 0 {
			continue
		}
		rec := strings.TrimRight(string(chunk), "\r\n")
		fields := strings.SplitN(rec, "\x00", 3)
		if len(fields) < 3 {
			continue
		}
		sha, gd, gs := fields[0], fields[1], fields[2]
		if !isCommitSHA(sha) {
			continue
		}
		movedAt, ok := parseReflogSelectorTime(gd)
		if !ok {
			continue
		}
		entries = append(entries, ReflogEntry{
			SHA:     sha,
			MovedAt: movedAt,
			Kind:    ReflogKind(gs),
		})
	}
	return entries
}

// isCommitSHA reports whether s is a well-formed git object id: 40
// (sha1) or 64 (sha256) lowercase hex characters.
func isCommitSHA(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

// parseReflogSelectorTime extracts the unix-seconds timestamp from a
// "--date=unix"-rendered reflog selector such as "HEAD@{1690000000}" and
// returns it as a UTC time.Time. Anything not shaped
// "<anything>@{<integer>}" reports ok=false.
func parseReflogSelectorTime(selector string) (t time.Time, ok bool) {
	open := strings.Index(selector, "@{")
	if open < 0 || !strings.HasSuffix(selector, "}") {
		return time.Time{}, false
	}
	numStr := selector[open+2 : len(selector)-1]
	n, err := strconv.ParseInt(numStr, 10, 64)
	if err != nil {
		return time.Time{}, false
	}
	return time.Unix(n, 0).UTC(), true
}
