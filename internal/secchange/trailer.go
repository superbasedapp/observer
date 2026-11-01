package secchange

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// trailer.go is the pure text side of the two repository writers (security
// plan 7.10 "Where it lives"; roadmap section 11 item 5): the git note body
// (one DSSE envelope per line under refs/notes/observer) and the
// `Assisted-by: AGENT:MODEL` commit trailer (the Linux kernel convention)
// added by a prepare-commit-msg hook block. Both run only on a person's
// per-repository consent; neither ever rewrites history (a note is a
// separate ref; the trailer is added while the commit is being made, never
// after), and the trailer is added only to a commit the agent itself is
// making.

// NotesRef is the notes ref the change records are written under.
const NotesRef = "refs/notes/observer"

// TrailerKey is the trailer name.
const TrailerKey = "Assisted-by"

// PendingCommitTTL is how long the hook's "the agent is committing here"
// marker stays valid; the prepare-commit-msg hook runs within seconds of
// the agent's tool call (audit finding F3: 30 seconds at most, so a
// person's commit a little later never inherits it).
const PendingCommitTTL = 30 * time.Second

// NoteHas reports whether a note body already carries the envelope line.
func NoteHas(note, envelope []byte) bool {
	want := bytes.TrimSpace(envelope)
	for _, line := range bytes.Split(note, []byte("\n")) {
		if bytes.Equal(bytes.TrimSpace(line), want) {
			return true
		}
	}
	return false
}

// NoteEnvelopes returns the envelope lines of a note body (blank lines
// skipped); each is checked by its reader, never trusted.
func NoteEnvelopes(note []byte) [][]byte {
	var out [][]byte
	for _, line := range bytes.Split(note, []byte("\n")) {
		if l := bytes.TrimSpace(line); len(l) > 0 {
			out = append(out, l)
		}
	}
	return out
}

// TrailerValue renders the trailer value AGENT:MODEL, or AGENT alone when
// the model is unknown. A name outside the record's item shape is left
// out ("" when the agent itself is not shaped).
func TrailerValue(agent, model string) string {
	if !itemShape(agent) {
		return ""
	}
	if itemShape(model) {
		return agent + ":" + model
	}
	return agent
}

var trailerLineRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]*:\s`)

// scissorsCut is the text git writes after the comment character on the
// scissors line of `git commit -v` (and cleanup=scissors): everything
// below it is dropped from the message.
const scissorsCut = " ------------------------ >8 ------------------------"

// AddTrailer returns the commit message with `Assisted-by: value` in its
// trailer block: appended to an existing trailer paragraph, or as a new
// paragraph after the last line of the message; comment lines (git's
// template, commentChar) after the message stay where they are, and so
// does a scissors line with everything below it (`git commit -v`): the
// trailer goes above the cut, where git keeps it (audit finding F8). A
// message that already carries the same line is returned unchanged, and so
// is an empty message (git aborts an empty commit; a trailer would make it
// non-empty).
func AddTrailer(msg, value string, commentChar byte) string {
	if value == "" {
		return msg
	}
	all := strings.Split(msg, "\n")
	cut := len(all)
	for i, l := range all {
		if strings.TrimRight(l, "\r") == string(commentChar)+scissorsCut {
			cut = i
			break
		}
	}
	head := addTrailerLines(all[:cut], TrailerKey+": "+value, commentChar)
	if head == nil {
		return msg
	}
	return strings.Join(append(head, all[cut:]...), "\n")
}

// addTrailerLines is AddTrailer over the lines above the cut; nil when the
// message stays as it is.
func addTrailerLines(lines []string, line string, commentChar byte) []string {
	isComment := func(l string) bool { return len(l) > 0 && l[0] == commentChar }
	last := -1
	for i, l := range lines {
		if isComment(l) {
			continue
		}
		if strings.TrimSpace(l) != "" {
			last = i
		}
		if strings.TrimRight(l, "\r") == line {
			return nil
		}
	}
	if last < 0 {
		return nil
	}
	// The last paragraph of content: a trailer block when every line is a
	// trailer line and it is not the subject alone.
	start := last
	for start > 0 && !isComment(lines[start-1]) && strings.TrimSpace(lines[start-1]) != "" {
		start--
	}
	trailers := start > 0
	for _, l := range lines[start : last+1] {
		if !trailerLineRE.MatchString(l) {
			trailers = false
		}
	}
	insert := []string{line}
	if !trailers {
		insert = []string{"", line}
	}
	out := append([]string{}, lines[:last+1]...)
	out = append(out, insert...)
	return append(out, lines[last+1:]...)
}

// commentCandidates are the characters core.commentChar=auto picks from
// (git's own list).
const commentCandidates = "#;@!$%^&|:"

// CommentChar resolves the comment character of a commit message from git's
// core.commentChar (or core.commentString) setting: "" means git's default
// '#'; "auto" is read from the message itself (the character of its
// scissors line, else the first candidate starting a line of git's
// template text), '#' when nothing says; a longer comment string is taken
// by its first byte (audit finding F8).
func CommentChar(setting, msg string) byte {
	setting = strings.TrimSpace(setting)
	switch {
	case setting == "":
		return '#'
	case setting != "auto":
		return setting[0]
	}
	lines := strings.Split(msg, "\n")
	for _, l := range lines {
		l = strings.TrimRight(l, "\r")
		if len(l) == 1+len(scissorsCut) && strings.HasSuffix(l, scissorsCut) && strings.IndexByte(commentCandidates, l[0]) >= 0 {
			return l[0]
		}
	}
	for _, l := range lines {
		if len(l) > 2 && l[1] == ' ' && strings.IndexByte(commentCandidates, l[0]) >= 0 && strings.Contains(l, "commit message") {
			return l[0]
		}
	}
	return '#'
}

// PendingCommit is the hook's marker that an agent is committing in a
// repository right now. It is written only after guard and the commit gate
// allowed the agent's commit, and it is bound to the repository's HEAD and
// index at that moment (audit finding F3): the prepare-commit-msg step adds
// the trailer only to a commit made on that HEAD from that index.
type PendingCommit struct {
	RootHash  string `json:"root_hash"`
	Agent     string `json:"agent"`
	SessionID string `json:"session_id"`
	At        string `json:"at"`
	// Head is the commit HEAD named when the marker was written ("" on an
	// unborn branch).
	Head string `json:"head"`
	// IndexFP is the fingerprint of the index the commit is made from
	// (IndexFingerprint); "" never matches.
	IndexFP string `json:"index_fp"`
	// Index is the index as it stood at the allow, one entry digest per
	// path (IndexListing), and Planned the scopes the command line stages
	// for its commit (policy.PlannedCommitStaging, made relative to the
	// top of the working tree): the commit may differ from Index only
	// inside Planned (lane SEC-F2B, decision log P-078 ruling 2), so an
	// agent's one-line `git add X && git commit` or `git commit -a` keeps
	// its trailer. A marker without them binds the index exactly.
	Index   map[string]string `json:"index,omitempty"`
	Planned []PlannedScope    `json:"planned,omitempty"`
}

// PlannedScope is one scope a commit's command line stages, relative to
// the top of the working tree with '/' separators: Prefix "" is the whole
// tree; TrackedOnly admits only paths the recorded index already held
// (`git commit -a`, `git add -u`).
type PlannedScope struct {
	Prefix      string `json:"prefix"`
	TrackedOnly bool   `json:"tracked_only,omitempty"`
}

// IndexListing parses `git ls-files -s -z` output into one digest per
// path (hex SHA-256 of every stage line of the path, so a conflicted path
// is one entry). ok is false for output it cannot read.
func IndexListing(lsFilesStage []byte) (map[string]string, bool) {
	lines := map[string][]byte{}
	for _, rec := range bytes.Split(lsFilesStage, []byte{0}) {
		if len(rec) == 0 {
			continue
		}
		meta, path, found := bytes.Cut(rec, []byte{'\t'})
		if !found || len(path) == 0 || len(bytes.Fields(meta)) != 3 {
			return nil, false
		}
		lines[string(path)] = append(append(lines[string(path)], meta...), '\n')
	}
	out := make(map[string]string, len(lines))
	for p, b := range lines {
		sum := sha256.Sum256(b)
		out[p] = hex.EncodeToString(sum[:16])
	}
	return out, true
}

// InPlannedScope reports whether path is inside scope.
func InPlannedScope(path string, scope PlannedScope) bool {
	return scope.Prefix == "" || path == scope.Prefix || strings.HasPrefix(path, scope.Prefix+"/")
}

// StagedWithinPlan reports whether every path whose entry differs between
// the recorded index (pre) and the index the commit is made from (now) is
// inside a planned scope; a TrackedOnly scope admits a path only when pre
// tracked it. Nil now never matches (the index was not read), and neither
// does an empty or absent pre-command listing (lane SEC-P4, SEC-F2B audit
// finding 8): with nothing recorded to compare against, every path of now
// would read as newly staged and a whole-tree plan would admit any index,
// so the trailer is never allowed on it (an index that did not change
// still matches by its fingerprint, without this check).
func StagedWithinPlan(pre, now map[string]string, planned []PlannedScope) bool {
	if now == nil || len(pre) == 0 {
		return false
	}
	allowed := func(p string) bool {
		_, tracked := pre[p]
		for _, s := range planned {
			if InPlannedScope(p, s) && (!s.TrackedOnly || tracked) {
				return true
			}
		}
		return false
	}
	for p, d := range now {
		if pre[p] != d && !allowed(p) {
			return false
		}
	}
	for p := range pre {
		if _, ok := now[p]; !ok && !allowed(p) {
			return false
		}
	}
	return true
}

// IndexFingerprint is the fingerprint of an index: hex SHA-256 over the
// output of `git ls-files -s -z` (every staged entry's mode, blob and
// path), the content the next commit's tree is written from.
func IndexFingerprint(lsFilesStage []byte) string {
	sum := sha256.Sum256(lsFilesStage)
	return hex.EncodeToString(sum[:])
}

// TrailerFacts is what the prepare-commit-msg decision reads.
type TrailerFacts struct {
	// Selected: security.provenance is selected on this node.
	Selected bool
	// Consent: a person consented to the trailer for this repository.
	Consent bool
	// Source is git's second prepare-commit-msg argument ("", message,
	// template, merge, squash, commit).
	Source string
	// Pending is the marker for this repository, nil when none.
	Pending  *PendingCommit
	RootHash string
	Now      time.Time
	// Head and IndexFP are the repository's HEAD and index fingerprint as
	// the prepare-commit-msg step reads them; IndexFP "" when unreadable.
	// Index is the same index listed per path (IndexListing), nil when
	// unreadable.
	Head    string
	IndexFP string
	Index   map[string]string
}

// trailerRule is one row of the trailer table.
type trailerRule struct {
	reason string
	skip   func(f TrailerFacts) bool
}

// trailerRules is the ordered decision table: the first row that skips
// decides; a commit no row skips gets the trailer.
var trailerRules = []trailerRule{
	{"provenance_off", func(f TrailerFacts) bool { return !f.Selected }},
	{"no_consent", func(f TrailerFacts) bool { return !f.Consent }},
	{"merge_or_squash", func(f TrailerFacts) bool { return f.Source == "merge" || f.Source == "squash" }},
	{"not_an_agent_commit", func(f TrailerFacts) bool { return f.Pending == nil || f.Pending.RootHash != f.RootHash }},
	{"marker_stale", func(f TrailerFacts) bool {
		t, err := time.Parse(time.RFC3339, f.Pending.At)
		return err != nil || f.Now.Sub(t) > PendingCommitTTL || t.Sub(f.Now) > PendingCommitTTL
	}},
	{"marker_unbound", func(f TrailerFacts) bool { return f.Pending.IndexFP == "" }},
	{"marker_other_head", func(f TrailerFacts) bool { return f.Pending.Head != f.Head }},
	// The commit is made from the index as it stood, or from one that
	// differs only inside what the command line planned to stage.
	{"marker_other_tree", func(f TrailerFacts) bool {
		return f.Pending.IndexFP != f.IndexFP && !StagedWithinPlan(f.Pending.Index, f.Index, f.Pending.Planned)
	}},
}

// DecideTrailer says whether the commit being made gets the trailer, and
// why not when it does not.
func DecideTrailer(f TrailerFacts) (add bool, reason string) {
	for _, r := range trailerRules {
		if r.skip(f) {
			return false, r.reason
		}
	}
	return true, "agent_commit"
}

// The prepare-commit-msg block markers, distinct from the security git
// hooks' block so each is installed and removed on its own consent.
const (
	trailerBegin   = "# >>> superbased-observer provenance trailer (remove with: observer security provenance consent --trailer=false) >>>"
	trailerEnd     = "# <<< superbased-observer provenance trailer <<<"
	trailerShebang = "#!/bin/sh"
)

// TrailerHookName is the hook file the block goes in.
const TrailerHookName = "prepare-commit-msg"

// ErrHookNotShell refuses an existing hook that is not a shell script.
var ErrHookNotShell = errors.New("the existing prepare-commit-msg hook is not a shell script, so Observer will not edit it; chain `observer security provenance trailer \"$@\"` from it yourself")

func trailerQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'" }

// TrailerBlock renders the block running observer at observerPath. It
// never fails the commit: every status of the trailer step is ignored.
func TrailerBlock(observerPath string) string {
	return trailerBegin + "\n" +
		"sbo_obs=" + trailerQuote(observerPath) + "\n" +
		"if [ -x \"$sbo_obs\" ]; then\n" +
		"  \"$sbo_obs\" security provenance trailer \"$@\" >/dev/null 2>&1 || :\n" +
		"fi\n" +
		trailerEnd + "\n"
}

// HasTrailerBlock reports whether a hook carries the block.
func HasTrailerBlock(text string) bool {
	_, _, ok := trailerSpan(text)
	return ok
}

func trailerSpan(text string) (int, int, bool) {
	i := strings.Index(text, trailerBegin)
	if i < 0 {
		return 0, 0, false
	}
	j := strings.Index(text[i:], trailerEnd)
	if j < 0 {
		return 0, 0, false
	}
	end := i + j + len(trailerEnd)
	if end < len(text) && text[end] == '\n' {
		end++
	}
	return i, end, true
}

// InstallTrailerBlock returns the hook text with the block: a new file, the
// block after an existing shell hook's shebang, or the block replaced in
// place.
func InstallTrailerBlock(existing, block string) (string, error) {
	if i, end, ok := trailerSpan(existing); ok {
		return existing[:i] + block + existing[end:], nil
	}
	if existing == "" {
		return trailerShebang + "\n" + block, nil
	}
	first, rest, hasRest := strings.Cut(existing, "\n")
	if !isShellLine(first) {
		return "", ErrHookNotShell
	}
	if !hasRest {
		return first + "\n" + block, nil
	}
	return first + "\n" + block + rest, nil
}

// RemoveTrailerBlock returns the hook without the block, byte-exact; empty
// reports that only the shebang Observer wrote is left.
func RemoveTrailerBlock(text string) (string, bool) {
	i, end, ok := trailerSpan(text)
	if !ok {
		return text, false
	}
	out := text[:i] + text[end:]
	return out, strings.TrimSpace(out) == trailerShebang
}

func isShellLine(line string) bool {
	line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
	if !strings.HasPrefix(line, "#!") {
		return false
	}
	f := strings.Fields(strings.TrimPrefix(line, "#!"))
	if len(f) == 0 {
		return false
	}
	interp := filepath.Base(f[0])
	if interp == "env" && len(f) > 1 {
		interp = f[1]
	}
	switch interp {
	case "sh", "bash", "dash", "zsh", "ksh":
		return true
	}
	return false
}
