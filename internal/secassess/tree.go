package secassess

import (
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"
)

// The boundary audit (plan W0.4): two snapshots of the project's git state, one
// at launch and one when the run ends, compared by a pure function. It sees
// only what git can see: HEAD, the branch, the stash, the refs, tracked-file
// edits and untracked files, and for each changed path a content fingerprint
// (fingerprint.go), so a second edit of a file that was already dirty is seen.
// Files git ignores (.env, local databases, caches, node_modules) are not
// covered, and the words say so. A change in the window includes anything the
// developer did themselves. When the comparison could not cover everything
// (paths cut off at the cap, a file that could not be fingerprinted) the verdict
// says that and never reads "no change".

// TreePolicy says how a kind's boundary audit reads a change; it is a column of
// the kind table.
type TreePolicy string

// The tree policies.
const (
	// TreeStrict: any change counts.
	TreeStrict TreePolicy = "strict"
	// TreeUntrackedReported: HEAD, branch, stash, refs and tracked-file edits
	// count; untracked churn (build caches, bytecode) is reported but is not a
	// change.
	TreeUntrackedReported TreePolicy = "untracked_reported"
	// TreeNotAudited: the kind legitimately changes git state (it makes a
	// branch and a worktree), so nothing is compared.
	TreeNotAudited TreePolicy = "not_audited"
)

// MaxTreeEntries caps the entries one snapshot keeps.
const MaxTreeEntries = 400

// TreeExclude is the pathspec that removes the module's own directory from a
// status snapshot. The whole directory is excluded so a collapsed untracked
// directory ("?? .observer/") cannot hide or fake a change.
const TreeExclude = ":(exclude)" + ResultRoot

// Counts reports whether a change to the entry counts toward the verdict under
// the policy: a tracked-file change always does, an untracked file only when
// the policy is strict (the other policies report untracked churn without
// counting it, so they need neither its fingerprint nor its comparison).
func (p TreePolicy) Counts(e TreeEntry) bool { return e.Tracked() || p == TreeStrict }

// TreeStatusArgs are the git arguments of the status snapshot for a policy. A
// strict policy lists every untracked file on its own (--untracked-files=all),
// so an edit inside a new directory can be fingerprinted; the other policies
// let git collapse an untracked directory to one line, because untracked files
// are not counted for them.
func TreeStatusArgs(policy TreePolicy) []string {
	untracked := "--untracked-files=normal"
	if policy == TreeStrict {
		untracked = "--untracked-files=all"
	}
	return []string{"status", "--porcelain=v1", "-z", untracked, "--", ".", TreeExclude}
}

// TreeEntry is one changed path of a status snapshot.
type TreeEntry struct {
	// Status is git's two-character status ("??" for untracked).
	Status string `json:"s"`
	Path   string `json:"p"`
	// Fp is the content fingerprint of the path (FpLen hex characters of its
	// hash, or FpAbsent for a deleted file). It is empty when the entry was not
	// fingerprinted: a snapshot stored before fingerprints existed, a file that
	// could not be read, a directory, or a path past the cap. An entry with no
	// fingerprint is never read as unchanged.
	Fp string `json:"f,omitempty"`
}

// Tracked reports whether the entry is a tracked-file change (anything but
// untracked).
func (e TreeEntry) Tracked() bool { return e.Status != "??" }

// TreeSnapshot is the project's git state at one moment.
type TreeSnapshot struct {
	// OK is false when the snapshot could not be taken (no git, not a
	// repository, a timeout). A snapshot that is not OK is never read as clean.
	OK         bool        `json:"ok"`
	Head       string      `json:"head,omitempty"`
	Branch     string      `json:"branch,omitempty"`
	StashCount int         `json:"stash,omitempty"`
	RefsDigest string      `json:"refs,omitempty"`
	Entries    []TreeEntry `json:"entries,omitempty"`
	// Truncated: more than MaxTreeEntries paths were changed; the rest were not
	// kept.
	Truncated bool      `json:"truncated,omitempty"`
	TakenAt   time.Time `json:"at,omitzero"`
}

// ParseStatusZ parses `git status --porcelain=v1 -z` output into entries, at
// most MaxTreeEntries (truncated reports the cut). A rename or copy entry
// carries a second path field, which is consumed and dropped. Entries are
// sorted by path so two snapshots compare by position.
func ParseStatusZ(out []byte) (entries []TreeEntry, truncated bool) {
	fields := strings.Split(string(out), "\x00")
	for i := 0; i < len(fields); i++ {
		f := fields[i]
		if len(f) < 4 || f[2] != ' ' {
			continue
		}
		st, path := f[:2], f[3:]
		if st[0] == 'R' || st[0] == 'C' || st[1] == 'R' || st[1] == 'C' {
			i++ // the original path of a rename or copy
		}
		if len(entries) >= MaxTreeEntries {
			truncated = true
			continue
		}
		entries = append(entries, TreeEntry{Status: st, Path: path})
	}
	sort.Slice(entries, func(a, b int) bool {
		if entries[a].Path != entries[b].Path {
			return entries[a].Path < entries[b].Path
		}
		return entries[a].Status < entries[b].Status
	})
	return entries, truncated
}

// AuditVerdict is the outcome of a boundary audit.
type AuditVerdict string

// The audit verdicts. The wording a person reads is AuditWords; none of them
// says "boundary crossed" (that wording belongs to the cloud command
// classifier) and none says "clean".
const (
	AuditNoChange AuditVerdict = "no_change"
	AuditChanged  AuditVerdict = "changed"
	// AuditPartial: nothing changed in what could be compared, but the check
	// could not cover every changed path (more than MaxTreeEntries paths, or a
	// file that could not be fingerprinted). It is never read as "no change".
	AuditPartial    AuditVerdict = "partly_checked"
	AuditUnchecked  AuditVerdict = "could_not_check"
	AuditNotAudited AuditVerdict = "not_audited"
	AuditOff        AuditVerdict = "not_checked"
)

// AuditWords returns the sentence for a verdict.
func AuditWords(v AuditVerdict) string {
	switch v {
	case AuditNoChange:
		return "No git change seen"
	case AuditChanged:
		return "Git state changed during the run window"
	case AuditPartial:
		return "No change seen in the files that could be compared; some changed files could not be compared"
	case AuditUnchecked:
		return "Could not be checked"
	case AuditNotAudited:
		return "Not audited for this kind of assessment"
	case AuditOff:
		return "Not checked (turned off in settings)"
	}
	return ""
}

// AuditLimits is the sentence the card shows once beside any verdict: what the
// check does not see. The numbers in it are MaxTreeEntries and FpMaxFileBytes (a
// test pins them).
const AuditLimits = "Files git ignores (.env, local databases, caches, node_modules) are not covered, and a change made by you in the same window is counted too. " +
	"Changed and untracked files are compared by their content, up to 400 paths; a file that cannot be read in time, is a folder or is over 32 MiB is not compared, and the verdict then says so."

// The closed reason codes of an Audit.
const (
	// ReasonBeforeFailed and ReasonAfterFailed: a snapshot could not be taken
	// (could_not_check).
	ReasonBeforeFailed = "before_failed"
	ReasonAfterFailed  = "after_failed"
	// ReasonTruncated: a snapshot kept only MaxTreeEntries paths (partly_checked).
	ReasonTruncated = "truncated"
	// ReasonNotFingerprinted: a changed path present in both snapshots has no
	// content fingerprint on one side (partly_checked).
	ReasonNotFingerprinted = "not_fingerprinted"
)

// Audit is the comparison of two snapshots.
type Audit struct {
	Verdict        AuditVerdict `json:"verdict"`
	HeadChanged    bool         `json:"head_changed,omitempty"`
	BranchChanged  bool         `json:"branch_changed,omitempty"`
	StashChanged   bool         `json:"stash_changed,omitempty"`
	RefsChanged    bool         `json:"refs_changed,omitempty"`
	TrackedChanged []string     `json:"tracked_changed,omitempty"`
	UntrackedAdded []string     `json:"untracked_added,omitempty"`
	UntrackedGone  []string     `json:"untracked_gone,omitempty"`
	// UntrackedEdited are untracked files present at both snapshots whose
	// content fingerprint differs.
	UntrackedEdited []string `json:"untracked_edited,omitempty"`
	TrackedMore     int      `json:"tracked_more,omitempty"`
	UntrackedMore   int      `json:"untracked_more,omitempty"`
	// Uncompared is how many paths that count under the policy and are present
	// at both snapshots could not be compared by content (no fingerprint on one
	// side).
	Uncompared int `json:"uncompared,omitempty"`
	// Reason is a closed code (the Reason constants): before_failed or
	// after_failed for could_not_check, truncated or not_fingerprinted for
	// partly_checked.
	Reason string `json:"reason,omitempty"`
}

// maxAuditPaths caps each path list of an Audit.
const maxAuditPaths = 20

// entryKey is the identity of a status line: the same path with a different
// status is a different line.
type entryKey struct{ status, path string }

func entryFps(es []TreeEntry) map[entryKey]string {
	m := make(map[entryKey]string, len(es))
	for _, e := range es {
		m[entryKey{e.Status, e.Path}] = e.Fp
	}
	return m
}

// fpRelation is how the fingerprints of one status line compare across the two
// snapshots.
type fpRelation int

const (
	// fpSame: both sides have a fingerprint and it is equal.
	fpSame fpRelation = iota
	// fpDiffer: both sides have a fingerprint and it differs.
	fpDiffer
	// fpUnknown: a side has no fingerprint, so the content was not compared.
	fpUnknown
)

func relate(before, after string) fpRelation {
	switch {
	case before == "" || after == "":
		return fpUnknown
	case before == after:
		return fpSame
	}
	return fpDiffer
}

// entryDiff is the difference of two entry lists.
type entryDiff struct {
	tracked         []string // appeared, disappeared, re-statused or edited
	untrackedAdded  []string
	untrackedGone   []string
	untrackedEdited []string
	uncompared      int
}

// compareEntries compares the entries of the launch and the closing snapshot.
// A line (status and path) in only one of them is added or gone; a line in both
// is compared by fingerprint. Lines that do not count under the policy are not
// counted as uncompared.
func compareEntries(before, after []TreeEntry, policy TreePolicy) entryDiff {
	var d entryDiff
	was, now := entryFps(before), entryFps(after)
	for _, e := range after {
		if _, ok := was[entryKey{e.Status, e.Path}]; ok {
			continue
		}
		if e.Tracked() {
			d.tracked = append(d.tracked, e.Path)
		} else {
			d.untrackedAdded = append(d.untrackedAdded, e.Path)
		}
	}
	for _, e := range before {
		fpAfter, ok := now[entryKey{e.Status, e.Path}]
		switch {
		case !ok && e.Tracked():
			d.tracked = append(d.tracked, e.Path)
		case !ok:
			d.untrackedGone = append(d.untrackedGone, e.Path)
		default:
			d.compareFingerprints(e, fpAfter, policy)
		}
	}
	return d
}

// compareFingerprints compares one line present at both ends by content. A
// differing fingerprint is an edit, listed wherever the policy counts it; a
// missing one is counted as not compared only for a line that counts.
func (d *entryDiff) compareFingerprints(e TreeEntry, fpAfter string, policy TreePolicy) {
	switch rel := relate(e.Fp, fpAfter); {
	case rel == fpDiffer && e.Tracked():
		d.tracked = append(d.tracked, e.Path)
	case rel == fpDiffer:
		d.untrackedEdited = append(d.untrackedEdited, e.Path)
	case rel == fpUnknown && policy.Counts(e):
		d.uncompared++
	}
}

func capPaths(p []string) ([]string, int) {
	sort.Strings(p)
	out := p[:0:0]
	for i, s := range p {
		if i > 0 && s == p[i-1] {
			continue
		}
		out = append(out, s)
	}
	if len(out) > maxAuditPaths {
		return out[:maxAuditPaths], len(out) - maxAuditPaths
	}
	return out, 0
}

// AuditTree compares the snapshot taken at launch with the one taken at the
// end of the run under the kind's policy. It never reads a snapshot that was
// not taken as clean: an unavailable snapshot is "could not be checked". A
// path present at both ends is compared by its content fingerprint, so a file
// that was already dirty and is edited again is a change. When the comparison
// cannot cover everything the verdict is partly_checked, never no_change; a
// change that is seen reads changed whatever the coverage.
func AuditTree(before, after TreeSnapshot, policy TreePolicy) Audit {
	if policy == TreeNotAudited {
		return Audit{Verdict: AuditNotAudited}
	}
	switch {
	case !before.OK:
		return Audit{Verdict: AuditUnchecked, Reason: ReasonBeforeFailed}
	case !after.OK:
		return Audit{Verdict: AuditUnchecked, Reason: ReasonAfterFailed}
	}
	a := Audit{
		HeadChanged: before.Head != after.Head, BranchChanged: before.Branch != after.Branch,
		StashChanged: before.StashCount != after.StashCount, RefsChanged: before.RefsDigest != after.RefsDigest,
	}
	d := compareEntries(before.Entries, after.Entries, policy)
	var more int
	a.TrackedChanged, a.TrackedMore = capPaths(d.tracked)
	a.UntrackedAdded, a.UntrackedMore = capPaths(d.untrackedAdded)
	a.UntrackedGone, more = capPaths(d.untrackedGone)
	a.UntrackedMore += more
	a.UntrackedEdited, more = capPaths(d.untrackedEdited)
	a.UntrackedMore += more
	a.Uncompared = d.uncompared
	changed := a.HeadChanged || a.BranchChanged || a.StashChanged || a.RefsChanged || len(a.TrackedChanged) > 0
	if policy == TreeStrict && (len(a.UntrackedAdded) > 0 || len(a.UntrackedGone) > 0 || len(a.UntrackedEdited) > 0) {
		changed = true
	}
	switch {
	case changed:
		a.Verdict = AuditChanged
	case before.Truncated || after.Truncated:
		// With paths cut off a difference may be hiding past the cap.
		a.Verdict, a.Reason = AuditPartial, ReasonTruncated
	case a.Uncompared > 0:
		a.Verdict, a.Reason = AuditPartial, ReasonNotFingerprinted
	default:
		a.Verdict = AuditNoChange
	}
	return a
}

// TreeRecord is what a run's tree.json holds: the snapshot taken at launch,
// the one taken at the end and the comparison.
type TreeRecord struct {
	Before *TreeSnapshot `json:"before,omitempty"`
	After  *TreeSnapshot `json:"after,omitempty"`
	Audit  *Audit        `json:"audit,omitempty"`
}

// shrinkSnapshot makes one snapshot smaller. It first drops the content
// fingerprints (every path stays, so an added, removed or re-statused file
// still compares and the entries read as not compared), then entries (and marks
// the snapshot truncated). Either way a later comparison against the shrunk
// snapshot cannot read "no change".
func shrinkSnapshot(s *TreeSnapshot) {
	if hasFingerprints(s.Entries) {
		stripped := make([]TreeEntry, len(s.Entries))
		for i, e := range s.Entries {
			e.Fp = ""
			stripped[i] = e
		}
		s.Entries = stripped
		return
	}
	s.Entries = s.Entries[:len(s.Entries)*3/4]
	s.Truncated = true
}

func hasFingerprints(es []TreeEntry) bool {
	for _, e := range es {
		if e.Fp != "" {
			return true
		}
	}
	return false
}

// FitTreeRecord marshals rec to at most maxBytes, shrinking the longer
// snapshot until it fits: its content fingerprints go first, then its entries
// (and it is marked truncated). The result is always valid JSON; a record whose
// scalars alone do not fit returns an error.
func FitTreeRecord(rec TreeRecord, maxBytes int) ([]byte, error) {
	// The caller's snapshots are not touched: work on copies of the two structs
	// (the entry slices are only re-sliced or replaced, never written in place).
	if rec.Before != nil {
		c := *rec.Before
		rec.Before = &c
	}
	if rec.After != nil {
		c := *rec.After
		rec.After = &c
	}
	for i := 0; i < 64; i++ {
		b, err := json.Marshal(rec)
		if err != nil {
			return nil, err
		}
		if len(b) <= maxBytes {
			return b, nil
		}
		victim := rec.Before
		if rec.After != nil && (victim == nil || len(rec.After.Entries) > len(victim.Entries)) {
			victim = rec.After
		}
		if victim == nil || len(victim.Entries) == 0 {
			return nil, errors.New("secassess.FitTreeRecord: the record does not fit")
		}
		shrinkSnapshot(victim)
	}
	return nil, errors.New("secassess.FitTreeRecord: the record does not fit")
}
