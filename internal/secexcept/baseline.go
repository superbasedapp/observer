package secexcept

import (
	"errors"
	"strings"
	"time"
	"unicode"
)

// Baselines (security pillar plan section 4.5.2): on an individual node a
// baseline is a commit the developer approves ("treat the code at this
// commit as my starting point"), offered as a picker of recent commits
// with the merge base with the default branch proposed first. A finding
// becomes pre_existing only when the same rule pack, run over the
// baseline commit's tree, reports the same local key (the lazy rescan in
// internal/secsvc); secrets and malicious packages never do.

// ErrBaselineCommit reports a baseline ref that is not a full commit id.
var ErrBaselineCommit = errors.New("a baseline is a full commit id (40 or 64 lowercase hex characters), resolved by git")

// CheckBaselineCommit accepts only a full, lowercase commit id: a branch
// name, a short id or an expression is resolved by the caller through git
// first, so the record names exactly one commit.
func CheckBaselineCommit(sha string) error {
	if len(sha) != 40 && len(sha) != 64 {
		return ErrBaselineCommit
	}
	for _, c := range sha {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return ErrBaselineCommit
		}
	}
	return nil
}

// Commit is one commit the picker offers.
type Commit struct {
	SHA     string    `json:"sha"`
	When    time.Time `json:"when"`
	Subject string    `json:"subject"`
	// MergeBase marks the merge base with the default branch, the
	// proposed baseline.
	MergeBase bool `json:"merge_base"`
}

// MaxProposed is the most commits the picker offers.
const MaxProposed = 20

// maxSubject is the most characters of a commit subject the picker shows
// (repository-controlled text, shown as data).
const maxSubject = 80

// Propose builds the baseline picker: the merge base first (when known),
// then the recent commits newest first, without duplicates, at most
// MaxProposed, every subject cut and stripped of control characters.
func Propose(mergeBase Commit, recent []Commit) []Commit {
	var out []Commit
	seen := map[string]bool{}
	add := func(c Commit, mb bool) {
		if CheckBaselineCommit(c.SHA) != nil || seen[c.SHA] || len(out) >= MaxProposed {
			return
		}
		seen[c.SHA] = true
		c.MergeBase = mb
		c.Subject = SafeSubject(c.Subject)
		out = append(out, c)
	}
	if mergeBase.SHA != "" {
		add(mergeBase, true)
	}
	for _, c := range recent {
		add(c, false)
	}
	return out
}

// SafeSubject is a commit subject as a picker shows it: control and
// format characters dropped, cut to 80 characters.
func SafeSubject(s string) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			continue
		}
		if n == maxSubject {
			b.WriteString("...")
			break
		}
		b.WriteRune(r)
		n++
	}
	return b.String()
}
