package secverify

import (
	"errors"
	"fmt"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/secchange"
)

// provenance.go is verify's change record step (security plan 7.9 F2 and
// 7.10; lane SEC-F2A): each commit of the pull request is looked up in the
// signed AI change records the repository carries (git notes under
// secchange.NotesRef, read by the caller as data), checked offline against
// a keys file the caller names outside the repository under test (hermetic,
// like the policy), and decided by secchange.DecideCommit. A commit with no
// record is unknown_provenance: a review label by default, a failure only
// when the policy's provenance floor says "fail". A record that is present
// and fails verification (forged, revoked, expired, not matching the
// commit, replayed onto another commit) is verification_failed: named in
// the report and a failure whatever the floor (decision log P-059). The squash
// statement a squash merge of the pull request would carry is derived from
// the verified records. Org mode (orgmode.go, lane SEC-F2B) adds the org's
// keys file and, per commit, the records the org received with its
// countersign; the bounded wait for them is the fetch job's, not this
// step's.

// MaxProvenanceCommits caps the commits one run checks; a longer range
// leaves the rest unchecked, which reads as unknown_provenance.
const MaxProvenanceCommits = 500

// ProvenanceCommit is one pull request commit as the caller read it.
type ProvenanceCommit struct {
	Facts secchange.CommitFacts
	// Notes are the envelope lines of the commit's note ("" note: none).
	Notes [][]byte
	// Trailer is the commit's Assisted-by trailer value, "" when none. A
	// trailer is an unsigned claim: it never verifies a commit, it only
	// names the commit as AI-assisted in the report.
	Trailer string
	// ReadErr is a failure reading this commit's identity or note.
	ReadErr string
	// Path is the repository-relative file the commit's SARIF result is
	// located at (ProvenanceAnchor); "" lets the SARIF writer use
	// ProvenanceFallbackPath.
	Path string
	// IdentityHashes are orgcontract.ChangeMemberEmailHash of the commit's
	// committer and author emails, read in org mode only: when two verified
	// records from two keys speak for the commit, the one whose certified
	// member matches decides (orgResolveClaim, lane SEC-P4 decision 8).
	IdentityHashes []string
	// CommitterHash is the committer's entry of IdentityHashes ("" when not
	// read). When the author and the committer are the certified members of
	// the two keys, the committer's record decides (orgResolveClaim, lane
	// LEFT-SHARED: the committer made the commit object).
	CommitterHash string
}

// ProvenanceInput is the provenance step's input; nil in a Request means
// the step did not run (no keys file named).
type ProvenanceInput struct {
	Trust   secchange.TrustSet
	Commits []ProvenanceCommit
	// Truncated reports a range longer than MaxProvenanceCommits.
	Truncated bool
	// Org is the org mode's input (orgmode.go); nil outside org mode. Trust
	// then already holds the org's keys file.
	Org *OrgProvenance
}

// ProvenanceCommitReport is one commit's line in the report.
type ProvenanceCommitReport struct {
	secchange.CommitOutcome
	Trailer string `json:"trailer,omitempty"`
	// Countersigned: in org mode, the deciding record carries the org's
	// checked receipt.
	Countersigned bool `json:"countersigned,omitempty"`
	// Errors are the record refusals seen (closed reason text only).
	Errors []string `json:"errors,omitempty"`
	// Path is the commit's SARIF anchor (ProvenanceCommit.Path); it is not
	// part of the JSON report.
	Path string `json:"-"`
}

// ProvenanceReport is the provenance step's outcome.
type ProvenanceReport struct {
	Checked  bool                     `json:"checked"`
	Floor    secchange.FloorAction    `json:"floor"`
	Commits  []ProvenanceCommitReport `json:"commits"`
	Verified int                      `json:"verified"`
	Unknown  int                      `json:"unknown"`
	// Failed counts the commits whose record is present and fails
	// verification (decision log P-059).
	Failed    int  `json:"failed"`
	Truncated bool `json:"truncated,omitempty"`
	// Label is "unknown_provenance" when any commit has no verified
	// record: the review label a CI step attaches.
	Label  string                    `json:"label,omitempty"`
	Squash secchange.SquashStatement `json:"squash_statement"`
	// TrustIssues are the keys file entries the trust set dropped.
	TrustIssues []string `json:"trust_issues,omitempty"`
	// Org is the org mode's outcome; nil outside org mode.
	Org *OrgReport `json:"org,omitempty"`
}

// refusalCode is the closed text for a record refusal, so nothing a
// repository controls is echoed into the report (secchange.RefusalCode,
// the one table the node's own record view also names failures with).
func refusalCode(err error) string {
	var oe orgRefusal
	if errors.As(err, &oe) {
		return oe.code
	}
	return secchange.RefusalCode(err)
}

// checkProvenance runs the step.
func checkProvenance(in *ProvenanceInput, floor secchange.FloorAction) ProvenanceReport {
	rep := ProvenanceReport{Checked: true, Floor: floor, Commits: []ProvenanceCommitReport{}, Truncated: in.Truncated}
	if rep.Floor == "" {
		rep.Floor = secchange.FloorLabel
	}
	rep.TrustIssues = in.Trust.Issues
	if in.Org != nil {
		rep.Org = &OrgReport{OrgID: in.Org.OrgID, PolicyVersion: in.Org.PolicyVersion, Lookup: OrgLookupUnavailable}
		if in.Org.Lookup != nil {
			rep.Org.Lookup, rep.Org.AnsweredAt = OrgLookupAnswered, in.Org.Lookup.AnsweredAt
		}
	}
	var outcomes []secchange.CommitOutcome
	for _, c := range in.Commits {
		cr := ProvenanceCommitReport{Trailer: c.Trailer, Path: c.Path}
		var cands []secchange.Candidate
		seen := map[string]bool{}
		if c.ReadErr != "" {
			cr.Errors = append(cr.Errors, "unreadable")
		}
		for _, line := range c.Notes {
			env, err := secchange.ParseEnvelope(line)
			if err == nil {
				var v secchange.Verified
				if v, err = secchange.Verify(env, in.Trust); err == nil {
					seen[v.Digest] = true
					cands = append(cands, secchange.Candidate{Verified: v})
					if code := secchange.BindingRefusal(v.Record.Binding, c.Facts); code != "" {
						cr.Errors = append(cr.Errors, code)
					}
					continue
				}
			}
			cands = append(cands, secchange.Candidate{Err: err})
			cr.Errors = append(cr.Errors, refusalCode(err))
		}
		var countersigned map[string]bool
		envelopeMissing := false
		if in.Org != nil {
			cands, countersigned, envelopeMissing = orgCommit(in.Org, in.Trust, c, &cr, cands, seen, rep.Org)
		}
		cr.CommitOutcome = secchange.DecideCommit(c.Facts, cands)
		if in.Org != nil && cr.Reason == secchange.ReasonReplay {
			if picked, ok := orgResolveClaim(in.Org, c, cands); ok {
				cr.CommitOutcome = secchange.DecideCommit(c.Facts, picked)
				cr.Errors = append(cr.Errors, ReasonClaimByAnotherMember)
			}
		}
		if envelopeMissing && cr.Provenance == secchange.ProvenanceUnknown {
			cr.Reason = ReasonEnvelopeMissing
		}
		if rep.Org != nil && cr.Digest != "" && (cr.Provenance == secchange.ProvenanceVerified || cr.Provenance == secchange.ProvenanceRebased) {
			if countersigned[cr.Digest] {
				cr.Countersigned = true
				rep.Org.Countersigned++
			} else {
				rep.Org.Pending++
			}
		}
		switch cr.Provenance {
		case secchange.ProvenanceUnknown:
			rep.Unknown++
		case secchange.ProvenanceFailed:
			rep.Failed++
		default:
			rep.Verified++
		}
		outcomes = append(outcomes, cr.CommitOutcome)
		rep.Commits = append(rep.Commits, cr)
	}
	if in.Truncated {
		rep.Unknown++
	}
	if rep.Unknown > 0 {
		rep.Label = string(secchange.ProvenanceUnknown)
	}
	head := ""
	if len(in.Commits) > 0 {
		head = in.Commits[0].Facts.SHA
	}
	rep.Squash, _ = secchange.DeriveSquash(head, outcomes)
	return rep
}

// validFloor reports whether a provenance floor is in the vocabulary.
func validFloor(f secchange.FloorAction) bool {
	return f == "" || f == secchange.FloorLabel || f == secchange.FloorFail
}

// PathArgRefusal says why a command-line path argument is refused, "" when
// it may be used (decision log P-005 leftover, task PT-10). A `file:` URI
// is never a path verify opens (fail closed, exit 2), and on a system
// whose paths have no drive letters a value with a colon as its second
// character ("C:x", "c:/x") is a Windows path that cannot name what the
// caller meant. windows reports a Windows host, where a drive letter is an
// ordinary absolute path.
func PathArgRefusal(flag, v string, windows bool) string {
	switch {
	case v == "":
		return ""
	case len(v) >= 5 && strings.EqualFold(v[:5], "file:"):
		return fmt.Sprintf("%s takes a path, not a file: URI", flag)
	case !windows && len(v) >= 2 && v[1] == ':':
		return fmt.Sprintf("%s looks like a Windows drive path (a colon as its second character), which this system cannot open", flag)
	}
	return ""
}
