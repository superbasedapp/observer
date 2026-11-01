package secdetect

import (
	"strconv"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
)

// SecretRulePrefix prefixes a detector type into a finding rule id
// ("secret.aws_access_key"); finding rule ids are never guard ids.
const SecretRulePrefix = "secret."

// SecretFixHint is the fixed fix hint of a secret finding.
const SecretFixHint = "Move the value to an environment variable or a secret store, then rotate it: a secret that reached a file may already be in a commit or a log." //nolint:gosec // G101: advice wording, not a credential

// FindingInput is one blocking secret hit, located, for SecretFinding.
type FindingInput struct {
	// ProjectRootHash is secposture.ProjectRootHash of the project.
	ProjectRootHash string
	// Path is project-relative and slash-separated.
	Path string
	Line int
	Hit  Hit
	// Scope says where the hit was found (post-write, commit, push).
	Scope policy.FindingScope
	// SessionID and ActionID tie a post-write finding to its write.
	SessionID string
	ActionID  int64
	// CommitSHA is the commit a commit-scan hit landed in ("" otherwise).
	CommitSHA string
}

// SecretFinding builds the normalized finding of one blocking secret hit:
// category secret, severity high, high confidence, baseline new, keyed by
// the hit's value-free identity so the same secret in another file or on
// another line keeps one finding. ok is false for a hit that does not
// block, that has no identity (no Identify was set) or no project: such a
// hit is never stored. The message and fix hint are fixed text; nothing
// from the file reaches the finding but its path and line.
func SecretFinding(in FindingInput) (secfinding.Finding, bool) {
	if !in.Hit.Blocking() || in.Hit.Identity == "" || in.ProjectRootHash == "" || in.Hit.Type == "" {
		return secfinding.Finding{}, false
	}
	rule := SecretRulePrefix + in.Hit.Type
	f := secfinding.Finding{
		LocalKey:   secfinding.LocalKey(in.ProjectRootHash, rule, secfinding.MatchIdentity{Kind: secfinding.MatchSecret, Value: in.Hit.Identity}),
		Location:   secfinding.Location{RelPath: in.Path, StartLine: in.Line, EndLine: in.Line},
		Rule:       secfinding.Rule{ID: rule, Pack: "security.secrets"},
		Engine:     secfinding.Engine{Driver: "native"},
		Category:   policy.FindingSecret,
		Severity:   policy.FindingSeverityHigh,
		Confidence: policy.FindingConfidenceHigh,
		Scope:      in.Scope,
		Project:    secfinding.Project{RootHash: in.ProjectRootHash},
		Message:    "A " + in.Hit.Type + " secret is in this file.",
		FixHint:    SecretFixHint,
		Baseline:   policy.FindingBaselineNew,
		Lineage:    secfinding.Lineage{SessionID: in.SessionID},
		Commit:     secfinding.Commit{SHA: in.CommitSHA},
		Status:     policy.FindingStatusOpen,
	}
	if in.ActionID > 0 {
		f.Lineage.ActionID = strconv.FormatInt(in.ActionID, 10)
	}
	return secfinding.Normalize(f), true
}
