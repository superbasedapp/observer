//go:build !sbo_omit_security

package secsvc

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secciwf"
	"github.com/marmutapp/superbased-observer/internal/secexcept"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/secscan"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// Baseline approval (security pillar plan section 4.5.2 item 1, lane
// sec-c3): the developer approves a commit as the project's starting
// point, from a picker of recent commits with the merge base with the
// default branch proposed first. Git runs only through the injected
// read-only envelope (gitview.RunReadOnlyTimeout in the daemon and the
// CLI), never with a checkout.

// GitRunner is the read-only git envelope: run args in root, at most
// maxBytes of output (truncated reports a cut), within timeout.
type GitRunner func(ctx context.Context, root string, maxBytes int, timeout time.Duration, args ...string) (out []byte, truncated bool, err error)

// gitTimeout bounds one git call of the approval flow and the baseline
// driver.
const gitTimeout = 10 * time.Second

// ErrBadRef reports a ref that cannot name a commit safely.
var ErrBadRef = errors.New("a commit, branch or tag name, not an option")

// ResolveCommit resolves ref (a commit id, branch or tag) to the full id
// of the commit it names.
func ResolveCommit(ctx context.Context, git GitRunner, root, ref string) (string, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" || strings.HasPrefix(ref, "-") || strings.ContainsAny(ref, "\x00\n\r") {
		return "", ErrBadRef
	}
	out, _, err := git(ctx, root, 256, gitTimeout, "rev-parse", "--verify", "--quiet", ref+"^{commit}")
	if err != nil {
		return "", fmt.Errorf("secsvc.ResolveCommit: %q is not a commit in this repository", ref)
	}
	sha := strings.TrimSpace(string(out))
	if err := secexcept.CheckBaselineCommit(sha); err != nil {
		return "", fmt.Errorf("secsvc.ResolveCommit: %w", err)
	}
	return sha, nil
}

// logFormat is one commit per record: id, committer date, subject.
const logFormat = "--format=%H%x00%cI%x00%s%x1e"

func parseCommits(out []byte) []secexcept.Commit {
	var cs []secexcept.Commit
	for _, rec := range bytes.Split(out, []byte{0x1e}) {
		parts := strings.SplitN(strings.TrimSpace(string(rec)), "\x00", 3)
		if len(parts) != 3 {
			continue
		}
		when, _ := time.Parse(time.RFC3339, parts[1])
		cs = append(cs, secexcept.Commit{SHA: parts[0], When: when.UTC(), Subject: parts[2]})
	}
	return cs
}

// defaultBranchCandidates are tried, in order, for the merge base when the
// remote's HEAD is not recorded.
var defaultBranchCandidates = []string{"origin/main", "origin/master", "main", "master"}

// ProposeBaseline returns the baseline picker for the repository at root:
// the merge base of HEAD with the default branch first (when one is
// found), then the 20 newest commits of HEAD.
func ProposeBaseline(ctx context.Context, git GitRunner, root string) ([]secexcept.Commit, error) {
	out, _, err := git(ctx, root, 64<<10, gitTimeout, "log", "-n", "20", logFormat, "HEAD", "--")
	if err != nil {
		return nil, fmt.Errorf("secsvc.ProposeBaseline: no commits to propose: %w", err)
	}
	recent := parseCommits(out)
	var mb secexcept.Commit
	branches := defaultBranchCandidates
	if head, _, err := git(ctx, root, 256, gitTimeout, "symbolic-ref", "--quiet", "--short", "refs/remotes/origin/HEAD"); err == nil {
		if b := strings.TrimSpace(string(head)); b != "" && !strings.HasPrefix(b, "-") {
			branches = append([]string{b}, branches...)
		}
	}
	for _, b := range branches {
		base, _, err := git(ctx, root, 256, gitTimeout, "merge-base", "HEAD", b)
		if err != nil {
			continue
		}
		sha := strings.TrimSpace(string(base))
		if secexcept.CheckBaselineCommit(sha) != nil {
			continue
		}
		one, _, err := git(ctx, root, 4<<10, gitTimeout, "log", "-n", "1", logFormat, sha, "--")
		if err != nil {
			continue
		}
		if cs := parseCommits(one); len(cs) == 1 {
			mb = cs[0]
		}
		break
	}
	return secexcept.Propose(mb, recent), nil
}

// BaselineWriter is the part of the store a baseline approval writes.
type BaselineWriter interface {
	AddSecBaseline(ctx context.Context, b store.SecBaseline) error
	LatestSecBaseline(ctx context.Context, rootHash string) (store.SecBaseline, bool, error)
}

// ApproveBaseline records ref, resolved to a full commit id in the
// repository at root, as the project's baseline, with who approved it and
// the rule pack in force. The lazy rescan relabels the open findings at
// the next posture pass; secrets and malicious packages stay new.
func ApproveBaseline(ctx context.Context, git GitRunner, w BaselineWriter, root, ref string, origin secexcept.Origin, packVersion string, now time.Time) (store.SecBaseline, error) {
	if origin != secexcept.OriginCLI && origin != secexcept.OriginDashboard {
		return store.SecBaseline{}, errors.New("secsvc.ApproveBaseline: a baseline is approved only by the developer, from the CLI or the dashboard")
	}
	sha, err := ResolveCommit(ctx, git, root, ref)
	if err != nil {
		return store.SecBaseline{}, err
	}
	b := store.SecBaseline{
		ProjectRootHash: secposture.ProjectRootHash(root), Kind: "commit", Ref: sha, Approver: string(origin),
		PackVersion: packVersion, CreatedAt: now.UTC(),
	}
	if err := w.AddSecBaseline(ctx, b); err != nil {
		return store.SecBaseline{}, fmt.Errorf("secsvc.ApproveBaseline: %w", err)
	}
	return b, nil
}

// ErrBaselineNotOffered refuses an approval of a commit the picker does not
// offer.
var ErrBaselineNotOffered = errors.New("secsvc: the commit is not one the baseline picker offers (the merge base or the 20 newest commits of HEAD)")

// ApproveOfferedBaseline is the dashboard's approval (lane sec-gate2,
// decision log P-025, ledger SECP-23): sha is approved only when the
// picker offers it now (ProposeBaseline), so the page can approve only a
// commit it showed, never an arbitrary full commit id.
func ApproveOfferedBaseline(ctx context.Context, git GitRunner, w BaselineWriter, root, sha string, origin secexcept.Origin, packVersion string, now time.Time) (store.SecBaseline, error) {
	offered, err := ProposeBaseline(ctx, git, root)
	if err != nil {
		return store.SecBaseline{}, err
	}
	for _, c := range offered {
		if c.SHA == sha {
			return ApproveBaseline(ctx, git, w, root, sha, origin, packVersion, now)
		}
	}
	return store.SecBaseline{}, ErrBaselineNotOffered
}

// ResetBaseline records a reset: the project has no trusted baseline until
// another commit is approved. A reset relabels nothing by itself (section
// 4.5.2 item 5).
func ResetBaseline(ctx context.Context, w BaselineWriter, root string, origin secexcept.Origin, now time.Time) error {
	if origin != secexcept.OriginCLI && origin != secexcept.OriginDashboard {
		return errors.New("secsvc.ResetBaseline: a baseline is reset only by the developer, from the CLI or the dashboard")
	}
	return w.AddSecBaseline(ctx, store.SecBaseline{
		ProjectRootHash: secposture.ProjectRootHash(root), Kind: "reset", Approver: string(origin), CreatedAt: now.UTC(),
	})
}

// WorkflowBaselineDriver is the native driver the lazy baseline rescan
// asks to read a baseline commit's tree: it runs the CI workflow rules
// (S-771 to S-778, internal/secciwf) over the workflow files at the commit
// through blob reads, no checkout. Its findings carry the same local key
// the commit scan gives a workflow rule hit (WorkflowFindingKey), so a hit
// present at the baseline becomes pre_existing.
type WorkflowBaselineDriver struct {
	Git GitRunner
}

// maxBaselineWorkflows bounds the workflow files one baseline run reads.
const maxBaselineWorkflows = 64

// WorkflowFindingKey is the local key of a workflow rule hit: the rule
// ("ci." + the lowercased rule id) and the workflow file, never the line.
// cmd/observer's commit-scan finding uses the same key (a test pins it).
func WorkflowFindingKey(rootHash, ruleID, rel string) string {
	return secfinding.LocalKey(rootHash, "ci."+strings.ToLower(ruleID), secfinding.TextIdentity(rel))
}

// Row is the driver's registry row.
func (d WorkflowBaselineDriver) Row() secscan.DriverRow {
	return secscan.DriverRow{
		ID: "native.workflow_baseline", Kind: secscan.KindNative, ComponentID: "security.code",
		Categories: []secfinding.Category{policy.FindingCIConfig},
		Triggers:   []secfinding.Scope{policy.FindingScopeScheduled},
		Licence:    "first-party",
	}
}

// Probe reports the driver ready: it needs only the git envelope.
func (d WorkflowBaselineDriver) Probe(context.Context) secscan.Probe {
	return secscan.Probe{Installed: d.Git != nil, Verified: d.Git != nil, Platform: secscan.SupportSupported}
}

// Scan reads the workflow files of t.HeadRev and reports every rule hit.
// A file over the cap or not parsable is a skip (its hits stay new, never
// pre_existing); a git failure fails the run, which is retried later.
func (d WorkflowBaselineDriver) Scan(ctx context.Context, t secscan.Target) (secscan.Result, error) {
	res := secscan.Result{Engine: secscan.EngineIdentity{Name: "native"}}
	if d.Git == nil || secexcept.CheckBaselineCommit(t.HeadRev) != nil {
		res.Coverage = secscan.Coverage{Outcome: secscan.OutcomeNotScanned, Reason: "no_commit"}
		return res, nil
	}
	out, truncated, err := d.Git(ctx, t.ProjectRoot, 256<<10, gitTimeout, "ls-tree", "-r", "-z", "--name-only", t.HeadRev, "--", ".github/workflows")
	if err != nil {
		res.Coverage = secscan.Coverage{Outcome: secscan.OutcomeFailed, Reason: "git_unavailable"}
		return res, fmt.Errorf("secsvc.WorkflowBaselineDriver: %w", err)
	}
	hash := secposture.ProjectRootHash(t.ProjectRoot)
	cov := secscan.Coverage{Truncated: truncated}
	for _, rel := range strings.Split(string(out), "\x00") {
		if rel == "" || !secciwf.IsWorkflowPath(rel) {
			continue
		}
		if cov.FilesScanned >= maxBaselineWorkflows {
			cov.Skipped = append(cov.Skipped, secscan.Skip{Path: rel, Reason: "file_cap"})
			continue
		}
		blob, over, err := d.Git(ctx, t.ProjectRoot, secciwf.MaxWorkflowBytes+1, gitTimeout, "cat-file", "blob", t.HeadRev+":"+rel)
		if err != nil {
			res.Coverage = secscan.Coverage{Outcome: secscan.OutcomeFailed, Reason: "git_unavailable"}
			return res, fmt.Errorf("secsvc.WorkflowBaselineDriver: %w", err)
		}
		rep := secciwf.Check(blob)
		if over || !rep.Complete() {
			cov.Skipped = append(cov.Skipped, secscan.Skip{Path: rel, Reason: "not_parsed"})
			continue
		}
		cov.FilesScanned++
		for _, h := range rep.Findings {
			res.Findings = append(res.Findings, secfinding.Finding{
				LocalKey: WorkflowFindingKey(hash, h.RuleID, rel),
				Location: secfinding.Location{RelPath: rel, StartLine: h.Line, EndLine: h.Line},
				Rule:     secfinding.Rule{ID: "ci." + strings.ToLower(h.RuleID), Pack: "security.code"},
				Category: policy.FindingCIConfig, Scope: policy.FindingScopeScheduled,
				Project: secfinding.Project{RootHash: hash},
			})
		}
	}
	cov.Outcome = secscan.OutcomeClean
	if len(res.Findings) > 0 {
		cov.Outcome = secscan.OutcomeFindings
	}
	res.Coverage = cov
	return res, nil
}

// ApprovedBaseline is a project's current baseline as the CLI and the
// dashboard show it.
type ApprovedBaseline struct {
	Kind      string    `json:"kind"`
	Ref       string    `json:"ref"`
	Approver  string    `json:"approver"`
	CreatedAt time.Time `json:"created_at"`
	// OrgApprovedAt is when the node's org approved this same reference,
	// as its security managed pull last served it (lane LEFT-SHARED); ""
	// when it did not, or on an individual node. A label only: nothing
	// decides on it.
	OrgApprovedAt string `json:"org_approved_at,omitempty"`
}

// OrgBaselineApprovals is the optional reader LoadBaselineView labels a
// baseline with (the store implements it where the security module is
// built): when the org approved the project's reference kind/ref.
type OrgBaselineApprovals interface {
	SecOrgBaselineApproval(ctx context.Context, rootHash, kind, ref string) (approvedAt string, ok bool, err error)
}

// BaselineView is one project's baseline: the current one (nil when there
// is no trusted baseline) and the picker.
type BaselineView struct {
	ProjectRootHash string             `json:"project_root_hash"`
	Current         *ApprovedBaseline  `json:"current"`
	Proposed        []secexcept.Commit `json:"proposed"`
	// ProposalError says why no commit is offered.
	ProposalError string `json:"proposal_error,omitempty"`
}

// LoadBaselineView reads the project's current baseline and builds the
// picker. A repository git cannot read gives an empty picker with a
// reason, not an error.
func LoadBaselineView(ctx context.Context, git GitRunner, r BaselineWriter, root string) (BaselineView, error) {
	hash := secposture.ProjectRootHash(root)
	v := BaselineView{ProjectRootHash: hash, Proposed: []secexcept.Commit{}}
	b, ok, err := r.LatestSecBaseline(ctx, hash)
	if err != nil {
		return v, fmt.Errorf("secsvc.LoadBaselineView: %w", err)
	}
	if ok {
		v.Current = &ApprovedBaseline{Kind: b.Kind, Ref: b.Ref, Approver: b.Approver, CreatedAt: b.CreatedAt}
		// The org's approval of this reference is a label; an unreadable
		// approval leaves the baseline unlabelled, never an error.
		if oa, isOA := r.(OrgBaselineApprovals); isOA {
			if at, approved, aerr := oa.SecOrgBaselineApproval(ctx, hash, b.Kind, b.Ref); aerr == nil && approved {
				v.Current.OrgApprovedAt = at
			}
		}
	}
	proposed, err := ProposeBaseline(ctx, git, root)
	if err != nil {
		v.ProposalError = "the repository has no commits git can read"
		return v, nil
	}
	v.Proposed = proposed
	return v, nil
}
