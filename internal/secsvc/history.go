//go:build !sbo_omit_security

package secsvc

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/gitview"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secdetect"
	"github.com/marmutapp/superbased-observer/internal/secexcept"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/secquickscan"
	"github.com/marmutapp/superbased-observer/internal/secscan"
)

// The on-demand history scan (security pillar plan section 5.3 (f), lane
// sec-c3): the secret rows over the newest commits of HEAD, one commit at
// a time (never the net tree, so a secret added and removed again is still
// found), bounded by a commit cap and a total deadline, through the
// read-only git envelope with the no-lazy-fetch rule of ledger SKILL-2 (a
// partial clone never fetches a missing blob). Every hit is recorded as a
// manual-scope finding through the one findings writer; the same secret in
// many commits stays one finding (its identity is value-keyed).

// History scan bounds.
const (
	// DefaultHistoryCommits is how many commits a history scan reads by
	// default; MaxHistoryCommits is the most it reads.
	DefaultHistoryCommits = 200
	MaxHistoryCommits     = 5000
	// DefaultHistoryDeadline bounds one whole scan.
	DefaultHistoryDeadline = 60 * time.Second
)

// HistoryOptions bounds one history scan.
type HistoryOptions struct {
	// MaxCommits is the newest commits read (0: DefaultHistoryCommits,
	// at most MaxHistoryCommits).
	MaxCommits int
	// Deadline bounds the whole scan (0: DefaultHistoryDeadline).
	Deadline time.Duration
}

// HistoryResult is what one history scan did.
type HistoryResult struct {
	// Commits were read in full; Unknown could not be judged (over the
	// diff cap or the per-commit budget); Remaining were not reached
	// before the deadline.
	Commits   int `json:"commits"`
	Unknown   int `json:"unknown"`
	Remaining int `json:"remaining"`
	// Hits counts blocking secret hits; NewFindings the findings that were
	// new to the store.
	Hits        int `json:"hits"`
	NewFindings int `json:"new_findings"`
}

// Complete reports a scan that read every commit it was asked to.
func (r HistoryResult) Complete() bool { return r.Unknown == 0 && r.Remaining == 0 }

// HistoryDeps are the history scan's injected parts.
type HistoryDeps struct {
	// Git is the read-only envelope used to list the commits (the
	// engine's own Git reads each diff).
	Git GitRunner
	// Engine scans one commit (secquickscan, Form{To: sha}).
	Engine *secquickscan.Engine
	// Store records the findings (RecordRun).
	Store RunStore
	// Now is the clock (default time.Now).
	Now func() time.Time
	// Finding turns a hit into its finding (default secdetect.SecretFinding).
	// LocalHistoryDeps sets OrgKeyMemo.SecretFinding, the path every native
	// secret finding takes, so a history finding carries the org_key its
	// Identify noted (lane LEFT-SHARED merge audit finding 5).
	Finding func(secdetect.FindingInput) (secfinding.Finding, bool)
}

// ScanHistory scans the newest commits of HEAD in the repository at root.
func ScanHistory(ctx context.Context, d HistoryDeps, root string, o HistoryOptions) (HistoryResult, error) {
	var out HistoryResult
	if d.Git == nil || d.Engine == nil || d.Store == nil {
		return out, errors.New("secsvc.ScanHistory: git, engine and store are required")
	}
	now := time.Now
	if d.Now != nil {
		now = d.Now
	}
	n := o.MaxCommits
	if n <= 0 {
		n = DefaultHistoryCommits
	}
	n = min(n, MaxHistoryCommits)
	deadline := o.Deadline
	if deadline <= 0 {
		deadline = DefaultHistoryDeadline
	}
	ctx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()
	list, _, err := d.Git(ctx, root, 64*(n+1), gitTimeout, "rev-list", "--max-count="+strconv.Itoa(n), "HEAD", "--")
	if err != nil {
		return out, fmt.Errorf("secsvc.ScanHistory: no commits git can read: %w", err)
	}
	var shas []string
	for _, s := range strings.Fields(string(list)) {
		if secexcept.CheckBaselineCommit(s) == nil {
			shas = append(shas, s)
		}
	}
	hash := secposture.ProjectRootHash(root)
	finding := d.Finding
	if finding == nil {
		finding = secdetect.SecretFinding
	}
	started := now()
	var fs []secfinding.Finding
	for i, sha := range shas {
		if ctx.Err() != nil {
			out.Remaining = len(shas) - i
			break
		}
		r := d.Engine.Scan(ctx, secquickscan.Request{Root: root, Form: secquickscan.Form{To: sha}})
		switch r.Verdict {
		case secquickscan.VerdictUnknown:
			if ctx.Err() != nil {
				out.Remaining = len(shas) - i
			} else {
				out.Unknown++
			}
		default:
			out.Commits++
		}
		if out.Remaining > 0 {
			break
		}
		for _, f := range r.Findings {
			if fd, ok := finding(secdetect.FindingInput{
				ProjectRootHash: hash, Path: f.Path, Line: f.Line,
				Hit:   secdetect.Hit{Type: f.Type, Line: f.Line, Confidence: f.Confidence, Fixture: f.Fixture, Identity: f.Identity},
				Scope: policy.FindingScopeManual, CommitSHA: sha,
			}); ok {
				fs = append(fs, fd)
				out.Hits++
			}
		}
	}
	cov := secscan.Coverage{Outcome: secscan.OutcomeClean, FilesScanned: out.Commits}
	switch {
	case len(fs) > 0:
		cov.Outcome = secscan.OutcomeFindings
	case !out.Complete():
		cov.Outcome, cov.Reason = secscan.OutcomeUnknown, "history_incomplete"
	}
	res := secscan.Result{Findings: fs, Coverage: cov, Engine: secscan.EngineIdentity{Name: "native"}}
	// The run is recorded with a fresh context: a scan that reached its
	// deadline still records what it found.
	created, err := RecordRun(context.WithoutCancel(ctx), d.Store, secscan.Target{ProjectRoot: root, Scope: policy.FindingScopeManual}, res, started, now().Sub(started), Gone{}, nil)
	if err != nil {
		return out, fmt.Errorf("secsvc.ScanHistory: %w", err)
	}
	out.NewFindings = created
	return out, nil
}

// FindingKeyName is the per-node key a secret finding's identity is keyed
// under, in the owner-only security directory (cmd/observer's daemon uses
// the same name; a test pins the two).
const FindingKeyName = "finding.key"

// LocalHistoryDeps builds the history scan's parts for the node whose
// global config is at resolved: the read-only git envelope with the
// no-lazy-fetch rule (ledger SKILL-2), and the quick-scan engine with the
// secret rows keyed by the node's finding key. Without a readable key the
// scan still runs, but no secret finding is stored (no identity).
func LocalHistoryDeps(resolved, packVersion string, st RunStore) HistoryDeps {
	memo := &OrgKeyMemo{}
	identify, err := SecretIdentify(secposture.LayoutFor(resolved).Dir, memo)
	if err != nil {
		identify = nil
	}
	e := &secquickscan.Engine{
		Git: gitview.RunReadOnlyNoLazyFetch, Version: packVersion, Budget: 10 * time.Second,
		Scanner: secdetect.Scanner{Identify: identify},
	}
	return HistoryDeps{Git: gitview.RunReadOnlyNoLazyFetch, Engine: e, Store: st, Finding: memo.SecretFinding}
}
