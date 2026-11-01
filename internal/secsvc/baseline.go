//go:build !sbo_omit_security

package secsvc

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/secscan"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// The lazy baseline rescan (security pillar plan section 4.5.2 item 2): a
// finding is pre_existing only if the same rule pack, run against the
// baseline commit's tree, reports the same local key. When the pack or
// policy version changes, the daemon re-reads the baseline tree once per
// project and version, on the posture loop, never on the hook path, and
// relabels the project's open findings through the relabel table.

// BaselineStore is the part of the findings store the rescan reads and
// writes (internal/store implements it).
type BaselineStore interface {
	LatestSecBaseline(ctx context.Context, rootHash string) (store.SecBaseline, bool, error)
	SecBaselineScanned(ctx context.Context, rootHash string, b store.SecBaselineScan) (bool, error)
	ListSecFindings(ctx context.Context, f store.SecFindingFilter) ([]secfinding.Finding, error)
	SetSecFindingBaseline(ctx context.Context, id string, b secfinding.Baseline, ref secfinding.BaselineRef) error
	InsertSecScanRun(ctx context.Context, r store.SecScanRun) error
}

// BaselineRescanner runs the lazy baseline rescan.
type BaselineRescanner struct {
	Store BaselineStore
	// Drivers are the drivers that read a commit's tree (their row
	// supports the scheduled scope); the rescan asks each for the baseline
	// commit (Target.HeadRev). None registered: nothing is rescanned.
	Drivers []secscan.Driver
	// PackVersion and PolicyVersion are the versions in force; a change of
	// either makes a project's baseline due again.
	PackVersion   string
	PolicyVersion string
	// Now is the clock (default time.Now).
	Now func() time.Time

	mu sync.Mutex
	// done holds, per project root hash, the rescan already recorded in
	// this process, so a pass costs no store read once it is current.
	done map[string]store.SecBaselineScan
}

// BaselineOutcome is what one project's rescan did.
type BaselineOutcome string

// The BaselineOutcome values.
const (
	BaselineNoBaseline BaselineOutcome = "no_baseline"
	BaselineCurrent    BaselineOutcome = "current"
	BaselineNoDriver   BaselineOutcome = "no_driver"
	BaselineIncomplete BaselineOutcome = "incomplete"
	BaselineRescanned  BaselineOutcome = "rescanned"
)

// BaselineResult is one project's rescan result.
type BaselineResult struct {
	Outcome BaselineOutcome
	// Relabelled counts the findings whose baseline label changed.
	Relabelled int
}

// Rescan rescans one project's baseline if it is due. A run that is not
// complete (a driver error, an outcome other than clean or findings)
// changes no label and is retried at a later pass.
func (b *BaselineRescanner) Rescan(ctx context.Context, projectRoot string) (BaselineResult, error) {
	hash := secposture.ProjectRootHash(projectRoot)
	if hash == "" || b.Store == nil {
		return BaselineResult{}, errors.New("secsvc.Rescan: a project and a store are required")
	}
	if len(b.Drivers) == 0 {
		// Nothing can read a tree: no store read either.
		return BaselineResult{Outcome: BaselineNoDriver}, nil
	}
	now := time.Now
	if b.Now != nil {
		now = b.Now
	}
	base, ok, err := b.Store.LatestSecBaseline(ctx, hash)
	if err != nil {
		return BaselineResult{}, fmt.Errorf("secsvc.Rescan: %w", err)
	}
	if !ok || base.Ref == "" {
		return BaselineResult{Outcome: BaselineNoBaseline}, nil
	}
	want := store.SecBaselineScan{Ref: base.Ref, PackVersion: b.PackVersion, PolicyVersion: b.PolicyVersion}
	if b.isDone(hash, want) {
		return BaselineResult{Outcome: BaselineCurrent}, nil
	}
	if done, err := b.Store.SecBaselineScanned(ctx, hash, want); err != nil {
		return BaselineResult{}, fmt.Errorf("secsvc.Rescan: %w", err)
	} else if done {
		b.markDone(hash, want)
		return BaselineResult{Outcome: BaselineCurrent}, nil
	}
	keys := map[string]bool{}
	for _, d := range b.Drivers {
		started := now()
		res, err := d.Scan(ctx, secscan.Target{ProjectRoot: projectRoot, Scope: policy.FindingScopeScheduled, HeadRev: base.Ref})
		outcome := runOutcome(res.Coverage.Outcome, err)
		complete := outcome == secscan.OutcomeClean || outcome == secscan.OutcomeFindings
		if rerr := b.Store.InsertSecScanRun(ctx, store.SecScanRun{
			ProjectRootHash: hash, Driver: store.SecBaselineDriverPrefix + d.Row().ID, Scope: policy.FindingScopeScheduled,
			Target: want, Coverage: res.Coverage, Engine: res.Engine, Outcome: string(outcome), Findings: len(res.Findings),
			StartedAt: started, Duration: now().Sub(started),
		}); rerr != nil {
			return BaselineResult{}, fmt.Errorf("secsvc.Rescan: %w", rerr)
		}
		if !complete {
			return BaselineResult{Outcome: BaselineIncomplete}, err
		}
		for _, f := range res.Findings {
			keys[f.LocalKey] = true
		}
	}
	open, err := b.Store.ListSecFindings(ctx, store.SecFindingFilter{ProjectRootHash: hash, Status: policy.FindingStatusOpen, Limit: 1000})
	if err != nil {
		return BaselineResult{}, fmt.Errorf("secsvc.Rescan: %w", err)
	}
	ref := secfinding.BaselineRef{Kind: base.Kind, Ref: base.Ref, PackVersion: b.PackVersion, PolicyVersion: b.PolicyVersion}
	out := BaselineResult{Outcome: BaselineRescanned}
	for _, f := range open {
		next := Relabel(f, keys[f.LocalKey])
		if next == f.Baseline {
			continue
		}
		if err := b.Store.SetSecFindingBaseline(ctx, f.ID, next, ref); err != nil {
			return out, fmt.Errorf("secsvc.Rescan: %w", err)
		}
		out.Relabelled++
	}
	b.markDone(hash, want)
	return out, nil
}

// runOutcome is the outcome a baseline run records: failed on a driver
// error, the driver's own outcome when it is one of the closed values, and
// unknown otherwise. Only clean and findings are complete.
func runOutcome(o secscan.Outcome, err error) secscan.Outcome {
	switch {
	case err != nil:
		return secscan.OutcomeFailed
	case o == secscan.OutcomeClean, o == secscan.OutcomeFindings, o == secscan.OutcomeNotScanned, o == secscan.OutcomeFailed:
		return o
	default:
		return secscan.OutcomeUnknown
	}
}

func (b *BaselineRescanner) isDone(hash string, want store.SecBaselineScan) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.done[hash] == want
}

func (b *BaselineRescanner) markDone(hash string, want store.SecBaselineScan) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.done == nil {
		b.done = map[string]store.SecBaselineScan{}
	}
	b.done[hash] = want
}

// relabelRow is one row of the relabel table, walked top to bottom: the
// first row whose when matches decides (CLAUDE.md module rule 5).
type relabelRow struct {
	when func(f secfinding.Finding, atBaseline bool) bool
	// to is the new label; empty keeps the current one.
	to secfinding.Baseline
}

// neverPreExisting are the categories that are never pre_existing (section
// 4.5.2 item 4): a secret is a live credential and a malicious package is
// malware whatever their age.
var neverPreExisting = map[secfinding.Category]bool{
	policy.FindingSecret:           true,
	policy.FindingMaliciousPackage: true,
}

var relabelTable = []relabelRow{
	// A secret or a malicious package is never pre_existing; one that was
	// labelled so becomes new.
	{func(f secfinding.Finding, _ bool) bool {
		return neverPreExisting[f.Category] && f.Baseline == policy.FindingBaselinePreExisting
	}, policy.FindingBaselineNew},
	{func(f secfinding.Finding, _ bool) bool { return neverPreExisting[f.Category] }, ""},
	// The pack reports the same local key at the baseline commit.
	{func(_ secfinding.Finding, at bool) bool { return at }, policy.FindingBaselinePreExisting},
	// Not at the baseline: pre_existing (an older pack's answer), no trusted
	// baseline yet, or unknown all become new.
	{func(f secfinding.Finding, _ bool) bool { return f.Baseline != policy.FindingBaselineNew }, policy.FindingBaselineNew},
	{func(secfinding.Finding, bool) bool { return true }, ""},
}

// Relabel is the baseline label an open finding gets after a complete
// rescan of a trusted baseline: atBaseline reports that the pack reported
// the finding's local key in the baseline commit's tree.
func Relabel(f secfinding.Finding, atBaseline bool) secfinding.Baseline {
	for _, r := range relabelTable {
		if r.when(f, atBaseline) {
			if r.to == "" {
				return f.Baseline
			}
			return r.to
		}
	}
	return f.Baseline
}
