package main

import (
	"context"
	"sort"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/policystate"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// Gen3 guard-row inputs for the policy-state report (T-846 / T-848, guard
// tamper visibility audit 2026-10-15 rows b2 and a2): the on-disk org bundle
// re-verification and the EFFECTIVE local guard configuration as the hook
// path resolves it.

// guardBundleVerifier is the on-disk bundle seam (satisfied by
// *orgclient.Client). An interface so the reporter tests run with a fake.
type guardBundleVerifier interface {
	VerifyCachedPolicyBundle(ctx context.Context, cachePath string) (orgclient.CachedBundleCheck, error)
	KickPolicyBundlePoll()
}

// guardBundleCheck is the guard reader's view of the on-disk bundle: the
// version it claims, the integrity verdict, and the gen1 reject reason for a
// tampered file.
type guardBundleCheck struct {
	Version    int64
	Integrity  string
	RejectCode string
}

// guardBundleCheckFrom re-verifies the bundle at cachePath through v on every
// report. A tampered file kicks the policy poll so the repair (a
// re-download, which a tampered file can no longer 304 its way out of) runs
// now rather than at the next hourly poll. A genuine read/store error is
// returned so the reader errors and the snapshot is skipped (never a
// fabricated "tampered" on an I/O hiccup).
//
// With no verifier (a test poster, or a client that predates it) it falls
// back to the pre-gen3 envelope-version read and reports no integrity.
func guardBundleCheckFrom(v guardBundleVerifier, cachePath string) func(ctx context.Context) (guardBundleCheck, error) {
	if v == nil || cachePath == "" {
		legacy := guardCachedVersionFromFile(cachePath)
		return func(context.Context) (guardBundleCheck, error) {
			ver, err := legacy()
			return guardBundleCheck{Version: ver}, err
		}
	}
	return func(ctx context.Context) (guardBundleCheck, error) {
		c, err := v.VerifyCachedPolicyBundle(ctx, cachePath)
		if err != nil {
			return guardBundleCheck{}, err
		}
		out := guardBundleCheck{Integrity: c.Integrity}
		switch c.Integrity {
		case orgcontract.BundleIntegrityVerified:
			out.Version = c.Version
		case orgcontract.BundleIntegrityTampered:
			out.Version = c.Version
			out.RejectCode = string(c.RejectCode)
			v.KickPolicyBundlePoll()
		case orgcontract.BundleIntegrityMissing:
			// A deleted bundle (T-864 gap 1): the file is gone, so the poll
			// sends no If-None-Match and downloads it again now.
			v.KickPolicyBundlePoll()
		}
		return out, nil
	}
}

// hookGuardConfig resolves the [guard] configuration the report describes
// for a given loaded config. config.Load already applies the managed-node
// floor (D-672, internal/config guardfloor.go), so the loaded switches are
// what the hook enforces; the report instead carries the switches the LOCAL
// config set (GuardConfig.WithLocalSwitches, the pre-floor snapshot), so a
// local weakening the floor overrode still reaches the organization as a
// local_weakening finding (an attempt, not a gap). Per-detector modes and
// the allow-list are never floored in config (the guard floors them per
// rule), so they are reported as the local config set them either way.
var hookGuardConfig = func(cfg config.Config) config.GuardConfig { return cfg.Guard.WithLocalSwitches() }

// localGuardPostureFrom projects a resolved [guard] config onto the gen3
// wire shape: bools, closed enums, the detector ids whose EFFECTIVE mode
// differs from the global prompt mode (resolved through
// guard.EffectivePromptMode, the same rule the hook evaluates), and the
// allow-list COUNT. The allow-list's regex text never leaves this function.
func localGuardPostureFrom(gc config.GuardConfig) *orgcontract.LocalGuardPosture {
	p := &orgcontract.LocalGuardPosture{
		Enabled:        gc.Enabled,
		Mode:           policystate.NormalizeMode(gc.Mode),
		PromptEnabled:  gc.Prompt.Enabled,
		PromptMode:     gc.Prompt.Mode,
		AllowListCount: len(gc.Prompt.Allow),
	}
	if !orgcontract.LocalGuardPromptModeKnown(p.PromptMode) {
		// The config loader rejects an unknown mode, so this is a
		// hand-built config; report the fail-closed reading the guard uses.
		p.PromptMode = "off"
	}
	ids := make([]string, 0, len(gc.Prompt.Detectors))
	for id := range gc.Prompt.Detectors {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		eff := string(guard.EffectivePromptMode(gc.Prompt.Mode, gc.Prompt.Detectors, id))
		if eff == p.PromptMode {
			continue
		}
		if p.DetectorModes == nil {
			p.DetectorModes = map[string]string{}
		}
		p.DetectorModes[id] = eff
	}
	return p
}

// guardTamperCounter is the store seam guardTamperFromStore reads (satisfied
// by *store.Store): the guard_error rows the daemon's posture loop wrote when
// it repaired an org-held guard file, grouped by kind.
type guardTamperCounter interface {
	HookFailureCounts(ctx context.Context, ruleID string, kinds []string, since time.Time) ([]store.HookFailureCount, error)
}

// guardTamperFromStore summarises the org-held guard files the daemon found
// changed or removed outside it and repaired in the last
// orgcontract.GuardTamperWindow (T-864 gap 4). The repair is fast, so by the
// next report the file verifies again; this record is what keeps the event on
// the organization's side. The source is the node's own guard_events (the
// high guard_error rows the posture loop records, one per repair), so a
// daemon restart does not erase it. A read error reports nil (not reported)
// rather than failing the snapshot.
func guardTamperFromStore(st guardTamperCounter, now func() time.Time) func(ctx context.Context) *orgcontract.GuardTamperReport {
	return func(ctx context.Context) *orgcontract.GuardTamperReport {
		if st == nil {
			return nil
		}
		at := now().UTC()
		counts, err := st.HookFailureCounts(ctx, guard.GuardErrorRuleID, orgcontract.GuardTamperKinds(), at.Add(-orgcontract.GuardTamperWindow))
		if err != nil {
			return nil
		}
		return guardTamperReportOf(counts)
	}
}

// guardTamperReportOf folds per-kind counts into the wire report: the total,
// and the newest repair's time and kind (ties broken by kind for a stable
// report). nil when nothing was repaired.
func guardTamperReportOf(counts []store.HookFailureCount) *orgcontract.GuardTamperReport {
	var out orgcontract.GuardTamperReport
	var last time.Time
	for _, c := range counts {
		if !orgcontract.GuardTamperKindKnown(c.Kind) || c.Count <= 0 {
			continue
		}
		out.Repairs += c.Count
		if c.LastAt.After(last) || (c.LastAt.Equal(last) && c.Kind < out.LastKind) {
			last, out.LastKind = c.LastAt, c.Kind
		}
	}
	if out.Repairs == 0 || last.IsZero() {
		return nil
	}
	out.LastAt = last.UTC().Format(time.RFC3339)
	return &out
}

// guardTamperSource adapts a possibly-nil store to the counter seam (a nil
// *store.Store must become a nil interface, not a typed nil).
func guardTamperSource(st *store.Store) guardTamperCounter {
	if st == nil {
		return nil
	}
	return st
}

// withGuardTamper decorates the guard point reader with the gen4 tamper
// record (T-864). A separate decorator so the guard reader's own inputs stay
// as they were.
func withGuardTamper(r policystate.PointReader, tamper func(ctx context.Context) *orgcontract.GuardTamperReport) policystate.PointReader {
	if tamper == nil {
		return r
	}
	return func(ctx context.Context) (policystate.PointFacts, error) {
		f, err := r(ctx)
		if err != nil {
			return f, err
		}
		f.GuardTamper = tamper(ctx)
		return f, nil
	}
}

// withProjectSectionStatus decorates the guard point reader with the gen5
// per-section project policy status (lane sec-p2b): status(now) is the
// guard's read accessor over the cached mapping, envelopes and the daemon's
// match records, already capped and checked against the server's rule
// (guard.OrgProjectSectionReport), so a list the server would refuse never
// reaches the wire. nil leaves the reader unchanged.
func withProjectSectionStatus(r policystate.PointReader, status func() guard.ProjectSectionReport) policystate.PointReader {
	if status == nil {
		return r
	}
	return func(ctx context.Context) (policystate.PointFacts, error) {
		f, err := r(ctx)
		if err != nil {
			return f, err
		}
		rep := status()
		f.ProjectSectionStatus, f.ProjectSectionTruncated = rep.Sections, rep.Truncated
		return f, nil
	}
}

// withProjectFamilyStatus decorates the guard point reader with the gen6
// project family section status (lane sec-p3): status() is the security
// module's report (security_scanning_project.go), already capped and checked
// against the server's rule; a cut list sets the gen7 family truncation flag
// (lane SEC-P4 decision 11; it shared the section flag before). nil leaves
// the reader unchanged (a build without the security module).
func withProjectFamilyStatus(r policystate.PointReader, status func() ([]orgcontract.ProjectFamilySectionState, bool)) policystate.PointReader {
	if status == nil {
		return r
	}
	return func(ctx context.Context) (policystate.PointFacts, error) {
		f, err := r(ctx)
		if err != nil {
			return f, err
		}
		list, truncated := status()
		f.ProjectFamilyStatus, f.ProjectFamilyTruncated = list, truncated
		return f, nil
	}
}

// projectSectionStatusFrom reads the per-section status from the daemon's
// live guard (nil guard: not reported).
func projectSectionStatusFrom(g *guard.Guard, now func() time.Time) func() guard.ProjectSectionReport {
	if g == nil {
		return nil
	}
	return func() guard.ProjectSectionReport { return g.OrgProjectSectionReport(now(), nil) }
}

// localGuardPostureFromDisk re-reads the node config the way the hook does
// (config.Load on the daemon's config path) on every report, so a local
// edit made after the daemon started (the a2 tamper: no restart needed for
// the hook to pick it up) is what gets reported. A load error reports nil
// (not reported) rather than a guess.
func localGuardPostureFromDisk(configPath func() string) func() *orgcontract.LocalGuardPosture {
	return func() *orgcontract.LocalGuardPosture {
		cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath()})
		if err != nil {
			return nil
		}
		return localGuardPostureFrom(hookGuardConfig(cfg))
	}
}
