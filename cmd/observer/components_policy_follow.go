package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/components"
	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/componentsvc"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/policyfam/nodecomponents"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// components_policy_follow.go is the daemon's follow-up of a node.components
// policy change (modular packaging plan 6.3, T-682). The daemon resolves its
// component set once at start; every short-lived process already follows a
// new policy at once. This loop closes the remaining gap for the daemon
// without restarting anything:
//
//   - live teardown: a component the policy in force newly blocks, with
//     on_remove.teardown "auto", has its catalog teardown run at once (hooks,
//     MCP entries, proxy routes and other vendor config it wrote come out,
//     through the same clientwire removers `observer components teardown`
//     uses). Its in-process background work stops at the daemon's next
//     restart, and the loop says so ("removal pending restart");
//   - scheduled purge: componentsvc.RunScheduledPurges, when the policy
//     authorises it (on_remove.data "purge" with purge_after_days > 0).
//
// It only ever acts on what the org's verified policy blocks (reasons
// policy_denied and policy_unlisted), never on a local selection, and an
// individual node (no policy in force) does nothing.

// componentPolicyFollowEvery is the pass interval.
const componentPolicyFollowEvery = 10 * time.Minute

// componentPolicyFollower holds the loop's in-memory state.
type componentPolicyFollower struct {
	configPath string
	st         *store.Store
	logger     *slog.Logger
	// tornDown are components whose teardown already ran in this process (or
	// that were inactive at start, when start-time wiring already skipped
	// them); a component is torn down live at most once per process.
	tornDown map[string]bool
	// resolve and teardown are seams for tests.
	resolve  func(ctx context.Context, cfg config.Config) (componentstate.Snapshot, nodecomponents.Outcome)
	teardown func(ctx context.Context, ids []string) ([]componentsvc.StepOutcome, error)
	now      func() time.Time
	// liveSandboxed is the live sandboxed run count (the live-run gate's
	// source); a blocked sandbox component's teardown waits while it is
	// above zero (deferred_live_sandbox, SBX-UPD-1). waiting holds the ids
	// already reported as waiting, so the audit row is written once.
	liveSandboxed func() int
	waiting       map[string]bool
}

// newComponentPolicyFollower builds the follower; start is the daemon's
// start-time snapshot.
func newComponentPolicyFollower(configPath string, st *store.Store, start componentstate.Snapshot, logger *slog.Logger) *componentPolicyFollower {
	if logger == nil {
		logger = slog.Default()
	}
	f := &componentPolicyFollower{
		configPath: configPath, st: st, logger: logger, tornDown: map[string]bool{}, now: time.Now,
		liveSandboxed: liveSandboxedNow, waiting: map[string]bool{},
	}
	for _, id := range start.Inactive() {
		f.tornDown[id] = true
	}
	f.resolve = func(ctx context.Context, cfg config.Config) (componentstate.Snapshot, nodecomponents.Outcome) {
		g, out := componentGovernanceWithOutcome(ctx, cfg)
		return componentstate.ResolveGoverned(cfg.Components, nil, g), out
	}
	f.teardown = func(ctx context.Context, ids []string) ([]componentsvc.StepOutcome, error) {
		svc, err := newComponentsService(configPath, nil)
		if err != nil {
			return nil, err
		}
		return svc.RunTeardown(ctx, ids, false)
	}
	return f
}

// run loops until ctx ends, one pass at start and every interval.
func (f *componentPolicyFollower) run(ctx context.Context) {
	t := time.NewTicker(componentPolicyFollowEvery)
	defer t.Stop()
	for {
		f.pass(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// holdForLiveRuns takes the sandbox components out of fresh while sandboxed
// runs are live: their teardown waits for the runs (the gate's
// org_policy_teardown row answers defer), never ending a run silently. The
// wait is logged and audited once as deferred_live_sandbox; the next pass
// after the runs end tears them down.
func (f *componentPolicyFollower) holdForLiveRuns(ctx context.Context, fresh []string) []string {
	held := liveRunHeldIDs(fresh)
	if len(held) == 0 || f.liveSandboxed == nil {
		return fresh
	}
	n := f.liveSandboxed()
	if liveRunGate(liveRunTriggerPolicyTeardown, n, "") == liveRunProceed {
		return fresh
	}
	var keep, newlyWaiting []string
	for _, id := range fresh {
		if !liveRunHoldsComponent(id) {
			keep = append(keep, id)
			continue
		}
		if !f.waiting[id] {
			f.waiting[id] = true
			newlyWaiting = append(newlyWaiting, id)
		}
	}
	if len(newlyWaiting) > 0 {
		f.logger.Warn("components: the organization's policy blocks sandbox components; their teardown waits for the live sandboxed runs (deferred_live_sandbox)",
			"ids", strings.Join(newlyWaiting, ","), "live", n)
		f.audit(ctx, "components.policy.teardown", "deferred_live_sandbox ids="+strings.Join(newlyWaiting, ","))
	}
	return keep
}

// policyBlocked lists the components the org's policy blocks in snap.
func policyBlocked(snap componentstate.Snapshot) []string {
	var out []string
	for _, d := range snap.Result.Decisions {
		if d.State == components.StateBlocked && (d.Reason == components.ReasonPolicyDenied || d.Reason == components.ReasonPolicyUnlisted) {
			out = append(out, d.ID)
		}
	}
	sort.Strings(out)
	return out
}

// purgePolicyOf renders the outcome's purge authorisation, nil when the
// policy in force keeps data (or no policy is in force).
func purgePolicyOf(out nodecomponents.Outcome) *componentsvc.ScheduledPurgePolicy {
	if out.Spec == nil || out.Spec.OnRemove.Data != nodecomponents.DataPurge || out.Spec.OnRemove.PurgeAfterDays <= 0 {
		return nil
	}
	return &componentsvc.ScheduledPurgePolicy{
		Version: policyVersionOf(out.Spec), AfterDays: out.Spec.OnRemove.PurgeAfterDays,
		// A last-known-good policy may be one the org has since replaced (the
		// node refused the newer version), so it holds open plans rather than
		// authorising a delete (ledger MODPKG-17 (3)).
		Held: out.Source != nodecomponents.SourcePolicy,
	}
}

// policyVersionOf identifies a compiled policy by a digest of its canonical
// JSON (map keys sort), so any change of the policy in force is a new
// version.
func policyVersionOf(spec *nodecomponents.PolicySpec) string {
	b, err := json.Marshal(spec)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:12])
}

// pass runs one follow-up. Errors are logged, never fatal.
func (f *componentPolicyFollower) pass(ctx context.Context) {
	cfg, err := config.Load(config.LoadOptions{GlobalPath: f.configPath})
	if err != nil {
		return
	}
	snap, out := f.resolve(ctx, cfg)
	if !snap.Governed.OrgManaged {
		return
	}
	blocked := policyBlocked(snap)

	// Live teardown of newly policy-blocked components.
	if out.Spec != nil && out.Spec.OnRemove.Teardown == nodecomponents.TeardownAuto {
		var fresh []string
		for _, id := range blocked {
			if !f.tornDown[id] {
				fresh = append(fresh, id)
			}
		}
		fresh = f.holdForLiveRuns(ctx, fresh)
		if len(fresh) > 0 {
			outcomes, terr := f.teardown(ctx, fresh)
			for _, id := range fresh {
				f.tornDown[id] = true
			}
			detail := "ids=" + strings.Join(fresh, ",")
			if terr != nil {
				detail += " error=" + terr.Error()
				f.logger.Warn("components: the organization's policy blocks components; teardown failed", "ids", strings.Join(fresh, ","), "err", terr)
			} else {
				f.logger.Warn("components: the organization's policy now blocks components; their vendor config was removed and their background work stops at the next daemon restart (removal pending restart)",
					"ids", strings.Join(fresh, ","), "steps", len(outcomes))
			}
			f.audit(ctx, "components.policy.teardown", detail)
		}
	}

	// Scheduled purge.
	if f.st == nil {
		return
	}
	policy := purgePolicyOf(out)
	recheck := func(ctx context.Context, plan store.ComponentPurgePlan) error {
		cfg, err := config.Load(config.LoadOptions{GlobalPath: f.configPath})
		if err != nil {
			return err
		}
		snap, out := f.resolve(ctx, cfg)
		p := purgePolicyOf(out)
		if p == nil || p.Version != plan.PolicyVersion {
			return fmt.Errorf("the organization's policy in force no longer authorises this purge")
		}
		if p.Held {
			return fmt.Errorf("the organization's current policy did not verify; the purge waits for one that does")
		}
		for _, id := range policyBlocked(snap) {
			if id == plan.Component {
				return nil
			}
		}
		return fmt.Errorf("%s is no longer blocked by the organization's policy", plan.Component)
	}
	if _, err := componentsvc.RunScheduledPurges(ctx, f.st, componentsvc.ScheduledPurgeRun{
		Now: f.now(), Policy: policy, Blocked: blocked, Recheck: recheck, CatalogVersion: components.CatalogVersion,
	}, f.audit); err != nil {
		f.logger.Warn("components: scheduled purge pass", "err", err)
	}
}

// audit writes one node audit row (the remote-audit table every component
// change uses, components_manage.go).
func (f *componentPolicyFollower) audit(ctx context.Context, action, detail string) {
	if f.st == nil {
		return
	}
	actx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	_ = f.st.InsertRemoteAudit(actx, store.RemoteAuditEvent{
		Kind: "manage", Principal: "org-policy", Route: "components", Decision: "ok",
		Detail: strings.TrimSpace(action + " " + detail),
	})
}
