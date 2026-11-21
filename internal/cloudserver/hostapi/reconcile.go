package hostapi

import (
	"fmt"
	"slices"

	pc "github.com/marmutapp/superbased-observer/internal/platformcontract"
)

// FindingKind is the closed vocabulary of a reconciliation mismatch. The SQL
// CHECK on org_reconcile_findings.kind holds the same values (pinned by a
// hostclient test).
type FindingKind string

// Finding kinds.
const (
	// FindingNotServed: the org's host does not hold the tenant (or no host
	// is assigned) while the org is not purged.
	FindingNotServed FindingKind = "not_served"
	// FindingUnreachable: the host gave no verified route-check answer.
	FindingUnreachable FindingKind = "unreachable"
	// FindingStateBehind: the host's generation is below the org's.
	FindingStateBehind FindingKind = "state_behind"
	// FindingStateDiverged: same generation, different state.
	FindingStateDiverged FindingKind = "state_diverged"
	// FindingGenAhead: the host's generation is above the org's. Never
	// corrected: the control plane never moves a tenant backwards.
	FindingGenAhead FindingKind = "gen_ahead"
	// FindingUnhealthy: the host reports the tenant degraded or unhealthy.
	FindingUnhealthy FindingKind = "unhealthy"
)

// KnownFindingKinds returns every FindingKind.
func KnownFindingKinds() []FindingKind {
	return []FindingKind{
		FindingNotServed, FindingUnreachable, FindingStateBehind,
		FindingStateDiverged, FindingGenAhead, FindingUnhealthy,
	}
}

// Desired is the control plane's record of one org (the orgs row) plus
// whether an intent for it is still open in the outbox.
type Desired struct {
	// OrgID is the org id.
	OrgID string
	// DisplayName is the org name (a create correction carries it).
	DisplayName string
	// State is the desired tenant state (orgs.status).
	State pc.TenantState
	// LifecycleGen is the desired generation (orgs.lifecycle_gen).
	LifecycleGen int64
	// HostAssigned is true when orgs.host_id is set.
	HostAssigned bool
	// OpenIntent is true when a pending or sent outbox row exists for the org.
	OpenIntent bool
}

// NeedsProbe reports whether the reconciler must ask the host about d: not
// while an intent is in flight (the host is converging) and not when no host
// is assigned (there is no one to ask). Rules 1 to 4 of reconcileRules decide
// those cases without a probe.
func (d Desired) NeedsProbe() bool { return !d.OpenIntent && d.HostAssigned }

// Probe is what the org's host answered. Only verified answers fill it.
type Probe struct {
	// Reached is true when a verified route-check answer came back.
	Reached bool
	// Served is the route-check verdict.
	Served bool
	// State is the host's state for the tenant.
	State pc.TenantState
	// LifecycleGen is the host's generation for the tenant.
	LifecycleGen int64
	// Health is the verified health verdict ("" when not read).
	Health pc.HealthStatus
}

// Reconciliation is the outcome for one org.
type Reconciliation struct {
	// Rule names the reconcileRules row that matched.
	Rule string
	// Skip means leave the org's findings as they are (an intent is in
	// flight; the next pass judges the result).
	Skip bool
	// Findings are the mismatches now open for the org; every other open
	// finding of the org is resolved.
	Findings []FindingKind
	// Correction is the one intent to enqueue, or nil. It goes through the
	// outbox like any other intent; its key is deterministic, so repeating
	// the pass never adds a second row.
	Correction *Intent
}

// reconcileRule is one row of reconcileRules.
type reconcileRule struct {
	name string
	// served marks the rows reached only with a served tenant; the health
	// rule applies after them.
	served bool
	match  func(d Desired, p Probe) bool
	// finding is the row's finding ("" for none).
	finding FindingKind
	// correct builds the row's correction (nil: alert only).
	correct func(d Desired) (Intent, error)
}

// reconcileRules compares one org with its host, walked top-down, first match
// wins; one test case per row (reconcile_test.go). Corrections are limited to
// the two cases the control plane can repair by re-sending its own intent: a
// tenant that was never created, and a host behind the org's generation.
// Everything else is a finding for an operator (design 4.6: never repair
// blindly).
var reconcileRules = []reconcileRule{
	{name: "in_flight", match: func(d Desired, _ Probe) bool { return d.OpenIntent }},
	{
		name:    "unplaced_provisioning",
		match:   func(d Desired, _ Probe) bool { return !d.HostAssigned && d.State == pc.StateProvisioning },
		finding: FindingNotServed, correct: createCorrection,
	},
	{name: "unplaced_purged", match: func(d Desired, _ Probe) bool { return !d.HostAssigned && d.State == pc.StatePurged }},
	{name: "unplaced", match: func(d Desired, _ Probe) bool { return !d.HostAssigned }, finding: FindingNotServed},
	{name: "unreachable", match: func(_ Desired, p Probe) bool { return !p.Reached }, finding: FindingUnreachable},
	{name: "purged_gone", match: func(d Desired, p Probe) bool { return !p.Served && d.State == pc.StatePurged }},
	{
		name:    "create_missing",
		match:   func(d Desired, p Probe) bool { return !p.Served && d.State == pc.StateProvisioning },
		finding: FindingNotServed, correct: createCorrection,
	},
	{name: "not_served", match: func(_ Desired, p Probe) bool { return !p.Served }, finding: FindingNotServed},
	{
		name: "gen_ahead", served: true, finding: FindingGenAhead,
		match: func(d Desired, p Probe) bool { return p.LifecycleGen > d.LifecycleGen },
	},
	{
		name: "state_behind", served: true, finding: FindingStateBehind, correct: stateCorrection,
		match: func(d Desired, p Probe) bool { return p.LifecycleGen < d.LifecycleGen },
	},
	{
		name: "state_diverged", served: true, finding: FindingStateDiverged,
		match: func(d Desired, p Probe) bool { return p.State != d.State },
	},
	{name: "in_sync", served: true, match: func(Desired, Probe) bool { return true }},
}

// unhealthyStatuses are the health verdicts that open FindingUnhealthy for a
// served tenant.
var unhealthyStatuses = []pc.HealthStatus{pc.HealthDegraded, pc.HealthUnhealthy}

func createCorrection(d Desired) (Intent, error) { return CreateTenantIntent(d.OrgID, d.DisplayName) }

func stateCorrection(d Desired) (Intent, error) {
	in, err := SetStateIntent(d.OrgID, d.State, d.LifecycleGen)
	if err != nil {
		return Intent{}, err
	}
	return in.AsCorrection(), nil
}

// Reconcile compares desired state d with the host's answer p.
func Reconcile(d Desired, p Probe) (Reconciliation, error) {
	for _, r := range reconcileRules {
		if !r.match(d, p) {
			continue
		}
		out := Reconciliation{Rule: r.name, Skip: r.name == "in_flight"}
		if r.finding != "" {
			out.Findings = append(out.Findings, r.finding)
		}
		if r.served && slices.Contains(unhealthyStatuses, p.Health) {
			out.Findings = append(out.Findings, FindingUnhealthy)
		}
		if r.correct != nil {
			in, err := r.correct(d)
			if err != nil {
				return Reconciliation{}, fmt.Errorf("hostapi.Reconcile: %s: %w", r.name, err)
			}
			out.Correction = &in
		}
		return out, nil
	}
	// Unreachable: the last row matches everything.
	return Reconciliation{Rule: "none", Skip: true}, nil
}
