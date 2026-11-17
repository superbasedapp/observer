package hostapi

import (
	"slices"
	"testing"

	pc "github.com/marmutapp/superbased-observer/internal/platformcontract"
)

// TestReconcileRules is one case per reconcileRules row, in table order. A
// correction is named by its verb and key; "" means alert-only.
func TestReconcileRules(t *testing.T) {
	t.Parallel()
	active := Desired{OrgID: testOrg, DisplayName: "Acme", State: pc.StateActive, LifecycleGen: 3, HostAssigned: true}
	with := func(f func(*Desired)) Desired { d := active; f(&d); return d }
	served := func(state pc.TenantState, gen int64) Probe {
		return Probe{Reached: true, Served: true, State: state, LifecycleGen: gen, Health: pc.HealthHealthy}
	}
	cases := []struct {
		rule     string
		d        Desired
		p        Probe
		skip     bool
		findings []FindingKind
		key      string
	}{
		{"in_flight", with(func(d *Desired) { d.OpenIntent = true }), Probe{}, true, nil, ""},
		{
			"unplaced_provisioning", with(func(d *Desired) { d.HostAssigned, d.State, d.LifecycleGen = false, pc.StateProvisioning, 0 }),
			Probe{},
			false,
			[]FindingKind{FindingNotServed},
			testOrg,
		},
		{"unplaced_purged", with(func(d *Desired) { d.HostAssigned, d.State = false, pc.StatePurged }), Probe{}, false, nil, ""},
		{"unplaced", with(func(d *Desired) { d.HostAssigned = false }), Probe{}, false, []FindingKind{FindingNotServed}, ""},
		{"unreachable", active, Probe{}, false, []FindingKind{FindingUnreachable}, ""},
		{"purged_gone", with(func(d *Desired) { d.State = pc.StatePurged }), Probe{Reached: true}, false, nil, ""},
		{
			"create_missing", with(func(d *Desired) { d.State, d.LifecycleGen = pc.StateProvisioning, 0 }),
			Probe{Reached: true},
			false,
			[]FindingKind{FindingNotServed},
			testOrg,
		},
		{"not_served", active, Probe{Reached: true}, false, []FindingKind{FindingNotServed}, ""},
		{"gen_ahead", active, served(pc.StateActive, 5), false, []FindingKind{FindingGenAhead}, ""},
		{
			"state_behind", with(func(d *Desired) { d.State = pc.StateSuspended }), served(pc.StateActive, 2),
			false,
			[]FindingKind{FindingStateBehind},
			KeyPrefixReconcile + "state:" + testOrg + ":3:suspended",
		},
		{"state_diverged", active, served(pc.StateSuspended, 3), false, []FindingKind{FindingStateDiverged}, ""},
		{"in_sync", active, served(pc.StateActive, 3), false, nil, ""},
	}
	if len(cases) != len(reconcileRules) {
		t.Fatalf("%d cases for %d rules: one case per row", len(cases), len(reconcileRules))
	}
	for i, tc := range cases {
		if reconcileRules[i].name != tc.rule {
			t.Fatalf("case %d is %q but rule %d is %q (keep table order)", i, tc.rule, i, reconcileRules[i].name)
		}
		t.Run(tc.rule, func(t *testing.T) {
			t.Parallel()
			got, err := Reconcile(tc.d, tc.p)
			if err != nil {
				t.Fatalf("Reconcile: %v", err)
			}
			if got.Rule != tc.rule || got.Skip != tc.skip || !slices.Equal(got.Findings, tc.findings) {
				t.Fatalf("Reconcile = %+v, want rule %s skip %v findings %v", got, tc.rule, tc.skip, tc.findings)
			}
			key := ""
			if got.Correction != nil {
				key = got.Correction.IdempotencyKey
			}
			if key != tc.key {
				t.Fatalf("correction key = %q, want %q", key, tc.key)
			}
		})
	}
}

// TestReconcileHealth: a served tenant whose host reports it degraded or
// unhealthy also opens FindingUnhealthy; healthy and unknown do not; an
// unserved or unreached tenant never does.
func TestReconcileHealth(t *testing.T) {
	t.Parallel()
	d := Desired{OrgID: testOrg, DisplayName: "Acme", State: pc.StateActive, LifecycleGen: 1, HostAssigned: true}
	cases := []struct {
		probe Probe
		want  []FindingKind
	}{
		{Probe{Reached: true, Served: true, State: pc.StateActive, LifecycleGen: 1, Health: pc.HealthDegraded}, []FindingKind{FindingUnhealthy}},
		{Probe{Reached: true, Served: true, State: pc.StateActive, LifecycleGen: 1, Health: pc.HealthUnhealthy}, []FindingKind{FindingUnhealthy}},
		{Probe{Reached: true, Served: true, State: pc.StateActive, LifecycleGen: 1, Health: pc.HealthUnknown}, nil},
		{Probe{Reached: true, Served: true, State: pc.StateActive, LifecycleGen: 0, Health: pc.HealthUnhealthy}, []FindingKind{FindingStateBehind, FindingUnhealthy}},
		{Probe{Reached: true, Health: pc.HealthUnhealthy}, []FindingKind{FindingNotServed}},
		{Probe{Health: pc.HealthUnhealthy}, []FindingKind{FindingUnreachable}},
	}
	for i, tc := range cases {
		got, err := Reconcile(d, tc.probe)
		if err != nil || !slices.Equal(got.Findings, tc.want) {
			t.Errorf("case %d: Reconcile = %+v, %v; want findings %v", i, got, err, tc.want)
		}
	}
}

// TestReconcileNeedsProbe: no probe while an intent is in flight or when no
// host is assigned.
func TestReconcileNeedsProbe(t *testing.T) {
	t.Parallel()
	cases := []struct {
		d    Desired
		want bool
	}{
		{Desired{HostAssigned: true}, true},
		{Desired{HostAssigned: true, OpenIntent: true}, false},
		{Desired{}, false},
	}
	for _, tc := range cases {
		if got := tc.d.NeedsProbe(); got != tc.want {
			t.Errorf("NeedsProbe(%+v) = %v", tc.d, got)
		}
	}
}

// TestReconcileCorrectionError: a create correction needs a display name.
func TestReconcileCorrectionError(t *testing.T) {
	t.Parallel()
	if _, err := Reconcile(Desired{OrgID: testOrg, State: pc.StateProvisioning}, Probe{}); err == nil {
		t.Fatal("a create correction without a name was built")
	}
}
