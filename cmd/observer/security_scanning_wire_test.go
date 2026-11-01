//go:build !sbo_omit_security

package main

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/policyfam"
	"github.com/marmutapp/superbased-observer/internal/policyfam/securityscanning"
	"github.com/marmutapp/superbased-observer/internal/policystate"
)

// withSecurityScanningNode binds the family's provider over a fixed base for
// the length of t and puts the process state back after it.
func withSecurityScanningNode(t *testing.T, managed bool, sc config.SecurityConfig, active ...string) {
	t.Helper()
	secScanning.mu.Lock()
	savedActive, savedHeld, savedLoad := secScanning.active, secScanning.held, secScanning.load
	savedBase, savedOK, savedAt := secScanning.base, secScanning.baseOK, secScanning.loadedAt
	savedOff := secScanning.moduleOff
	secScanning.mu.Unlock()
	m := map[string]bool{}
	for _, a := range active {
		m[a] = true
	}
	secScanning.mu.Lock()
	secScanning.active = m
	secScanning.held = nil
	secScanning.baseOK = false
	secScanning.moduleOff = false
	secScanning.load = func(context.Context) (securityScanningBase, error) {
		return securityScanningBase{Managed: managed, Security: sc}, nil
	}
	secScanning.mu.Unlock()
	restore := securityscanning.SetNodeFactsProvider(secScanning.facts)
	t.Cleanup(func() {
		restore()
		secScanning.mu.Lock()
		secScanning.active, secScanning.held, secScanning.load = savedActive, savedHeld, savedLoad
		secScanning.base, secScanning.baseOK, secScanning.loadedAt = savedBase, savedOK, savedAt
		secScanning.moduleOff = savedOff
		secScanning.mu.Unlock()
	})
}

func compileFloor(t *testing.T, body string) securityscanning.PolicySpec {
	t.Helper()
	s, _, err := securityscanning.CompileBody([]byte(body), 0)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func installFloor(t *testing.T, body string, version int64, inEffect bool) {
	t.Helper()
	res := orgclient.PolicyResourceResult{Status: orgclient.PRApplied, Version: version, BodyHash: "h", Spec: compileFloor(t, body), EnforceAllowed: inEffect}
	if !inEffect {
		res.Status, res.InertReason = orgclient.PRAppliedInert, "not_preauthorized"
	}
	securityScanningPublish(res, nil)
}

// TestSecurityFloorRowsNameRealAxes: every built setting row sits on an axis
// of the family, once.
func TestSecurityFloorRowsNameRealAxes(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range securityFloorRows {
		if _, ok := securityscanning.LookupAxis(r.Axis); !ok {
			t.Errorf("row %s names no axis", r.Axis)
		}
		if seen[r.Axis] {
			t.Errorf("axis %s has two rows", r.Axis)
		}
		seen[r.Axis] = true
	}
}

// TestSecurityFloorsApplied walks the read seam: a floor in effect raises,
// an inert one or none leaves the node's own values, and managed-only keys
// act only on a managed node.
func TestSecurityFloorsApplied(t *testing.T) {
	local := config.DefaultSecurityConfig() // retention 365, online on
	offline := local
	offline.Deps.Online = false
	cases := []struct {
		name          string
		managed       bool
		base          config.SecurityConfig
		body          string
		inEffect      bool
		wantRetention int
		wantOnline    bool
	}{
		{"no floor", false, local, "", false, 365, true},
		{"retention raised", false, local, `{"require":{"finding_retention_days":730}}`, true, 730, true},
		{"retention forever", false, local, `{"require":{"finding_retention_days":0}}`, true, 0, true},
		{"retention never shortened", false, local, `{"require":{"finding_retention_days":90}}`, true, 365, true},
		{"inert floor", false, local, `{"require":{"finding_retention_days":730}}`, false, 365, true},
		{"online forbidden", false, local, `{"allow":{"online_checks":"forbidden"}}`, true, 365, false},
		{"online required, individual", false, offline, `{"require":{"online_checks":"required"}}`, true, 365, false},
		{"online required, managed", true, offline, `{"require":{"online_checks":"required"}}`, true, 365, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			withSecurityScanningNode(t, c.managed, c.base, "security.deps")
			if c.body != "" {
				installFloor(t, c.body, 1, c.inEffect)
			}
			got := securityFloorsApplied(c.base)
			if got.Retention.Days != c.wantRetention || got.Deps.Online != c.wantOnline {
				t.Fatalf("retention=%d online=%v, want %d %v", got.Retention.Days, got.Deps.Online, c.wantRetention, c.wantOnline)
			}
		})
	}
}

func TestSecurityRetentionDaysNowFollowsTheFloor(t *testing.T) {
	withSecurityScanningNode(t, false, config.DefaultSecurityConfig())
	if d := securityRetentionDaysNow(180); d != 180 {
		t.Fatalf("no floor: %d", d)
	}
	installFloor(t, `{"require":{"finding_retention_days":365}}`, 1, true)
	if d := securityRetentionDaysNow(180); d != 365 {
		t.Fatalf("floor 365 over 180: %d", d)
	}
	securityScanningClear()
	if d := securityRetentionDaysNow(180); d != 180 {
		t.Fatalf("after clear: %d", d)
	}
}

// TestSecurityScanningPostureGate: the accept gate the kit binds
// (policyfam.CheckLinkedPosture) refuses, on an individual node, a body that
// would loosen the floor in force, naming the axis; a managed node may lower
// its own floor.
func TestSecurityScanningPostureGate(t *testing.T) {
	if !policyfam.IsFamilyLinked(policyfam.FamilySecurityScanning) {
		t.Skip("family not linked")
	}
	lower := compileFloor(t, `{"require":{"finding_retention_days":180}}`)
	for _, managed := range []bool{false, true} {
		withSecurityScanningNode(t, managed, config.DefaultSecurityConfig())
		installFloor(t, `{"require":{"finding_retention_days":730}}`, 1, true)
		axis, err := policyfam.CheckLinkedPosture(policyfam.FamilySecurityScanning, lower)
		if managed && err != nil {
			t.Fatalf("managed: refused %s: %v", axis, err)
		}
		if !managed && (axis != securityscanning.AxisFindingRetention || err == nil) {
			t.Fatalf("individual: axis=%q err=%v, want a refusal on %s", axis, err, securityscanning.AxisFindingRetention)
		}
	}
}

// TestSecurityScanningCapabilities: a managed node advertises only its
// active children's section tokens, so a section for a missing child is
// refused at the capability gate naming the token; an individual node
// advertises them all and reports not_applicable instead.
func TestSecurityScanningCapabilities(t *testing.T) {
	if !policyfam.IsFamilyLinked(policyfam.FamilySecurityScanning) {
		t.Skip("family not linked")
	}
	withSecurityScanningNode(t, true, config.DefaultSecurityConfig(), "security.trust")
	caps := nodeLiveCapabilities(nil)
	if slices.Contains(caps, "security.deps.v1") || !slices.Contains(caps, "security.trust.v1") {
		t.Fatalf("managed caps %v", caps)
	}
	withSecurityScanningNode(t, false, config.DefaultSecurityConfig())
	if caps := nodeLiveCapabilities(nil); !slices.Contains(caps, "security.deps.v1") {
		t.Fatalf("individual caps %v", caps)
	}
}

func TestSecurityScanningPointReader(t *testing.T) {
	withSecurityScanningNode(t, false, config.DefaultSecurityConfig())
	now := func() time.Time { return time.Unix(1, 0) }
	slot := orgclient.PolicyResourceFetchOutcome{}
	read := newSecurityScanningPointReader(func() orgclient.PolicyResourceFetchOutcome { return slot }, now)
	row := func() orgcontract.PolicyStateRow {
		f, err := read(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		return policystate.Resolve(policystate.PointNodeSecurity, policystate.FamilySecurityScanning, f)
	}
	if r := row(); r.Status != orgcontract.StatusNone || r.Reason != orgcontract.ReasonNoPolicy {
		t.Fatalf("no floor: %+v", r)
	}
	installFloor(t, `{"require":{"finding_retention_days":730}}`, 3, false)
	if r := row(); r.Status != orgcontract.StatusAcceptedInert || r.Reason != orgcontract.ReasonNotPreauthorized {
		t.Fatalf("inert: %+v", r)
	}
	installFloor(t, `{"require":{"finding_retention_days":730}}`, 4, true)
	if r := row(); r.Status != orgcontract.StatusEffective || r.RunningVersion != 4 {
		t.Fatalf("effective: %+v", r)
	}
	slot = orgclient.PolicyResourceFetchOutcome{Reached: true, RejectCode: orgclient.PRRejectPostureLoosened, Version: 5}
	if r := row(); r.Status != orgcontract.StatusDeliveredUnaccepted || r.Reason != orgcontract.ReasonPostureLoosened {
		t.Fatalf("posture_loosened NACK: %+v", r)
	}
}

func TestSecurityScanningStatusNotEnrolled(t *testing.T) {
	st, _ := openTestStore(t)
	lines := securityOrgStatusLines(context.Background(), "", config.Default(), st)
	if len(lines) == 0 || !strings.Contains(lines[0], "not enrolled") {
		t.Fatalf("lines %v", lines)
	}
}
