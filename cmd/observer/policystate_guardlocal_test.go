package main

import (
	"context"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/policystate"
)

// fakeBundleVerifier is a guardBundleVerifier double.
type fakeBundleVerifier struct {
	check orgclient.CachedBundleCheck
	err   error
	kicks int
}

func (f *fakeBundleVerifier) VerifyCachedPolicyBundle(context.Context, string) (orgclient.CachedBundleCheck, error) {
	return f.check, f.err
}
func (f *fakeBundleVerifier) KickPolicyBundlePoll() { f.kicks++ }

// TestGuardReader_OnDiskBundleIntegrity pins T-846 (audit row b2), one case
// per row: the on-disk verdict decides whether the guard row can read
// effective, a tampered file kicks the poll, and an absent one reads none.
func TestGuardReader_OnDiskBundleIntegrity(t *testing.T) {
	running := func() guardRunning { return guardRunning{RunningVersion: 29, EffectiveHash: psHex64, Mode: "enforce"} }
	noFetch := func() orgclient.GuardFetchOutcome { return orgclient.GuardFetchOutcome{} }
	tests := []struct {
		name       string
		check      orgclient.CachedBundleCheck
		wantStatus string
		wantReason string
		wantKicks  int
		wantInteg  string
	}{
		{
			"verified bundle reads effective",
			orgclient.CachedBundleCheck{Integrity: orgcontract.BundleIntegrityVerified, Version: 29},
			orgcontract.StatusEffective, orgcontract.ReasonOK, 0, orgcontract.BundleIntegrityVerified,
		},
		{
			"edited body (signature fails) reads delivered_unaccepted sig_invalid",
			orgclient.CachedBundleCheck{Integrity: orgcontract.BundleIntegrityTampered, RejectCode: orgclient.RejectSigInvalid, Version: 29},
			orgcontract.StatusDeliveredUnaccepted, orgcontract.ReasonSigInvalid, 1, orgcontract.BundleIntegrityTampered,
		},
		{
			"forged key reads key_pin_mismatch",
			orgclient.CachedBundleCheck{Integrity: orgcontract.BundleIntegrityTampered, RejectCode: orgclient.RejectKeyPinMismatch, Version: 29},
			orgcontract.StatusDeliveredUnaccepted, orgcontract.ReasonKeyPinMismatch, 1, orgcontract.BundleIntegrityTampered,
		},
		{
			"deleted bundle is not effective",
			orgclient.CachedBundleCheck{Integrity: orgcontract.BundleIntegrityAbsent},
			orgcontract.StatusNone, orgcontract.ReasonInconsistentObservation, 0, orgcontract.BundleIntegrityAbsent,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v := &fakeBundleVerifier{check: tc.check}
			reader := newGuardPointReader(guardBundleCheckFrom(v, "/x/org-policy-bundle.json"), running, noFetch, nil, time.Now)
			f, err := reader(context.Background())
			if err != nil {
				t.Fatalf("reader: %v", err)
			}
			row := policystate.Resolve(policystate.PointGuard, policystate.FamilyGuardCoding, f)
			if row.Status != tc.wantStatus || row.Reason != tc.wantReason {
				t.Fatalf("row = %s/%s, want %s/%s", row.Status, row.Reason, tc.wantStatus, tc.wantReason)
			}
			if row.BundleIntegrity != tc.wantInteg {
				t.Fatalf("bundle_integrity = %q, want %q", row.BundleIntegrity, tc.wantInteg)
			}
			if v.kicks != tc.wantKicks {
				t.Fatalf("poll kicks = %d, want %d", v.kicks, tc.wantKicks)
			}
		})
	}
}

// TestLocalGuardPostureFrom pins the T-848 projection: effective values,
// detector overrides that took effect, and the allow-list as a COUNT only.
func TestLocalGuardPostureFrom(t *testing.T) {
	const secretRegex = `(?i)acme-internal-[0-9]+`
	gc := config.GuardConfig{Enabled: false, Mode: "advise"}
	gc.Prompt.Enabled = true
	gc.Prompt.Mode = "ask-once"
	gc.Prompt.Detectors = map[string]string{"github_pat": "off", "aws_access_key": "block", "slack_token": "warn"}
	gc.Prompt.Allow = []string{secretRegex, "b"}
	p := localGuardPostureFrom(gc)
	want := &orgcontract.LocalGuardPosture{
		Enabled: false, Mode: "observe", PromptEnabled: true, PromptMode: "ask-once",
		// github_pat "off" is an exemption; aws "block" is stricter and wins;
		// slack "warn" clamps up to the ask-once floor, so it is not listed.
		DetectorModes:  map[string]string{"github_pat": "off", "aws_access_key": "block"},
		AllowListCount: 2,
	}
	if !reflect.DeepEqual(p, want) {
		t.Fatalf("posture = %+v, want %+v", p, want)
	}
	raw := strings.Join([]string{p.Mode, p.PromptMode}, "")
	for k, v := range p.DetectorModes {
		raw += k + v
	}
	if strings.Contains(raw, "acme") {
		t.Fatal("allow-list text crossed into the posture")
	}
}

// gen3RejectingPoster models a gen2 server: it 400s any report carrying a
// gen3 guard-row field and accepts everything else, gen2 fields included.
type gen3RejectingPoster struct {
	mu    sync.Mutex
	calls []orgcontract.PolicyStateReport
}

func (p *gen3RejectingPoster) PostPolicyState(_ context.Context, rep orgcontract.PolicyStateReport) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls = append(p.calls, rep)
	for _, row := range rep.Rows {
		if row.BundleIntegrity != "" || row.LocalGuard != nil {
			return orgclient.ErrPolicyAckRejected
		}
	}
	return nil
}

func (p *gen3RejectingPoster) ManagedMachineIdentity(context.Context) string {
	return "org-salted-machine-id"
}

// TestReporter_Gen3RungKeepsGen2 pins the compat rung: a gen2 server that
// refuses the gen3 guard fields gets the SAME snapshot with only those
// fields stripped (gen2 fields and identity kept, the honest tamper status
// kept), and the reporter latches there for the daemon lifetime.
func TestReporter_Gen3RungKeepsGen2(t *testing.T) {
	readers := gen2Readers(t)
	v := &fakeBundleVerifier{check: orgclient.CachedBundleCheck{Integrity: orgcontract.BundleIntegrityTampered, RejectCode: orgclient.RejectSigInvalid, Version: 4}}
	readers[policystate.PointGuard] = newGuardPointReader(
		guardBundleCheckFrom(v, "/x/b.json"),
		func() guardRunning { return guardRunning{RunningVersion: 4, EffectiveHash: psHex64, Mode: "enforce"} },
		func() orgclient.GuardFetchOutcome { return orgclient.GuardFetchOutcome{} },
		func() *orgcontract.LocalGuardPosture { return &orgcontract.LocalGuardPosture{Mode: "off"} },
		time.Now,
	)
	fp := &gen3RejectingPoster{}
	rep := newPolicyStateReporter(fp, readers, seqCounter(t), "v", true, nil)
	rep.report(context.Background())
	if len(fp.calls) != 2 {
		t.Fatalf("posted %d times, want 2 (gen3 rejected, gen2 accepted)", len(fp.calls))
	}
	second := fp.calls[1]
	if second.MachineIdentity == "" {
		t.Fatal("the gen2 rung must keep the machine identity")
	}
	var sawGen2, sawTamperStatus bool
	for _, row := range second.Rows {
		if row.BundleIntegrity != "" || row.LocalGuard != nil {
			t.Fatalf("gen2 rung row still carries a gen3 field: %+v", row)
		}
		if row.EnforcementPoint == policystate.PointNodeDashboard && len(row.AcceptedAuthority) > 0 {
			sawGen2 = true
		}
		if row.EnforcementPoint == policystate.PointGuard && row.Status == orgcontract.StatusDeliveredUnaccepted {
			sawTamperStatus = true
		}
	}
	if !sawGen2 {
		t.Fatal("the gen2 rung dropped the gen2 node-dashboard fields")
	}
	if !sawTamperStatus {
		t.Fatal("the gen2 rung lost the honest tamper status (a gen2 server would read effective)")
	}
	if !rep.latched.Load() || !rep.latchGen2.Load() || rep.latchGen1.Load() {
		t.Fatalf("latched=%v gen2=%v gen1=%v, want a gen2 latch", rep.latched.Load(), rep.latchGen2.Load(), rep.latchGen1.Load())
	}
	rep.report(context.Background())
	if len(fp.calls) != 3 || fp.calls[2].MachineIdentity == "" {
		t.Fatal("a latched gen2 send must go straight out with identity and no gen3 fields")
	}
}
