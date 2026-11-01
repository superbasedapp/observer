package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/guardposture"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/policystate"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestGuardReader_MissingBundleKicksAndReports pins T-864 gap 1's report
// half: a bundle the node had accepted and that is now missing reads
// "missing" (not "absent") and kicks the policy poll, which downloads it
// again without If-None-Match.
func TestGuardReader_MissingBundleKicksAndReports(t *testing.T) {
	v := &fakeBundleVerifier{check: orgclient.CachedBundleCheck{Integrity: orgcontract.BundleIntegrityMissing}}
	running := func() guardRunning { return guardRunning{RunningVersion: 29, EffectiveHash: psHex64, Mode: "enforce"} }
	noFetch := func() orgclient.GuardFetchOutcome { return orgclient.GuardFetchOutcome{} }
	reader := newGuardPointReader(guardBundleCheckFrom(v, "/x/org-policy-bundle.json"), running, noFetch, nil, time.Now)
	f, err := reader(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	row := policystate.Resolve(policystate.PointGuard, policystate.FamilyGuardCoding, f)
	if row.BundleIntegrity != orgcontract.BundleIntegrityMissing || row.Status == orgcontract.StatusEffective {
		t.Fatalf("row = %s/%s integrity %q, want a non-effective missing row", row.Status, row.Reason, row.BundleIntegrity)
	}
	if v.kicks != 1 {
		t.Fatalf("poll kicks = %d, want 1", v.kicks)
	}
}

// TestGuardTamperReportOf pins the gen4 fold (T-864 gap 4): the total, the
// newest repair, and nothing for an unknown kind or no rows.
func TestGuardTamperReportOf(t *testing.T) {
	t0 := time.Date(2026, 10, 16, 7, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name   string
		counts []store.HookFailureCount
		want   *orgcontract.GuardTamperReport
	}{
		{"nothing repaired", nil, nil},
		{
			"one bundle repair",
			[]store.HookFailureCount{{Kind: orgcontract.GuardTamperOrgBundle, Count: 1, LastAt: t0}},
			&orgcontract.GuardTamperReport{Repairs: 1, LastAt: "2026-10-16T07:00:00Z", LastKind: orgcontract.GuardTamperOrgBundle},
		},
		{"newest kind wins, total summed", []store.HookFailureCount{
			{Kind: orgcontract.GuardTamperGovernance, Count: 42, LastAt: t0.Add(10 * time.Minute)},
			{Kind: orgcontract.GuardTamperOrgBundle, Count: 1, LastAt: t0},
		}, &orgcontract.GuardTamperReport{Repairs: 43, LastAt: "2026-10-16T07:10:00Z", LastKind: orgcontract.GuardTamperGovernance}},
		{"an unknown kind is ignored", []store.HookFailureCount{{Kind: "timeout", Count: 3, LastAt: t0}}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := guardTamperReportOf(tc.counts); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("report = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// gen4RejectingPoster models a gen3 server: it 400s a report carrying the
// gen4 guard tamper record or the "missing" integrity value.
type gen4RejectingPoster struct {
	mu    sync.Mutex
	calls []orgcontract.PolicyStateReport
}

func (p *gen4RejectingPoster) PostPolicyState(_ context.Context, rep orgcontract.PolicyStateReport) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls = append(p.calls, rep)
	for _, row := range rep.Rows {
		if row.GuardTamper != nil || row.BundleIntegrity == orgcontract.BundleIntegrityMissing {
			return orgclient.ErrPolicyAckRejected
		}
	}
	return nil
}

func (p *gen4RejectingPoster) ManagedMachineIdentity(context.Context) string {
	return "org-salted-machine-id"
}

// TestReporter_Gen4RungKeepsGen3 pins the compat rung (T-864): a gen3 server
// gets the same snapshot with only the gen4 content stripped (the tamper
// record dropped, "missing" reported as "absent"), every gen3 field kept,
// and the reporter latches there.
func TestReporter_Gen4RungKeepsGen3(t *testing.T) {
	readers := gen2Readers(t)
	v := &fakeBundleVerifier{check: orgclient.CachedBundleCheck{Integrity: orgcontract.BundleIntegrityMissing}}
	tamper := &orgcontract.GuardTamperReport{Repairs: 1, LastAt: "2026-10-16T07:00:00Z", LastKind: orgcontract.GuardTamperOrgBundle}
	readers[policystate.PointGuard] = withGuardTamper(newGuardPointReader(
		guardBundleCheckFrom(v, "/x/b.json"),
		func() guardRunning { return guardRunning{RunningVersion: 4, EffectiveHash: psHex64, Mode: "enforce"} },
		func() orgclient.GuardFetchOutcome { return orgclient.GuardFetchOutcome{} },
		func() *orgcontract.LocalGuardPosture {
			return &orgcontract.LocalGuardPosture{Mode: "observe", PromptMode: "ask-once"}
		},
		time.Now,
	), func(context.Context) *orgcontract.GuardTamperReport { return tamper })
	fp := &gen4RejectingPoster{}
	rep := newPolicyStateReporter(fp, readers, seqCounter(t), "v", true, nil)
	rep.report(context.Background())
	if len(fp.calls) != 2 {
		t.Fatalf("posted %d times, want 2 (gen4 rejected, gen3 accepted)", len(fp.calls))
	}
	var guardRow *orgcontract.PolicyStateRow
	for i := range fp.calls[1].Rows {
		if fp.calls[1].Rows[i].EnforcementPoint == policystate.PointGuard {
			guardRow = &fp.calls[1].Rows[i]
		}
	}
	if guardRow == nil || guardRow.GuardTamper != nil || guardRow.BundleIntegrity != orgcontract.BundleIntegrityAbsent || guardRow.LocalGuard == nil {
		t.Fatalf("gen3 rung guard row = %+v, want no tamper record, absent integrity, local guard kept", guardRow)
	}
	if !rep.latched.Load() || !rep.latchGen3.Load() || rep.latchGen2.Load() || rep.latchGen1.Load() {
		t.Fatalf("latch = %v gen3 %v gen2 %v gen1 %v, want a gen3 latch", rep.latched.Load(), rep.latchGen3.Load(), rep.latchGen2.Load(), rep.latchGen1.Load())
	}
	rep.report(context.Background())
	if len(fp.calls) != 3 {
		t.Fatalf("a latched gen3 send must go straight out, got %d calls", len(fp.calls))
	}
}

// TestCheckOrgBundleReportsADeletion pins the daemon half of T-864 gap 1: a
// deleted bundle on a managed node is a high org_bundle_tamper event (once
// per episode) and an immediate poll wake-up, while the live guard keeps the
// org layer and its lock. An individual node's deletion is not a tamper.
func TestCheckOrgBundleReportsADeletion(t *testing.T) {
	for _, tc := range []struct {
		name    string
		managed bool
	}{
		{"managed node", true},
		{"individual node", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			bundlePath := filepath.Join(dir, "org-policy-bundle.json")
			sign, pin := bundleSigner(t)
			writeFileT(t, bundlePath, sign(29, orgLockBundleTOML))
			gc := config.Default().Guard
			gc.Enabled, gc.Mode = true, "enforce"
			gc.Rules.OrgBundle = bundlePath
			managed := tc.managed
			gd, err := guard.New(guard.Options{
				Config: gc, Home: dir, OrgKeyPinHash: pin, OrgBundleExpected: true,
				ManagedTenancy: func() bool { return managed },
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(bundlePath); err != nil {
				t.Fatal(err)
			}
			kicks := 0
			setProcessPolicyBundleKick(func() { kicks++ })
			t.Cleanup(func() { setProcessPolicyBundleKick(nil) })
			w := &guardPostureWriter{}
			w.checkOrgBundle(gd)
			w.checkOrgBundle(gd)
			got := w.takeExtraTampers()
			if !tc.managed {
				if len(got) != 0 || kicks != 0 {
					t.Fatalf("individual node: tampers %+v kicks %d, want none", got, kicks)
				}
				return
			}
			if len(got) != 1 || got[0].kind != tamperOrgBundle || kicks != 1 {
				t.Fatalf("tampers %+v kicks %d, want one org_bundle_tamper and one kick", got, kicks)
			}
			if err := gd.ReloadOrgLayer(context.Background()); err == nil {
				t.Fatal("a reload over a deleted bundle must fail (fail-safe) rather than drop the org layer")
			}
			if _, locked := gd.OrgOverrideStatus("R-101"); !locked {
				t.Fatal("the live guard dropped the org lock after the deletion")
			}
		})
	}
}

// TestHookPostureHeldOnManagedConfigEdit pins T-864 gap 2's hook half: in the
// window between a local config.toml edit and the daemon's next re-sign, a
// managed node's hook keeps the organization's fail-closed answer instead of
// following the edited file alone. An individual node follows its file.
func TestHookPostureHeldOnManagedConfigEdit(t *testing.T) {
	for _, tc := range []struct {
		name    string
		managed bool
		want    bool
	}{
		{"managed node: the posture's answer holds", true, true},
		{"individual node: the edited config decides", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			cfgPath := filepath.Join(dir, "config.toml")
			writeFileT(t, cfgPath, fmt.Sprintf("[observer]\ndb_path = %q\n[guard]\nenabled = false\nmode = \"off\"\n", filepath.ToSlash(filepath.Join(dir, "o.db"))))
			key, err := guardposture.LoadOrCreateKey(guardposture.KeyPath(cfgPath))
			if err != nil {
				t.Fatal(err)
			}
			p := enforcedPosture
			p.Managed, p.TenancyRecorded = tc.managed, true
			p.WrittenAt = time.Now().Add(-30 * time.Second)
			if _, err := guardposture.Write(guardposture.PosturePath(cfgPath), p, key); err != nil {
				t.Fatal(err)
			}
			now := time.Now()
			if err := os.Chtimes(cfgPath, now, now); err != nil {
				t.Fatal(err)
			}
			got := hookPostureFailsClosed(cfgPath, cfgPath, integration.HookCapToolGate)
			if got.FailsClosed != tc.want {
				t.Fatalf("FailsClosed = %v, want %v", got.FailsClosed, tc.want)
			}
		})
	}
}
