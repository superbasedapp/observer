package main

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
)

// TestBundleIncidentTableIsTotal pins the dedup table's shape: every (state,
// event) pair has exactly one row, so no observation falls through.
func TestBundleIncidentTableIsTotal(t *testing.T) {
	states := []bundleIncidentState{bundleIncidentNone, bundleIncidentReported, bundleIncidentRepaired, bundleIncidentResolved}
	events := []bundleIncidentEvent{bundleSeenSame, bundleSeenNew, bundleSeenVerified, bundlePollRepair}
	if len(bundleIncidentTable) != len(states) {
		t.Fatalf("table has %d states, want %d", len(bundleIncidentTable), len(states))
	}
	for _, s := range states {
		if len(bundleIncidentTable[s]) != len(events) {
			t.Fatalf("state %d has %d rows, want %d", s, len(bundleIncidentTable[s]), len(events))
		}
		for _, e := range events {
			if _, ok := bundleIncidentTable[s][e]; !ok {
				t.Fatalf("state %d has no row for event %d", s, e)
			}
		}
	}
}

// t869Step is one thing that happens to the cached org bundle in a
// TestBundleTamperRecordedOnce sequence.
type t869Step int

const (
	stepEdit       t869Step = iota // deny -> allow, version kept (no longer verifies)
	stepDelete                     // the file is removed
	stepUpgrade                    // the org's v30 is written (a normal upgrade, verifies)
	stepPosture                    // the 15 s posture check runs (checkOrgBundle)
	stepPollWrite                  // the poll writes the org's bundle back (before its result is handled)
	stepTamperRes                  // the poll's result: applied, repaired a tampered cache
	stepMissingRes                 // the poll's result: applied, repaired a missing cache
	stepCleanRes                   // the poll's result: applied, nothing repaired
)

// TestBundleTamperRecordedOnce pins T-869: whichever check finds a tampered
// or deleted org bundle first (the posture check, or the policy poll that
// re-downloads it), the incident is ONE org_bundle_tamper event; a normal
// upgrade and a first fetch record none; and a deletion on an individual node
// is no tamper (the posture check's own rule). "poll" below is stepPollWrite
// followed by its result, the order the daemon runs them in.
func TestBundleTamperRecordedOnce(t *testing.T) {
	for _, tc := range []struct {
		name       string
		managed    bool
		steps      []t869Step
		wantEvents int
		wantDetail string
	}{
		{
			"poll first: an edited cache the poll repairs", true,
			[]t869Step{stepEdit, stepPollWrite, stepTamperRes, stepPosture},
			1, "changed outside the daemon and no longer verified (sig_invalid); the policy poll restored",
		},
		{
			"posture first, then the poll", true,
			[]t869Step{stepEdit, stepPosture, stepPollWrite, stepTamperRes, stepPosture},
			1, "org bundle",
		},
		{
			"posture saw the file verify before the poll's result arrived", true,
			[]t869Step{stepEdit, stepPosture, stepPollWrite, stepPosture, stepTamperRes, stepPosture},
			1, "org bundle",
		},
		{
			"posture sees the same edit twice before the poll", true,
			[]t869Step{stepEdit, stepPosture, stepPosture, stepPollWrite, stepTamperRes, stepPosture},
			1, "org bundle",
		},
		{
			"deletion repaired by the poll", true,
			[]t869Step{stepDelete, stepPollWrite, stepMissingRes, stepPosture},
			1, "was removed outside the daemon",
		},
		{
			"deletion seen by the posture check first, then the poll", true,
			[]t869Step{stepDelete, stepPosture, stepPollWrite, stepMissingRes, stepPosture},
			1, "is missing",
		},
		{
			"two edits, each repaired by the poll first, are two incidents", true,
			[]t869Step{stepEdit, stepPollWrite, stepTamperRes, stepPosture, stepEdit, stepPollWrite, stepTamperRes, stepPosture},
			2, "no longer verified",
		},
		{
			"normal upgrade v29 to v30", true,
			[]t869Step{stepUpgrade, stepCleanRes, stepPosture},
			0, "",
		},
		{
			"a first fetch on a node that never accepted a bundle", true,
			[]t869Step{stepPollWrite, stepCleanRes, stepPosture},
			0, "",
		},
		{
			"individual node: a deletion the poll repairs is no tamper", false,
			[]t869Step{stepDelete, stepPollWrite, stepMissingRes, stepPosture},
			0, "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			bundlePath := filepath.Join(dir, "org-policy-bundle.json")
			sign, pin := bundleSigner(t)
			good := sign(29, orgLockBundleTOML)
			writeFileT(t, bundlePath, good)
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
			setProcessPolicyBundleKick(func() {})
			t.Cleanup(func() { setProcessPolicyBundleKick(nil) })
			w := &guardPostureWriter{}
			r := &policyBundleRunner{
				logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
				orgURL:    "https://org.example",
				acquire:   func(context.Context) *guard.Guard { return gd },
				cachePath: bundlePath,
				posture:   w,
			}
			for _, s := range tc.steps {
				switch s {
				case stepEdit:
					writeFileT(t, bundlePath, strings.Replace(good, "deny", "allow", 1))
				case stepDelete:
					if err := os.Remove(bundlePath); err != nil {
						t.Fatal(err)
					}
				case stepUpgrade:
					writeFileT(t, bundlePath, sign(30, orgLockBundleTOML))
				case stepPosture:
					w.checkOrgBundle(gd)
				case stepPollWrite:
					writeFileT(t, bundlePath, good)
				case stepTamperRes:
					r.onResult(orgclient.PolicyResult{Status: orgclient.PolicyApplied, Version: 29, RepairedCache: orgclient.CacheRepairTampered, RepairedCode: orgclient.RejectSigInvalid})
				case stepMissingRes:
					r.onResult(orgclient.PolicyResult{Status: orgclient.PolicyApplied, Version: 29, RepairedCache: orgclient.CacheRepairMissing})
				case stepCleanRes:
					r.onResult(orgclient.PolicyResult{Status: orgclient.PolicyApplied, Version: 30})
				}
			}
			got := w.takeExtraTampers()
			if len(got) != tc.wantEvents {
				t.Fatalf("events = %+v, want %d", got, tc.wantEvents)
			}
			for _, e := range got {
				if e.kind != tamperOrgBundle || !strings.Contains(e.detail, tc.wantDetail) {
					t.Fatalf("event = %+v, want an org bundle tamper containing %q", e, tc.wantDetail)
				}
			}
		})
	}
}

// TestBundleRepairDetail pins the repair rows, one per poll result shape:
// only an Applied fetch that repaired something is an event, a displaced
// entry is named as such, and the reason renders the cache path as "~/...".
func TestBundleRepairDetail(t *testing.T) {
	home := t.TempDir()
	prev := guardEventHome
	guardEventHome = func() (string, error) { return home, nil }
	t.Cleanup(func() { guardEventHome = prev })
	cachePath := filepath.Join(home, ".observer", "org-policy-bundle.json")
	// The reason keeps the path's own separators after the home becomes ~
	// (guard.HomeTilde rewrites only the home), so "~\.observer\..." on
	// Windows (Windows 11 Pro rerun 2026-10-25, D5 group 4).
	tildeBundle := filepath.Join("~", ".observer", "org-policy-bundle.json")
	for _, tc := range []struct {
		name       string
		in         bundleRepair
		wantOK     bool
		wantReason string
	}{
		{
			"tampered",
			bundleRepair{res: orgclient.PolicyResult{Status: orgclient.PolicyApplied, RepairedCache: orgclient.CacheRepairTampered, RepairedCode: orgclient.RejectSigInvalid}, cachePath: cachePath, deletionIsTamper: true},
			true, "org policy bundle tampered: " + tildeBundle + " was changed outside the daemon and no longer verified (sig_invalid); the policy poll restored the organization's bundle",
		},
		{
			"missing on a managed node",
			bundleRepair{res: orgclient.PolicyResult{Status: orgclient.PolicyApplied, RepairedCache: orgclient.CacheRepairMissing}, cachePath: cachePath, deletionIsTamper: true},
			true, "org policy bundle tampered: " + tildeBundle + " was removed outside the daemon although this node had accepted a verified bundle; the policy poll restored the organization's bundle",
		},
		{"missing on an individual node", bundleRepair{res: orgclient.PolicyResult{Status: orgclient.PolicyApplied, RepairedCache: orgclient.CacheRepairMissing}, cachePath: cachePath}, false, ""},
		{
			"displaced wins over missing",
			bundleRepair{res: orgclient.PolicyResult{Status: orgclient.PolicyApplied, RepairedCache: orgclient.CacheRepairMissing, DisplacedTo: cachePath + ".displaced-x"}, cachePath: cachePath, deletionIsTamper: true},
			true, "moved it aside to org-policy-bundle.json.displaced-x",
		},
		{"clean upgrade", bundleRepair{res: orgclient.PolicyResult{Status: orgclient.PolicyApplied, Version: 2}, cachePath: cachePath, deletionIsTamper: true}, false, ""},
		{"not applied", bundleRepair{res: orgclient.PolicyResult{Status: orgclient.PolicyUnchanged, RepairedCache: orgclient.CacheRepairTampered}, cachePath: cachePath, deletionIsTamper: true}, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			detail, ok := bundleRepairDetail(tc.in)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v (%q), want %v", ok, detail, tc.wantOK)
			}
			if !ok {
				return
			}
			reason := tamperVerdict(guardTamper{tamperOrgBundle, detail}, time.Time{}).Verdict.Reason
			if !strings.Contains(reason, tc.wantReason) {
				t.Fatalf("reason = %q, want it to contain %q", reason, tc.wantReason)
			}
			if strings.Contains(reason, home) {
				t.Fatalf("reason = %q names the absolute home", reason)
			}
		})
	}
}
