//go:build !sbo_omit_security

package secsvc

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/secscan"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestRelabelTable has one case per row of the relabel table (section
// 4.5.2 items 2 and 4).
func TestRelabelTable(t *testing.T) {
	t.Parallel()
	f := func(cat secfinding.Category, b secfinding.Baseline) secfinding.Finding {
		return secfinding.Finding{Category: cat, Baseline: b}
	}
	code := policy.FindingCategory("code_vuln")
	cases := []struct {
		name string
		f    secfinding.Finding
		at   bool
		want secfinding.Baseline
	}{
		{"a pre_existing secret becomes new", f(policy.FindingSecret, policy.FindingBaselinePreExisting), true, policy.FindingBaselineNew},
		{"a secret at the baseline stays as it is", f(policy.FindingSecret, policy.FindingBaselineUntrusted), true, policy.FindingBaselineUntrusted},
		{"a malicious package is never pre_existing", f(policy.FindingMaliciousPackage, policy.FindingBaselineNew), true, policy.FindingBaselineNew},
		{"at the baseline: pre_existing", f(code, policy.FindingBaselineUntrusted), true, policy.FindingBaselinePreExisting},
		{"at the baseline, already new: pre_existing", f(code, policy.FindingBaselineNew), true, policy.FindingBaselinePreExisting},
		{"an older pack's pre_existing not at the baseline: new", f(code, policy.FindingBaselinePreExisting), false, policy.FindingBaselineNew},
		{"untrusted, not at the baseline: new", f(code, policy.FindingBaselineUntrusted), false, policy.FindingBaselineNew},
		{"unknown, not at the baseline: new", f(code, policy.FindingBaselineUnknown), false, policy.FindingBaselineNew},
		{"new stays new", f(code, policy.FindingBaselineNew), false, policy.FindingBaselineNew},
	}
	for _, tc := range cases {
		if got := Relabel(tc.f, tc.at); got != tc.want {
			t.Errorf("%s: %s, want %s", tc.name, got, tc.want)
		}
	}
}

type treeDriver struct {
	keys    []string
	outcome secscan.Outcome
	err     error
	calls   int
	rev     string
}

func (d *treeDriver) Row() secscan.DriverRow {
	return secscan.DriverRow{ID: "tree", Kind: secscan.KindNative, ComponentID: "security", Triggers: []secfinding.Scope{policy.FindingScopeScheduled}}
}
func (d *treeDriver) Probe(context.Context) secscan.Probe { return secscan.Probe{} }
func (d *treeDriver) Scan(_ context.Context, t secscan.Target) (secscan.Result, error) {
	d.calls++
	d.rev = t.HeadRev
	res := secscan.Result{Coverage: secscan.Coverage{Outcome: d.outcome}}
	for _, k := range d.keys {
		res.Findings = append(res.Findings, secfinding.Finding{LocalKey: k})
	}
	return res, d.err
}

func codeFinding(root, key string) secfinding.Finding {
	return secfinding.Normalize(secfinding.Finding{
		LocalKey: key, Rule: secfinding.Rule{ID: "S-761"}, Category: policy.FindingCategory("code_vuln"),
		Severity: policy.FindingSeverityHigh, Confidence: policy.FindingConfidenceHigh, Baseline: policy.FindingBaselineUntrusted,
		Project: secfinding.Project{RootHash: root}, Location: secfinding.Location{RelPath: "a.go", StartLine: 1, EndLine: 1},
	})
}

// TestBaselineRescan: a rescan runs once per baseline and version, a
// changed pack version makes it due again, an incomplete run relabels
// nothing and is retried, and no driver means nothing is rescanned.
func TestBaselineRescan(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "o.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	st := store.New(database)
	root := "/work/p"
	hash := secposture.ProjectRootHash(root)
	t0 := time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC)
	for _, k := range []string{"old", "fresh"} {
		if _, _, err := st.UpsertSecFinding(ctx, codeFinding(hash, k), t0); err != nil {
			t.Fatal(err)
		}
	}
	d := &treeDriver{keys: []string{"old"}, outcome: secscan.OutcomeFindings}
	b := &BaselineRescanner{Store: st, Drivers: []secscan.Driver{d}, PackVersion: "p1"}
	if r, err := b.Rescan(ctx, root); err != nil || r.Outcome != BaselineNoBaseline || d.calls != 0 {
		t.Fatalf("no baseline: %+v, %v, %d calls", r, err, d.calls)
	}
	if err := st.AddSecBaseline(ctx, store.SecBaseline{ProjectRootHash: hash, Kind: "commit", Ref: "abc123", CreatedAt: t0}); err != nil {
		t.Fatal(err)
	}
	r, err := b.Rescan(ctx, root)
	if err != nil || r.Outcome != BaselineRescanned || r.Relabelled != 2 || d.rev != "abc123" {
		t.Fatalf("first rescan: %+v, %v, rev %q", r, err, d.rev)
	}
	labels := func() map[string]secfinding.Baseline {
		t.Helper()
		got, err := st.ListSecFindings(ctx, store.SecFindingFilter{ProjectRootHash: hash})
		if err != nil {
			t.Fatal(err)
		}
		m := map[string]secfinding.Baseline{}
		for _, f := range got {
			m[f.LocalKey] = f.Baseline
		}
		return m
	}
	if l := labels(); l["old"] != policy.FindingBaselinePreExisting || l["fresh"] != policy.FindingBaselineNew {
		t.Fatalf("labels after the rescan: %v", l)
	}
	// Current: no second scan, in this process or a fresh one.
	if r, _ := b.Rescan(ctx, root); r.Outcome != BaselineCurrent || d.calls != 1 {
		t.Fatalf("second pass: %+v, %d calls", r, d.calls)
	}
	b2 := &BaselineRescanner{Store: st, Drivers: []secscan.Driver{d}, PackVersion: "p1"}
	if r, _ := b2.Rescan(ctx, root); r.Outcome != BaselineCurrent || d.calls != 1 {
		t.Fatalf("restart: %+v, %d calls", r, d.calls)
	}
	// A new pack version: due again; an incomplete run relabels nothing.
	d.outcome, d.keys = secscan.OutcomeUnknown, nil
	b3 := &BaselineRescanner{Store: st, Drivers: []secscan.Driver{d}, PackVersion: "p2"}
	if r, _ := b3.Rescan(ctx, root); r.Outcome != BaselineIncomplete {
		t.Fatalf("incomplete: %+v", r)
	}
	if l := labels(); l["old"] != policy.FindingBaselinePreExisting {
		t.Fatalf("an incomplete run changed a label: %v", l)
	}
	d.err = errors.New("boom")
	if _, err := b3.Rescan(ctx, root); err == nil {
		t.Fatal("a driver error is reported")
	}
	d.err, d.outcome = nil, secscan.OutcomeClean
	if r, _ := b3.Rescan(ctx, root); r.Outcome != BaselineRescanned || r.Relabelled != 1 {
		t.Fatalf("p2 rescan: %+v", r)
	}
	if l := labels(); l["old"] != policy.FindingBaselineNew {
		t.Fatalf("the new pack no longer reports old at the baseline: %v", l)
	}
	if last, _ := st.SecLastScan(ctx, hash); !last.IsZero() {
		t.Fatalf("a baseline rescan is not a scan of the working tree: %v", last)
	}
	if r, _ := (&BaselineRescanner{Store: st, PackVersion: "p3"}).Rescan(ctx, root); r.Outcome != BaselineNoDriver {
		t.Fatalf("no driver: %+v", r)
	}
}
