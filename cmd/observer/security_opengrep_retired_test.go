//go:build linux && !sbo_omit_security && !sbo_omit_security_scan_opengrep

package main

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/secrulepack"
	"github.com/marmutapp/superbased-observer/internal/secscan"
	"github.com/marmutapp/superbased-observer/internal/secscan/opengrep"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestPackUpgradeClosesARetiredRulesFindings is lane SEC-G4 milestone 3: a
// node moving from pack 1.1.0 to 1.2.0 holds open findings of a rule the
// new pack no longer carries (retired) and of a rewritten rule whose old
// match the new rule no longer reports. On its next closable full run
// (the canary passed, nothing cut, driver.go closable), both close, while
// a finding the new pack reports again stays open; the close is keyed by
// pack and file (codeScanGone), so no driver change is needed.
func TestPackUpgradeClosesARetiredRulesFindings(t *testing.T) {
	ctx := context.Background()
	floor, err := secrulepack.Floor()
	if err != nil {
		t.Fatal(err)
	}
	if floor.Version() != "1.5.0" {
		t.Fatalf("the embedded pack is %s, want 1.5.0", floor.Version())
	}
	const retired = "go.retired-in-1-2-0"
	if _, ok := floor.Rule(retired); ok {
		t.Fatalf("%s is in the pack", retired)
	}
	root := evalDir(t, filepath.Join(t.TempDir(), "p"))
	for _, f := range []string{"a.go", "b.py", "c.py"} {
		if err := os.WriteFile(filepath.Join(root, f), []byte("x = 1\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	st, _ := openTestStore(t)
	if _, err := st.UpsertProject(ctx, root, ""); err != nil {
		t.Fatal(err)
	}
	hash := secposture.ProjectRootHash(root)
	seed := func(rule, path string) {
		t.Helper()
		f := secfinding.Normalize(secfinding.Finding{
			LocalKey: rule + "@" + path, Rule: secfinding.Rule{ID: rule, Pack: secrulepack.PackID, PackVersion: "1.1.0"},
			Engine: secfinding.Engine{Driver: opengrep.DriverID}, Category: policy.FindingCodeVuln,
			Severity: policy.FindingSeverityHigh, Confidence: policy.FindingConfidenceMedium,
			Project: secfinding.Project{RootHash: hash}, Scope: policy.FindingScopeManual,
			Location: secfinding.Location{RelPath: path, StartLine: 1},
		})
		if _, _, err := st.UpsertSecFinding(ctx, f, time.Now().Add(-time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	seed(retired, "a.go")                    // a retired rule's finding
	seed("python.sql-string-concat", "b.py") // a rewritten rule's old match, gone
	seed("python.sql-string-concat", "c.py") // reported again by 1.2.0
	status := func() map[string]secfinding.Status {
		list, err := st.ListSecFindings(ctx, store.SecFindingFilter{ProjectRootHash: hash, Limit: 100})
		if err != nil {
			t.Fatal(err)
		}
		// Any open finding of a rule in a file reads open: the run records
		// its own match under its own fingerprint.
		out := map[string]secfinding.Status{}
		for _, f := range list {
			k := f.Rule.ID + "@" + f.Location.RelPath
			if out[k] != policy.FindingStatusOpen {
				out[k] = f.Status
			}
		}
		return out
	}

	// An unclosable run (the files read are not handed back, as for a diff
	// scope or a failed canary) closes nothing.
	tgt := secscan.Target{ProjectRoot: root, Scope: policy.FindingScopeManual}
	bin, _ := fakeOpengrep(t, t.TempDir(), [][2]string{{"python.sql-string-concat", "c.py"}}, []string{"a.go", "b.py", "c.py"}, "")
	res, scanned, err := liveDriver(t, bin).ScanFiles(ctx, tgt)
	if err != nil || !slices.Equal(scanned.Files, []string{"a.go", "b.py", "c.py"}) {
		t.Fatalf("1.2.0 full run: %+v, closable %v, %v", res.Coverage, scanned.Files, err)
	}
	if _, err := recordCodeScan(ctx, st, tgt, res, opengrep.Scanned{}, time.Now(), nil); err != nil {
		t.Fatal(err)
	}
	if s := status(); s[retired+"@a.go"] != policy.FindingStatusOpen || s["python.sql-string-concat@b.py"] != policy.FindingStatusOpen {
		t.Fatalf("an unclosable run closed findings: %v", s)
	}
	for _, f := range res.Findings {
		if f.Rule.PackVersion != "1.5.0" {
			t.Fatalf("a 1.5.0 run labelled its finding %s", f.Rule.PackVersion)
		}
	}

	// The closable full run closes the retired rule's and the gone match's
	// findings and keeps the one reported again.
	if _, err := recordCodeScan(ctx, st, tgt, res, scanned, time.Now(), nil); err != nil {
		t.Fatal(err)
	}
	s := status()
	if s[retired+"@a.go"] == policy.FindingStatusOpen || s["python.sql-string-concat@b.py"] == policy.FindingStatusOpen {
		t.Fatalf("after the closable 1.2.0 run: %v (the retired rule's and the gone match's findings stay open)", s)
	}
	if s["python.sql-string-concat@c.py"] != policy.FindingStatusOpen {
		t.Fatalf("after the closable 1.2.0 run: %v (the finding reported again closed)", s)
	}
}
