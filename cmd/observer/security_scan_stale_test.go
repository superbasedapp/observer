//go:build !sbo_omit_security && !sbo_omit_security_deps

package main

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/secscan"
	"github.com/marmutapp/superbased-observer/internal/secscan/depscan"
	"github.com/marmutapp/superbased-observer/internal/secsvc"
)

// TestOpenDepFindingsCarriesEvidence: the open-findings list a dependency
// scan closes stale findings from carries each dependency finding's
// evidence, which is where its ecosystem is read. Before, the list query
// returned none, so StaleFindings skipped every finding and a fixed
// dependency stayed open after a complete scan.
func TestOpenDepFindingsCarriesEvidence(t *testing.T) {
	dir := t.TempDir()
	setTestHome(t, t.TempDir())
	cfgPath := filepath.Join(dir, "config.toml")
	body := "[observer]\ndb_path = " + strconv.Quote(filepath.Join(dir, "observer.db")) +
		"\n[components]\nadd = [\"security.deps\", \"security.scan.scalibr\"]\n[security.deps]\nonline = false\n"
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	e, err := openDepsScanEnv(ctx, cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.cleanup)

	root := filepath.Join(dir, "proj")
	f := secfinding.Finding{
		LocalKey:         "dep-left-pad",
		Rule:             secfinding.Rule{ID: "CVE-2099-0002"},
		Engine:           secfinding.Engine{Driver: depscan.ScalibrID},
		Category:         policy.FindingVulnerableDependency,
		Severity:         policy.FindingSeverityHigh,
		Confidence:       policy.FindingConfidenceHigh,
		Location:         secfinding.Location{RelPath: "package-lock.json", StartLine: 1},
		EvidenceRedacted: "npm left-pad@1.0.0",
		Message:          "Known vulnerability in an npm package (CVE-2099-0002).",
	}
	tgt := secscan.Target{ProjectRoot: root}
	res := secscan.Result{Findings: []secfinding.Finding{f}, Coverage: secscan.Coverage{Outcome: secscan.OutcomeFindings, Scanned: []string{"npm"}}}
	if _, err := secsvc.RecordRun(ctx, e.st, tgt, res, time.Now(), time.Second, secsvc.Gone{}, nil); err != nil {
		t.Fatal(err)
	}
	open, err := e.openDepFindings(ctx, secposture.ProjectRootHash(root))
	if err != nil || len(open) != 1 {
		t.Fatalf("open %v %v", open, err)
	}
	if open[0].EvidenceRedacted != "npm left-pad@1.0.0" {
		t.Fatalf("evidence %q: the ecosystem cannot be read without it", open[0].EvidenceRedacted)
	}
	// A later complete npm scan that no longer reports it closes it.
	stale := depscan.StaleFindings(open, depscan.ScalibrID, nil, map[string]bool{"npm": true})
	if !slices.Equal(stale, []string{open[0].ID}) {
		t.Fatalf("stale %v, want the fixed dependency's finding", stale)
	}
}
