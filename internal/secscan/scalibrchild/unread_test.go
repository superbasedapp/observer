//go:build !sbo_omit_security_scan_scalibr

package scalibrchild

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/secscan"
	"github.com/marmutapp/superbased-observer/internal/secscan/depscan"
	"github.com/marmutapp/superbased-observer/internal/secscan/scalibrfacade"
)

// The crates.io canary record (time 0.1.42 lies inside RUSTSEC-2020-0071).
const timeAdvisory = `{"id":"RUSTSEC-2020-0071","modified":"2024-01-01T00:00:00Z","aliases":["CVE-2020-26235"],
"affected":[{"package":{"ecosystem":"crates.io","name":"time"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"0.2.23"}]}]}]}`

func writeFiles(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, body := range files {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// coverageOf runs the child over root and returns the run's coverage, as
// the driver's shared result path computes it.
func coverageOf(t *testing.T, root, db string, epochs map[string]string) (depscan.ChildResponse, secscan.Coverage) {
	t.Helper()
	resp := Run(context.Background(), depscan.ChildRequest{Version: depscan.ProtocolVersion, Root: root, DBDir: db, Epochs: epochs, GOOS: "linux"}, nil)
	if resp.Error != "" {
		t.Fatalf("resp %+v", resp)
	}
	final, gaps := depscan.Finalize(resp)
	failures := 0
	for _, x := range final.Extractors {
		if !x.OK {
			failures++
		}
	}
	return resp, depscan.Coverage(depscan.RunFacts{Ecosystems: final.Ecosystems, Gaps: gaps, ExtractorFailures: failures})
}

// TestRunUnreadDependencyFiles: a project whose only dependency file is a
// pubspec.lock is never clean (a gap until an extractor reads it), while a
// Cargo.toml with its Cargo.lock still reads clean.
func TestRunUnreadDependencyFiles(t *testing.T) {
	db := t.TempDir()
	writeDB(t, db, "crates.io", map[string]string{"a.json": timeAdvisory})
	epochs := map[string]string{"crates.io": "crates-epoch"}

	resp, cov := coverageOf(t, writeFiles(t, map[string]string{"pubspec.lock": "packages: {}\n"}), db, epochs)
	if cov.Outcome == secscan.OutcomeClean {
		t.Fatalf("coverage %+v: a project of unread files is never clean", cov)
	}
	if !scalibrfacade.Reads("pubspec.lock") {
		found := false
		for _, g := range resp.Gaps {
			found = found || (g.Ecosystem == "Pub" && g.Path == "pubspec.lock" && g.Reason == depscan.ReasonNoExtractor)
		}
		if !found {
			t.Fatalf("gaps %+v lack the unread pubspec.lock", resp.Gaps)
		}
	}

	cargo := writeFiles(t, map[string]string{
		"Cargo.toml": "[package]\nname = \"app\"\nversion = \"0.1.0\"\n[dependencies]\nserde = \"1\"\n",
		"Cargo.lock": "version = 3\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.200\"\n" +
			"source = \"registry+https://github.com/rust-lang/crates.io-index\"\n",
	})
	resp, cov = coverageOf(t, cargo, db, epochs)
	if cov.Outcome != secscan.OutcomeClean || len(resp.Gaps) != 0 || len(resp.Unlocked) != 0 {
		t.Fatalf("coverage %+v gaps %+v unlocked %+v: a locked crate with no advisory is clean", cov, resp.Gaps, resp.Unlocked)
	}
}

// TestUnreadProbeFailureIsAGap: a probe that could not finish leaves a gap
// naming no file, so the run is partial, never clean.
func TestUnreadProbeFailureIsAGap(t *testing.T) {
	gaps := unreadGaps(context.Background(), depscan.ChildRequest{Root: filepath.Join(t.TempDir(), "missing")})
	if len(gaps) != 1 || gaps[0].Path != "" || gaps[0].Reason != depscan.ReasonExtractorFailed {
		t.Fatalf("gaps %+v", gaps)
	}
	cov := depscan.Coverage(depscan.RunFacts{Ecosystems: []depscan.EcoResult{{Ecosystem: "npm", Outcome: depscan.EcoScanned, Packages: 1}}, Gaps: gaps})
	if cov.Outcome == secscan.OutcomeClean {
		t.Fatalf("coverage %+v", cov)
	}
}
