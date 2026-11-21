//go:build !sbo_omit_security_scan_scalibr

package scalibrchild

import (
	"archive/zip"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/secscan"
	"github.com/marmutapp/superbased-observer/internal/secscan/depscan"
	"github.com/marmutapp/superbased-observer/internal/secscan/scalibrfacade"
)

// artifacts_test.go: the scan child carries the artifact extractors'
// packages (marked Artifact) into the matched result, and an artifact over
// the size cap becomes a gap, so the run is partial, never clean. The
// extractor canaries themselves are in scalibrfacade/artifacts_test.go.

const log4j = `{"id":"GHSA-jfh8-c2jp-5v3q","modified":"2024-01-01T00:00:00Z","aliases":["CVE-2021-44228"],
"affected":[{"package":{"ecosystem":"Maven","name":"org.apache.logging.log4j:log4j-core"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"2.0-beta9"},{"fixed":"2.15.0"}]}]}],
"database_specific":{"severity":"CRITICAL"}}`

func TestRunReadsArtifacts(t *testing.T) {
	root := t.TempDir()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties")
	_, _ = w.Write([]byte("groupId=org.apache.logging.log4j\nartifactId=log4j-core\nversion=2.14.1\n"))
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	jar := filepath.Join(root, "lib", "log4j-core-2.14.1.jar")
	if err := os.MkdirAll(filepath.Dir(jar), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(jar, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	db := t.TempDir()
	writeDB(t, db, "Maven", map[string]string{"a.json": log4j})
	resp := Run(context.Background(), depscan.ChildRequest{
		Version: depscan.ProtocolVersion, Root: root, DBDir: db, Epochs: map[string]string{"Maven": "maven-epoch"}, GOOS: "linux",
	}, nil)
	if resp.Error != "" {
		t.Fatalf("resp %+v", resp)
	}
	idx := -1
	for i, p := range resp.Packages {
		if p.Ecosystem == "Maven" && p.Name == "org.apache.logging.log4j:log4j-core" {
			idx = i
			if !p.Artifact || p.Path != "lib/log4j-core-2.14.1.jar" {
				t.Fatalf("package %+v", p)
			}
		}
	}
	if idx < 0 {
		t.Fatalf("the JAR's package is missing: %+v", resp.Packages)
	}
	var maven depscan.EcoResult
	for _, e := range resp.Ecosystems {
		if e.Ecosystem == "Maven" {
			maven = e
		}
	}
	if maven.Outcome != depscan.EcoScanned || len(maven.Advisories) != 1 || maven.Advisories[0].Index != idx {
		t.Fatalf("Maven %+v: the JAR's log4j-core must match (the Maven canary log4j-core 2.14.1 is the same advisory)", maven)
	}
}

func TestArtifactGapsMakeTheRunPartial(t *testing.T) {
	gaps := artifactGaps([]scalibrfacade.ArtifactSkip{{Path: "bin/huge"}, {Ecosystem: "Maven", Path: "lib/huge.jar"}})
	if len(gaps) != 2 || gaps[0].Reason != depscan.ReasonArtifactTooLarge || gaps[0].Ecosystem != "" || gaps[1].Ecosystem != "Maven" {
		t.Fatalf("gaps %+v", gaps)
	}
	resp, all := depscan.Finalize(depscan.ChildResponse{
		Ecosystems: []depscan.EcoResult{{Ecosystem: "Maven", Outcome: depscan.EcoScanned, Packages: 1}},
		Gaps:       gaps,
	})
	cov := depscan.Coverage(depscan.RunFacts{Ecosystems: resp.Ecosystems, Gaps: all})
	if cov.Outcome == secscan.OutcomeClean || len(cov.Scanned) != 0 {
		t.Fatalf("an artifact over the cap must keep the run from reading clean: %+v", cov)
	}
	if depscan.ReasonWords(depscan.ReasonArtifactTooLarge) == depscan.ReasonArtifactTooLarge {
		t.Fatal("the gap reason has no words")
	}
}
