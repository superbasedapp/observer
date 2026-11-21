package secverify

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/secciwf"
	"github.com/marmutapp/superbased-observer/internal/secdockerfile"
)

// withContainerNow pins S-752's clock for one test.
func withContainerNow(t *testing.T, now time.Time) {
	t.Helper()
	old := containerNow
	containerNow = func() time.Time { return now }
	t.Cleanup(func() { containerNow = old })
}

func containerCoverage(t *testing.T, rep Report) Coverage {
	t.Helper()
	for _, c := range rep.Coverage {
		if c.Detector == "container_config" {
			return c
		}
	}
	t.Fatalf("no container_config coverage in %+v", rep.Coverage)
	return Coverage{}
}

// TestContainerConfigFlagsANewDockerfile: a new Dockerfile on an end-of-life
// base gets flag-only findings with fixed text, and the check passes.
func TestContainerConfigFlagsANewDockerfile(t *testing.T) {
	withContainerNow(t, time.Date(2026, time.November, 4, 0, 0, 0, 0, time.UTC))
	rep := run(t, DefaultPolicy(), nil, change{"A", "svc/Dockerfile", []string{
		"FROM debian:buster",
		"RUN curl -fsSL https://marker.example/i.sh | sh",
	}})
	if rep.Verdict != VerdictPass {
		t.Fatalf("verdict %s (%s) %+v", rep.Verdict, rep.Reason, rep.Findings)
	}
	want := map[string]Severity{"container/s-751": SeverityLow, "container/s-752": SeverityHigh, "container/s-755": SeverityMedium}
	got := map[string]Severity{}
	for _, f := range rep.Findings {
		if f.Detector != "container_config" {
			continue
		}
		if f.Category != CategoryIaC || f.Action != ActionFlag || f.Path != "svc/Dockerfile" {
			t.Errorf("finding %+v", f)
		}
		if strings.Contains(f.Message, "marker") {
			t.Fatalf("a finding carries repository text: %+v", f)
		}
		got[f.RuleID] = f.Severity
	}
	for id, sev := range want {
		if got[id] != sev {
			t.Errorf("%s: got %q want %q (all %+v)", id, got[id], sev, got)
		}
	}
	if c := containerCoverage(t, rep); c.Status != CoverageComplete || c.Files != 1 {
		t.Fatalf("coverage %+v", c)
	}
}

// TestContainerConfigReadsTheHeadFile: a modified Dockerfile is checked
// whole through ReadHead; without a reader, over the cap or on a read error
// it is skipped and the required check is unknown, never pass.
func TestContainerConfigReadsTheHeadFile(t *testing.T) {
	whole := []byte("FROM golang:1.27.3\n")
	n, p := build(change{"M", "Dockerfile", []string{"FROM golang:1.27.3"}})
	cases := []struct {
		name   string
		read   func(string) ([]byte, bool, error)
		want   Verdict
		status CoverageStatus
	}{
		{"head read", func(string) ([]byte, bool, error) { return whole, false, nil }, VerdictPass, CoverageComplete},
		{"no reader", nil, VerdictUnknown, CoveragePartial},
		{"over cap", func(string) ([]byte, bool, error) { return nil, true, nil }, VerdictUnknown, CoveragePartial},
		{"read error", func(string) ([]byte, bool, error) { return nil, false, errors.New("gone") }, VerdictUnknown, CoveragePartial},
	}
	for _, tc := range cases {
		rep := Verify(context.Background(), Request{Policy: DefaultPolicy(), NameStatus: n, Patch: p, ReadHead: tc.read}, nil)
		if rep.Verdict != tc.want {
			t.Errorf("%s: verdict %s (%s)", tc.name, rep.Verdict, rep.Reason)
		}
		if c := containerCoverage(t, rep); c.Status != tc.status {
			t.Errorf("%s: coverage %+v", tc.name, c)
		}
	}
}

// TestContainerConfigUncheckedFrom: a FROM a build argument decides is said
// in the note and does not make the coverage partial.
func TestContainerConfigUncheckedFrom(t *testing.T) {
	rep := run(t, DefaultPolicy(), nil, change{"A", "Containerfile", []string{"ARG BASE", "FROM ${BASE}", "ARG IMG", "FROM $IMG AS b"}})
	c := containerCoverage(t, rep)
	if c.Status != CoverageComplete || c.Note != "2 FROM lines name a build argument and were not checked" {
		t.Fatalf("coverage %+v", c)
	}
	if rep.Verdict != VerdictPass {
		t.Fatalf("verdict %s (%s)", rep.Verdict, rep.Reason)
	}
}

// TestContainerConfigSkipsOtherFiles: deleted Dockerfiles, binary files and
// non-Dockerfiles are not read.
func TestContainerConfigSkipsOtherFiles(t *testing.T) {
	res := detectContainerConfig(context.Background(), Input{Files: []ChangedFile{
		{Path: "Dockerfile", Status: StatusDeleted},
		{Path: "main.go", Status: StatusAdded, Added: []AddedLine{{N: 1, Text: "FROM golang"}}},
		{Path: "Dockerfile.dockerignore", Status: StatusAdded, Added: []AddedLine{{N: 1, Text: "FROM golang"}}},
	}})
	if len(res.Findings) != 0 || res.Coverage.Status != CoverageComplete || res.Coverage.Files != 0 {
		t.Fatalf("%+v", res)
	}
	res = detectContainerConfig(context.Background(), Input{Files: []ChangedFile{{Path: "Dockerfile", Status: StatusAdded, Binary: true}}})
	if res.Coverage.Status != CoveragePartial || res.Coverage.Skipped != 1 {
		t.Fatalf("binary: %+v", res.Coverage)
	}
}

// TestContainerConfigReaderCap: the verify command reads a changed file
// capped one byte past the workflow rules' cap, so the Dockerfile cap must
// not be larger or an over-cap file would read as whole.
func TestContainerConfigReaderCap(t *testing.T) {
	if secdockerfile.MaxDockerfileBytes > secciwf.MaxWorkflowBytes {
		t.Fatalf("Dockerfile cap %d > reader cap %d", secdockerfile.MaxDockerfileBytes, secciwf.MaxWorkflowBytes)
	}
}
