package secsignal

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secdepdetail"
	"github.com/marmutapp/superbased-observer/internal/secexploit"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secrank"
	"github.com/marmutapp/superbased-observer/internal/secreach"
	"github.com/marmutapp/superbased-observer/internal/secreachsvc"
)

func tree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, body := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

var records = map[string]string{
	"GO-1": `{"id":"GO-1","aliases":["CVE-2021-44228","GHSA-jfh8-c2jp-5v3q"],"affected":[{"package":{"ecosystem":"Go","name":"golang.org/x/net"},"ecosystem_specific":{"imports":[{"path":"golang.org/x/net/html"}]}}]}`,
	"GO-2": `{"id":"GO-2","aliases":["CVE-2024-3094"],"affected":[{"package":{"ecosystem":"Go","name":"golang.org/x/net"},"ecosystem_specific":{"imports":[{"path":"golang.org/x/net/http2"}]}}]}`,
}

func depFinding(id, rule string) secfinding.Finding {
	return secfinding.Finding{
		ID: id, Category: policy.FindingVulnerableDependency, Rule: secfinding.Rule{ID: rule},
		Message: "Known vulnerability in a Go dependency.", Location: secfinding.Location{RelPath: "go.mod"},
	}
}

// fakeExploit lists CVE-2021-44228 in KEV and scores both CVEs.
func fakeExploit(asked *[][]string) func(ids []string) secexploit.Exploit {
	return func(ids []string) secexploit.Exploit {
		*asked = append(*asked, ids)
		x := secexploit.Exploit{KEVAvailable: true, EPSSAvailable: true}
		for _, id := range ids {
			switch id {
			case "CVE-2021-44228":
				x.KEV = &secexploit.KEVEntry{CVE: id, DateAdded: "2021-12-10"}
				x.EPSS, x.EPSSCVE = &secexploit.Score{Score: 0.944, ScoreMilli: 944, PercentileMilli: 1000}, id
			case "CVE-2024-3094":
				x.EPSS, x.EPSSCVE = &secexploit.Score{Score: 0.861, ScoreMilli: 861, PercentileMilli: 993}, id
			}
		}
		return x
	}
}

func TestCompute(t *testing.T) {
	root := tree(t, map[string]string{
		"go.mod":  "module example.com/app\n\ngo 1.22\n\nrequire golang.org/x/net v0.1.0\n",
		"main.go": "package main\n\nimport _ \"golang.org/x/net/html\"\n",
	})
	reads := 0
	record := func(eco, id string) ([]byte, error) {
		reads++
		if r, ok := records[id]; ok && eco == "Go" {
			return []byte(r), nil
		}
		return nil, secdepdetail.ErrRecordNotFound
	}
	findings := []secfinding.Finding{
		depFinding("html", "GO-1"),
		depFinding("http2", "GO-2"),
		depFinding("nopkg", "GO-1"),
		{ID: "secret", Category: policy.FindingSecret, Rule: secfinding.Rule{ID: "S-1"}},
	}
	evidence := map[string]string{"html": "Go golang.org/x/net@v0.1.0", "http2": "Go golang.org/x/net@v0.1.0"}
	var asked [][]string
	got := Compute(context.Background(), Inputs{
		Root: root, Findings: findings, Evidence: evidence, Record: record, Exploit: fakeExploit(&asked),
		Reach: []secreachsvc.Option{secreachsvc.WithCache(secreachsvc.NewCache(0))},
	})
	if _, ok := got["secret"]; ok {
		t.Fatal("a non-dependency finding got a signal")
	}
	if g := got["html"]; g.Reach.Level != secreach.Imported || g.Exploit.KEV == nil {
		t.Fatalf("html %+v", g)
	}
	if g := got["http2"]; g.Reach.Level != secreach.NotImportedDirectly || g.Exploit.KEV != nil || g.Exploit.EPSS == nil {
		t.Fatalf("http2 %+v", g)
	}
	// No package in the evidence: no advisory read, the finding's own ids
	// still asked (and here, GO-1 names no CVE of its own).
	if g := got["nopkg"]; g.Reach != secreach.UnknownTier(secreach.ReasonNoAdvisory) || g.Exploit.KEV != nil {
		t.Fatalf("nopkg %+v", g)
	}
	// The record's aliases (the CVE ids) reach the exploit lookup.
	if !reflect.DeepEqual(asked[0], []string{"GO-1", "CVE-2021-44228", "GHSA-jfh8-c2jp-5v3q"}) {
		t.Fatalf("exploit ids %v", asked[0])
	}
	// Each record is read once per Compute.
	if reads != 2 {
		t.Fatalf("record reads %d, want 2", reads)
	}
	// The rank: KEV-listed html before http2.
	if secrank.Compare(got["html"].Key(), got["http2"].Key()) >= 0 {
		t.Fatal("the KEV-listed finding does not rank first")
	}
}

func TestComputeWithoutData(t *testing.T) {
	findings := []secfinding.Finding{depFinding("html", "GO-1")}
	got := Compute(context.Background(), Inputs{Findings: findings, Evidence: map[string]string{"html": "Go golang.org/x/net@v0.1.0"}})
	g, ok := got["html"]
	if !ok {
		t.Fatal("no signal")
	}
	// No OSV store, no exploit data, no root: unknown and unavailable, never
	// "not imported" or "not exploited".
	if g.Reach.Level != secreach.Unknown || g.Exploit.Available() {
		t.Fatalf("%+v", g)
	}
	if !reflect.DeepEqual(secexploit.Badges(g.Exploit), []string{secexploit.BadgeUnavailable}) {
		t.Fatalf("badges %q", secexploit.Badges(g.Exploit))
	}
	if g.Key() != secrank.NoSignal() {
		t.Fatalf("key %+v", g.Key())
	}
	if len(Compute(context.Background(), Inputs{})) != 0 {
		t.Fatal("no findings, no signals")
	}
}

// TestComputeSymbolChecks: a stored binary check moves a finding seen only
// in that binary to "called" or "not called"; a finding also seen in
// go.mod is never "not called" from the binary alone, and without
// sightings neither is any other.
func TestComputeSymbolChecks(t *testing.T) {
	root := tree(t, map[string]string{
		"go.mod":  "module example.com/app\n\ngo 1.22\n\nrequire golang.org/x/net v0.1.0\n",
		"main.go": "package main\n\nimport _ \"golang.org/x/net/html\"\n",
	})
	record := func(eco, id string) ([]byte, error) {
		if r, ok := records[id]; ok && eco == "Go" {
			return []byte(r), nil
		}
		return nil, secdepdetail.ErrRecordNotFound
	}
	inBin := func(id, rule string) secfinding.Finding {
		f := depFinding(id, rule)
		f.Location.RelPath = "bin/app"
		return f
	}
	findings := []secfinding.Finding{inBin("called", "GO-1"), inBin("not", "GO-2"), inBin("also-gomod", "GO-2")}
	evidence := map[string]string{"called": "Go golang.org/x/net@v0.1.0", "not": "Go golang.org/x/net@v0.1.0", "also-gomod": "Go golang.org/x/net@v0.1.0"}
	runs := []secreach.SymbolRun{{Source: secreach.SourceGovulncheckBinary, Target: "bin/app", Records: []secreach.SymbolRecord{
		{ID: "GO-1", Module: "golang.org/x/net", Version: "v0.1.0", Verdict: secreach.VerdictCalled, Symbol: "html.Parse"},
		{ID: "GO-2", Module: "golang.org/x/net", Version: "v0.1.0", Verdict: secreach.VerdictNotCalled},
	}}}
	sightings := func(_ context.Context, id string) ([]string, error) {
		if id == "also-gomod" {
			return []string{"bin/app", "go.mod"}, nil
		}
		return []string{"bin/app"}, nil
	}
	in := Inputs{
		Root: root, Findings: findings, Evidence: evidence, Record: record, Symbol: runs, Sightings: sightings,
		Reach: []secreachsvc.Option{secreachsvc.WithCache(secreachsvc.NewCache(0))},
	}
	got := Compute(context.Background(), in)
	if g := got["called"].Reach; g.Level != secreach.Called || g.Match != "html.Parse" || g.Target != "bin/app" {
		t.Fatalf("called: %+v", g)
	}
	if g := got["not"].Reach; g.Level != secreach.NotCalled || g.Source != secreach.SourceGovulncheckBinary {
		t.Fatalf("not called: %+v", g)
	}
	if g := got["also-gomod"].Reach; g.Level != secreach.NotImportedDirectly {
		t.Fatalf("seen in go.mod too: %+v, want the 3a tier", g)
	}
	if secrank.Compare(got["called"].Key(), got["not"].Key()) >= 0 {
		t.Fatal("called does not rank before not called")
	}
	in.Sightings = nil
	if g := Compute(context.Background(), in)["not"].Reach; g.Level != secreach.NotImportedDirectly {
		t.Fatalf("no sightings: %+v, want the 3a tier", g)
	}
}
