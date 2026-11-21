package trivyimage

import (
	"context"
	"errors"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/extrun"
	"github.com/marmutapp/superbased-observer/internal/extrun/extruntest"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secscan"
	"github.com/marmutapp/superbased-observer/internal/secscan/depscan"
	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestPackageImports_Bounded pins the driver free of its own I/O.
func TestPackageImports_Bounded(t *testing.T) {
	t.Parallel()
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{
			"database/sql", "net", "net/http", "os", "os/exec", "syscall", "github.com/fsnotify/fsnotify",
			"github.com/marmutapp/superbased-observer/internal/secscan/trivydb",
		},
		Reason: "the Trivy image driver does no I/O of its own (Env injects it) and never links the database download lane",
	})
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestArgsCarryTheFlagTable: both modes pass every required flag, none of
// the never flags, the target last; the pinned version's help lists them.
func TestArgsCarryTheFlagTable(t *testing.T) {
	t.Parallel()
	for _, m := range []Mode{ModeImage, ModeRootfs} {
		p := Paths{Target: "/in/image.tar", Cache: "/c/cache", Report: "/c/out/report.json"}
		args := Args(m, p)
		if args[0] != string(m) || args[len(args)-1] != p.Target {
			t.Errorf("%s: %v", m, args)
		}
		for _, f := range RequiredFlags(m) {
			if !slices.Contains(args, f) {
				t.Errorf("%s does not pass %s", m, f)
			}
		}
		for _, f := range NeverFlags {
			for _, a := range args {
				if a == f || strings.HasPrefix(a, f+"=") {
					t.Errorf("%s passes the never flag %s", m, f)
				}
			}
		}
		for _, pair := range [][2]string{{"--scanners", "vuln"}, {"--pkg-types", "os"}, {"--cache-backend", "memory"}, {"--format", "json"}, {"--cache-dir", p.Cache}, {"--exit-code", "0"}} {
			i := slices.Index(args, pair[0])
			if i < 0 || i+1 >= len(args) || args[i+1] != pair[1] {
				t.Errorf("%s: %s is not %q: %v", m, pair[0], pair[1], args)
			}
		}
		if missing := MissingFlags(m, readFixture(t, "trivy-0.75.0-"+string(m)+"-help.txt")); len(missing) > 0 {
			t.Errorf("trivy 0.75.0 %s --help lacks %v", m, missing)
		}
		if missing := MissingFlags(m, []byte("  --scanners string\n")); len(missing) == 0 {
			t.Errorf("%s: a thin help passed", m)
		}
	}
	if slices.Contains(Args(ModeRootfs, Paths{Target: "/r"}), "--input") {
		t.Error("rootfs passes --input")
	}
	if !slices.Contains(Args(ModeImage, Paths{Target: "/i.tar"}), "--input") {
		t.Error("image does not pass --input")
	}
}

// TestParse: the schema version is checked, and an empty, oversized or
// malformed report is refused.
func TestParse(t *testing.T) {
	t.Parallel()
	if r, err := Parse(readFixture(t, "debian-image-report.json")); err != nil || len(r.OSResults()) != 1 || r.Metadata.OS.Family != "debian" {
		t.Fatalf("%+v %v", r, err)
	}
	for name, b := range map[string][]byte{
		"empty":     nil,
		"malformed": []byte(`{`),
		"schema 1":  []byte(`{"SchemaVersion":1}`),
	} {
		if _, err := Parse(b); !errors.Is(err, ErrReport) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func mapDebian(t *testing.T, label string) MapOutput {
	t.Helper()
	r, err := Parse(readFixture(t, "debian-image-report.json"))
	if err != nil {
		t.Fatal(err)
	}
	return Map(MapInput{
		Report: r, Label: label, RootHash: "h", Scope: policy.FindingScopeManual, Epoch: "trivy-db@sha256:abc",
		Engine: secscan.EngineIdentity{Name: DriverID, Version: "0.75.0", Digest: "d"}, Location: Location{RelPath: "Dockerfile", Line: 3},
	})
}

// TestMapFindings: route A's shape, Trivy's severity, the CVE (else the
// vendor id) as the rule, the fixed version in the hint, the no-fix note,
// kernel packages left out and named, and an id or version outside the
// charset never carried.
func TestMapFindings(t *testing.T) {
	t.Parallel()
	out := mapDebian(t, "Debian:12")
	byRule := map[string]secfinding.Finding{}
	for _, f := range out.Findings {
		byRule[f.Rule.ID] = f
	}
	if len(out.Findings) != 4 {
		t.Fatalf("got %d findings: %+v", len(out.Findings), byRule)
	}
	if out.Unreadable != 2 {
		t.Errorf("unreadable %d, want 2 (an injected version and an id with spaces)", out.Unreadable)
	}
	if out.Matched != 3 || len(out.Packages) != 4 {
		t.Errorf("matched %d of %d packages", out.Matched, len(out.Packages))
	}
	if !strings.HasPrefix(out.KernelNote, depscan.KernelNotePrefix) || !strings.Contains(out.KernelNote, "linux-libc-dev") {
		t.Errorf("kernel note %q", out.KernelNote)
	}
	if _, ok := byRule["CVE-2026-2222"]; ok {
		t.Error("a kernel package's advisory was recorded")
	}
	crit := byRule["CVE-2025-9230"]
	if crit.Severity != policy.FindingSeverityCritical || crit.Category != policy.FindingVulnerableDependency ||
		crit.EvidenceRedacted != "Debian:12 libssl3@3.0.17-1~deb12u2" || !strings.Contains(crit.FixHint, "3.0.17-1~deb12u3") ||
		!strings.Contains(crit.Message, "DSA-6015-1") || crit.Engine.Driver != DriverID || crit.Rule.Pack != RulePack ||
		crit.Engine.DatabaseEpoch != "trivy-db@sha256:abc" || crit.Location.RelPath != "Dockerfile" || crit.Location.StartLine != 3 {
		t.Errorf("critical %+v", crit)
	}
	if strings.Contains(crit.Message, NoFixNote) {
		t.Error("a fixed advisory says no fix")
	}
	wnf := byRule["CVE-2026-1111"]
	row, _ := secscan.Adapter("osv")
	if wnf.Severity != row.Default || !strings.Contains(wnf.Message, NoFixNote+" (the distribution will not fix it)") || !strings.HasPrefix(wnf.FixHint, NoFixNote) {
		t.Errorf("will not fix %+v", wnf)
	}
	if f, ok := byRule["DLA-4867-1"]; !ok || !strings.Contains(f.FixHint, "2025c-0+deb12u1") {
		t.Errorf("the vendor id is not the rule of a CVE-less advisory: %+v", byRule)
	}
	if out.NoFix != 2 {
		t.Errorf("no fix %d, want 2", out.NoFix)
	}
	// A Trivy finding never shares a lifecycle row with route A's finding
	// of the same advisory.
	routeA := secfinding.LocalKey("h", "CVE-2025-9230", secfinding.DependencyIdentity("Debian:12", "libssl3", "3.0.17-1~deb12u2", "CVE-2025-9230"))
	if crit.LocalKey == routeA || crit.LocalKey == "" {
		t.Error("the Trivy finding's local key equals route A's")
	}
	// The ecosystem stale-closing reads is the release label.
	if got := depscan.EcosystemOfFinding(crit); got != "Debian:12" {
		t.Errorf("ecosystem of finding %q", got)
	}
	// No label from the caller: Trivy's detected OS.
	if out := mapDebian(t, ""); out.Label != "debian:12.15" || len(out.Findings) != 4 {
		t.Errorf("fallback label %q, %d findings", out.Label, len(out.Findings))
	}
}

// TestReleaseLabel: Trivy's detected OS, or nothing.
func TestReleaseLabel(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		os   *OSInfo
		want string
	}{
		{nil, ""},
		{&OSInfo{Family: "none"}, ""},
		{&OSInfo{Family: "amazon", Name: "2023"}, "amazon:2023"},
		{&OSInfo{Family: "wolfi", Name: "20230201"}, "wolfi:20230201"},
		{&OSInfo{Family: "evil", Name: "a;b"}, ""},
	} {
		if got := ReleaseLabel(c.os); got != c.want {
			t.Errorf("%+v: %q, want %q", c.os, got, c.want)
		}
	}
}

// TestCanary: the canary report is a hit; an image report and a report
// with another release are not; the files carry the package Trivy needs.
func TestCanary(t *testing.T) {
	t.Parallel()
	c, err := Parse(readFixture(t, "canary-report.json"))
	if err != nil || !CanaryHit(c) {
		t.Fatalf("canary %v", err)
	}
	d, _ := Parse(readFixture(t, "debian-image-report.json"))
	if CanaryHit(d) {
		t.Error("an image report read as the canary")
	}
	c.Metadata.OS = &OSInfo{Family: "ubuntu", Name: "24.04"}
	if CanaryHit(c) {
		t.Error("another release read as the canary")
	}
	files := CanaryFiles()
	if !strings.Contains(files["var/lib/dpkg/status"], "Version: "+CanaryVersion) || files["etc/debian_version"] == "" || !strings.Contains(files["etc/os-release"], "ID=debian") {
		t.Errorf("canary files %v", files)
	}
}

// --- the run seam -----------------------------------------------------------

const (
	dTrivy   = "/opt/trivy/bin/trivy"
	dCache   = "/c/run/cache"
	dOut     = "/c/run/out"
	dCanary  = "/c/run/canary"
	dInput   = "/c/run/input"
	dTarget  = "/c/run/input/image.tar"
	trivySum = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

type fakeProvider struct{}

func (fakeProvider) Name() string { return "test-no-network" }
func (fakeProvider) Wrap(_ context.Context, p extrun.Plan) (extrun.Plan, error) {
	p.Path = "/isolate"
	return p, nil
}

// trivyFake scripts Trivy: what --version and --help print and what a run
// writes.
type trivyFake struct {
	t        *testing.T
	mu       sync.Mutex
	written  map[string][]byte
	version  string
	help     map[Mode][]byte
	image    []byte
	noCanary bool
	exit     int
	files    extruntest.Files
}

func newTrivyFake(t *testing.T) *trivyFake {
	return &trivyFake{
		t: t, written: map[string][]byte{}, version: "Version: 0.75.0\n",
		help:  map[Mode][]byte{ModeImage: readFixture(t, "trivy-0.75.0-image-help.txt"), ModeRootfs: readFixture(t, "trivy-0.75.0-rootfs-help.txt")},
		image: readFixture(t, "debian-image-report.json"),
		files: extruntest.Files{dTrivy: {Digest: trivySum}},
	}
}

func (f *trivyFake) facts(p extrun.Plan) extrun.ExecFacts {
	switch {
	case slices.Contains(p.Args, "--version"):
		return extrun.ExecFacts{Stdout: []byte(f.version), PeakChildren: -1}
	case slices.Contains(p.Args, "--help"):
		return extrun.ExecFacts{Stdout: f.help[Mode(p.Args[0])], PeakChildren: -1}
	}
	if f.exit != 0 {
		return extrun.ExecFacts{ExitCode: f.exit, PeakChildren: -1}
	}
	out := p.Args[slices.Index(p.Args, "--output")+1]
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case p.Args[len(p.Args)-1] == dCanary && f.noCanary:
		f.written[out] = []byte(`{"SchemaVersion":2,"Metadata":{"OS":{"Family":"debian","Name":"12.2"}},"Results":[]}`)
	case p.Args[len(p.Args)-1] == dCanary:
		f.written[out] = readFixture(f.t, "canary-report.json")
	default:
		f.written[out] = f.image
	}
	return extrun.ExecFacts{PeakChildren: -1}
}

func (f *trivyFake) env(ex *extruntest.Executor, isolated bool) Env {
	ex.Facts = f.facts
	e := Env{
		Binary: dTrivy, Digest: trivySum, CacheDir: dCache, OutDir: dOut, CanaryDir: dCanary, GOOS: "linux",
		ReadFile: func(p string, _ int64) ([]byte, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			b, ok := f.written[p]
			if !ok {
				return nil, errors.New("no such file " + p)
			}
			return b, nil
		},
	}
	e.RunnerFor = func(string) (*extrun.Runner, string) {
		if !isolated {
			return nil, ReasonIsolationRequired
		}
		r := extruntest.NewRunner("linux", f.files, ex, nil)
		r.Isolation = fakeProvider{}
		return r, ""
	}
	return e
}

func scanIn() ScanInput {
	return ScanInput{
		Mode: ModeImage, Target: dTarget, Project: dInput,
		Map: MapInput{Label: "Debian:12", RootHash: "h", Scope: policy.FindingScopeManual, Epoch: "trivy-db@sha256:abc", Location: Location{RelPath: "image.tar"}},
	}
}

// TestScanVerifiedRun: the version, both helps, the canary and the image
// run, isolated, under the driver's component and caps; the result carries
// the findings, the release scanned and the coverage notes.
func TestScanVerifiedRun(t *testing.T) {
	t.Parallel()
	f := newTrivyFake(t)
	ex := &extruntest.Executor{}
	out := f.env(ex, true).Scan(context.Background(), scanIn())
	res := out.Result
	if res.Coverage.Outcome != secscan.OutcomeFindings || len(res.Findings) != 4 || out.Version != "0.75.0" || !out.FlagsOK {
		t.Fatalf("%+v %d", res.Coverage, len(res.Findings))
	}
	if !slices.Equal(res.Coverage.Scanned, []string{"Debian:12"}) || res.Engine.Name != DriverID || res.Engine.Digest != trivySum ||
		res.Engine.DatabaseEpoch != "Debian:12=trivy-db@sha256:abc" {
		t.Errorf("coverage %+v engine %+v", res.Coverage, res.Engine)
	}
	for _, f := range res.Findings {
		if f.Engine.Driver != DriverID || f.Engine.DriverVersion != "0.75.0" || f.Engine.EngineDigest != trivySum {
			t.Errorf("finding engine %+v: the binary's version and digest are not recorded", f.Engine)
		}
	}
	notes := strings.Join(res.Coverage.Notes, "\n")
	for _, want := range []string{CoveragePrefix, depscan.KernelNotePrefix, NoFixPrefix} {
		if !strings.Contains(notes, want) {
			t.Errorf("notes lack %q:\n%s", want, notes)
		}
	}
	calls := ex.Calls()
	if len(calls) != 5 {
		t.Fatalf("%d calls", len(calls))
	}
	if !slices.Contains(calls[3].Args, dCanary) || calls[3].Args[0] != string(ModeRootfs) || calls[4].Args[0] != string(ModeImage) || calls[4].Args[len(calls[4].Args)-1] != dTarget {
		t.Errorf("canary then image: %v / %v", calls[3].Args, calls[4].Args)
	}
	for _, c := range calls {
		if c.Component != ComponentID || c.Path != "/isolate" {
			t.Errorf("%s ran as %s at %s", c.Args, c.Component, c.Path)
		}
	}
	if calls[4].Limits.MemoryBytes != Limits().MemoryBytes || calls[4].Limits.Wall != Limits().Wall {
		t.Errorf("limits %+v", calls[4].Limits)
	}
	// A recorded flag check is not asked again.
	ex2 := &extruntest.Executor{}
	e := f.env(ex2, true)
	e.FlagsChecked = true
	if out := e.Scan(context.Background(), scanIn()); out.FlagsOK || len(ex2.Calls()) != 3 {
		t.Errorf("flags asked again: %d calls", len(ex2.Calls()))
	}
}

// TestScanRefusals: each stop is honest (never clean): no isolation, a
// canary that is not flagged, a help without a flag, a crash, a digest the
// runner refuses, an unknown OS, an untested version labelled.
func TestScanRefusals(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		setup    func(*trivyFake, *Env)
		isolated bool
		outcome  secscan.Outcome
		reason   string
	}{
		{"no isolation", nil, false, secscan.OutcomeNotScanned, ReasonIsolationRequired},
		{"canary not flagged", func(f *trivyFake, _ *Env) { f.noCanary = true }, true, secscan.OutcomeNotScanned, depscan.ReasonSelfTestFailed},
		{"help lacks a flag", func(f *trivyFake, _ *Env) { f.help[ModeImage] = []byte("--scanners\n") }, true, secscan.OutcomeFailed, ReasonFlagsMissing},
		{"crash", func(f *trivyFake, _ *Env) { f.exit = 2 }, true, secscan.OutcomeFailed, depscan.ReasonEngineFailed},
		{"digest mismatch", func(_ *trivyFake, e *Env) { e.Digest = strings.Repeat("c", 64) }, true, secscan.OutcomeFailed, ReasonUnverified},
		{"no version", func(f *trivyFake, _ *Env) { f.version = "trivy dev\n" }, true, secscan.OutcomeFailed, ReasonUnverified},
		{"unknown os", func(f *trivyFake, _ *Env) { f.image = readFixture(t, "unknown-os-report.json") }, true, secscan.OutcomeNotScanned, depscan.ReasonNoOSRelease},
		{"unreadable report", func(f *trivyFake, _ *Env) { f.image = []byte("{") }, true, secscan.OutcomeFailed, ReasonOutput},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			f := newTrivyFake(t)
			ex := &extruntest.Executor{}
			e := f.env(ex, c.isolated)
			if c.setup != nil {
				c.setup(f, &e)
			}
			res := e.Scan(context.Background(), scanIn()).Result
			if res.Coverage.Outcome != c.outcome || res.Coverage.Reason != c.reason || len(res.Findings) != 0 || len(res.Coverage.Scanned) != 0 {
				t.Fatalf("%+v", res.Coverage)
			}
		})
	}
	f := newTrivyFake(t)
	f.version = "Version: 0.76.1\n"
	res := f.env(&extruntest.Executor{}, true).Scan(context.Background(), scanIn()).Result
	if res.Coverage.Outcome != secscan.OutcomeFindings || !slices.Contains(depscan.RunLabels(res.Coverage.Notes), "untested engine version") {
		t.Errorf("untested: %+v %v", res.Coverage, depscan.RunLabels(res.Coverage.Notes))
	}
}
