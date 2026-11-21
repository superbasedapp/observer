package depscan

import (
	"slices"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secscan"
)

func osPkg(eco, name, binary, version, extractor string) Package {
	return Package{Ecosystem: eco, Name: name, Binary: binary, Version: version, Extractor: extractor, Path: "Dockerfile", Line: 3}
}

func TestKernelRules(t *testing.T) {
	cases := []struct {
		name string
		p    Package
		want bool
	}{
		{"linux-libc-dev", osPkg("Ubuntu:24.04:LTS", "linux", "linux-libc-dev", "6.8.0-45.45", "os/dpkg"), true},
		{"linux-headers", osPkg("Ubuntu:24.04:LTS", "linux-hwe-6.8", "linux-headers-6.8.0-45-generic", "6.8.0-45.45", "os/dpkg"), true},
		{"linux-image", osPkg("Debian:12", "linux-signed-amd64", "linux-image-6.1.0-26-amd64", "6.1.112-1", "os/dpkg"), true},
		{"linux-modules", osPkg("Ubuntu:24.04:LTS", "linux", "linux-modules-6.8.0-45-generic", "6.8.0-45.45", "os/dpkg"), true},
		{"source linux", osPkg("Debian:12", "linux", "linux-tools-common", "6.1.112-1", "os/dpkg"), true},
		{"rpm kernel", osPkg("Rocky Linux:9", "kernel", "", "5.14.0-427.el9", "os/rpm"), true},
		{"rpm kernel-headers", osPkg("Red Hat:enterprise_linux:9", "kernel-headers", "", "5.14.0-427.el9", "os/rpm"), true},
		{"glibc kept", osPkg("Debian:12", "glibc", "libc6", "2.36-9+deb12u2", "os/dpkg"), false},
		{"linux-base kept (a helper, source linux-base)", osPkg("Debian:12", "linux-base", "", "4.9", "os/dpkg"), false},
		{"kernelshark kept", osPkg("Rocky Linux:9", "kernelshark", "", "2.1", "os/rpm"), false},
		{"a language package is never a kernel package", Package{Ecosystem: "npm", Name: "linux", Version: "1.0.0"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := KernelPackage(c.p); got != c.want {
				t.Fatalf("KernelPackage = %v, want %v", got, c.want)
			}
		})
	}
	pkgs := []Package{cases[0].p, cases[1].p, cases[7].p, cases[0].p}
	note := KernelNote(pkgs)
	if note != KernelNotePrefix+": 3 kernel packages left out: a container does not run its own kernel (linux-headers-6.8.0-45-generic, linux-libc-dev)." {
		t.Fatalf("note %q", note)
	}
	if KernelNote([]Package{cases[7].p}) != "" {
		t.Fatal("no kernel package, no note")
	}
	var many []Package
	for i := range 25 {
		many = append(many, osPkg("Debian:12", "linux", "linux-image-"+string(rune('a'+i)), "1", "os/dpkg"))
	}
	if n := KernelNote(many); !strings.Contains(n, "and 5 more") {
		t.Fatalf("a long list is capped: %q", n)
	}
}

func TestOSCanaryTable(t *testing.T) {
	want := []string{"Alpine:v3.20", "Debian:12", "Red Hat:enterprise_linux:9", "Rocky Linux:9", "Ubuntu:24.04:LTS"}
	if got := OSCanaryEcosystems(); !slices.Equal(got, want) {
		t.Fatalf("canary releases %v, want %v", got, want)
	}
	for _, eco := range want {
		c, _ := OSCanaryFor(eco)
		if c.Name == "" || c.Version == "" || c.Advisory == "" || !slices.Contains([]string{"deb", "apk", "rpm"}, c.Kind) {
			t.Errorf("%s: malformed canary %+v", eco, c)
		}
		if (c.Kind == "rpm") != (c.Source == "") {
			t.Errorf("%s: an rpm canary names its binary only; a deb or apk canary names its source", eco)
		}
		if KernelPackage(Package{Name: c.Name, Extractor: "os/x"}) {
			t.Errorf("%s: the canary would be left out as a kernel package", eco)
		}
	}
	if _, ok := OSCanaryFor("Debian:11"); ok {
		t.Fatal("Debian 11 has no grounded canary; it must read no_canary")
	}
}

func TestDecideOSRelease(t *testing.T) {
	ok := OSFacts{Compiled: true, HasCanary: true, DatabaseInstalled: true, CanaryHit: true}
	with := func(f func(*OSFacts)) OSFacts { c := ok; f(&c); return c }
	cases := []struct {
		name    string
		f       OSFacts
		outcome EcoOutcome
		reason  string
	}{
		{"scanned", ok, EcoScanned, ""},
		{"not compiled", with(func(f *OSFacts) { f.Compiled = false }), EcoNotScanned, ReasonNotCompiled},
		{"rpm on windows", with(func(f *OSFacts) { f.RPMOnWindows = true }), EcoNotScanned, ReasonRPMOnWindows},
		{"no canary", with(func(f *OSFacts) { f.HasCanary = false }), EcoNotScanned, ReasonNoOSCanary},
		{"no database", with(func(f *OSFacts) { f.DatabaseInstalled = false }), EcoNotScanned, ReasonNoDatabase},
		{"matcher found no database", with(func(f *OSFacts) { f.NoDatabase = true }), EcoNotScanned, ReasonNoDatabase},
		{"match failed", with(func(f *OSFacts) { f.MatchError = true }), EcoNotScanned, ReasonMatchFailed},
		{"self-test failed", with(func(f *OSFacts) { f.CanaryHit = false }), EcoNotScanned, ReasonSelfTestFailed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if o, r := DecideOSRelease(c.f); o != c.outcome || r != c.reason {
				t.Fatalf("%s %q, want %s %q", o, r, c.outcome, c.reason)
			}
		})
	}
}

func TestOSReleaseNotesAndLabels(t *testing.T) {
	notes := append(OSReleaseNotes(true, "Debian LTS advisories (DLA) are not in OSV for this release"), KernelNote([]Package{osPkg("Debian:12", "linux", "linux-libc-dev", "1", "os/dpkg")}))
	if len(notes) != 3 || notes[1] != "Known gap: Debian LTS advisories (DLA) are not in OSV for this release." {
		t.Fatalf("notes %q", notes)
	}
	if got := RunLabels(notes); !slices.Equal(got, []string{"fixed issues only", "known gap", "kernel packages left out"}) {
		t.Fatalf("labels %v", got)
	}
	if OSReleaseNotes(false, "") != nil {
		t.Fatal("a release with nothing to say has no notes")
	}
}

func TestOSFindings(t *testing.T) {
	pkgs := []Package{
		osPkg("Red Hat:enterprise_linux:9", "glib2", "", "2.68.4-11.el9", "os/rpm"),
		osPkg("Debian:12", "glibc", "libc6", "2.36-9+deb12u2", "os/dpkg"),
	}
	groups := GroupByAliases([]Advisory{
		{ID: "RHSA-2024:6464", Aliases: []string{"CVE-2024-34397"}, Index: 0},
		{ID: "DSA-5514-1", Index: 1},
	}, policy.FindingSeverityMedium)
	fs, truncated := Findings(FindingInput{Packages: pkgs, Groups: groups, RootHash: "h", Scope: policy.FindingScopeManual, Epochs: map[string]string{"Debian:12": "e1"}, DriverID: ScalibrID})
	if truncated || len(fs) != 2 {
		t.Fatalf("findings %+v", fs)
	}
	rh, deb := fs[0], fs[1]
	if rh.Rule.ID != "CVE-2024-34397" || deb.Rule.ID != "DSA-5514-1" {
		t.Errorf("rule ids %q %q: the CVE when there is one, else the distribution's advisory", rh.Rule.ID, deb.Rule.ID)
	}
	if deb.EvidenceRedacted != "Debian:12 glibc@2.36-9+deb12u2" || rh.EvidenceRedacted != "Red Hat:enterprise_linux:9 glib2@2.68.4-11.el9" {
		t.Errorf("evidence %q / %q", deb.EvidenceRedacted, rh.EvidenceRedacted)
	}
	if !strings.Contains(rh.Message, "Red Hat:enterprise_linux:9 OS package") || deb.FixHint != osFixHint {
		t.Errorf("message %q fix %q", rh.Message, deb.FixHint)
	}
	if deb.Location.RelPath != "Dockerfile" || deb.Location.StartLine != 3 || deb.Category != policy.FindingVulnerableDependency || deb.Engine.DatabaseEpoch != "e1" {
		t.Errorf("finding %+v", deb)
	}
	if got := EcosystemOfFinding(rh); got != "Red Hat:enterprise_linux:9" {
		t.Errorf("EcosystemOfFinding %q: a release label with a space must come back whole", got)
	}
	if got := EcosystemOfFinding(deb); got != "Debian:12" {
		t.Errorf("EcosystemOfFinding %q", got)
	}
	// A full scan of the same image closes what it no longer reports; a
	// not-scanned release proves nothing.
	rh.ID, deb.ID = "1", "2"
	if got := StaleFindings([]secfinding.Finding{rh, deb}, ScalibrID, nil, map[string]bool{"Debian:12": true}); !slices.Equal(got, []string{"2"}) {
		t.Errorf("stale %v, want only the Debian finding", got)
	}
}

func TestFinalizeCarriesCallerGaps(t *testing.T) {
	resp := ChildResponse{
		Ecosystems: []EcoResult{{Ecosystem: "Debian:12", Outcome: EcoScanned, Packages: 3}},
		Gaps:       []Gap{{Ecosystem: "Debian:12", Path: "var/lib/rpm/rpmdb.sqlite", Reason: ReasonImageEntryRefused}},
	}
	out, gaps := Finalize(resp)
	if len(gaps) != 1 || out.Ecosystems[0].Gaps != 1 {
		t.Fatalf("gaps %v ecosystems %+v", gaps, out.Ecosystems)
	}
	cov := Coverage(RunFacts{Ecosystems: out.Ecosystems, Gaps: gaps})
	if cov.Outcome != secscan.OutcomeUnknown || len(cov.Scanned) != 0 {
		t.Fatalf("coverage %+v: a refused package database makes the image partial, never clean", cov)
	}
}
