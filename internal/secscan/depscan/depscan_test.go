package depscan

import (
	"context"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secscan"
)

func TestDropRules(t *testing.T) {
	cases := []struct {
		name string
		p    Package
		rule string
	}{
		{"empty version", Package{Ecosystem: "PyPI", Name: "flask"}, "empty_version"},
		{"blank version", Package{Ecosystem: "PyPI", Name: "flask", Version: "  "}, "empty_version"},
		{"workspace member", Package{Ecosystem: "npm", Name: "web", Version: "0.1.0", Local: true}, "local_package"},
		{"restored entry kept", Package{Ecosystem: "npm", Name: "vite", Version: "5.4.21", Local: false, Restored: true}, ""},
		{"root package.json", Package{Ecosystem: "npm", Name: "app", Version: "1.0.0", Extractor: "javascript/packagejson", Path: "package.json"}, "root_project"},
		{"nested root package.json", Package{Ecosystem: "npm", Name: "web", Version: "0.1.0", Extractor: "javascript/packagejson", Path: "web/package.json"}, "root_project"},
		{"installed package.json kept", Package{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0", Extractor: "javascript/packagejson", Path: "node_modules/left-pad/package.json"}, ""},
		{"go directive", Package{Ecosystem: "Go", Name: "stdlib", Version: "1.22"}, "go_directive"},
		{"go module kept", Package{Ecosystem: "Go", Name: "golang.org/x/text", Version: "v0.3.5"}, ""},
		{"unpinned requirements line", Package{Ecosystem: "PyPI", Name: "requests", Version: "2.0", Unpinned: true}, "unpinned_version"},
		{"local entry of an oversize lockfile", Package{Ecosystem: "npm", Name: "vite", Version: "5.4.21", Local: true, LockfileTooLarge: true}, "local_unchecked"},
		{"root package.json with no version is no gap", Package{Ecosystem: "npm", Name: "app", Extractor: "javascript/packagejson", Path: "package.json"}, "root_project"},
		{"action pinned by a SHA with no comment", Package{Ecosystem: "GitHub Actions", Name: "actions/checkout", PinnedBySHA: true}, "sha_no_version"},
		{"action on a branch", Package{Ecosystem: "GitHub Actions", Name: "actions/checkout", Version: "main", NotAVersion: true}, "not_a_version"},
		{"action on a moving tag kept", Package{Ecosystem: "GitHub Actions", Name: "actions/checkout", Version: "v4", MovingTag: true}, ""},
		{"action from a SHA comment kept", Package{Ecosystem: "GitHub Actions", Name: "actions/checkout", Version: "v4.1.0", VersionFromComment: true}, ""},
		{"kernel headers of an image", Package{Ecosystem: "Debian:12", Name: "linux", Binary: "linux-libc-dev", Version: "6.1.112-1", Extractor: "os/dpkg"}, "kernel_package"},
		{"package of another release", Package{Ecosystem: "Debian:12", Name: "musl", Version: "1.2.5-r0", Extractor: "os/apk", OtherRelease: true}, "other_release"},
		{"an npm package named like a kernel is kept", Package{Ecosystem: "npm", Name: "linux-headers-x", Version: "1.0.0"}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			keep, dropped := Prepare([]Package{c.p})
			if c.rule == "" {
				if len(dropped) != 0 || len(keep[c.p.Ecosystem]) != 1 {
					t.Fatalf("kept=%v dropped=%v, want kept", keep, dropped)
				}
				return
			}
			if dropped[c.rule] != 1 || len(keep) != 0 {
				t.Fatalf("kept=%v dropped=%v, want dropped by %s", keep, dropped, c.rule)
			}
		})
	}
	if got := DropRuleNames(); !slices.Equal(got, []string{"kernel_package", "other_release", "go_directive", "artifact_toolchain", "go_version_unknown", "artifact_main_module", "root_project", "sha_no_version", "not_a_version", "empty_version", "unpinned_version", "local_unchecked", "local_package"}) {
		t.Fatalf("drop table order %v", got)
	}
	// The Gap column: only real dependencies the run could not check leave
	// a gap; the project's own code and the go line do not.
	gaps := map[string]string{}
	for _, r := range dropRules {
		gaps[r.Name] = r.Gap
	}
	want := map[string]string{"kernel_package": "", "other_release": ReasonOtherRelease, "go_directive": "", "root_project": "", "sha_no_version": ReasonPinnedBySHA, "not_a_version": ReasonUnpinned, "empty_version": ReasonUnpinned, "unpinned_version": ReasonUnpinned, "local_unchecked": ReasonLockfileTooLarge, "local_package": ""}
	for k, v := range want {
		if gaps[k] != v {
			t.Errorf("rule %s gap %q, want %q", k, gaps[k], v)
		}
	}
}

func TestFinalize(t *testing.T) {
	scanned := EcoResult{Ecosystem: "npm", Outcome: EcoScanned, Packages: 1}
	cases := []struct {
		name string
		resp ChildResponse
		gaps []Gap
		// ecos is the finalized ecosystem rows: name -> outcome/reason/gaps.
		ecos map[string]string
	}{
		{
			name: "nothing to add",
			resp: ChildResponse{Packages: []Package{{Ecosystem: "npm", Name: "a", Version: "1", Path: "package-lock.json"}}, Ecosystems: []EcoResult{scanned}},
			ecos: map[string]string{"npm": "scanned//0"},
		},
		{
			name: "unpinned lines of the only Python file",
			resp: ChildResponse{
				Packages: []Package{
					{Ecosystem: "npm", Name: "a", Version: "1", Path: "package-lock.json"},
					{Ecosystem: "PyPI", Name: "flask", Path: "requirements.txt"},
					{Ecosystem: "PyPI", Name: "requests", Version: "2.0", Unpinned: true, Path: "requirements.txt"},
				},
				Ecosystems: []EcoResult{scanned},
			},
			gaps: []Gap{{Ecosystem: "PyPI", Path: "requirements.txt", Reason: ReasonUnpinned, Packages: 2}},
			ecos: map[string]string{"npm": "scanned//0", "PyPI": "not_scanned/unpinned_version/1"},
		},
		{
			name: "oversize lockfile next to matched packages",
			resp: ChildResponse{
				Packages: []Package{
					{Ecosystem: "npm", Name: "a", Version: "1", Path: "package-lock.json"},
					{Ecosystem: "npm", Name: "vite", Version: "5", Local: true, LockfileTooLarge: true, Path: "package-lock.json"},
				},
				Ecosystems: []EcoResult{scanned},
			},
			gaps: []Gap{{Ecosystem: "npm", Path: "package-lock.json", Reason: ReasonLockfileTooLarge, Packages: 1}},
			ecos: map[string]string{"npm": "scanned//1"},
		},
		{
			name: "manifest with no lockfile",
			resp: ChildResponse{Unlocked: []Manifest{{Ecosystem: "crates.io", Path: "tool/Cargo.toml"}}, Ecosystems: []EcoResult{scanned}},
			gaps: []Gap{{Ecosystem: "crates.io", Path: "tool/Cargo.toml", Reason: ReasonNoLockfile}},
			ecos: map[string]string{"npm": "scanned//0", "crates.io": "not_scanned/no_lockfile/1"},
		},
		{
			name: "lockfile caught mid-write",
			resp: ChildResponse{
				Extractors: []ExtractorStatus{{Extractor: "javascript/packagelockjson", Ecosystem: "npm", OK: true}, {Extractor: "python/poetrylock", Ecosystem: "PyPI", Files: []string{"poetry.lock"}}},
				Ecosystems: []EcoResult{scanned},
			},
			gaps: []Gap{{Ecosystem: "PyPI", Path: "poetry.lock", Reason: ReasonExtractorFailed}},
			ecos: map[string]string{"npm": "scanned//0", "PyPI": "not_scanned/extractor_failed/1"},
		},
		{
			name: "failed extractor that named no file",
			resp: ChildResponse{Extractors: []ExtractorStatus{{Extractor: "go/gomod", Ecosystem: "Go"}}},
			gaps: []Gap{{Ecosystem: "Go", Reason: ReasonExtractorFailed}},
			ecos: map[string]string{"Go": "not_scanned/extractor_failed/1"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, gaps := Finalize(c.resp)
			if len(gaps) != len(c.gaps) || (len(gaps) > 0 && !slices.Equal(gaps, c.gaps)) {
				t.Fatalf("gaps %+v, want %+v", gaps, c.gaps)
			}
			got := map[string]string{}
			for _, e := range out.Ecosystems {
				got[e.Ecosystem] = string(e.Outcome) + "/" + e.Reason + "/" + strconv.Itoa(e.Gaps)
			}
			if len(got) != len(c.ecos) {
				t.Fatalf("ecosystems %v, want %v", got, c.ecos)
			}
			for k, v := range c.ecos {
				if got[k] != v {
					t.Fatalf("ecosystem %s %q, want %q (all %v)", k, got[k], v, got)
				}
			}
			if len(c.resp.Ecosystems) > 0 && c.resp.Ecosystems[0].Gaps != 0 {
				t.Fatal("Finalize changed its input")
			}
		})
	}
}

func TestManifestDeclares(t *testing.T) {
	cases := []struct {
		name, file, body string
		want             bool
	}{
		{"crate with dependencies", "Cargo.toml", "[package]\nname = \"x\"\n[dependencies]\nserde = \"1\"\n", true},
		{"crate with no dependencies", "Cargo.toml", "[package]\nname = \"x\"\n", false},
		{"crate with target dependencies", "Cargo.toml", "[package]\nname = \"x\"\n[target.'cfg(unix)'.dependencies]\nlibc = \"0.2\"\n", true},
		{"workspace dependencies", "Cargo.toml", "[workspace]\nmembers = [\"a\"]\n[workspace.dependencies]\nserde = \"1\"\n", true},
		{"pyproject with dependencies", "pyproject.toml", "[project]\nname = \"x\"\ndependencies = [\"requests>=2\"]\n", true},
		{"pyproject for tools only", "pyproject.toml", "[tool.ruff]\nline-length = 100\n", false},
		{"poetry project", "pyproject.toml", "[tool.poetry.dependencies]\npython = \"^3.11\"\nflask = \"*\"\n", true},
		{"poetry with python only", "pyproject.toml", "[tool.poetry.dependencies]\npython = \"^3.11\"\n", false},
		{"dependency groups", "pyproject.toml", "[dependency-groups]\ndev = [\"pytest\"]\n", true},
		{"unparseable is taken to declare", "pyproject.toml", "[project\n", true},
		{"other file", "setup.cfg", "[metadata]\n", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ManifestDeclares(c.file, []byte(c.body)); got != c.want {
				t.Fatalf("got %v, want %v", got, c.want)
			}
		})
	}
	if _, locks, ok := ManifestFor("pyproject.toml"); !ok || !IsLockfile("requirements-dev.txt", locks) || !IsLockfile("uv.lock", locks) || IsLockfile("setup.py", locks) {
		t.Fatalf("pyproject lockfiles %v", locks)
	}
	if _, locks, ok := ManifestFor("Cargo.toml"); !ok || !IsLockfile("Cargo.lock", locks) {
		t.Fatalf("cargo lockfiles %v", locks)
	}
}

func TestDecideEcosystem(t *testing.T) {
	ok := MatchFacts{DatabaseInstalled: true, HasCanary: true, CanaryHit: true}
	cases := []struct {
		name   string
		f      MatchFacts
		out    EcoOutcome
		reason string
	}{
		{"scanned", ok, EcoScanned, ""},
		{"unsupported first", MatchFacts{Unsupported: true, DatabaseInstalled: true, HasCanary: true, CanaryHit: true}, EcoNotScanned, ReasonUnsupported},
		{"no canary row", MatchFacts{DatabaseInstalled: true, CanaryHit: true}, EcoNotScanned, ReasonNoCanary},
		{"database not installed", MatchFacts{HasCanary: true, CanaryHit: true}, EcoNotScanned, ReasonNoDatabase},
		{"matcher found no database", MatchFacts{DatabaseInstalled: true, NoDatabase: true, HasCanary: true}, EcoNotScanned, ReasonNoDatabase},
		{"match error", MatchFacts{DatabaseInstalled: true, MatchError: true, HasCanary: true}, EcoNotScanned, ReasonMatchFailed},
		{"canary missed", MatchFacts{DatabaseInstalled: true, HasCanary: true}, EcoNotScanned, ReasonSelfTestFailed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, reason := DecideEcosystem(c.f)
			if out != c.out || reason != c.reason {
				t.Fatalf("got %s/%q, want %s/%q", out, reason, c.out, c.reason)
			}
		})
	}
}

func TestCoverage(t *testing.T) {
	scanned := EcoResult{Ecosystem: "npm", Outcome: EcoScanned}
	missing := EcoResult{Ecosystem: "PyPI", Outcome: EcoNotScanned, Reason: ReasonNoDatabase}
	cases := []struct {
		name   string
		f      RunFacts
		out    secscan.Outcome
		reason string
		skips  int
	}{
		{"clean needs every ecosystem scanned", RunFacts{Ecosystems: []EcoResult{scanned}}, secscan.OutcomeClean, "", 0},
		{"one missing database is not clean", RunFacts{Ecosystems: []EcoResult{scanned, missing}}, secscan.OutcomeUnknown, "partial_coverage", 1},
		{"findings with a missing database", RunFacts{Ecosystems: []EcoResult{scanned, missing}, Findings: 2}, secscan.OutcomeFindings, "partial_coverage", 1},
		{"findings, full coverage", RunFacts{Ecosystems: []EcoResult{scanned}, Findings: 1}, secscan.OutcomeFindings, "", 0},
		{"withheld private names are not clean", RunFacts{Ecosystems: []EcoResult{{Ecosystem: "npm", Outcome: EcoScanned, Withheld: 1}}}, secscan.OutcomeUnknown, "partial_coverage", 0},
		{"failed extractor is not clean", RunFacts{Ecosystems: []EcoResult{scanned}, ExtractorFailures: 1}, secscan.OutcomeUnknown, "partial_coverage", 0},
		{"a gap is not clean", RunFacts{Ecosystems: []EcoResult{{Ecosystem: "npm", Outcome: EcoScanned, Gaps: 1}}, Gaps: []Gap{{Ecosystem: "npm", Path: "package-lock.json", Reason: ReasonLockfileTooLarge}}}, secscan.OutcomeUnknown, "partial_coverage", 1},
		{"findings with a gap", RunFacts{Ecosystems: []EcoResult{scanned}, Gaps: []Gap{{Ecosystem: "PyPI", Path: "requirements.txt", Reason: ReasonUnpinned}}, Findings: 1}, secscan.OutcomeFindings, "partial_coverage", 1},
		{"nothing scanned", RunFacts{Ecosystems: []EcoResult{missing}}, secscan.OutcomeNotScanned, "no_ecosystem_scanned", 1},
		{"no packages", RunFacts{}, secscan.OutcomeNotScanned, "no_packages", 0},
		{"not installed", RunFacts{Reason: ReasonNotInstalled}, secscan.OutcomeNotScanned, ReasonNotInstalled, 0},
		{"not compiled", RunFacts{Reason: ReasonNotCompiled}, secscan.OutcomeNotScanned, ReasonNotCompiled, 0},
		{"engine failed", RunFacts{Failed: true}, secscan.OutcomeFailed, ReasonEngineFailed, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cov := Coverage(c.f)
			if cov.Outcome != c.out || cov.Reason != c.reason || len(cov.Skipped) != c.skips {
				t.Fatalf("got %+v, want %s/%q with %d skips", cov, c.out, c.reason, c.skips)
			}
		})
	}
}

func TestGroupByAliases(t *testing.T) {
	advs := []Advisory{
		{ID: "GHSA-aaaa", Aliases: []string{"CVE-2024-1"}, Severity: "MODERATE", Index: 0},
		{ID: "GO-2024-9", Aliases: []string{"CVE-2024-1", "GHSA-aaaa"}, Index: 0},
		{ID: "PYSEC-1", Aliases: []string{"GO-2024-9"}, Severity: "HIGH", Index: 0},
		{ID: "GHSA-bbbb", Index: 0},
		{ID: "GHSA-aaaa", Index: 1},
		{ID: "bad id with spaces", Index: 1},
	}
	got := GroupByAliases(advs, policy.FindingSeverityMedium)
	if len(got) != 3 {
		t.Fatalf("groups %+v, want 3 (two for package 0, one for package 1)", got)
	}
	g := got[0]
	if g.Index != 0 || g.Primary != "CVE-2024-1" || !slices.Equal(g.IDs, []string{"CVE-2024-1", "GHSA-aaaa", "GO-2024-9", "PYSEC-1"}) || g.Severity != policy.FindingSeverityHigh {
		t.Fatalf("transitive alias group %+v", g)
	}
	if got[1].Primary != "GHSA-bbbb" || got[1].Severity != policy.FindingSeverityMedium {
		t.Fatalf("unlabelled group %+v must take the default severity", got[1])
	}
	if got[2].Index != 1 || got[2].Primary != "GHSA-aaaa" {
		t.Fatalf("package 1 group %+v (the bad id must be dropped)", got[2])
	}
}

func TestFindingsAreTemplatesOnly(t *testing.T) {
	pkgs := []Package{{Ecosystem: "npm", Name: "lodash", Version: "4.17.20", Path: `web\package-lock.json`}}
	groups := []Group{{Index: 0, Primary: "CVE-2021-23337", IDs: []string{"CVE-2021-23337", "GHSA-35jh-r3h4-6jhm"}, Severity: policy.FindingSeverityHigh}}
	fs, trunc := Findings(FindingInput{
		Packages: pkgs, Groups: groups, RootHash: "root", Scope: policy.FindingScopeScheduled,
		Engine: secscan.EngineIdentity{Name: "scalibr", Version: SCALIBRVersion}, Epochs: map[string]string{"npm": "e1"}, DriverID: ScalibrID,
	})
	if trunc || len(fs) != 1 {
		t.Fatalf("findings %v trunc %v", fs, trunc)
	}
	f := fs[0]
	switch {
	case f.Category != policy.FindingVulnerableDependency, f.Confidence != policy.FindingConfidenceHigh, f.Severity != policy.FindingSeverityHigh:
		t.Fatalf("adapter row not applied: %+v", f)
	case f.Location.RelPath != "web/package-lock.json":
		t.Fatalf("path %q, want forward slashes", f.Location.RelPath)
	case strings.Contains(f.Message, "lodash"):
		t.Fatalf("message %q carries the package name; names ride only in redacted evidence", f.Message)
	case f.EvidenceRedacted != "npm lodash@4.17.20" || f.EvidenceHash == "":
		t.Fatalf("evidence %q", f.EvidenceRedacted)
	case f.Engine.DatabaseEpoch != "e1" || f.Engine.Driver != ScalibrID:
		t.Fatalf("engine %+v must carry the database epoch", f.Engine)
	case f.LocalKey == "":
		t.Fatal("no local key")
	}
	again, _ := Findings(FindingInput{Packages: []Package{{Ecosystem: "npm", Name: "lodash", Version: "4.17.20", Path: "moved/package-lock.json"}}, Groups: groups, RootHash: "root"})
	if again[0].LocalKey != f.LocalKey {
		t.Fatal("the local key must not depend on the location")
	}
}

func TestDriverRowsRegister(t *testing.T) {
	scal := ScalibrRow([]string{"javascript/packagelockjson"})
	if _, err := secscan.NewRegistry(staticDriver{scal}, staticDriver{OSVRow()}); err != nil {
		t.Fatal(err)
	}
	if !Beta(scal, "windows", "amd64") || Beta(scal, "linux", "amd64") {
		t.Fatal("SCALIBR is beta on Windows and supported on linux (D-764 Q25)")
	}
	if PlatformSupport(scal, "windows", "amd64", "javascript/packagelockjson") != secscan.SupportUntested {
		t.Fatal("per-extractor Windows cell must be untested")
	}
	if PlatformSupport(scal, "plan9", "amd64", "") != secscan.SupportUnsupported {
		t.Fatal("an unnamed platform is unsupported")
	}
	for _, eco := range Ecosystems() {
		if c, ok := CanaryFor(eco); !ok || c.Name == "" || c.Version == "" || c.Advisory == "" {
			t.Errorf("canary row for %s incomplete", eco)
		}
	}
}

type staticDriver struct{ row secscan.DriverRow }

func (d staticDriver) Row() secscan.DriverRow            { return d.row }
func (staticDriver) Probe(context.Context) secscan.Probe { return secscan.Probe{} }
func (staticDriver) Scan(context.Context, secscan.Target) (secscan.Result, error) {
	return secscan.Result{}, nil
}

func TestStaleFindings(t *testing.T) {
	mk := func(id, key, eco, driver string) secfinding.Finding {
		return secfinding.Finding{
			ID: id, LocalKey: key, Status: policy.FindingStatusOpen, Category: policy.FindingVulnerableDependency,
			EvidenceRedacted: eco + " pkg@1", Engine: secfinding.Engine{Driver: driver},
		}
	}
	open := []secfinding.Finding{
		mk("1", "k1", "npm", ScalibrID),  // still reported
		mk("2", "k2", "npm", ScalibrID),  // fixed: npm scanned, k2 gone
		mk("3", "k3", "PyPI", ScalibrID), // PyPI not scanned this time: proves nothing
		mk("4", "k4", "npm", OSVID),      // another driver's
	}
	run := []secfinding.Finding{{LocalKey: "k1"}}
	got := StaleFindings(open, ScalibrID, run, map[string]bool{"npm": true})
	if !slices.Equal(got, []string{"2"}) {
		t.Fatalf("stale %v, want [2]", got)
	}
}

// TestScannedOnlyFromFullScans pins milestone 1a: an ecosystem closes an
// older finding only when the run names it scanned in full. An ecosystem
// the run never mentions, one with a gap, and every ecosystem of a run
// with a failed extractor prove nothing, so an Unknown run closes nothing.
func TestScannedOnlyFromFullScans(t *testing.T) {
	npm := EcoResult{Ecosystem: "npm", Outcome: EcoScanned}
	pypi := EcoResult{Ecosystem: "PyPI", Outcome: EcoScanned}
	cases := []struct {
		name string
		f    RunFacts
		want []string
	}{
		{"both scanned", RunFacts{Ecosystems: []EcoResult{pypi, npm}}, []string{"PyPI", "npm"}},
		{"an ecosystem the run never mentions is not scanned", RunFacts{Ecosystems: []EcoResult{npm}}, []string{"npm"}},
		{"a not-scanned ecosystem", RunFacts{Ecosystems: []EcoResult{npm, {Ecosystem: "PyPI", Outcome: EcoNotScanned, Reason: ReasonNoDatabase}}}, []string{"npm"}},
		{"a gap keeps its ecosystem out", RunFacts{Ecosystems: []EcoResult{npm, {Ecosystem: "PyPI", Outcome: EcoScanned, Gaps: 1}}}, []string{"npm"}},
		{"withheld names keep it out", RunFacts{Ecosystems: []EcoResult{npm, {Ecosystem: "PyPI", Outcome: EcoScanned, Withheld: 2}}}, []string{"npm"}},
		{"a failed extractor closes nothing", RunFacts{Ecosystems: []EcoResult{npm, pypi}, ExtractorFailures: 1}, nil},
		{"a failed run", RunFacts{Failed: true}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cov := Coverage(c.f)
			if !slices.Equal(cov.Scanned, c.want) {
				t.Fatalf("scanned %v, want %v", cov.Scanned, c.want)
			}
		})
	}
	// End to end: a run whose poetry.lock was caught mid-write is Unknown,
	// and the open PyPI and npm findings stay open.
	resp, gaps := Finalize(ChildResponse{
		Ecosystems: []EcoResult{npm},
		Extractors: []ExtractorStatus{{Extractor: "python/poetrylock", Ecosystem: "PyPI", Files: []string{"poetry.lock"}}},
	})
	cov := Coverage(RunFacts{Ecosystems: resp.Ecosystems, ExtractorFailures: 1, Gaps: gaps})
	if cov.Outcome != secscan.OutcomeUnknown {
		t.Fatalf("outcome %s, want unknown", cov.Outcome)
	}
	open := []secfinding.Finding{
		{ID: "1", LocalKey: "k1", Status: policy.FindingStatusOpen, Category: policy.FindingVulnerableDependency, EvidenceRedacted: "PyPI a@1", Engine: secfinding.Engine{Driver: ScalibrID}},
		{ID: "2", LocalKey: "k2", Status: policy.FindingStatusOpen, Category: policy.FindingVulnerableDependency, EvidenceRedacted: "npm b@1", Engine: secfinding.Engine{Driver: ScalibrID}},
	}
	if got := StaleFindings(open, ScalibrID, nil, ScannedEcosystems(cov)); len(got) != 0 {
		t.Fatalf("closed %v; a run with a failed extractor closes nothing", got)
	}
	var sawPoetry bool
	for _, s := range cov.Skipped {
		if s.Path == "poetry.lock" && s.Reason == ReasonExtractorFailed {
			sawPoetry = true
		}
	}
	if !sawPoetry {
		t.Fatalf("skipped %+v: the failed file is reported not scanned", cov.Skipped)
	}
}
