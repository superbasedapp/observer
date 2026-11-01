package depscan

import (
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/secscan"
)

// dropRule is one row of the drop table, walked top-down: the first rule
// that matches removes the package before matching and is counted.
type dropRule struct {
	Name  string
	Match func(Package) bool
	// Gap, when set, is the gap reason the drop leaves: the package is a
	// real dependency the run could not check, so the run is partial,
	// never clean (Finalize). Empty for a drop that is not a dependency
	// (the project's own code, the go line).
	Gap string
}

// dropRules are the packages neither driver matches (JSP-9b section 5:
// osv-scanner drops all of them, the library path must too). The rows
// that are not dependencies come first, so a project's own package with
// no version is not counted as a gap:
var dropRules = []dropRule{
	// The `go` line of a go.mod names a minimum language version, not the
	// toolchain that builds the module; govulncheck covers the toolchain.
	{Name: "go_directive", Match: func(p Package) bool {
		return p.Ecosystem == "Go" && (p.Name == "stdlib" || p.Name == "go" || p.Name == "toolchain")
	}},
	// The project's own package.json (not one under node_modules): the
	// root project, not a dependency.
	{Name: "root_project", Match: func(p Package) bool {
		return p.Extractor == "javascript/packagejson" && !underNodeModules(p.Path)
	}},
	// A manifest dependency with no pinned version: every advisory for the
	// name would match, so it is dropped and the run is partial.
	{Name: "empty_version", Gap: ReasonUnpinned, Match: func(p Package) bool { return strings.TrimSpace(p.Version) == "" }},
	// A requirements line with a range (`requests>=2.0`): the extractor
	// reports the lowest bound, which is not what pip installs.
	{Name: "unpinned_version", Gap: ReasonUnpinned, Match: func(p Package) bool { return p.Unpinned }},
	// A LOCAL entry of a package-lock.json too large for the lockfile
	// rule: it may be a hoisted registry package (JSP-9b section 5), so
	// it is dropped and the run is partial.
	{Name: "local_unchecked", Gap: ReasonLockfileTooLarge, Match: func(p Package) bool {
		return p.Local && !p.Restored && p.LockfileTooLarge
	}},
	// An npm workspace member or a file: dependency, which the lockfile
	// rule did not pass on (it is the project's own code).
	{Name: "local_package", Match: func(p Package) bool { return p.Local && !p.Restored }},
}

// dropRuleFor returns the first drop rule that matches p, or nil.
func dropRuleFor(p Package) *dropRule {
	for i := range dropRules {
		if dropRules[i].Match(p) {
			return &dropRules[i]
		}
	}
	return nil
}

func underNodeModules(path string) bool {
	return strings.Contains("/"+strings.ReplaceAll(path, `\`, "/"), "/node_modules/")
}

// DropRuleNames returns the drop table's rule names in order.
func DropRuleNames() []string {
	out := make([]string, 0, len(dropRules))
	for _, r := range dropRules {
		out = append(out, r.Name)
	}
	return out
}

// Prepare applies the drop table and returns, per ecosystem, the indices of
// the packages to match (sorted ecosystems, indices in input order), and
// how many packages each rule dropped.
func Prepare(pkgs []Package) (map[string][]int, map[string]int) {
	keep := map[string][]int{}
	dropped := map[string]int{}
	for i, p := range pkgs {
		if r := dropRuleFor(p); r != nil {
			dropped[r.Name]++
			continue
		}
		keep[p.Ecosystem] = append(keep[p.Ecosystem], i)
	}
	return keep, dropped
}

// SortedEcosystems returns the keys of m, sorted.
func SortedEcosystems[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Canary is one ecosystem's self-test package: public, long published,
// with a well-known advisory that stays in the OSV data.
type Canary struct {
	Name    string
	Version string
	// Advisory is the advisory it is known for (documentation and tests).
	Advisory string
}

// canaries is the self-test table, one row per ecosystem the extractor
// table feeds. An ecosystem without a row is "not scanned", never clean.
var canaries = map[string]Canary{
	"npm":       {Name: "lodash", Version: "4.17.20", Advisory: "CVE-2021-23337"},
	"PyPI":      {Name: "requests", Version: "2.19.0", Advisory: "CVE-2018-18074"},
	"Go":        {Name: "golang.org/x/text", Version: "v0.3.5", Advisory: "CVE-2022-32149"},
	"crates.io": {Name: "time", Version: "0.1.42", Advisory: "RUSTSEC-2020-0071"},
	"RubyGems":  {Name: "rack", Version: "2.0.0", Advisory: "CVE-2018-16471"},
	"Packagist": {Name: "symfony/http-kernel", Version: "4.0.0", Advisory: "CVE-2018-14773"},
	"NuGet":     {Name: "Newtonsoft.Json", Version: "12.0.1", Advisory: "GHSA-5crp-9r3c-p9vr"},
	"Maven":     {Name: "org.apache.logging.log4j:log4j-core", Version: "2.14.1", Advisory: "CVE-2021-44228"},
}

// CanaryFor returns the ecosystem's self-test package.
func CanaryFor(eco string) (Canary, bool) {
	c, ok := canaries[eco]
	return c, ok
}

// Ecosystems returns the ecosystems the drivers can scan (the canary
// table's keys), sorted. The database store downloads exactly these.
func Ecosystems() []string { return SortedEcosystems(canaries) }

// MatchFacts is what the child observed for one ecosystem's match.
type MatchFacts struct {
	// Unsupported: every extractor that fed the ecosystem is unsupported
	// on this platform.
	Unsupported bool
	// DatabaseInstalled: the store holds a verified database for it.
	DatabaseInstalled bool
	// NoDatabase: the matcher reported no local database.
	NoDatabase bool
	// MatchError: the matcher failed for another reason.
	MatchError bool
	// HasCanary: the ecosystem has a self-test row.
	HasCanary bool
	// CanaryHit: the canary matched at least one advisory.
	CanaryHit bool
}

// ecoRule is one row of the per-ecosystem outcome table.
type ecoRule struct {
	When    func(MatchFacts) bool
	Outcome EcoOutcome
	Reason  string
}

// ecoRules is walked top-down; the first row that matches decides.
var ecoRules = []ecoRule{
	{When: func(f MatchFacts) bool { return f.Unsupported }, Outcome: EcoNotScanned, Reason: ReasonUnsupported},
	{When: func(f MatchFacts) bool { return !f.HasCanary }, Outcome: EcoNotScanned, Reason: ReasonNoCanary},
	{When: func(f MatchFacts) bool { return !f.DatabaseInstalled || f.NoDatabase }, Outcome: EcoNotScanned, Reason: ReasonNoDatabase},
	{When: func(f MatchFacts) bool { return f.MatchError }, Outcome: EcoNotScanned, Reason: ReasonMatchFailed},
	{When: func(f MatchFacts) bool { return !f.CanaryHit }, Outcome: EcoNotScanned, Reason: ReasonSelfTestFailed},
	{When: func(MatchFacts) bool { return true }, Outcome: EcoScanned},
}

// DecideEcosystem returns one ecosystem's outcome and reason.
func DecideEcosystem(f MatchFacts) (EcoOutcome, string) {
	for _, r := range ecoRules {
		if r.When(f) {
			return r.Outcome, r.Reason
		}
	}
	return EcoNotScanned, ReasonMatchFailed
}

// RunFacts is what a whole run produced, for the coverage table.
type RunFacts struct {
	// Reason, when set, is a run-level failure that leaves nothing scanned
	// (not_compiled, not_installed, engine_failed, unsupported_platform).
	Reason string
	// Failed: the engine itself failed (a crash, a refused run).
	Failed     bool
	Ecosystems []EcoResult
	// ExtractorFailures counts extractors that did not succeed.
	ExtractorFailures int
	// Gaps are the parts of the project the run could not check
	// (Finalize); any gap makes the run partial.
	Gaps []Gap
	// Findings is the number of grouped findings.
	Findings int
}

// coverageRule is one row of the run coverage table.
type coverageRule struct {
	When    func(RunFacts, int, int) bool // facts, scanned ecosystems, not scanned ecosystems
	Outcome secscan.Outcome
	Reason  func(RunFacts) string
}

func fixed(s string) func(RunFacts) string { return func(RunFacts) string { return s } }

// coverageRules is walked top-down. "Clean" needs every ecosystem the
// inventory found scanned with a passed self-test, no failed extractor and
// no finding; partial coverage with no finding is "unknown", never clean.
var coverageRules = []coverageRule{
	{When: func(f RunFacts, _, _ int) bool { return f.Failed }, Outcome: secscan.OutcomeFailed, Reason: func(f RunFacts) string {
		if f.Reason != "" {
			return f.Reason
		}
		return ReasonEngineFailed
	}},
	{When: func(f RunFacts, _, _ int) bool { return f.Reason != "" }, Outcome: secscan.OutcomeNotScanned, Reason: func(f RunFacts) string { return f.Reason }},
	{When: func(f RunFacts, _, _ int) bool { return f.Findings > 0 }, Outcome: secscan.OutcomeFindings, Reason: func(f RunFacts) string {
		if partial(f) {
			return "partial_coverage"
		}
		return ""
	}},
	{When: func(_ RunFacts, scanned, notScanned int) bool { return scanned == 0 && notScanned == 0 }, Outcome: secscan.OutcomeNotScanned, Reason: fixed("no_packages")},
	{When: func(_ RunFacts, scanned, _ int) bool { return scanned == 0 }, Outcome: secscan.OutcomeNotScanned, Reason: fixed("no_ecosystem_scanned")},
	{When: func(f RunFacts, _, notScanned int) bool { return notScanned > 0 || partial(f) }, Outcome: secscan.OutcomeUnknown, Reason: fixed("partial_coverage")},
	{When: func(RunFacts, int, int) bool { return true }, Outcome: secscan.OutcomeClean, Reason: fixed("")},
}

func partial(f RunFacts) bool {
	if f.ExtractorFailures > 0 || len(f.Gaps) > 0 {
		return true
	}
	for _, e := range f.Ecosystems {
		if !complete(e) {
			return true
		}
	}
	return false
}

// complete reports whether an ecosystem was scanned in full: matched with
// a passed self-test, nothing withheld, no gap.
func complete(e EcoResult) bool {
	return e.Outcome == EcoScanned && e.Withheld == 0 && e.Gaps == 0
}

// EcosystemSkipPrefix starts the Skip.Path of an ecosystem that was not
// scanned; every other Skip.Path is a dependency file, relative to the
// project root.
const EcosystemSkipPrefix = "ecosystem:"

// Coverage returns the run's coverage: its outcome, reason, one Skip per
// ecosystem that was not scanned (Path names the ecosystem), one Skip per
// gap (Path names the file), and Scanned, the ecosystems scanned in full.
// A run with a failed extractor scans nothing in full: a lockfile caught
// mid-write proves nothing about the packages it would have listed, so
// such a run closes no finding.
func Coverage(f RunFacts) secscan.Coverage {
	scanned, notScanned := 0, 0
	var skipped []secscan.Skip
	var full []string
	for _, e := range f.Ecosystems {
		if e.Outcome == EcoScanned {
			scanned++
			if complete(e) && f.ExtractorFailures == 0 {
				full = append(full, e.Ecosystem)
			}
			continue
		}
		notScanned++
		skipped = append(skipped, secscan.Skip{Path: EcosystemSkipPrefix + e.Ecosystem, Reason: e.Reason})
	}
	for _, g := range f.Gaps {
		skipped = append(skipped, secscan.Skip{Path: g.Path, Reason: g.Reason})
	}
	sort.Strings(full)
	for _, r := range coverageRules {
		if r.When(f, scanned, notScanned) {
			return secscan.Coverage{Outcome: r.Outcome, Reason: r.Reason(f), Skipped: skipped, Scanned: full}
		}
	}
	return secscan.Coverage{Outcome: secscan.OutcomeUnknown, Reason: "partial_coverage", Skipped: skipped, Scanned: full}
}

// CanaryFiles is the self-test project for a driver that reads files, not
// an in-memory request (osv-scanner): one dependency file per ecosystem,
// each pinning that ecosystem's canary. The daemon writes them under its
// own directory and scans that directory with the project; a canary that
// does not come back flagged marks its ecosystem "not scanned".
func CanaryFiles() map[string]string {
	return map[string]string{
		"package-lock.json": `{"name":"observer-canary","version":"0.0.0","lockfileVersion":3,"requires":true,"packages":{` +
			`"":{"name":"observer-canary","version":"0.0.0"},` +
			`"node_modules/lodash":{"version":"4.17.20","resolved":"https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz"}}}` + "\n",
		"requirements.txt": "requests==2.19.0\n",
		"go.mod":           "module example.com/observer-canary\n\ngo 1.22\n\nrequire golang.org/x/text v0.3.5\n",
		"Cargo.lock": "version = 3\n\n[[package]]\nname = \"time\"\nversion = \"0.1.42\"\n" +
			"source = \"registry+https://github.com/rust-lang/crates.io-index\"\n",
		"Gemfile.lock":       "GEM\n  remote: https://rubygems.org/\n  specs:\n    rack (2.0.0)\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n  rack (= 2.0.0)\n",
		"composer.lock":      `{"packages":[{"name":"symfony/http-kernel","version":"v4.0.0"}],"packages-dev":[]}` + "\n",
		"packages.lock.json": `{"version":1,"dependencies":{"net6.0":{"Newtonsoft.Json":{"type":"Direct","requested":"[12.0.1, )","resolved":"12.0.1"}}}}` + "\n",
		"pom.xml": "<project><modelVersion>4.0.0</modelVersion><groupId>example</groupId><artifactId>observer-canary</artifactId><version>0</version>" +
			"<dependencies><dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>2.14.1</version></dependency></dependencies></project>\n",
	}
}
