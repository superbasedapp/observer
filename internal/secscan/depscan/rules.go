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
	// An image's kernel packages (osimage.go kernelRules): a container does
	// not run its own kernel, and matching them breaks the scan child's
	// memory cap (spike JSP-OS S6). Left out on purpose, counted and named
	// in the run's notes (KernelNote), not a gap.
	{Name: KernelDropRule, Match: KernelPackage},
	// An OS package of another release than the image's os-release names:
	// the release's database cannot answer for it, so the run is partial.
	{Name: "other_release", Gap: ReasonOtherRelease, Match: func(p Package) bool { return p.OtherRelease }},
	// The `go` line of a go.mod names a minimum language version, not the
	// toolchain that builds the module; govulncheck covers the toolchain.
	// A Go binary's stdlib row is kept: its build info names the toolchain
	// that built it, which is the standard library compiled in.
	{Name: "go_directive", Match: func(p Package) bool {
		return p.Ecosystem == "Go" && !p.Artifact && (p.Name == "stdlib" || p.Name == "go" || p.Name == "toolchain")
	}},
	// The Go toolchain is its own advisory identity ("toolchain" in the Go
	// vulnerability database: the go command, which runs where the code is
	// built), never merged with the standard library a binary embeds and
	// never attached to a binary (operator ruling 2026-11-05, item 4 Go
	// stdlib (c)). The build info names no such module; this row keeps one
	// that a future extractor emits from being matched against a binary.
	{Name: "artifact_toolchain", Match: func(p Package) bool {
		return p.Artifact && p.Ecosystem == "Go" && p.Name == "toolchain"
	}},
	// A Go binary whose Go version is a development build or unreadable
	// (NormalizeGoVersion): nothing to match, so the binary's standard
	// library reads as not checked (a gap), never clean. Before
	// empty_version, whose reason would name it unpinned.
	{Name: "go_version_unknown", Gap: ReasonGoVersionUnknown, Match: func(p Package) bool {
		return p.Artifact && p.Ecosystem == "Go" && p.VersionUnknown
	}},
	// A Go binary's main module built from a working tree ("(devel)"): the
	// project's own code, not a dependency.
	{Name: "artifact_main_module", Match: func(p Package) bool {
		return p.Artifact && p.Ecosystem == "Go" && p.Version == "(devel)"
	}},
	// The project's own package.json (not one under node_modules): the
	// root project, not a dependency.
	{Name: "root_project", Match: func(p Package) bool {
		return p.Extractor == "javascript/packagejson" && !underNodeModules(p.Path)
	}},
	// A GitHub Actions uses: pinned by a commit SHA with no version
	// comment: there is no version to match (Observer resolves no SHA), so
	// it is dropped and the run is partial. Before empty_version, whose
	// reason would name it unpinned.
	{Name: "sha_no_version", Gap: ReasonPinnedBySHA, Match: func(p Package) bool { return p.PinnedBySHA }},
	// A ref that names a branch or another name, not a version (`@main`):
	// not pinned, so it is dropped and the run is partial.
	{Name: "not_a_version", Gap: ReasonUnpinned, Match: func(p Package) bool { return p.NotAVersion }},
	// A manifest dependency with no pinned version: every advisory for the
	// name would match, so it is dropped and the run is partial.
	{Name: "empty_version", Gap: ReasonUnpinned, Match: func(p Package) bool { return strings.TrimSpace(p.Version) == "" }},
	// A requirements line with a range (`requests>=2.0`): the extractor
	// reports the lowest bound, which is not what pip installs. Also a
	// NuGet or Gradle version catalog range, floating version or MSBuild
	// property: a string that names no one release.
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

// ecosystemRow is one ecosystem the drivers can scan: its self-test
// package and what reads it. Decisions about an ecosystem read these
// columns, never its name.
type ecosystemRow struct {
	Canary Canary
	// OSVScanner: osv-scanner reads this ecosystem's dependency files, so
	// its run needs the ecosystem's database installed (it fails the whole
	// run on a missing one, exit 127) and its canary file is in
	// CanaryFiles. An ecosystem osv-scanner does not read (GitHub Actions
	// workflows) is matched by the SCALIBR driver only.
	OSVScanner bool
	// NativeRule is the native rule id a finding of this ecosystem also
	// is, for policy and feedback ("S-779" for an action with a known
	// advisory); "" for none. The finding's own rule id stays the
	// advisory's (NativeRuleOf).
	NativeRule string
	// Noun is the dependency's name in the finding message ("a npm
	// dependency", "an action"); "" uses the ecosystem's name.
	Noun string
	// FixHint is the finding's fix hint; "" uses the lockfile hint.
	FixHint string
}

// lockfileFixHint is the fix hint of an ecosystem with no hint of its own.
const lockfileFixHint = "Upgrade the dependency to a version the advisory lists as fixed, then regenerate the lockfile."

// ecosystems is the self-test table, one row per ecosystem the extractor
// table feeds. An ecosystem without a row is "not scanned", never clean.
// Every canary of the first nine matched the real exports (the eight
// language ecosystems on 2026-10-21; GitHub Actions on 2026-11-04:
// tj-actions/changed-files v45.0.0 is inside GHSA-mrrh-fwg8-r2c3's ECOSYSTEM
// range, introduced 0, fixed 46.0.1, the March 2025 compromise).
//
// The six of the 2026-11-06 coverage review were chosen from their OSV
// records (api.osv.dev, read 2026-11-06; none withdrawn); matching them
// against the real exports is a live check still owed
// (docs/dependency-scanning.md "The extractor table"):
//   - Pub http 0.13.2: GHSA-4rgh-jx4f-qfcq (CVE-2020-35669), introduced 0,
//     fixed 0.13.3, and 0.13.2 is in its versions list;
//   - SwiftURL github.com/apple/swift-nio-http2 1.19.1: GHSA-pgfx-g6rc-8cjv
//     (CVE-2022-24668), SEMVER introduced 1.0.0, fixed 1.19.2;
//   - Hex plug 1.3.4: GHSA-9h73-w7ch-rh73 (CVE-2018-1000883), introduced
//     1.3.0, fixed 1.3.5, and 1.3.4 is in its versions list;
//   - Hackage aeson 1.5.6.0: HSEC-2023-0001 (CVE-2022-3433), introduced
//     0.4.0.0, fixed 2.0.1.0, and 1.5.6.0 is in its versions list;
//   - Julia HTTP 1.10.16: JLSEC-2025-1 (CVE-2025-52479), SEMVER introduced
//     0, fixed 1.10.17;
//   - CRAN readxl 1.2.0: RSEC-2023-1 (no alias), introduced 0.1.0, fixed
//     1.3.0, and 1.2.0 is in its versions list.
//
// osv-scanner v2.6.0 reads Pub, SwiftURL, Hex, Hackage and CRAN files (its
// lockfile preset links pubspec, packageresolved, mixlock, cabal, stacklock
// and renvlock); it reads no Julia Manifest.toml, so Julia is matched by the
// SCALIBR driver only, like GitHub Actions.
var ecosystems = map[string]ecosystemRow{
	"npm":       {Canary: Canary{Name: "lodash", Version: "4.17.20", Advisory: "CVE-2021-23337"}, OSVScanner: true},
	"PyPI":      {Canary: Canary{Name: "requests", Version: "2.19.0", Advisory: "CVE-2018-18074"}, OSVScanner: true},
	"Go":        {Canary: Canary{Name: "golang.org/x/text", Version: "v0.3.5", Advisory: "CVE-2022-32149"}, OSVScanner: true},
	"crates.io": {Canary: Canary{Name: "time", Version: "0.1.42", Advisory: "RUSTSEC-2020-0071"}, OSVScanner: true},
	"RubyGems":  {Canary: Canary{Name: "rack", Version: "2.0.0", Advisory: "CVE-2018-16471"}, OSVScanner: true},
	"Packagist": {Canary: Canary{Name: "symfony/http-kernel", Version: "4.0.0", Advisory: "CVE-2018-14773"}, OSVScanner: true},
	"NuGet":     {Canary: Canary{Name: "Newtonsoft.Json", Version: "12.0.1", Advisory: "GHSA-5crp-9r3c-p9vr"}, OSVScanner: true},
	"Maven":     {Canary: Canary{Name: "org.apache.logging.log4j:log4j-core", Version: "2.14.1", Advisory: "CVE-2021-44228"}, OSVScanner: true},
	"Pub":       {Canary: Canary{Name: "http", Version: "0.13.2", Advisory: "CVE-2020-35669"}, OSVScanner: true},
	"SwiftURL":  {Canary: Canary{Name: "github.com/apple/swift-nio-http2", Version: "1.19.1", Advisory: "CVE-2022-24668"}, OSVScanner: true},
	"Hex":       {Canary: Canary{Name: "plug", Version: "1.3.4", Advisory: "CVE-2018-1000883"}, OSVScanner: true},
	"Hackage":   {Canary: Canary{Name: "aeson", Version: "1.5.6.0", Advisory: "CVE-2022-3433"}, OSVScanner: true},
	"Julia":     {Canary: Canary{Name: "HTTP", Version: "1.10.16", Advisory: "CVE-2025-52479"}},
	"CRAN":      {Canary: Canary{Name: "readxl", Version: "1.2.0", Advisory: "RSEC-2023-1"}, OSVScanner: true},
	"GitHub Actions": {
		Canary:     Canary{Name: "tj-actions/changed-files", Version: "v45.0.0", Advisory: "CVE-2025-30066"},
		NativeRule: "S-779",
		Noun:       "GitHub Actions action",
		FixHint:    "Move the action to a version the advisory lists as fixed, and pin that version by its full commit SHA with the version in a trailing comment.",
	},
}

// CanaryFor returns the ecosystem's self-test package.
func CanaryFor(eco string) (Canary, bool) {
	r, ok := ecosystems[eco]
	return r.Canary, ok
}

// Ecosystems returns the ecosystems the drivers can scan (the table's
// keys), sorted. The database store downloads exactly these.
func Ecosystems() []string { return SortedEcosystems(ecosystems) }

// OSVScannerEcosystems returns the ecosystems osv-scanner reads, sorted:
// the databases its run requires and the canaries of CanaryFiles. Never
// every store ecosystem: osv-scanner exits 127 on any missing database, so
// an ecosystem it does not read must never be a precondition of its run.
func OSVScannerEcosystems() []string {
	var out []string
	for _, eco := range Ecosystems() {
		if ecosystems[eco].OSVScanner {
			out = append(out, eco)
		}
	}
	return out
}

// OSVScannerReads reports whether osv-scanner reads the ecosystem.
func OSVScannerReads(eco string) bool { return ecosystems[eco].OSVScanner }

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
		"pubspec.lock": "packages:\n  http:\n    dependency: \"direct main\"\n    description:\n      name: http\n      url: \"https://pub.dev\"\n" +
			"    source: hosted\n    version: \"0.13.2\"\nsdks:\n  dart: \">=2.12.0 <3.0.0\"\n",
		"Package.resolved": `{"pins":[{"identity":"swift-nio-http2","kind":"remoteSourceControl","location":"https://github.com/apple/swift-nio-http2.git",` +
			`"state":{"version":"1.19.1"}}],"version":2}` + "\n",
		"mix.lock":             "%{\n  \"plug\": {:hex, :plug, \"1.3.4\", \"0000000000000000000000000000000000000000000000000000000000000000\", [:mix], [], \"hexpm\"},\n}\n",
		"cabal.project.freeze": "active-repositories: hackage.haskell.org:merge\nconstraints: any.aeson ==1.5.6.0\nindex-state: hackage.haskell.org 2021-06-01T00:00:00Z\n",
		"renv.lock": `{"R":{"Version":"4.3.0","Repositories":[{"Name":"CRAN","URL":"https://cloud.r-project.org"}]},` +
			`"Packages":{"readxl":{"Package":"readxl","Version":"1.2.0","Source":"Repository","Repository":"CRAN"}}}` + "\n",
	}
}
