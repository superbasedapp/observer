package osvscanner

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/extrun"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/secscan"
	"github.com/marmutapp/superbased-observer/internal/secscan/depdriver"
	"github.com/marmutapp/superbased-observer/internal/secscan/depscan"
	"github.com/marmutapp/superbased-observer/internal/toolresolve"
)

// Spec is how osv-scanner is found: a separately installed binary, never a
// shim, never a bare PATH lookup by the runner.
var Spec = integration.BinaryResolveSpec{
	Names: integration.BinaryNames{Unix: []string{"osv-scanner"}, Windows: []string{"osv-scanner.exe"}},
}

// Limits are osv-scanner's caps (JSP-8: 1 GB without call analysis, 0.6 GB
// measured; 600 s background).
var Limits = extrun.Limits{
	Wall:        600 * time.Second,
	StdoutBytes: 64 << 20,
	StderrBytes: 1 << 20,
	MemoryBytes: 1 << 30,
	Children:    64,
}

// engine is osv-scanner's run profile: its own HOME and cache, a UTF-8
// locale, and its exit-code table.
var engine = extrun.Engine{
	Name: "osv-scanner", OwnHome: true, Locale: "C.UTF-8",
	ExitCodes: []extrun.ExitCodeRow{
		{Code: 0, Meaning: extrun.ExitClean},
		{Code: 1, Meaning: extrun.ExitFindings},
		{Code: 128, Meaning: extrun.ExitNoInput},
		{Code: 127, Meaning: extrun.ExitFailure},
	},
}

// ConfigFile is the name of Observer's own, empty osv-scanner config inside
// the canary directory; passing it overrides any osv-scanner.toml the
// repository carries.
const ConfigFile = "observer-osv-scanner.toml"

// Args returns the full argument list for one run.
func Args(root, canaryDir, sep string) []string {
	args := append([]string(nil), depscan.OSVScannerFlags.Always...)
	args = append(args, "--all-packages", "--verbosity", "error", "--config", canaryDir+sep+ConfigFile, root, canaryDir)
	return args
}

// versionPattern reads `osv-scanner version: 2.6.0`.
var versionPattern = regexp.MustCompile(`osv-scanner version:\s*v?(\d+\.\d+\.\d+)`)

// VersionProbe is how a run asks osv-scanner its version (the driver and
// the Go source check, source.go).
func VersionProbe() extrun.VersionProbe {
	return extrun.VersionProbe{Args: []string{"--version"}, Pattern: versionPattern}
}

// Env is what the driver needs from the caller.
type Env struct {
	Runner *extrun.Runner
	// DBDir is the store directory (OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY).
	DBDir string
	// Epochs are the installed ecosystems' epochs.
	Epochs map[string]string
	// CanaryDir holds depscan.CanaryFiles and the empty ConfigFile; the
	// caller writes them.
	CanaryDir string
	// HomeDir is the engine's own HOME and cache directory.
	HomeDir string
	// GOOS and GOARCH select the Platforms cells.
	GOOS, GOARCH string
	// InventorySink receives every parsed scan's package inventory (the
	// project SBOM's source), with the driver id; nil keeps it nowhere.
	InventorySink func(root, driver string, pkgs []depscan.Package)
}

// Driver is the subprocess driver.
type Driver struct{ env Env }

// New returns the driver over env.
func New(env Env) *Driver { return &Driver{env: env} }

// Row is the registry row.
func (d *Driver) Row() secscan.DriverRow { return depscan.OSVRow() }

// resolve finds the binary without starting anything.
func (d *Driver) resolve() (string, bool) {
	if d.env.Runner == nil || d.env.Runner.Resolve == nil {
		return "", false
	}
	r := d.env.Runner.Resolve(Spec)
	switch r.Verdict {
	case toolresolve.VerdictOK, toolresolve.VerdictOKOffPath, toolresolve.VerdictShadowed:
		return r.Bin, r.Bin != ""
	}
	return "", false
}

// missingDatabases lists the ecosystems osv-scanner reads that have no
// installed database (depscan.OSVScannerEcosystems: never an ecosystem it
// does not read, such as GitHub Actions, whose absence must not stop it).
func (d *Driver) missingDatabases() []string {
	var out []string
	for _, eco := range depscan.OSVScannerEcosystems() {
		if d.env.Epochs[eco] == "" {
			out = append(out, eco)
		}
	}
	return out
}

// Probe resolves the binary (no process), and reports the platform cell,
// the beta label and a missing database.
func (d *Driver) Probe(context.Context) secscan.Probe {
	row := d.Row()
	p := secscan.Probe{
		Platform: depscan.PlatformSupport(row, d.env.GOOS, d.env.GOARCH, ""),
		Beta:     depscan.Beta(row, d.env.GOOS, d.env.GOARCH),
	}
	_, p.Installed = d.resolve()
	switch {
	case !p.Installed:
		p.Reason = depscan.ReasonNotInstalled
	case len(d.missingDatabases()) > 0:
		p.Reason = depscan.ReasonNoDatabase
	}
	return p
}

// Scan runs osv-scanner once over the project and the canary directory.
func (d *Driver) Scan(ctx context.Context, t secscan.Target) (secscan.Result, error) {
	ident := secscan.EngineIdentity{Name: depscan.OSVID}
	in := depdriver.Input{DriverID: depscan.OSVID, Target: t, Engine: ident}
	bin, ok := d.resolve()
	if !ok {
		in.RunReason = depscan.ReasonNotInstalled
		return depdriver.Result(in), nil
	}
	if depscan.PlatformSupport(d.Row(), d.env.GOOS, d.env.GOARCH, "") == secscan.SupportUnsupported {
		in.RunReason = depscan.ReasonUnsupported
		return depdriver.Result(in), nil
	}
	if len(d.missingDatabases()) > 0 {
		in.RunReason = depscan.ReasonNoDatabase
		return depdriver.Result(in), nil
	}
	req := Request(bin, t.ProjectRoot, d.env.DBDir, d.env.CanaryDir, d.env.HomeDir, d.env.GOOS)
	v, _ := d.env.Runner.ProbeVersion(ctx, req, VersionProbe())
	in.Engine.Version, in.Engine.Digest = v.Version, v.Digest
	switch Verdict(v.Version) {
	case VersionRefused:
		in.Failed, in.RunReason = true, "driver_unverified"
		return depdriver.Result(in), nil
	case VersionUntested:
		// A fixed sentence: the reported version is on Engine.Version,
		// never copied into a note (lane SEC-DEPS3 item 6).
		in.Notes = append(in.Notes, untestedNote)
	}
	run := d.env.Runner.Run(ctx, req)
	if run.Digests.Binary != "" {
		in.Engine.Digest = run.Digests.Binary
	}
	facts := readStderr(run.Stderr, run.StderrTruncated, t.ProjectRoot, d.env.CanaryDir)
	switch run.ExitMeaning {
	case extrun.ExitClean, extrun.ExitFindings:
	case extrun.ExitNoInput:
		in.RunReason = "no_packages"
		return depdriver.Result(in), nil
	default:
		if !completedDespiteMissing(run, facts) {
			in.Failed, in.RunReason = true, failReason(run)
			return depdriver.Result(in), nil
		}
	}
	if run.StdoutTruncated {
		in.Failed, in.RunReason = true, "budget_exceeded"
		return depdriver.Result(in), nil
	}
	resp, err := Parse(run.Stdout, t.ProjectRoot, d.env.CanaryDir, d.env.Epochs)
	if err != nil {
		in.Failed, in.RunReason = true, depscan.ReasonEngineFailed
		return depdriver.Result(in), nil
	}
	if d.env.InventorySink != nil && t.CheckoutRoot == "" {
		d.env.InventorySink(t.ProjectRoot, depscan.OSVID, resp.Packages)
	}
	resp.Extractors = append(resp.Extractors, facts.failures()...)
	resp.Gaps = append(resp.Gaps, MissingDatabaseGaps(facts.missing, resp.Packages)...)
	in.Response = resp
	return depdriver.Result(in), nil
}

// untestedNote is the note of a run by an osv-scanner newer than the
// tested range.
var untestedNote = depscan.UntestedVersionPrefix + ": this osv-scanner is newer than the tested range " + depscan.OSVScannerTested + "; its results are shown, labelled untested."

// lockfileEcosystems maps a dependency file's name (path.Match patterns
// over the base name) to the OSV ecosystem it feeds, for attributing an
// extraction failure osv-scanner reports. Walked top-down.
var lockfileEcosystems = []struct{ pattern, eco string }{
	{"package-lock.json", "npm"},
	{"npm-shrinkwrap.json", "npm"},
	{"pnpm-lock.yaml", "npm"},
	{"yarn.lock", "npm"},
	{"bun.lock", "npm"},
	{"package.json", "npm"},
	{"uv.lock", "PyPI"},
	{"poetry.lock", "PyPI"},
	{"Pipfile.lock", "PyPI"},
	{"pdm.lock", "PyPI"},
	{"pylock.toml", "PyPI"},
	{"pylock.*.toml", "PyPI"},
	{"requirements*.txt", "PyPI"},
	{"Cargo.lock", "crates.io"},
	{"go.mod", "Go"},
	{"go.sum", "Go"},
	{"Gemfile.lock", "RubyGems"},
	{"gems.locked", "RubyGems"},
	{"composer.lock", "Packagist"},
	{"packages.lock.json", "NuGet"},
	{"*.csproj", "NuGet"},
	{"*.fsproj", "NuGet"},
	{"*.vbproj", "NuGet"},
	{"*.deps.json", "NuGet"},
	{"Directory.Packages.props", "NuGet"},
	{"Directory.Build.props", "NuGet"},
	{"packages.config", "NuGet"},
	{"pom.xml", "Maven"},
	{"gradle.lockfile", "Maven"},
	{"buildscript-gradle.lockfile", "Maven"},
	{"verification-metadata.xml", "Maven"},
	// The files of ecosystems beyond the original eight, so a failure on
	// one is placed on its own ecosystem, not on every one. Pub, SwiftURL,
	// Hex, Hackage and CRAN are in osv-scanner v2.6.0's lockfile preset and
	// Observer downloads their databases (the 2026-11-06 coverage review);
	// CocoaPods, Julia (SCALIBR only), Conan and vcpkg have no database
	// osv-scanner is given, so their packages are MissingDatabaseGaps.
	{"pubspec.lock", "Pub"},
	{"Package.resolved", "SwiftURL"},
	{"Podfile.lock", "CocoaPods"},
	{"mix.lock", "Hex"},
	{"cabal.project.freeze", "Hackage"},
	{"stack.yaml.lock", "Hackage"},
	{"Manifest.toml", "Julia"},
	{"renv.lock", "CRAN"},
	{"conan.lock", "ConanCenter"},
	{"vcpkg.json", "vcpkg"},
}

// lockfileEcosystem returns the ecosystem a dependency file feeds, "" when
// the name is not in the table.
func lockfileEcosystem(name string) string {
	for _, r := range lockfileEcosystems {
		if ok, _ := path.Match(r.pattern, name); ok {
			return r.eco
		}
	}
	return ""
}

// ExtractionFailures reads osv-scanner's stderr (run at --verbosity
// error, so every line it prints is an error) into failed extractor rows
// (lane SEC-DEPS3 item 4, the P-027 rule on the second driver): a
// dependency file it could not read is an extractor failure of that file's
// ecosystem, so the run is partial and StaleFindings closes nothing. A line
// naming a file of the canary directory is left to the canary rule. A line
// that names no file under the root, a file the table does not know, or a
// truncated stderr cannot be placed, and fails every ecosystem.
//
// A line is placed against the more specific of the two directories (lane
// sec-deps4, decision log P-036): when a path in it lies under both the
// root and the canary directory (a project inside the canary directory, or
// a project path that contains the canary path), the longer directory
// owns it, so a project's unreadable lockfile is never mistaken for a
// canary file and hidden.
//
// A line naming the ecosystems osv-scanner found no local database for is
// no extraction failure when Observer offers a database for none of them
// (they are gaps, MissingDatabaseGaps); one that names an ecosystem whose
// database Observer does offer is unplaced, since the driver refuses to
// start without it.
func ExtractionFailures(stderr []byte, truncated bool, root, canaryDir string) []depscan.ExtractorStatus {
	return readStderr(stderr, truncated, root, canaryDir).failures()
}

// stderrFacts is what one run's stderr says (readStderr).
type stderrFacts struct {
	// byEco are the dependency files each ecosystem failed on.
	byEco map[string][]string
	// unplaced: a line (or a truncated stderr) that cannot be placed, which
	// fails every ecosystem.
	unplaced bool
	// missing are the ecosystems osv-scanner found no local database for,
	// none of them one Observer offers a database for; sorted, each once.
	missing []string
}

// readStderr reads osv-scanner's stderr into facts (ExtractionFailures).
func readStderr(stderr []byte, truncated bool, root, canaryDir string) stderrFacts {
	f := stderrFacts{byEco: map[string][]string{}, unplaced: truncated}
	for _, line := range strings.Split(string(stderr), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if ecos, ok := missingDatabaseEcosystems(line); ok {
			if slices.ContainsFunc(ecos, depscan.OSVScannerReads) {
				f.unplaced = true
				continue
			}
			for _, eco := range ecos {
				if !slices.Contains(f.missing, eco) {
					f.missing = append(f.missing, eco)
				}
			}
			continue
		}
		if p, ok := pathUnder(line, canaryDir); ok && p != "" && !moreSpecific(line, root, canaryDir) {
			continue
		}
		rel, ok := pathUnder(line, root)
		if !ok || rel == "" || rel == "." {
			f.unplaced = true
			continue
		}
		eco := lockfileEcosystem(path.Base(rel))
		if eco == "" {
			f.unplaced = true
			continue
		}
		if !slices.Contains(f.byEco[eco], rel) {
			f.byEco[eco] = append(f.byEco[eco], rel)
		}
	}
	sort.Strings(f.missing)
	return f
}

// failures returns the failed extractor rows: one per ecosystem a file
// failed in, and every ecosystem osv-scanner reads when a line could not be
// placed.
func (f stderrFacts) failures() []depscan.ExtractorStatus {
	byEco := map[string][]string{}
	for eco, files := range f.byEco {
		byEco[eco] = files
	}
	if f.unplaced {
		for _, eco := range depscan.OSVScannerEcosystems() {
			if _, ok := byEco[eco]; !ok {
				byEco[eco] = nil
			}
		}
	}
	ecos := make([]string, 0, len(byEco))
	for eco := range byEco {
		ecos = append(ecos, eco)
	}
	sort.Strings(ecos)
	out := make([]depscan.ExtractorStatus, 0, len(ecos))
	for _, eco := range ecos {
		files := append([]string(nil), byEco[eco]...)
		sort.Strings(files)
		out = append(out, depscan.ExtractorStatus{Extractor: "osv-scanner", OK: false, Ecosystem: eco, Files: files})
	}
	return out
}

// missingDBLine is osv-scanner's line naming the ecosystems it found no
// local database for. Its local matcher (v2) gives each such package an
// empty result, keeps matching the rest and logs this once at the end; the
// logged error then makes the run exit 127 unless vulnerabilities were
// found (exit 1). Matched case-insensitively and with an optional plural;
// a rewording it does not match stays an unplaced error, which fails every
// ecosystem (the safe side). NOT verified against a live binary on the
// lane's host (none installed there): read from osv-scanner v2's source.
var missingDBLine = regexp.MustCompile(`(?i)could not find local databases? for ecosystems?:\s*(.+?)\s*$`)

// missingDatabaseEcosystems returns the ecosystems a stderr line names as
// having no local database, ok false when the line is not that message.
func missingDatabaseEcosystems(line string) ([]string, bool) {
	m := missingDBLine.FindStringSubmatch(line)
	if m == nil {
		return nil, false
	}
	var out []string
	for _, e := range strings.Split(m[1], ",") {
		if e = strings.TrimSpace(e); e != "" {
			out = append(out, e)
		}
	}
	return out, len(out) > 0
}

// completedDespiteMissing reports a run that exited 127 only because it
// logged the ecosystems Observer offers no database for: its output is
// still the whole scan, so it is read (the other ecosystems keep their
// results) and each missing ecosystem becomes gaps. Any other error line,
// or a truncated stderr, keeps the run failed.
func completedDespiteMissing(run extrun.Result, f stderrFacts) bool {
	return run.Outcome == extrun.OutcomeExitNonZero && run.ExitCode == 127 && len(f.missing) > 0 && !f.unplaced
}

// MissingDatabaseGaps turns the ecosystems osv-scanner found no local
// database for, and Observer offers none for, into gaps: one per
// dependency file that carried packages of the ecosystem (with their
// count), or one naming no file when the output listed none. Their
// packages were not matched, so the run is partial, never clean.
func MissingDatabaseGaps(ecos []string, pkgs []depscan.Package) []depscan.Gap {
	var out []depscan.Gap
	for _, eco := range ecos {
		count := map[string]int{}
		for _, p := range pkgs {
			if p.Ecosystem == eco {
				count[p.Path]++
			}
		}
		if len(count) == 0 {
			out = append(out, depscan.Gap{Ecosystem: eco, Reason: depscan.ReasonNoDatabaseOffered})
			continue
		}
		paths := make([]string, 0, len(count))
		for p := range count {
			paths = append(paths, p)
		}
		sort.Strings(paths)
		for _, p := range paths {
			out = append(out, depscan.Gap{Ecosystem: eco, Path: p, Reason: depscan.ReasonNoDatabaseOffered, Packages: count[p]})
		}
	}
	return out
}

// moreSpecific reports whether line names a path under base that is a
// longer (more specific) directory than other: base owns such a line.
func moreSpecific(line, base, other string) bool {
	if _, ok := pathUnder(line, base); !ok {
		return false
	}
	return len(strings.TrimRight(slashPath(base), "/")) > len(strings.TrimRight(slashPath(other), "/"))
}

// pathUnder finds the first path under base in line and returns it
// relative to base (forward slashes). The path runs from base to the
// first quote, whitespace, or ": ". base must start a path in the line:
// at the line's start or after a character that cannot be part of a path
// (a space, a quote, a bracket), so a directory that merely appears inside
// a longer path never matches.
func pathUnder(line, base string) (string, bool) {
	if base == "" {
		return "", false
	}
	b := strings.TrimRight(slashPath(base), "/")
	l := slashPath(line)
	for from := 0; from < len(l); {
		i := strings.Index(l[from:], b+"/")
		if i < 0 {
			return "", false
		}
		i += from
		if i > 0 && pathByte(l[i-1]) {
			from = i + 1
			continue
		}
		rest := l[i+len(b)+1:]
		end := len(rest)
		for j, c := range rest {
			if c == '"' || c == '\'' || c == ' ' || c == '\t' || c == ')' || c == ',' || (c == ':' && (j+1 == len(rest) || rest[j+1] == ' ')) {
				end = j
				break
			}
		}
		rel := path.Clean(rest[:end])
		if rel == "." || rel == ".." || strings.HasPrefix(rel, "../") {
			return "", true
		}
		return rel, true
	}
	return "", false
}

// pathByte reports whether c can be part of a path name, so a base that
// follows it is inside a longer path rather than its start.
func pathByte(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	}
	return strings.IndexByte("/._-~+@", c) >= 0
}

func failReason(run extrun.Result) string {
	switch run.Outcome {
	case extrun.OutcomeTimeout, extrun.OutcomeOutputCap, extrun.OutcomeChildrenCap:
		return "budget_exceeded"
	case extrun.OutcomeRefused:
		return "driver_unverified"
	case extrun.OutcomeCanceled:
		return "canceled"
	}
	return depscan.ReasonEngineFailed
}

// Request is the runner request for one scan.
func Request(bin, root, dbDir, canaryDir, homeDir, goos string) extrun.Request {
	sep := "/"
	if goos == "windows" {
		sep = `\`
	}
	e := engine
	return extrun.Request{
		Component: depscan.OSVComponent,
		Program:   extrun.Program{Path: bin},
		Args:      Args(root, canaryDir, sep),
		Env:       extrun.EnvSpec{Set: []string{"OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=" + dbDir}},
		Dir:       root,
		Limits:    Limits,
		CacheDir:  homeDir,
		Engine:    &e,
	}
}

// VersionVerdict is what the driver does with one osv-scanner version.
type VersionVerdict string

// The VersionVerdict values.
const (
	// VersionTested: inside depscan.OSVScannerTested; the run is not
	// labelled.
	VersionTested VersionVerdict = "tested"
	// VersionUntested: newer than the tested range; the run goes ahead,
	// labelled with an UntestedVersionPrefix note (its JSON shape and exit
	// codes were not checked by Observer).
	VersionUntested VersionVerdict = "untested"
	// VersionRefused: unreadable or older than the minimum; nothing runs
	// and the result is "failed" (driver_unverified).
	VersionRefused VersionVerdict = "refused"
)

// versionRules is the version table, walked top-down: the first row whose
// test holds decides (CLAUDE.md module rule 5).
var versionRules = []struct {
	when    func(v []int) bool
	verdict VersionVerdict
}{
	{func(v []int) bool { return v == nil }, VersionRefused},
	{func(v []int) bool { return compareVersion(v, parseVersion(depscan.OSVScannerMinVersion)) < 0 }, VersionRefused},
	{func(v []int) bool { return compareVersion(v, parseVersion(depscan.OSVScannerTestedBelow)) >= 0 }, VersionUntested},
	{func([]int) bool { return true }, VersionTested},
}

// Verdict returns the version table's verdict for a reported version (the
// driver's own engine range, not package version logic).
func Verdict(v string) VersionVerdict {
	p := parseVersion(v)
	for _, r := range versionRules {
		if r.when(p) {
			return r.verdict
		}
	}
	return VersionRefused
}

// parseVersion reads a dotted numeric version of three parts ("2.6.0"),
// nil when it is anything else.
func parseVersion(v string) []int {
	parts := strings.Split(strings.TrimPrefix(strings.TrimSpace(v), "v"), ".")
	if len(parts) != 3 {
		return nil
	}
	out := make([]int, 3)
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nil
		}
		out[i] = n
	}
	return out
}

func compareVersion(a, b []int) int {
	for i := 0; i < 3; i++ {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

// output is the part of osv-scanner's JSON the driver reads.
type output struct {
	Results []struct {
		Source struct {
			Path string `json:"path"`
		} `json:"source"`
		Packages []struct {
			Package struct {
				Name      string `json:"name"`
				Version   string `json:"version"`
				Ecosystem string `json:"ecosystem"`
			} `json:"package"`
			Groups []struct {
				IDs         []string `json:"ids"`
				Aliases     []string `json:"aliases"`
				MaxSeverity string   `json:"max_severity"`
			} `json:"groups"`
			Vulnerabilities []struct {
				ID string `json:"id"`
			} `json:"vulnerabilities"`
		} `json:"packages"`
	} `json:"results"`
}

// severityBand maps osv-scanner's max_severity (a CVSS base score) onto the
// label vocabulary depscan reads.
func severityBand(score string) string {
	f, err := strconv.ParseFloat(strings.TrimSpace(score), 64)
	switch {
	case err != nil || f <= 0:
		return ""
	case f >= 9:
		return "critical"
	case f >= 7:
		return "high"
	case f >= 4:
		return "medium"
	}
	return "low"
}

// slashPath normalizes a path to forward slashes.
func slashPath(p string) string { return strings.ReplaceAll(p, `\`, "/") }

// relUnder returns p relative to root when p is root or below it.
func relUnder(root, p string) (string, bool) {
	r, q := strings.TrimRight(slashPath(root), "/"), slashPath(p)
	if q == r {
		return ".", true
	}
	if strings.HasPrefix(q, r+"/") {
		return path.Clean(strings.TrimPrefix(q, r+"/")), true
	}
	return "", false
}

// Parse maps osv-scanner's JSON onto the shared child response: the
// project's packages and grouped advisories per ecosystem, the canary
// results as each ecosystem's self-test, and nothing from outside the
// project root.
func Parse(stdout []byte, root, canaryDir string, epochs map[string]string) (depscan.ChildResponse, error) {
	var out output
	if err := json.Unmarshal(stdout, &out); err != nil {
		return depscan.ChildResponse{}, fmt.Errorf("osvscanner.Parse: %w", err)
	}
	resp := depscan.ChildResponse{Version: depscan.ProtocolVersion, Compiled: true}
	canaryHit := map[string]bool{}
	advs := map[string][]depscan.Advisory{}
	for _, r := range out.Results {
		_, inCanary := relUnder(canaryDir, r.Source.Path)
		rel, inRoot := relUnder(root, r.Source.Path)
		for _, p := range r.Packages {
			eco := p.Package.Ecosystem
			flagged := len(p.Groups) > 0 || len(p.Vulnerabilities) > 0
			if inCanary {
				if c, ok := depscan.CanaryFor(eco); ok && flagged && c.Name == p.Package.Name {
					canaryHit[eco] = true
				}
				continue
			}
			if !inRoot {
				continue
			}
			idx := len(resp.Packages)
			resp.Packages = append(resp.Packages, depscan.Package{Ecosystem: eco, Name: p.Package.Name, Version: p.Package.Version, Path: rel, Extractor: "osv-scanner"})
			for _, g := range p.Groups {
				if len(g.IDs) == 0 {
					continue
				}
				aliases := append(append([]string(nil), g.IDs[1:]...), g.Aliases...)
				advs[eco] = append(advs[eco], depscan.Advisory{ID: g.IDs[0], Aliases: aliases, Severity: severityBand(g.MaxSeverity), Index: idx})
			}
		}
	}
	keep, dropped := depscan.Prepare(resp.Packages)
	resp.Dropped = dropped
	for _, eco := range depscan.SortedEcosystems(keep) {
		// Only an ecosystem osv-scanner reads has its canary in the canary
		// project; any other has no self-test in this run.
		hasCanary := depscan.OSVScannerReads(eco)
		e := depscan.EcoResult{Ecosystem: eco, Packages: len(keep[eco])}
		e.Outcome, e.Reason = depscan.DecideEcosystem(depscan.MatchFacts{
			DatabaseInstalled: epochs[eco] != "", HasCanary: hasCanary, CanaryHit: canaryHit[eco],
		})
		if e.Outcome == depscan.EcoScanned {
			e.Epoch = epochs[eco]
			kept := map[int]bool{}
			for _, i := range keep[eco] {
				kept[i] = true
			}
			for _, a := range advs[eco] {
				if kept[a.Index] {
					e.Advisories = append(e.Advisories, a)
				}
			}
			sort.SliceStable(e.Advisories, func(i, j int) bool { return e.Advisories[i].Index < e.Advisories[j].Index })
		}
		resp.Ecosystems = append(resp.Ecosystems, e)
	}
	return resp, nil
}
