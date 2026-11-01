package seccustom

import (
	"embed"
	"io/fs"
	"path"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/extrun"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
)

// Template is a built-in manifest for a common engine (section 8.6:
// gosec, Bandit, Semgrep; JSP-8 and JSP-12 ground the flags and exit
// codes). It carries everything but the executable and the digests, which
// import fills from discovery.
type Template struct {
	ID    string
	Title string
	// Binary is how the executable is discovered (internal/toolresolve
	// with the shim exclusion): never typed.
	Binary integration.BinaryResolveSpec
	// Companions are discovered the same way, in Manifest.Companions order.
	Companions []TemplateCompanion
	// Interpreted marks a launcher script (Bandit): executable_sha256 pins
	// only the launcher, so the pin is labelled "partial" (JSP-12).
	Interpreted bool
	// Engine is the runner profile: git hardening, locale and the engine's
	// own home and cache.
	Engine extrun.Engine
	// Note is one plain sentence shown with the template.
	Note string
	// Manifest is the template body (Executable and digests empty).
	Manifest Manifest
}

// TemplateCompanion is how one companion is discovered.
type TemplateCompanion struct {
	Binary        integration.BinaryResolveSpec
	OnPath        bool
	VersionArgv   []string
	VersionFormat string
	// FromShebang takes the companion from the executable's own "#!" line
	// (an interpreted launcher's interpreter) instead of discovery.
	FromShebang bool
}

// home-relative probe directories shared by the templates.
var (
	goProbes = []integration.ProbeDir{
		{OS: integration.ProbeUnix, Rel: "go/bin"},
		{OS: integration.ProbeUnix, Rel: "/usr/local/go/bin", Abs: true},
		{OS: integration.ProbeWindows, Rel: "go/bin"},
		{OS: integration.ProbeWindows, Rel: `C:\Program Files\Go\bin`, Abs: true},
	}
	pyProbes = []integration.ProbeDir{
		{OS: integration.ProbeUnix, Rel: ".local/bin"},
		{OS: integration.ProbeWindows, Rel: `AppData\Roaming\Python\Scripts`},
	}
	sevHML = map[string]secfinding.Severity{
		"HIGH": policy.FindingSeverityHigh, "MEDIUM": policy.FindingSeverityMedium, "LOW": policy.FindingSeverityLow,
	}
	confHML = map[string]secfinding.Confidence{
		"HIGH": policy.FindingConfidenceHigh, "MEDIUM": policy.FindingConfidenceMedium, "LOW": policy.FindingConfidenceLow,
	}
)

// templates is the built-in template table. CodeQL is not a row: its
// analysis is two programs (database create, then analyze), and a manifest
// runs exactly one argv (recorded as a D3 decision; it returns when the
// protocol gains a reviewed two-step shape).
var templates = []Template{
	{
		ID:    "gosec",
		Title: "gosec (Go security checker)",
		Binary: integration.BinaryResolveSpec{
			Names: integration.BinaryNames{Unix: []string{"gosec"}, Windows: []string{"gosec.exe"}}, ProbeDirs: goProbes,
		},
		Companions: []TemplateCompanion{{
			Binary:        integration.BinaryResolveSpec{Names: integration.BinaryNames{Unix: []string{"go"}, Windows: []string{"go.exe"}}, ProbeDirs: goProbes},
			OnPath:        true,
			VersionArgv:   []string{"version"},
			VersionFormat: "go",
		}},
		Engine: extrun.Engine{Name: "gosec", OwnHome: true, Locale: "C.UTF-8"},
		Note:   "gosec needs the go toolchain it was built for: with no go companion it writes an empty SARIF and exits 0, and gosec built with Go 1.26 silently drops three rules against Go 1.27 (JSP-12). The self-test catches both.",
		Manifest: Manifest{
			Schema: SchemaV1, Name: "gosec", Version: "2.29.0", Template: "gosec",
			Argv:  []string{"-fmt", "sarif", "-out", PlaceholderOutput, "-no-fail", "-quiet", "./..."},
			Input: InputStdin, Output: OutputSARIFFile,
			Limits: Limits{WallSeconds: 600, MemoryMiB: 2048, CPUSeconds: 600, OutputMiB: 32, ChildProcesses: 64, FileMiB: 256},
			Env:    []string{"GOTOOLCHAIN=local", "GOPROXY=off", "GOFLAGS=-mod=mod", "GOWORK=off"},
			Cache:  CachePerDriver,
			SelfTest: &SelfTest{
				Fixture: "go-basic", ExpectRules: []string{"G101", "G401", "G703"},
			},
			UnknownStderr: []string{"skipping SSA analysis"},
			// -no-fail: 0 with or without findings (read the SARIF); 1 is an
			// error.
			ExitCodes: []ExitCode{{0, extrun.ExitResult}, {1, extrun.ExitFailure}},
			Network:   Network{Mode: NetworkNone},
			Category:  string(policy.FindingCodeVuln),
			// gosec sets every result's level to error and puts its
			// severity in the rule's tags (JSP-12).
			Severity:   SeverityMap{Source: SeverityRuleTag, Levels: sevHML},
			Confidence: ConfidenceMap{Source: ConfidenceFixed, Fixed: policy.FindingConfidenceMedium},
		},
	},
	{
		ID:    "bandit",
		Title: "Bandit (Python security linter)",
		Binary: integration.BinaryResolveSpec{
			Names: integration.BinaryNames{Unix: []string{"bandit"}, Windows: []string{"bandit.exe"}}, ProbeDirs: pyProbes,
		},
		Companions:  []TemplateCompanion{{FromShebang: true}},
		Interpreted: true,
		Engine:      extrun.Engine{Name: "bandit", Locale: "C.UTF-8"},
		Note:        "Bandit is a Python launcher script: the pin covers the launcher and its interpreter, not the installed package tree, so it is labelled partial. Bandit needs its sarif extra (pip install \"bandit[sarif]\").",
		Manifest: Manifest{
			Schema: SchemaV1, Name: "bandit", Version: "1.9.4", Template: "bandit",
			Argv:  []string{"-r", PlaceholderProject, "-f", "sarif", "-o", PlaceholderOutput, "-q"},
			Input: InputStdin, Output: OutputSARIFFile,
			Limits: Limits{WallSeconds: 300, MemoryMiB: 1024, CPUSeconds: 300, OutputMiB: 16, ChildProcesses: 64, FileMiB: 64},
			Env:    []string{"PYTHONDONTWRITEBYTECODE=1"},
			Cache:  CacheNone,
			SelfTest: &SelfTest{
				Fixture: "python-basic", ExpectRules: []string{"B105", "B324", "B602"},
			},
			// 0 nothing found, 1 issues found (a result), 2 a usage error.
			ExitCodes: []ExitCode{{0, extrun.ExitResult}, {1, extrun.ExitFindings}, {2, extrun.ExitFailure}},
			Network:   Network{Mode: NetworkNone},
			Category:  string(policy.FindingCodeVuln),
			// Bandit omits level for medium and carries its grading in
			// result properties (JSP-12).
			Severity:   SeverityMap{Source: SeverityResultProperty, Property: "issue_severity", Levels: sevHML},
			Confidence: ConfidenceMap{Source: ConfidenceResultProperty, Property: "issue_confidence", Levels: confHML},
		},
	},
	{
		ID:    "semgrep",
		Title: "Semgrep (public registry rules)",
		Binary: integration.BinaryResolveSpec{
			Names: integration.BinaryNames{Unix: []string{"semgrep"}, Windows: []string{"semgrep.exe"}}, ProbeDirs: pyProbes,
		},
		Companions:  []TemplateCompanion{{FromShebang: true}},
		Interpreted: true,
		Engine:      extrun.Engine{Name: "semgrep", OwnHome: true, Locale: "C.UTF-8"},
		Note:        "Semgrep fetches its rules from semgrep.dev, so the run needs the network and cannot run isolated; a subscription's private rules need a login token, which a manifest never carries. It has no self-test, so a run with no findings is unknown, never clean.",
		Manifest: Manifest{
			Schema: SchemaV1, Name: "semgrep", Version: "1", Template: "semgrep",
			Argv:  []string{"scan", "--config", "p/default", "--sarif", "--output", PlaceholderOutput, "--metrics", "off", "--disable-version-check", "--quiet", PlaceholderProject},
			Input: InputStdin, Output: OutputSARIFFile,
			Limits: Limits{WallSeconds: 600, MemoryMiB: 2048, CPUSeconds: 600, OutputMiB: 32, ChildProcesses: 64, FileMiB: 256},
			Env:    []string{"SEMGREP_SEND_METRICS=off", "SEMGREP_ENABLE_VERSION_CHECK=0"},
			Cache:  CachePerDriver,
			// 0 completed (findings in the SARIF), 1 findings with --error;
			// anything else is a Semgrep error.
			ExitCodes:  []ExitCode{{0, extrun.ExitResult}, {1, extrun.ExitFindings}},
			Network:    Network{Mode: NetworkHosts, Hosts: []string{"semgrep.dev"}},
			Category:   string(policy.FindingCodeVuln),
			Severity:   SeverityMap{Source: SeverityLevel, Levels: map[string]secfinding.Severity{"error": policy.FindingSeverityHigh, "warning": policy.FindingSeverityMedium, "note": policy.FindingSeverityLow}},
			Confidence: ConfidenceMap{Source: ConfidenceFixed, Fixed: policy.FindingConfidenceMedium},
		},
	},
}

// Templates returns the built-in templates in display order.
func Templates() []Template {
	out := make([]Template, len(templates))
	copy(out, templates)
	return out
}

// TemplateByID returns one built-in template.
func TemplateByID(id string) (Template, bool) {
	for _, t := range templates {
		if t.ID == id {
			return t, true
		}
	}
	return Template{}, false
}

// EngineFor is the runner profile of a manifest: its template's engine
// when it came from one, else the strict default (a UTF-8 locale; its own
// home and cache when it asked for a cache). The exit-code table is always
// the manifest's.
func EngineFor(m Manifest) extrun.Engine {
	e := extrun.Engine{Name: "custom:" + m.Name, Locale: "C.UTF-8"}
	if t, ok := TemplateByID(m.Template); ok {
		e = t.Engine
	}
	e.OwnHome = m.Cache == CachePerDriver
	e.ExitCodes = m.ExitTable()
	return e
}

//go:embed fixtures
var fixtureFS embed.FS

// fixtureIDs are the built-in self-test fixtures.
var fixtureIDs = []string{"go-basic", "python-basic"}

// Fixture is one planted self-test project: relative path to content.
type Fixture map[string][]byte

// fixtureByID returns a fixture's files. They are stored with a ".txt"
// suffix (so the Go fixture is not a package of this module) and returned
// under their real names.
func fixtureByID(id string) (Fixture, bool) {
	found := false
	for _, f := range fixtureIDs {
		found = found || f == id
	}
	if !found {
		return nil, false
	}
	out := Fixture{}
	root := path.Join("fixtures", id)
	err := fs.WalkDir(fixtureFS, root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := fixtureFS.ReadFile(p)
		if err != nil {
			return err
		}
		out[strings.TrimSuffix(strings.TrimPrefix(p, root+"/"), ".txt")] = b
		return nil
	})
	return out, err == nil && len(out) > 0
}

// FixtureFiles returns a self-test fixture's files and their sorted paths.
func FixtureFiles(id string) (Fixture, []string, bool) {
	f, ok := fixtureByID(id)
	if !ok {
		return nil, nil, false
	}
	paths := make([]string, 0, len(f))
	for p := range f {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	return f, paths, true
}
