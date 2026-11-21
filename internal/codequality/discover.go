package codequality

import (
	"path"
	"sort"
	"strings"
)

// ReportLocation is one place a project's own tooling writes a coverage
// report by default. RelPath is slash-separated and relative to the
// directory probed (the project root, or one of its immediate child
// directories). Format is what the location is expected to hold; the
// content decides (Sniff), so a coverage.txt that is not a Go profile is
// reported as unrecognized rather than misread.
type ReportLocation struct {
	RelPath string
	Format  Format
	// Writer names the tool that writes it there, shown on the page.
	Writer string
}

// ReportLocations is the closed table of default report locations, probed in
// order. It is deliberately the writers' DEFAULT output paths only: Observer
// never runs a project's tests, so a report written elsewhere is not found
// (the page says "no coverage report found" and lists these paths).
var ReportLocations = []ReportLocation{
	{RelPath: "coverage/lcov.info", Format: FormatLCOV, Writer: "Istanbul / nyc / c8 / Jest / Vitest"},
	{RelPath: "lcov.info", Format: FormatLCOV, Writer: "lcov, cargo-llvm-cov, coverage.py (coverage lcov)"},
	{RelPath: "coverage/cobertura-coverage.xml", Format: FormatCobertura, Writer: "Istanbul cobertura reporter"},
	{RelPath: "coverage.xml", Format: FormatCobertura, Writer: "coverage.py (coverage xml), pytest-cov"},
	{RelPath: "coverage.cobertura.xml", Format: FormatCobertura, Writer: "coverlet"},
	{RelPath: "cobertura.xml", Format: FormatCobertura, Writer: "gcovr, cargo-tarpaulin"},
	{RelPath: "target/site/jacoco/jacoco.xml", Format: FormatJaCoCo, Writer: "JaCoCo (Maven)"},
	{RelPath: "build/reports/jacoco/test/jacocoTestReport.xml", Format: FormatJaCoCo, Writer: "JaCoCo (Gradle)"},
	{RelPath: "coverage.out", Format: FormatGoCover, Writer: "go test -coverprofile"},
	{RelPath: "cover.out", Format: FormatGoCover, Writer: "go test -coverprofile"},
	{RelPath: "coverage.txt", Format: FormatGoCover, Writer: "go test -coverprofile (Codecov convention)"},
}

// Read caps. A report over MaxReportBytes is not read (Problem
// too_large); at most MaxReports reports are parsed per measurement; at
// most MaxChildDirs immediate child directories are probed, in name order.
const (
	MaxReportBytes = 64 << 20
	MaxReports     = 12
	MaxChildDirs   = 64
)

// skipChildDirs are immediate child directories never probed: dependency
// trees, VCS metadata and build caches hold other projects' reports.
var skipChildDirs = map[string]bool{
	"node_modules": true, "vendor": true, "third_party": true, "testdata": true,
	"dist": true, "build": true, "out": true, "target": true, "bin": true, "obj": true,
	"venv": true, "env": true, "__pycache__": true,
}

// ProbeChild reports whether an immediate child directory of a project
// root is probed for reports: not hidden, not a dependency or build tree.
func ProbeChild(name string) bool {
	if name == "" || strings.HasPrefix(name, ".") {
		return false
	}
	return !skipChildDirs[name]
}

// PlanProbes returns the slash-separated relative paths to probe: every
// ReportLocation under the root, then every ReportLocation under each
// probed child directory (children filtered by ProbeChild, sorted, capped
// at MaxChildDirs). The order is deterministic.
func PlanProbes(children []string) []string {
	var kids []string
	for _, c := range children {
		if ProbeChild(c) {
			kids = append(kids, c)
		}
	}
	sort.Strings(kids)
	if len(kids) > MaxChildDirs {
		kids = kids[:MaxChildDirs]
	}
	out := make([]string, 0, len(ReportLocations)*(1+len(kids)))
	seen := map[string]bool{}
	add := func(p string) {
		// A child named like a location's first element ("coverage" +
		// "lcov.info") yields a root location again: probe it once.
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	for _, loc := range ReportLocations {
		add(loc.RelPath)
	}
	for _, k := range kids {
		for _, loc := range ReportLocations {
			add(path.Join(k, loc.RelPath))
		}
	}
	return out
}
