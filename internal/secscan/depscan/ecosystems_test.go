package depscan

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// ecosystems_test.go pins the depscan side of the 2026-11-06 coverage
// review's rows: the six new store ecosystems have canaries and canary
// files where osv-scanner reads them, a package two files report (a
// version catalog and the verification metadata, a project file and the
// restored graph) is one finding, and an unpinned or versionless row of
// the new files is a gap, never matched.

// TestNewEcosystemCanaries: every new ecosystem has a complete canary, and
// a canary file exactly where osv-scanner reads the ecosystem.
func TestNewEcosystemCanaries(t *testing.T) {
	files := CanaryFiles()
	for _, c := range []struct {
		eco, file string
	}{
		{"Pub", "pubspec.lock"},
		{"SwiftURL", "Package.resolved"},
		{"Hex", "mix.lock"},
		{"Hackage", "cabal.project.freeze"},
		{"CRAN", "renv.lock"},
		{"Julia", ""},
	} {
		can, ok := CanaryFor(c.eco)
		if !ok || can.Name == "" || can.Version == "" || can.Advisory == "" {
			t.Errorf("%s: canary row %+v incomplete", c.eco, can)
			continue
		}
		if OSVScannerReads(c.eco) != (c.file != "") {
			t.Errorf("%s: osv-scanner reads it %v, want %v", c.eco, OSVScannerReads(c.eco), c.file != "")
		}
		if c.file == "" {
			continue
		}
		body, ok := files[c.file]
		if !ok {
			t.Errorf("%s: no canary file %s", c.eco, c.file)
			continue
		}
		if !strings.Contains(body, can.Version) {
			t.Errorf("%s: canary file %s does not pin %s", c.eco, c.file, can.Version)
		}
	}
}

// TestSamePackageFromTwoFilesIsOneFinding: the finding's local key does
// not depend on the file or the extractor, so a package that a declared
// file and a resolved file both report stores as one finding.
func TestSamePackageFromTwoFilesIsOneFinding(t *testing.T) {
	pkgs := []Package{
		{Ecosystem: "Maven", Name: "com.google.guava:guava", Version: "33.3.1-jre", Path: "gradle/libs.versions.toml", Extractor: "java/gradleversioncatalog"},
		{Ecosystem: "Maven", Name: "com.google.guava:guava", Version: "33.3.1-jre", Path: "gradle/verification-metadata.xml", Extractor: "java/gradleverificationmetadataxml"},
		{Ecosystem: "NuGet", Name: "Newtonsoft.Json", Version: "13.0.3", Path: "src/App/App.csproj", Extractor: "dotnet/csproj"},
		{Ecosystem: "NuGet", Name: "Newtonsoft.Json", Version: "13.0.3", Path: "src/App/obj/project.assets.json", Extractor: "dotnet/projectassetsjson"},
	}
	var groups []Group
	for i, p := range pkgs {
		id := "GHSA-aaaa-bbbb-cccc"
		if p.Ecosystem == "NuGet" {
			id = "GHSA-dddd-eeee-ffff"
		}
		groups = append(groups, Group{Index: i, IDs: []string{id}, Primary: id, Severity: policy.FindingSeverityHigh})
	}
	fs, _ := Findings(FindingInput{Packages: pkgs, Groups: groups, RootHash: "root", DriverID: ScalibrID})
	if len(fs) != 4 {
		t.Fatalf("findings %d, want 4 rows before the store folds them", len(fs))
	}
	if fs[0].LocalKey != fs[1].LocalKey || fs[2].LocalKey != fs[3].LocalKey {
		t.Fatal("the same package and advisory from two files must share one local key")
	}
	if fs[0].LocalKey == fs[2].LocalKey {
		t.Fatal("two packages must not share a local key")
	}
}

// TestNewRowsThatAreNotPinnedAreGaps: the rows the new extractors leave
// with no version (a Swift branch pin, a Hex git dependency, a catalog
// library whose version a BOM gives, a CPM reference nothing resolves) and
// the ones the facade marks unpinned (a NuGet floating version, a catalog
// range) are dropped before matching and leave a gap.
func TestNewRowsThatAreNotPinnedAreGaps(t *testing.T) {
	pkgs := []Package{
		{Ecosystem: "SwiftURL", Name: "github.com/apple/swift-numerics", Path: "Package.resolved", Extractor: "swift/packageresolved"},
		{Ecosystem: "Hex", Name: "localdep", Path: "mix.lock", Extractor: "elixir/mixlock"},
		{Ecosystem: "Maven", Name: "androidx.compose.ui:ui", Path: "gradle/libs.versions.toml", Extractor: "java/gradleversioncatalog"},
		{Ecosystem: "NuGet", Name: "Unresolved.Package", Path: "App.csproj", Extractor: "dotnet/csproj"},
		{Ecosystem: "NuGet", Name: "FluentAssertions", Version: "6.*", Unpinned: true, Path: "App.csproj", Extractor: "dotnet/csproj"},
		{Ecosystem: "Maven", Name: "com.squareup.okhttp3:okhttp", Version: "4.+", Unpinned: true, Path: "gradle/libs.versions.toml", Extractor: "java/gradleversioncatalog"},
		{Ecosystem: "Pub", Name: "http", Version: "1.2.2", Path: "pubspec.lock", Extractor: "dart/pubspec"},
	}
	keep, dropped := Prepare(pkgs)
	if dropped["empty_version"] != 4 || dropped["unpinned_version"] != 2 {
		t.Fatalf("dropped %v, want 4 empty_version and 2 unpinned_version", dropped)
	}
	if len(keep) != 1 || len(keep["Pub"]) != 1 {
		t.Fatalf("kept %v, want only the pinned Pub package", keep)
	}
	for _, p := range pkgs[:6] {
		if r := dropRuleFor(p); r == nil || r.Gap != ReasonUnpinned {
			t.Errorf("%s %s: drop rule %+v, want a %s gap", p.Ecosystem, p.Name, r, ReasonUnpinned)
		}
	}
}
