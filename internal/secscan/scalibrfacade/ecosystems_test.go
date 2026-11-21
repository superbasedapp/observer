//go:build !sbo_omit_security_scan_scalibr

package scalibrfacade

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/semantic"

	"github.com/marmutapp/superbased-observer/internal/secscan/depscan"
)

// ecosystems_test.go pins the rows the 2026-11-06 coverage review added
// (Pub, SwiftURL, Hex, Hackage, Julia, CRAN; the .NET restored graph and
// central package management; the Gradle verification metadata and version
// catalog) against the synthetic tree under testdata/ecosystems, and the
// local matcher for each new ecosystem against tiny synthetic OSV records.

// pkgRow is the part of an inventory row the extraction test compares.
type pkgRow struct {
	Eco, Name, Version string
	Unpinned           bool
}

func extractEcosystems(t *testing.T) *Inventory {
	t.Helper()
	inv, err := Extract(context.Background(), filepath.Join("testdata", "ecosystems"), ExtractOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range inv.Statuses {
		if !s.OK {
			t.Errorf("extractor %s failed: %s %v", s.Extractor, s.Detail, s.Files)
		}
	}
	return inv
}

// rowsAt returns the rows extracted from one file, by name then version.
func rowsAt(inv *Inventory, rel string) (rows []pkgRow, extractors []string) {
	for _, p := range inv.Packages {
		if filepath.ToSlash(p.Path) != rel {
			continue
		}
		rows = append(rows, pkgRow{Eco: p.Ecosystem, Name: p.Name, Version: p.Version, Unpinned: p.Unpinned})
		if !slices.Contains(extractors, p.Extractor) {
			extractors = append(extractors, p.Extractor)
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Name != rows[j].Name {
			return rows[i].Name < rows[j].Name
		}
		return rows[i].Version < rows[j].Version
	})
	return rows, extractors
}

// TestNewEcosystemExtraction: each new extractor reads its fixture into
// rows with the OSV ecosystem spelling, the name and version the matcher
// compares, and the file's path relative to the root. A row with no
// version (a Swift branch pin, a Hex git dependency, a catalog library whose
// version a BOM gives, a CPM reference nothing resolves) stays in the
// inventory so depscan reports its file not pinned.
func TestNewEcosystemExtraction(t *testing.T) {
	inv := extractEcosystems(t)
	cases := []struct {
		path      string
		extractor string
		want      []pkgRow
	}{
		{"dart/pubspec.lock", "dart/pubspec", []pkgRow{
			{Eco: "Pub", Name: "http", Version: "1.2.2"},
			{Eco: "Pub", Name: "lints", Version: "4.0.0"},
		}},
		{"swift/Package.resolved", "swift/packageresolved", []pkgRow{
			{Eco: "SwiftURL", Name: "github.com/apple/swift-algorithms", Version: "1.2.0"},
			{Eco: "SwiftURL", Name: "github.com/apple/swift-numerics", Version: ""},
		}},
		{"elixir/mix.lock", "elixir/mixlock", []pkgRow{
			{Eco: "Hex", Name: "jason", Version: "1.4.4"},
			{Eco: "Hex", Name: "localdep", Version: ""},
		}},
		{"haskell/cabal/cabal.project.freeze", "haskell/cabal", []pkgRow{
			{Eco: "Hackage", Name: "aeson", Version: "2.2.3.0"},
			{Eco: "Hackage", Name: "base", Version: "4.19.1.0"},
			{Eco: "Hackage", Name: "text", Version: "2.1.1"},
		}},
		{"haskell/stack/stack.yaml.lock", "haskell/stacklock", []pkgRow{
			{Eco: "Hackage", Name: "acme-missiles", Version: "0.3"},
		}},
		{"julia/Manifest.toml", "julia/manifesttoml", []pkgRow{
			{Eco: "Julia", Name: "Dates", Version: "1.11.0"},
			{Eco: "Julia", Name: "JSON", Version: "0.21.4"},
		}},
		{"r/renv.lock", "r/renvlock", []pkgRow{
			{Eco: "CRAN", Name: "glue", Version: "1.8.0"},
		}},
		{"dotnet/Directory.Packages.props", "dotnet/nugetcpm", []pkgRow{
			{Eco: "NuGet", Name: "Nerdbank.GitVersioning", Version: "3.6.143"},
		}},
		{"dotnet/src/App/App.csproj", "dotnet/csproj", []pkgRow{
			{Eco: "NuGet", Name: "Dapper", Version: "2.1.35"},
			{Eco: "NuGet", Name: "FluentAssertions", Version: "6.*", Unpinned: true},
			{Eco: "NuGet", Name: "Newtonsoft.Json", Version: "13.0.3"},
			{Eco: "NuGet", Name: "Polly", Version: "7.2.4"},
			{Eco: "NuGet", Name: "Polly", Version: "8.4.1"},
			{Eco: "NuGet", Name: "Unresolved.Package", Version: ""},
			{Eco: "NuGet", Name: "serilog", Version: "3.1.1"},
			{Eco: "NuGet", Name: "xunit", Version: "2.9.0"},
		}},
		{"dotnet/src/App/obj/project.assets.json", "dotnet/projectassetsjson", []pkgRow{
			{Eco: "NuGet", Name: "Newtonsoft.Json", Version: "13.0.3"},
			{Eco: "NuGet", Name: "Serilog", Version: "3.1.1"},
			{Eco: "NuGet", Name: "Serilog.Sinks.Console", Version: "5.0.1"},
		}},
		{"gradle/gradle/verification-metadata.xml", "java/gradleverificationmetadataxml", []pkgRow{
			{Eco: "Maven", Name: "com.google.guava:failureaccess", Version: "1.0.2"},
			{Eco: "Maven", Name: "com.google.guava:guava", Version: "33.3.1-jre"},
		}},
		{"gradle/gradle/libs.versions.toml", "java/gradleversioncatalog", []pkgRow{
			{Eco: "Maven", Name: "androidx.compose.ui:ui", Version: ""},
			{Eco: "Maven", Name: "com.google.guava:guava", Version: "33.3.1-jre"},
			{Eco: "Maven", Name: "com.squareup.okhttp3:okhttp", Version: "4.+", Unpinned: true},
			{Eco: "Maven", Name: "org.apache.commons:commons-lang3", Version: "3.17.0"},
			{Eco: "Maven", Name: "org.junit.jupiter:junit-jupiter", Version: "[5.10,6.0)", Unpinned: true},
		}},
	}
	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			got, exs := rowsAt(inv, c.path)
			if !slices.Equal(got, c.want) {
				t.Errorf("rows %+v\nwant %+v", got, c.want)
			}
			if !slices.Equal(exs, []string{c.extractor}) {
				t.Errorf("extracted by %v, want only %s", exs, c.extractor)
			}
		})
	}
}

// TestProjectAssetsKeepsOnlyRestored: a target's "dependencies" values are
// what a package asked for (a minimum, or an interval), not what NuGet
// restored; only "Name/Version" keys of type package count.
func TestProjectAssetsKeepsOnlyRestored(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("testdata", "ecosystems", "dotnet", "src", "App", "obj", "project.assets.json"))
	if err != nil {
		t.Fatal(err)
	}
	got := restoredNuGetPackages(b)
	for _, k := range []string{"newtonsoft.json@13.0.3", "serilog@3.1.1", "serilog.sinks.console@5.0.1"} {
		if !got[k] {
			t.Errorf("%s: a restored package must be kept", k)
		}
	}
	for _, k := range []string{"serilog@3.0.0", "polly@[8.0.0, )", "lib@1.0.0"} {
		if got[k] {
			t.Errorf("%s: a requested minimum, an interval or a project reference is not a restored package", k)
		}
	}
	if len(restoredNuGetPackages([]byte("not json"))) != 0 {
		t.Error("a file that does not parse restores nothing")
	}
}

// TestCentralVersionsLookup: the nearest Directory.Packages.props wins and
// the walk stops there, a reference's own VersionOverride wins over it, and
// a project with no central file anywhere keeps an unpinned reference.
func TestCentralVersionsLookup(t *testing.T) {
	root := writeTree(t, map[string]string{
		"Directory.Packages.props":           `<Project><ItemGroup><PackageVersion Include="A" Version="1.0.0" /><PackageVersion Include="B" Version="5.0.0" /></ItemGroup></Project>`,
		"inner/Directory.Packages.props":     `<Project><ItemGroup><PackageVersion Include="a" Version="2.0.0" /></ItemGroup></Project>`,
		"inner/p/P.csproj":                   `<Project><ItemGroup><PackageReference Include="A" /><PackageReference Include="B" /><PackageReference Include="C" VersionOverride="[3.0.0]" /></ItemGroup></Project>`,
		"outer/Q.csproj":                     `<Project><ItemGroup><PackageReference Include="A"><Version>4.0.0</Version></PackageReference></ItemGroup></Project>`,
		"elsewhere/x/Directory.Build.props":  `<Project><ItemGroup><PackageReference Include="Z" Version="1.2.3" /></ItemGroup></Project>`,
		"elsewhere/x/Directory.Packages.txt": "not the central file",
	})
	inv := extractTree(t, root)
	want := map[string][]pkgRow{
		// inner's own file is the nearest: A resolves to 2.0.0 there, and B,
		// which only the root file lists, is not looked up past it.
		"inner/p/P.csproj": {
			{Eco: "NuGet", Name: "A", Version: "2.0.0"},
			{Eco: "NuGet", Name: "B", Version: ""},
			{Eco: "NuGet", Name: "C", Version: "3.0.0"},
		},
		"outer/Q.csproj":                    {{Eco: "NuGet", Name: "A", Version: "4.0.0"}},
		"elsewhere/x/Directory.Build.props": {{Eco: "NuGet", Name: "Z", Version: "1.2.3"}},
	}
	for rel, w := range want {
		got, _ := rowsAt(inv, rel)
		if !slices.Equal(got, w) {
			t.Errorf("%s: rows %+v, want %+v", rel, got, w)
		}
	}
}

// TestVersionShapes: the version strings that are not one version.
func TestVersionShapes(t *testing.T) {
	for _, c := range []struct {
		v            string
		nuget, maven bool
	}{
		{"1.2.3", false, false},
		{"13.0.3-beta1", false, false},
		{"[1.0,2.0)", true, true},
		{"(,1.0]", true, true},
		{"]1.0,2.0]", false, true},
		{"1.*", true, false},
		{"*", true, false},
		{"$(JsonVersion)", true, false},
		{"1.+", false, true},
		{"+", false, true},
		{"latest.release", false, true},
		{"", false, false},
	} {
		if got := nugetNotOneVersion(c.v); got != c.nuget {
			t.Errorf("NuGet %q: not one version %v, want %v", c.v, got, c.nuget)
		}
		if got := gradleNotOneVersion(c.v); got != c.maven {
			t.Errorf("catalog %q: not one version %v, want %v", c.v, got, c.maven)
		}
	}
	for in, want := range map[string]string{"[1.2.3]": "1.2.3", "[ 1.2.3 ]": "1.2.3", "[1.0,2.0)": "[1.0,2.0)", "[]": "[]", "1.2.3": "1.2.3"} {
		if got := exactNuGetVersion(in); got != want {
			t.Errorf("exactNuGetVersion(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestEveryMatchedEcosystemRoundTrips: for every ecosystem osvlocal
// matches, the canary PURL type maps back to exactly the OSV spelling the
// store, the canary table and the database directory use, and SCALIBR's
// semantic package has a comparator that parses the canary's version (a
// missing comparator would make osvlocal panic, as GitHub Actions did).
func TestEveryMatchedEcosystemRoundTrips(t *testing.T) {
	for _, eco := range depscan.Ecosystems() {
		if _, own := ownMatchers[eco]; own {
			continue
		}
		pt, ok := purlTypes[eco]
		if !ok {
			t.Errorf("%s: no PURL type, so no canary can be built", eco)
			continue
		}
		p := &extractor.Package{Name: "x", Version: "1.0.0", PURLType: pt}
		if got := string(p.Ecosystem().Ecosystem); got != eco {
			t.Errorf("PURL type %s maps to ecosystem %q, want %q", pt, got, eco)
		}
		c, _ := depscan.CanaryFor(eco)
		if _, err := semantic.Parse(strings.TrimPrefix(c.Version, "v"), eco); err != nil {
			t.Errorf("%s: SCALIBR cannot order the canary version %q: %v", eco, c.Version, err)
		}
	}
}

// TestCanaryFilesParse: osv-scanner reads the canary project with the same
// SCALIBR extractors the facade links, so every canary file must yield its
// ecosystem's canary here, or a broken parser would only show as a failed
// self-test on a live node.
func TestCanaryFilesParse(t *testing.T) {
	root := writeTree(t, depscan.CanaryFiles())
	inv := extractTree(t, root)
	for _, s := range inv.Statuses {
		if !s.OK {
			t.Errorf("extractor %s failed on the canary project: %s %v", s.Extractor, s.Detail, s.Files)
		}
	}
	for _, eco := range depscan.OSVScannerEcosystems() {
		c, _ := depscan.CanaryFor(eco)
		found := false
		for _, p := range inv.Packages {
			if p.Ecosystem == eco && p.Name == c.Name && strings.TrimPrefix(p.Version, "v") == strings.TrimPrefix(c.Version, "v") {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: canary %s %s not extracted from the canary project", eco, c.Name, c.Version)
		}
	}
}

// newEcoAdvisories are one synthetic OSV record per new ecosystem: it
// covers the fixture package matched below and that ecosystem's canary.
var newEcoAdvisories = map[string]struct {
	record string
	want   string // the fixture package the record matches
}{
	"Pub": {`{"id":"TEST-PUB-1","modified":"2026-01-01T00:00:00Z",
"affected":[{"package":{"ecosystem":"Pub","name":"http"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.2.3"}]}]}]}`, "http"},
	"SwiftURL": {`{"id":"TEST-SWIFT-1","modified":"2026-01-01T00:00:00Z",
"affected":[{"package":{"ecosystem":"SwiftURL","name":"github.com/apple/swift-algorithms"},"ranges":[{"type":"SEMVER","events":[{"introduced":"1.0.0"},{"fixed":"1.2.1"}]}]},
{"package":{"ecosystem":"SwiftURL","name":"github.com/apple/swift-nio-http2"},"ranges":[{"type":"SEMVER","events":[{"introduced":"1.0.0"},{"fixed":"1.19.2"}]}]}]}`, "github.com/apple/swift-algorithms"},
	"Hex": {`{"id":"TEST-HEX-1","modified":"2026-01-01T00:00:00Z",
"affected":[{"package":{"ecosystem":"Hex","name":"jason"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"1.0.0"},{"fixed":"1.4.5"}]}]},
{"package":{"ecosystem":"Hex","name":"plug"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"1.3.0"},{"fixed":"1.3.5"}]}]}]}`, "jason"},
	"Hackage": {`{"id":"TEST-HACKAGE-1","modified":"2026-01-01T00:00:00Z",
"affected":[{"package":{"ecosystem":"Hackage","name":"aeson"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0.4.0.0"},{"fixed":"2.2.4.0"}]}]}]}`, "aeson"},
	"Julia": {`{"id":"TEST-JULIA-1","modified":"2026-01-01T00:00:00Z",
"affected":[{"package":{"ecosystem":"Julia","name":"JSON"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"0.21.5"}]}]},
{"package":{"ecosystem":"Julia","name":"HTTP"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.10.17"}]}]}]}`, "JSON"},
	"CRAN": {`{"id":"TEST-CRAN-1","modified":"2026-01-01T00:00:00Z",
"affected":[{"package":{"ecosystem":"CRAN","name":"glue"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"1.0.0"},{"fixed":"1.8.1"}]}]},
{"package":{"ecosystem":"CRAN","name":"readxl"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0.1.0"},{"fixed":"1.3.0"}]}]}]}`, "glue"},
}

// TestMatchNewEcosystemsLocally: osvlocal, offline, matches each new
// ecosystem's fixture package and its canary against a one-record database
// under the ecosystem's OSV name, and nothing else of the ecosystem (the
// fixed boundary holds: aeson 2.2.3.0 is below 2.2.4.0, base and text are
// not named).
func TestMatchNewEcosystemsLocally(t *testing.T) {
	inv := extractEcosystems(t)
	for eco, adv := range newEcoAdvisories {
		t.Run(eco, func(t *testing.T) {
			db := t.TempDir()
			writeDB(t, db, eco, map[string]string{"TEST.json": adv.record})
			c, ok := depscan.CanaryFor(eco)
			if !ok {
				t.Fatalf("%s has no canary row", eco)
			}
			res, err := Match(context.Background(), inv, MatchRequest{
				Ecosystem: eco, Indices: indices(inv, eco), Canary: &Canary{Name: c.Name, Version: c.Version},
			}, MatchOptions{DBDir: db})
			if err != nil {
				t.Fatal(err)
			}
			if !res.CanaryHit {
				t.Errorf("canary %s %s did not match the record", c.Name, c.Version)
			}
			var names []string
			for _, v := range res.Vulns {
				names = append(names, inv.Packages[v.Index].Name)
			}
			if !slices.Equal(names, []string{adv.want}) {
				t.Errorf("matched %v, want [%s]", names, adv.want)
			}
		})
	}
}

// TestMatchUnorderableVersionFailsOneEcosystem: a CRAN version SCALIBR's
// comparator rejects makes osvlocal panic in semantic.MustParse; the facade
// turns that into a failed match of that ecosystem, never a crashed scan
// child.
func TestMatchUnorderableVersionFailsOneEcosystem(t *testing.T) {
	inv := extractTree(t, writeTree(t, map[string]string{
		"renv.lock": `{"Packages":{"glue":{"Package":"glue","Version":"1.8.x","Source":"Repository","Repository":"CRAN"}}}`,
	}))
	if len(inv.Packages) != 1 || inv.Packages[0].Version != "1.8.x" {
		t.Fatalf("inventory %+v", inv.Packages)
	}
	db := t.TempDir()
	writeDB(t, db, "CRAN", map[string]string{"TEST.json": newEcoAdvisories["CRAN"].record})
	_, err := Match(context.Background(), inv, MatchRequest{Ecosystem: "CRAN", Indices: indices(inv, "CRAN")}, MatchOptions{DBDir: db})
	if err == nil || errors.Is(err, ErrNoDatabase) {
		t.Fatalf("err = %v, want a match failure", err)
	}
}
