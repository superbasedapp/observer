package depscan

import (
	"slices"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/secscan"
)

// TestDepFileTable is one case per row of the dependency-file table: a
// path the row matches, its ecosystem and online flag, and for a row with
// a content check a body that declares and one that does not.
func TestDepFileTable(t *testing.T) {
	cases := []struct {
		pattern, rel, eco string
		online, lockfile  bool
		yes, no           string // content check bodies; "" = no check
	}{
		{"pubspec.lock", "app/pubspec.lock", "Pub", false, true, "", ""},
		{"pubspec.yaml", "app/pubspec.yaml", "Pub", false, false, "name: app\ndependencies:\n  http: ^1.0.0\n", "name: app\nenvironment:\n  sdk: '>=3.0.0'\n"},
		{"Package.resolved", "Package.resolved", "SwiftURL", false, true, "", ""},
		{"Package.swift", "Package.swift", "SwiftURL", false, false, `dependencies: [.package(url: "https://example.invalid/a.git", from: "1.0.0")]`, `let package = Package(name: "A")`},
		{"Podfile.lock", "ios/Podfile.lock", "CocoaPods", false, true, "", ""},
		{"Podfile", "ios/Podfile", "CocoaPods", false, false, "target 'App' do\n  pod 'Alamofire', '~> 5.0'\nend\n", "platform :ios, '15.0'\n"},
		{"mix.lock", "mix.lock", "Hex", false, true, "", ""},
		{"mix.exs", "mix.exs", "Hex", false, false, "defp deps do\n  [{:phoenix, \"~> 1.7\"}]\nend\n", "defp deps do\n  []\nend\n"},
		{"rebar.lock", "rebar.lock", "Hex", false, true, "", ""},
		{"rebar.config", "rebar.config", "Hex", false, false, "{deps, [{cowboy, \"2.10.0\"}]}.\n", "{deps, []}.\n"},
		{"cabal.project.freeze", "cabal.project.freeze", "Hackage", false, true, "", ""},
		{"stack.yaml.lock", "stack.yaml.lock", "Hackage", false, true, "", ""},
		{"*.cabal", "pkg/app.cabal", "Hackage", false, false, "library\n  build-depends: base >=4 && <5, text\n", "name: app\nversion: 0.1\n"},
		{"Manifest.toml", "Manifest.toml", "Julia", false, true, "julia_version = \"1.10.0\"\nmanifest_format = \"2.0\"\n", "[tool]\nname = \"other\"\n"},
		{"JuliaManifest.toml", "JuliaManifest.toml", "Julia", false, true, "manifest_format = \"2.0\"\n", "[tool]\nname = \"other\"\n"},
		{"Manifest-v*.toml", "Manifest-v1.11.toml", "Julia", false, true, "julia_version = \"1.11.0\"\n", "[tool]\nname = \"other\"\n"},
		{"Project.toml", "Project.toml", "Julia", false, false, "name = \"A\"\n[deps]\nJSON = \"682c06a0-de6a-54ab-a142-c8b1cf79cde6\"\n", "name = \"A\"\n"},
		{"renv.lock", "renv.lock", "CRAN", false, true, "", ""},
		{"DESCRIPTION", "DESCRIPTION", "CRAN", false, false, "Package: mypkg\nVersion: 0.1.0\nImports:\n    dplyr,\n    tidyr (>= 1.0)\n", "Package: mypkg\nVersion: 0.1.0\nDepends: R (>= 4.0)\n"},
		{"*.opam.locked", "app.opam.locked", "opam", false, true, "", ""},
		{"*.opam", "app.opam", "opam", false, false, "opam-version: \"2.0\"\ndepends: [\"dune\"]\n", "opam-version: \"2.0\"\n"},
		{"opam", "opam", "opam", false, false, "opam-version: \"2.0\"\ndepends: [\"dune\"]\n", "#!/bin/sh\necho hi\n"},
		{"bun.lockb", "bun.lockb", "npm", false, true, "", ""},
		{"gradle/verification-metadata.xml", "gradle/verification-metadata.xml", "Maven", false, true, "", ""},
		{"gradle/libs.versions.toml", "gradle/libs.versions.toml", "Maven", false, false, "[libraries]\nguava = \"com.google.guava:guava:33.0.0-jre\"\n", "[versions]\nkotlin = \"2.0.0\"\n"},
		{"build.gradle", "app/build.gradle", "Maven", false, false, "dependencies {\n  implementation 'com.google.guava:guava:33.0.0-jre'\n}\n", "plugins { id 'java' }\n"},
		{"build.gradle.kts", "build.gradle.kts", "Maven", false, false, "dependencies {\n  implementation(\"com.google.guava:guava:33.0.0-jre\")\n}\n", "plugins { java }\n"},
		{"settings.gradle", "settings.gradle", "Maven", false, false, "buildscript { dependencies { classpath 'a:b:1' } }\n", "rootProject.name = 'app'\ninclude 'lib'\n"},
		{"settings.gradle.kts", "settings.gradle.kts", "Maven", false, false, "buildscript { dependencies { classpath(\"a:b:1\") } }\n", "rootProject.name = \"app\"\n"},
		{"Directory.Packages.props", "Directory.Packages.props", "NuGet", false, false, "<Project><ItemGroup><PackageVersion Include=\"Newtonsoft.Json\" Version=\"13.0.3\" /></ItemGroup></Project>", "<Project></Project>"},
		{"obj/project.assets.json", "src/App/obj/project.assets.json", "NuGet", false, true, "", ""},
		{".gitmodules", ".gitmodules", "GIT", true, false, "[submodule \"third_party/zlib\"]\n\tpath = third_party/zlib\n", "\n"},
		{"conan.lock", "conan.lock", "ConanCenter", false, true, "", ""},
		{"conanfile.txt", "conanfile.txt", "ConanCenter", false, false, "[requires]\nzlib/1.3.1\n", "[generators]\nCMakeDeps\n"},
		{"conanfile.py", "conanfile.py", "ConanCenter", false, false, "def requirements(self):\n    self.requires(\"zlib/1.3.1\")\n", "class App:\n    pass\n"},
		{"vcpkg.json", "vcpkg.json", "vcpkg", false, false, `{"name":"app","dependencies":["zlib"]}`, `{"name":"app"}`},
	}
	covered := map[string]bool{}
	for _, c := range cases {
		t.Run(c.pattern, func(t *testing.T) {
			covered[c.pattern] = true
			row, ok := DepFileFor(c.rel)
			if !ok || row.Pattern != c.pattern || row.Ecosystem != c.eco || row.Online != c.online || row.Lockfile != c.lockfile {
				t.Fatalf("DepFileFor(%q) = %+v, %v; want pattern %q eco %q online %v lockfile %v", c.rel, row, ok, c.pattern, c.eco, c.online, c.lockfile)
			}
			if row.CheckContent != (c.yes != "") {
				t.Fatalf("row %q content check %v, case has bodies %v", c.pattern, row.CheckContent, c.yes != "")
			}
			if c.yes == "" {
				if !DepFileDeclares(c.rel, []byte("anything")) {
					t.Fatal("a row with no content check declares by its name")
				}
				return
			}
			if !DepFileDeclares(c.rel, []byte(c.yes)) {
				t.Errorf("declaring body read as nothing: %q", c.yes)
			}
			if DepFileDeclares(c.rel, []byte(c.no)) {
				t.Errorf("body with nothing to check read as declaring: %q", c.no)
			}
		})
	}
	for _, r := range DepFiles() {
		if !covered[r.Pattern] {
			t.Errorf("row %q has no test case", r.Pattern)
		}
	}
}

// TestDepFileNotMatched: a name no row knows, and a pattern with a slash
// that needs its directory, are not dependency files.
func TestDepFileNotMatched(t *testing.T) {
	for _, rel := range []string{"README.md", "libs.versions.toml", "project.assets.json", "src/verification-metadata.xml", "Cargo.toml", "package.json"} {
		if row, ok := DepFileFor(rel); ok {
			t.Errorf("DepFileFor(%q) = %+v, want no row", rel, row)
		}
	}
	if DepFileDeclares("README.md", []byte("x")) {
		t.Error("a path no row matches declares nothing")
	}
}

// TestDepFileUnparseableDeclares: a body that does not parse is taken to
// declare: unknown is never treated as nothing to check.
func TestDepFileUnparseableDeclares(t *testing.T) {
	for _, rel := range []string{"Project.toml", "Manifest.toml", "gradle/libs.versions.toml", "vcpkg.json"} {
		if !DepFileDeclares(rel, []byte("[[[ not parseable")) {
			t.Errorf("%s: an unparseable body must declare", rel)
		}
	}
}

// TestDepFilesDisjointFromManifests: a file is reported by exactly one
// table; the manifest table owns its names.
func TestDepFilesDisjointFromManifests(t *testing.T) {
	for _, name := range ManifestNames() {
		if row, ok := DepFileFor(name); ok {
			t.Errorf("%s is a manifest row and dependency-file row %q", name, row.Pattern)
		}
		if row, ok := DepFileFor("sub/" + name); ok {
			t.Errorf("sub/%s is a manifest row and dependency-file row %q", name, row.Pattern)
		}
	}
}

// TestDecideUnread is one case per row of the unread-file table, in table
// order, and the zero value.
func TestDecideUnread(t *testing.T) {
	cases := []struct {
		rule string
		f    UnreadFacts
		want string
	}{
		{"read", UnreadFacts{Read: true, Online: true, LockfileRead: true}, ""},
		{"declares_nothing", UnreadFacts{DeclaresNothing: true, Online: true}, ""},
		{"locked", UnreadFacts{Locked: true, Online: true, LockfileRead: true}, ""},
		{"online_only", UnreadFacts{Online: true, NoAdvisoryData: true, LockfileRead: true}, ReasonNeedsOnline},
		{"no_advisory_data", UnreadFacts{NoAdvisoryData: true, LockfileRead: true}, ReasonNoAdvisoryData},
		{"lockfile_missing", UnreadFacts{LockfileRead: true}, ReasonNoLockfile},
		{"no_extractor", UnreadFacts{}, ReasonNoExtractor},
	}
	var names []string
	for _, c := range cases {
		names = append(names, c.rule)
		if got := DecideUnread(c.f); got != c.want {
			t.Errorf("%s: DecideUnread(%+v) = %q, want %q", c.rule, c.f, got, c.want)
		}
	}
	if !slices.Equal(names, UnreadRuleNames()) {
		t.Fatalf("rules %v, cases %v: one case per row, in order", UnreadRuleNames(), names)
	}
}

// TestNewManifestRows: the manifest rows for npm, Ruby and PHP, with their
// lockfiles and content checks.
func TestNewManifestRows(t *testing.T) {
	cases := []struct {
		name, body string
		want       bool
	}{
		{"package.json", `{"name":"a","dependencies":{"left-pad":"^1.3.0"}}`, true},
		{"package.json", `{"name":"a","devDependencies":{"vite":"^5"}}`, true},
		{"package.json", `{"name":"a","peerDependencies":{"react":">=18"}}`, true},
		{"package.json", `{"name":"a","version":"1.0.0","workspaces":["web"]}`, false},
		{"package.json", `{"name":"a","dependencies":{}}`, false},
		{"package.json", `{"name":`, true},
		{"Gemfile", "source 'https://rubygems.org'\ngem 'rails', '~> 7.1'\n", true},
		{"Gemfile", "source 'https://rubygems.org'\ngemspec\n", true},
		{"Gemfile", "source 'https://rubygems.org'\n", false},
		{"gems.rb", "gem 'rack'\n", true},
		{"composer.json", `{"require":{"php":">=8.1","monolog/monolog":"^3.0"}}`, true},
		{"composer.json", `{"require-dev":{"phpunit/phpunit":"^10"}}`, true},
		{"composer.json", `{"require":{"php":">=8.1","ext-json":"*"}}`, false},
		{"composer.json", `{"require":`, true},
	}
	for _, c := range cases {
		if got := ManifestDeclares(c.name, []byte(c.body)); got != c.want {
			t.Errorf("ManifestDeclares(%s, %q) = %v, want %v", c.name, c.body, got, c.want)
		}
	}
	locks := map[string][]string{
		"package.json":  {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb"},
		"Gemfile":       {"Gemfile.lock", "gems.locked"},
		"gems.rb":       {"gems.locked", "Gemfile.lock"},
		"composer.json": {"composer.lock"},
	}
	ecos := map[string]string{"package.json": "npm", "Gemfile": "RubyGems", "gems.rb": "RubyGems", "composer.json": "Packagist"}
	for name, want := range locks {
		eco, got, ok := ManifestFor(name)
		if !ok || eco != ecos[name] {
			t.Errorf("ManifestFor(%s) = %q, %v", name, eco, ok)
		}
		for _, l := range want {
			if !IsLockfile(l, got) {
				t.Errorf("%s: %s is not one of its lockfiles %v", name, l, got)
			}
		}
	}
	if _, _, ok := ManifestFor("build.gradle"); ok {
		t.Error("build.gradle belongs to the dependency-file table, which can see gradle/verification-metadata.xml")
	}
}

// TestUnreadReasonWords: every new reason has words of its own.
func TestUnreadReasonWords(t *testing.T) {
	for _, r := range []string{ReasonNoExtractor, ReasonNeedsOnline, ReasonNoAdvisoryData, ReasonNoDatabaseOffered} {
		if w := ReasonWords(r); w == r || w == "" {
			t.Errorf("reason %q has no words", r)
		}
	}
	// The online words read right on the CLI and the dashboard alike
	// (dashboard CLI parity plan section 3): turn online checks on, then
	// scan with them; no terminal command, which would send a dashboard
	// reader away from the scan dialog's own option.
	if w := ReasonWords(ReasonNeedsOnline); !strings.Contains(w, "turn on online package checks") || !strings.Contains(w, "scan with online checks") || strings.Contains(w, "observer ") {
		t.Errorf("online words %q must say to turn online checks on and scan with them, in neither surface's own words", w)
	}
}

// TestUnreadGapIsNeverClean: a project whose only dependency file is a
// pubspec.lock reads "not scanned", one that adds a scanned Cargo.lock
// reads partial, and the Cargo.lock alone reads clean.
func TestUnreadGapIsNeverClean(t *testing.T) {
	cargo := EcoResult{Ecosystem: "crates.io", Outcome: EcoScanned, Packages: 1}
	pub := Gap{Ecosystem: "Pub", Path: "pubspec.lock", Reason: ReasonNoExtractor}
	cases := []struct {
		name string
		resp ChildResponse
		want secscan.Outcome
	}{
		{"only pubspec.lock", ChildResponse{Gaps: []Gap{pub}}, secscan.OutcomeNotScanned},
		{"pubspec.lock beside a scanned Cargo.lock", ChildResponse{Gaps: []Gap{pub}, Ecosystems: []EcoResult{cargo}}, secscan.OutcomeUnknown},
		{"Cargo.lock alone", ChildResponse{Ecosystems: []EcoResult{cargo}}, secscan.OutcomeClean},
		{"only online-only files", ChildResponse{Gaps: []Gap{{Ecosystem: "GIT", Path: ".gitmodules", Reason: ReasonNeedsOnline}}, Ecosystems: []EcoResult{cargo}}, secscan.OutcomeUnknown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, gaps := Finalize(c.resp)
			cov := Coverage(RunFacts{Ecosystems: out.Ecosystems, Gaps: gaps})
			if cov.Outcome != c.want {
				t.Fatalf("coverage %+v, want %s", cov, c.want)
			}
			if c.want != secscan.OutcomeClean && slices.Contains(cov.Scanned, "Pub") {
				t.Fatalf("scanned %v: an unread ecosystem is never scanned in full", cov.Scanned)
			}
		})
	}
}

// TestDepFileAdvisoryFlags pins which unread ecosystems carry which truth:
// no database publishes advisories (NoAdvisoryData), or one does but this
// build cannot read the files (AdvisoriesPublished).
func TestDepFileAdvisoryFlags(t *testing.T) {
	for _, tc := range []struct {
		file                     string
		noData, advisoriesPublic bool
	}{
		{"Podfile.lock", true, false},
		{"Podfile", true, false},
		{"app.opam", false, true},
		{"app.opam.locked", false, true},
		{"conan.lock", true, false},
		{"vcpkg.json", true, false},
	} {
		d, ok := DepFileFor(tc.file)
		if !ok {
			t.Fatalf("%s: no row", tc.file)
		}
		if d.NoAdvisoryData != tc.noData || d.AdvisoriesPublished != tc.advisoriesPublic {
			t.Errorf("%s: NoAdvisoryData=%v AdvisoriesPublished=%v", tc.file, d.NoAdvisoryData, d.AdvisoriesPublished)
		}
	}
}
