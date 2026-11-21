//go:build !sbo_omit_security_scan_scalibr

package scalibrfacade

import (
	"context"
	"errors"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/secscan/depscan"
)

// readSampleOverrides are the sample paths of a table row whose Files
// display string does not spell paths directly; every other row's samples
// are derived from its Files (tableSamples).
var readSampleOverrides = map[string][]string{
	".github/workflows/*.yml, *.yaml": {".github/workflows/ci.yml", ".github/workflows/ci.yaml"},
}

// tableSamples derives sample paths from a row's Files display string:
// each comma-separated name, a parenthetical dropped, "**" and "*" filled
// in ("node_modules/**/package.json" -> "node_modules/x/package.json").
func tableSamples(files string) []string {
	if o, ok := readSampleOverrides[files]; ok {
		return o
	}
	// A parenthetical note may itself hold commas ("project.assets.json
	// (the packages NuGet restored, transitive ones included)"), so the
	// notes go before the names are split.
	for {
		open := strings.Index(files, " (")
		if open < 0 {
			break
		}
		closeAt := strings.Index(files[open:], ")")
		if closeAt < 0 {
			files = files[:open]
			break
		}
		files = files[:open] + files[open+closeAt+1:]
	}
	var out []string
	for _, f := range strings.Split(files, ", ") {
		f = strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(f), "**", "x"), "*", "x")
		if f != "" {
			out = append(out, f)
		}
	}
	return out
}

// TestReadsEveryTableFile: the coverage helper answers true for every file
// each linked lockfile and manifest extractor claims, so a file stops
// being a gap by itself once its row is in the table. A row whose Files
// string derives no readable sample needs an entry in
// readSampleOverrides.
func TestReadsEveryTableFile(t *testing.T) {
	rows := 0
	for _, row := range extractorTable {
		if row.artifact != notArtifact {
			continue
		}
		rows++
		samples := tableSamples(row.info.Files)
		if len(samples) == 0 {
			t.Errorf("row %q derives no sample path", row.info.Files)
		}
		for _, s := range samples {
			if !Reads(s) {
				t.Errorf("row %s %q: Reads(%q) = false", row.info.Ecosystem, row.info.Files, s)
			}
		}
	}
	if rows == 0 {
		t.Fatal("no lockfile or manifest row in the table")
	}
	// Left out of the table on purpose (facade.go), artifacts read only
	// under turned-on folders, and names nothing reads.
	for _, rel := range []string{"Cargo.toml", "pyproject.toml", "bin/app", "lib/x.jar", "README.md", "rebar.lock", "bun.lockb"} {
		if Reads(rel) {
			t.Errorf("Reads(%q) = true", rel)
		}
	}
}

// TestCoverageLocksAreReadOrReported: every lockfile or lock path that
// clears a dependency file (the dependency-file table) or a manifest (the
// manifest table) is either read by this build or itself a row of the
// dependency-file table, so clearing a file never hides an unread one.
func TestCoverageLocksAreReadOrReported(t *testing.T) {
	check := func(owner, lock string) {
		sample := strings.ReplaceAll(lock, "*", "x")
		if Reads(sample) {
			return
		}
		if _, ok := depscan.DepFileFor(sample); ok {
			return
		}
		t.Errorf("%s: %q is neither read nor a dependency-file row", owner, lock)
	}
	for _, r := range depscan.DepFiles() {
		for _, l := range r.Lockfiles {
			check(r.Pattern, l)
		}
		for _, l := range r.LockPaths {
			check(r.Pattern, l)
		}
	}
	for _, name := range depscan.ManifestNames() {
		_, locks, _ := depscan.ManifestFor(name)
		for _, l := range locks {
			check(name, l)
		}
	}
}

// unreadBodies are declaring bodies for the content-checked rows.
var unreadBodies = map[string]string{
	"pubspec.yaml":              "name: app\ndependencies:\n  http: ^1.0.0\n",
	"Package.swift":             `dependencies: [.package(url: "https://example.invalid/a.git", from: "1.0.0")]`,
	"Podfile":                   "pod 'Alamofire', '~> 5.0'\n",
	"mix.exs":                   "defp deps do\n  [{:phoenix, \"~> 1.7\"}]\nend\n",
	"rebar.config":              "{deps, [{cowboy, \"2.10.0\"}]}.\n",
	"*.cabal":                   "library\n  build-depends: base, text\n",
	"Manifest.toml":             "julia_version = \"1.10.0\"\n",
	"JuliaManifest.toml":        "julia_version = \"1.10.0\"\n",
	"Manifest-v*.toml":          "julia_version = \"1.11.0\"\n",
	"Project.toml":              "name = \"A\"\n[deps]\nJSON = \"682c06a0-de6a-54ab-a142-c8b1cf79cde6\"\n",
	"DESCRIPTION":               "Package: mypkg\nImports: dplyr\n",
	"*.opam":                    "depends: [\"dune\"]\n",
	"opam":                      "depends: [\"dune\"]\n",
	"gradle/libs.versions.toml": "[libraries]\nguava = \"com.google.guava:guava:33.0.0-jre\"\n",
	"build.gradle":              "dependencies {\n  implementation 'a:b:1'\n}\n",
	"build.gradle.kts":          "dependencies {\n  implementation(\"a:b:1\")\n}\n",
	"settings.gradle":           "buildscript { dependencies { classpath 'a:b:1' } }\n",
	"settings.gradle.kts":       "buildscript { dependencies { classpath(\"a:b:1\") } }\n",
	"Directory.Packages.props":  "<Project><ItemGroup><PackageVersion Include=\"A\" Version=\"1.0.0\" /></ItemGroup></Project>",
	".gitmodules":               "[submodule \"third_party/zlib\"]\n\tpath = third_party/zlib\n",
	"conanfile.txt":             "[requires]\nzlib/1.3.1\n",
	"conanfile.py":              "self.requires(\"zlib/1.3.1\")\n",
	"vcpkg.json":                `{"name":"app","dependencies":["zlib"]}`,
}

// unreadSamplePath is a project path for a row's pattern.
func unreadSamplePath(pattern string) string {
	rel := strings.ReplaceAll(pattern, "*", "x")
	if pattern == "obj/project.assets.json" {
		return "src/App/" + rel
	}
	return rel
}

// wantUnreadReason is the reason a lone file of the row reads in this
// build: none once an extractor reads it, "needs the online lookup" for an
// online row, "no lockfile" for a manifest whose lockfile kind is read,
// else "no extractor".
func wantUnreadReason(row depscan.DepFile, rel string) string {
	switch {
	case Reads(rel):
		return ""
	case row.Online:
		return depscan.ReasonNeedsOnline
	case row.NoAdvisoryData:
		return depscan.ReasonNoAdvisoryData
	}
	if !row.Lockfile {
		for _, l := range row.Lockfiles {
			if Reads(path.Join(path.Dir(rel), strings.ReplaceAll(l, "*", "x"))) {
				return depscan.ReasonNoLockfile
			}
		}
	}
	return depscan.ReasonNoExtractor
}

// TestUnreadFilesPerRow: one case per row of the dependency-file table, a
// lone file of the row with a declaring body.
func TestUnreadFilesPerRow(t *testing.T) {
	for _, row := range depscan.DepFiles() {
		t.Run(row.Pattern, func(t *testing.T) {
			rel := unreadSamplePath(row.Pattern)
			body, ok := unreadBodies[row.Pattern]
			if row.CheckContent && !ok {
				t.Fatalf("row %q has a content check and no declaring body here", row.Pattern)
			}
			if !ok {
				body = "x\n"
			}
			gaps, err := UnreadFiles(context.Background(), writeTree(t, map[string]string{rel: body}), ExtractOptions{})
			if err != nil {
				t.Fatal(err)
			}
			want := wantUnreadReason(row, rel)
			if want == "" {
				if len(gaps) != 0 {
					t.Fatalf("gaps %+v: a file this build reads is no gap", gaps)
				}
				return
			}
			if len(gaps) != 1 || gaps[0] != (depscan.Gap{Ecosystem: row.Ecosystem, Path: rel, Reason: want}) {
				t.Fatalf("gaps %+v, want one %s gap of %s (%s)", gaps, row.Ecosystem, rel, want)
			}
		})
	}
	// Pinned for this build: Gradle lockfiles are read, so a lockless
	// build reads "no lockfile", never "no extractor".
	if got := wantUnreadReason(depscan.DepFile{Lockfiles: []string{"gradle.lockfile"}}, "build.gradle"); got != depscan.ReasonNoLockfile {
		t.Fatalf("lockless build.gradle reason %q", got)
	}
}

// gapRows spells gaps as "<ecosystem> <path> <reason>".
func gapRows(gaps []depscan.Gap) []string {
	out := make([]string, 0, len(gaps))
	for _, g := range gaps {
		out = append(out, g.Ecosystem+" "+g.Path+" "+g.Reason)
	}
	return out
}

// TestUnreadFilesLockedAndSkipped: a lockfile beside or above a manifest
// clears it (and is reported in its place when it is unread), a manifest
// that declares nothing is no gap, and skipped directories stay skipped.
// Built on files this build does not read (rebar, bun.lockb, opam), so
// another lane linking an extractor does not move it.
func TestUnreadFilesLockedAndSkipped(t *testing.T) {
	const deps = "{deps, [{cowboy, \"2.10.0\"}]}.\n"
	meta := "gradle/verification-metadata.xml"
	var metaGap []string
	if !Reads(meta) {
		metaGap = []string{"Maven " + meta + " " + depscan.ReasonNoExtractor}
	}
	cases := []struct {
		name  string
		files map[string]string
		skip  []string
		want  []string
	}{
		{"lockfile beside", map[string]string{"rebar.config": deps, "rebar.lock": "[]."}, nil, []string{"Hex rebar.lock no_extractor"}},
		{"lockfile above", map[string]string{"rebar.lock": "[].", "apps/a/rebar.config": deps}, nil, []string{"Hex rebar.lock no_extractor"}},
		{"lockfile below does not count", map[string]string{"rebar.config": deps, "apps/rebar.lock": "[]."}, nil, []string{"Hex apps/rebar.lock no_extractor", "Hex rebar.config no_extractor"}},
		{"declares nothing", map[string]string{"rebar.config": "{deps, []}.\n"}, nil, nil},
		{"lockless manifest", map[string]string{"sub/rebar.config": deps}, nil, []string{"Hex sub/rebar.config no_extractor"}},
		{"Gradle lockfile resolves the build", map[string]string{"build.gradle": "dependencies {\n}\n", "gradle.lockfile": "empty=\n"}, nil, nil},
		{"Gradle verification metadata resolves a nested build", map[string]string{"sub/build.gradle": "dependencies {\n}\n", meta: "<verification-metadata/>"}, nil, metaGap},
		{"lockless Gradle build", map[string]string{"build.gradle": "dependencies {\n}\n"}, nil, []string{"Maven build.gradle no_lockfile"}},
		{"skipped directories", map[string]string{
			"node_modules/x/rebar.lock": "[].", "vendor/y/app.opam.locked": "x", "a/vendor/b/bun.lockb": "x",
			".git/modules/z/bun.lockb": "x", "skipme/bun.lockb": "x", "skipme/deep/rebar.lock": "[].",
		}, []string{"skipme"}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := writeTree(t, c.files)
			var skips []string
			for _, s := range c.skip {
				skips = append(skips, filepath.Join(root, filepath.FromSlash(s)))
			}
			gaps, err := UnreadFiles(context.Background(), root, ExtractOptions{SkipDirs: skips})
			if err != nil {
				t.Fatal(err)
			}
			if got := gapRows(gaps); !slices.Equal(got, c.want) {
				t.Fatalf("gaps %v, want %v", got, c.want)
			}
		})
	}
}

// TestUnreadFilesOnlyPubspecLock: a project whose only dependency file is a
// pubspec.lock gets a gap for it (until an extractor reads it), so the run
// is never clean.
func TestUnreadFilesOnlyPubspecLock(t *testing.T) {
	gaps, err := UnreadFiles(context.Background(), writeTree(t, map[string]string{"pubspec.lock": "packages: {}\n"}), ExtractOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if Reads("pubspec.lock") {
		t.Skip("an extractor reads pubspec.lock in this build")
	}
	if got := gapRows(gaps); !slices.Equal(got, []string{"Pub pubspec.lock no_extractor"}) {
		t.Fatalf("gaps %v", got)
	}
}

// TestUnreadFilesInodeCap: the walk stops past its cap, with an error.
func TestUnreadFilesInodeCap(t *testing.T) {
	root := writeTree(t, map[string]string{"a/1": "x", "a/2": "x", "b/3": "x", "b/4": "x"})
	if _, err := UnreadFiles(context.Background(), root, ExtractOptions{MaxInodes: 2}); !errors.Is(err, errInodeCap) {
		t.Fatalf("err %v, want the inode cap", err)
	}
	if _, err := UnreadFiles(context.Background(), filepath.Join(root, "missing"), ExtractOptions{}); err == nil {
		t.Fatal("a root that cannot be read is an error, never no gap")
	}
}

// TestUnlockedManifestsNewRows: package.json, Gemfile and composer.json
// that declare dependencies with no lockfile beside or above them are
// reported by the facade's manifest probe; one with a lockfile, one that
// declares nothing and anything under node_modules are not.
func TestUnlockedManifestsNewRows(t *testing.T) {
	inv := extractTree(t, writeTree(t, map[string]string{
		"js/package.json":             `{"name":"js","dependencies":{"left-pad":"^1.3.0"}}`,
		"ws/yarn.lock":                "# yarn lockfile v1\n",
		"ws/web/package.json":         `{"name":"web","dependencies":{"left-pad":"^1.3.0"}}`,
		"nodeps/package.json":         `{"name":"nodeps","version":"1.0.0"}`,
		"node_modules/a/package.json": `{"name":"a","version":"1.0.0","dependencies":{"b":"^1"}}`,
		"bun/package.json":            `{"name":"bun","dependencies":{"left-pad":"^1.3.0"}}`,
		"bun/bun.lockb":               "x",
		"rb/Gemfile":                  "source 'https://rubygems.org'\ngem 'rack'\n",
		"rbok/Gemfile":                "gem 'rack'\n",
		"rbok/Gemfile.lock":           "GEM\n  remote: https://rubygems.org/\n  specs:\n\nPLATFORMS\n  ruby\n",
		"php/composer.json":           `{"require":{"php":">=8.1","monolog/monolog":"^3.0"}}`,
		"phpok/composer.json":         `{"require":{"monolog/monolog":"^3.0"}}`,
		"phpok/composer.lock":         `{"packages":[],"packages-dev":[]}`,
		"phpplat/composer.json":       `{"require":{"php":">=8.1"}}`,
	}))
	var got []string
	for _, m := range inv.Unlocked {
		got = append(got, m.Ecosystem+" "+m.Path)
	}
	want := []string{"npm js/package.json", "Packagist php/composer.json", "RubyGems rb/Gemfile"}
	if !slices.Equal(got, want) {
		t.Fatalf("unlocked %v, want %v", got, want)
	}
}

// TestLockedCargoStaysClean: a Cargo.toml with its Cargo.lock leaves no
// unlocked manifest and no unread file, so the run can still be clean.
func TestLockedCargoStaysClean(t *testing.T) {
	root := writeTree(t, map[string]string{
		"Cargo.toml": "[package]\nname = \"app\"\n[dependencies]\nserde = \"1\"\n",
		"Cargo.lock": "version = 3\n",
	})
	if inv := extractTree(t, root); len(inv.Unlocked) != 0 {
		t.Fatalf("unlocked %+v", inv.Unlocked)
	}
	gaps, err := UnreadFiles(context.Background(), root, ExtractOptions{})
	if err != nil || len(gaps) != 0 {
		t.Fatalf("gaps %+v err %v", gaps, err)
	}
}
