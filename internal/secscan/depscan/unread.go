package depscan

import (
	"bufio"
	"bytes"
	"encoding/json"
	"path"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"
)

// The gap reasons of a dependency file the run did not read (DecideUnread).
const (
	// ReasonNoExtractor: a known dependency file that no extractor in this
	// build reads, so its packages were not checked and the run is
	// partial, never clean.
	ReasonNoExtractor = "no_extractor"
	// ReasonNeedsOnline: a dependency file only the online lookup can check
	// (git submodules: their pinned commits; no offline database carries
	// them), so an offline run left it unchecked. A scan with online
	// checks (`observer security scan --online`, or the dashboard scan
	// dialog's "Also check online"), with their consent, checks it.
	ReasonNeedsOnline = "needs_online_lookup"
	// ReasonNoAdvisoryData: a dependency file of an ecosystem no
	// vulnerability database covers and the online lookup cannot map to
	// upstream releases (Conan, vcpkg: spike CPP-0), so its packages are
	// not checked at all.
	ReasonNoAdvisoryData = "no_advisory_data"
	// ReasonNoDatabaseOffered: osv-scanner read a dependency file of an
	// ecosystem Observer downloads no database for, so its packages were
	// not matched (osvscanner.MissingDatabases).
	ReasonNoDatabaseOffered = "no_database_offered"
)

// DepFile is one row of the dependency-file table as the facade's coverage
// probe reads it: a dependency file some ecosystem's tooling resolves
// packages from, which the run must read or report as a gap.
type DepFile struct {
	// Pattern is a path.Match pattern over the file's base name or, when it
	// holds a slash, over as many trailing path segments
	// ("gradle/libs.versions.toml").
	Pattern   string
	Ecosystem string
	// Online: only the online lookup can check the file; an offline run
	// reports it ReasonNeedsOnline.
	Online bool
	// NoAdvisoryData: no database covers the ecosystem and the online
	// lookup cannot map it either, so the file is reported
	// ReasonNoAdvisoryData whatever the run.
	NoAdvisoryData bool
	// AdvisoriesPublished: a vulnerability database publishes advisories
	// for the ecosystem but this build cannot read its files (no reader, or
	// no version ordering). The run's gap reason stays ReasonNoExtractor.
	AdvisoriesPublished bool
	// Lockfiles are path.Match patterns over the name of a file in the
	// file's directory or any directory above it (up to the project root)
	// that resolves its dependencies; LockPaths are paths below such a
	// directory that do ("gradle/verification-metadata.xml"). When one is
	// present the file is not reported: the lockfile is read, or is itself
	// a row of this table and reported in its place.
	Lockfiles []string
	LockPaths []string
	// Lockfile: the file is itself a resolved set (a lockfile, a restore
	// output). Its Lockfiles only stand in for it; a missing one never
	// makes it "no lockfile", which is a manifest's reason.
	Lockfile bool
	// CheckContent: the file's body decides whether it declares anything
	// to check (DepFileDeclares); otherwise its name alone does.
	CheckContent bool
}

// depFile is a table row with its content check (nil: the name decides).
type depFile struct {
	DepFile
	declares func([]byte) bool
}

// gradleLocks are what resolves a Gradle build: its lockfiles, and the
// dependency verification file, which lists every resolved artifact.
var (
	gradleLockfiles = []string{"gradle.lockfile", "buildscript-gradle.lockfile"}
	gradleLockPaths = []string{"gradle/verification-metadata.xml"}
)

// depFiles is the dependency-file table, walked top-down (the first row
// whose pattern matches decides). A file the facade's extractor table
// reads is never reported, so a row stops being a gap by itself once an
// extractor for it is linked. A manifest the lockedManifests table owns
// (Cargo.toml, pyproject.toml, package.json, Gemfile, gems.rb,
// composer.json) is never a row here: that table reports it.
var depFiles = []depFile{
	// Dart and Flutter.
	{DepFile: DepFile{Pattern: "pubspec.lock", Ecosystem: "Pub", Lockfile: true}},
	{DepFile: DepFile{Pattern: "pubspec.yaml", Ecosystem: "Pub", Lockfiles: []string{"pubspec.lock"}, CheckContent: true}, declares: pubspecDeclares},
	// Swift: Swift Package Manager and CocoaPods.
	{DepFile: DepFile{Pattern: "Package.resolved", Ecosystem: "SwiftURL", Lockfile: true}},
	{DepFile: DepFile{Pattern: "Package.swift", Ecosystem: "SwiftURL", Lockfiles: []string{"Package.resolved"}, CheckContent: true}, declares: swiftPackageDeclares},
	{DepFile: DepFile{Pattern: "Podfile.lock", Ecosystem: "CocoaPods", NoAdvisoryData: true, Lockfile: true}},
	{DepFile: DepFile{Pattern: "Podfile", Ecosystem: "CocoaPods", NoAdvisoryData: true, Lockfiles: []string{"Podfile.lock"}, CheckContent: true}, declares: podfileDeclares},
	// Elixir and Erlang (Hex).
	{DepFile: DepFile{Pattern: "mix.lock", Ecosystem: "Hex", Lockfile: true}},
	{DepFile: DepFile{Pattern: "mix.exs", Ecosystem: "Hex", Lockfiles: []string{"mix.lock"}, CheckContent: true}, declares: mixDeclares},
	{DepFile: DepFile{Pattern: "rebar.lock", Ecosystem: "Hex", Lockfile: true}},
	{DepFile: DepFile{Pattern: "rebar.config", Ecosystem: "Hex", Lockfiles: []string{"rebar.lock"}, CheckContent: true}, declares: rebarDeclares},
	// Haskell.
	{DepFile: DepFile{Pattern: "cabal.project.freeze", Ecosystem: "Hackage", Lockfile: true}},
	{DepFile: DepFile{Pattern: "stack.yaml.lock", Ecosystem: "Hackage", Lockfile: true}},
	{DepFile: DepFile{Pattern: "*.cabal", Ecosystem: "Hackage", Lockfiles: []string{"cabal.project.freeze", "stack.yaml.lock"}, CheckContent: true}, declares: cabalDeclares},
	// Julia.
	{DepFile: DepFile{Pattern: "Manifest.toml", Ecosystem: "Julia", Lockfile: true, CheckContent: true}, declares: juliaManifestDeclares},
	{DepFile: DepFile{Pattern: "JuliaManifest.toml", Ecosystem: "Julia", Lockfile: true, CheckContent: true}, declares: juliaManifestDeclares},
	{DepFile: DepFile{Pattern: "Manifest-v*.toml", Ecosystem: "Julia", Lockfile: true, CheckContent: true}, declares: juliaManifestDeclares},
	{DepFile: DepFile{Pattern: "Project.toml", Ecosystem: "Julia", Lockfiles: []string{"Manifest.toml", "JuliaManifest.toml", "Manifest-v*.toml"}, CheckContent: true}, declares: juliaProjectDeclares},
	// R.
	{DepFile: DepFile{Pattern: "renv.lock", Ecosystem: "CRAN", Lockfile: true}},
	{DepFile: DepFile{Pattern: "DESCRIPTION", Ecosystem: "CRAN", Lockfiles: []string{"renv.lock"}, CheckContent: true}, declares: rDescriptionDeclares},
	// OCaml.
	{DepFile: DepFile{Pattern: "*.opam.locked", Ecosystem: "opam", AdvisoriesPublished: true, Lockfile: true}},
	{DepFile: DepFile{Pattern: "*.opam", Ecosystem: "opam", AdvisoriesPublished: true, Lockfiles: []string{"*.opam.locked"}, CheckContent: true}, declares: opamDeclares},
	{DepFile: DepFile{Pattern: "opam", Ecosystem: "opam", AdvisoriesPublished: true, Lockfiles: []string{"*.opam.locked"}, CheckContent: true}, declares: opamDeclares},
	// Bun's binary lockfile (the text bun.lock is read).
	{DepFile: DepFile{Pattern: "bun.lockb", Ecosystem: "npm", Lockfile: true}},
	// Gradle. A build with no lockfile reads "no lockfile" once the
	// facade reads Gradle lockfiles (DecideUnread's lockfile_missing row).
	{DepFile: DepFile{Pattern: "gradle/verification-metadata.xml", Ecosystem: "Maven", Lockfile: true}},
	{DepFile: DepFile{Pattern: "gradle/libs.versions.toml", Ecosystem: "Maven", Lockfiles: gradleLockfiles, LockPaths: gradleLockPaths, CheckContent: true}, declares: versionCatalogDeclares},
	{DepFile: DepFile{Pattern: "build.gradle", Ecosystem: "Maven", Lockfiles: gradleLockfiles, LockPaths: gradleLockPaths, CheckContent: true}, declares: gradleDeclares},
	{DepFile: DepFile{Pattern: "build.gradle.kts", Ecosystem: "Maven", Lockfiles: gradleLockfiles, LockPaths: gradleLockPaths, CheckContent: true}, declares: gradleDeclares},
	{DepFile: DepFile{Pattern: "settings.gradle", Ecosystem: "Maven", Lockfiles: gradleLockfiles, LockPaths: gradleLockPaths, CheckContent: true}, declares: gradleDeclares},
	{DepFile: DepFile{Pattern: "settings.gradle.kts", Ecosystem: "Maven", Lockfiles: gradleLockfiles, LockPaths: gradleLockPaths, CheckContent: true}, declares: gradleDeclares},
	// .NET: central package management and the restore output.
	{DepFile: DepFile{Pattern: "Directory.Packages.props", Ecosystem: "NuGet", Lockfiles: []string{"packages.lock.json"}, CheckContent: true}, declares: cpmDeclares},
	{DepFile: DepFile{Pattern: "obj/project.assets.json", Ecosystem: "NuGet", Lockfiles: []string{"packages.lock.json"}, Lockfile: true}},
	// Checked only online (lane 4's `observer security scan --online`).
	{DepFile: DepFile{Pattern: ".gitmodules", Ecosystem: "GIT", Online: true, CheckContent: true}, declares: gitmodulesDeclares},
	{DepFile: DepFile{Pattern: "conan.lock", Ecosystem: "ConanCenter", NoAdvisoryData: true, Lockfile: true}},
	{DepFile: DepFile{Pattern: "conanfile.txt", Ecosystem: "ConanCenter", NoAdvisoryData: true, Lockfiles: []string{"conan.lock"}, CheckContent: true}, declares: conanTxtDeclares},
	{DepFile: DepFile{Pattern: "conanfile.py", Ecosystem: "ConanCenter", NoAdvisoryData: true, Lockfiles: []string{"conan.lock"}, CheckContent: true}, declares: conanPyDeclares},
	{DepFile: DepFile{Pattern: "vcpkg.json", Ecosystem: "vcpkg", NoAdvisoryData: true, CheckContent: true}, declares: vcpkgDeclares},
}

// DepFiles returns the dependency-file table's rows, in table order.
func DepFiles() []DepFile {
	out := make([]DepFile, 0, len(depFiles))
	for _, r := range depFiles {
		out = append(out, r.copyOut())
	}
	return out
}

func (r depFile) copyOut() DepFile {
	d := r.DepFile
	d.Lockfiles = append([]string(nil), r.Lockfiles...)
	d.LockPaths = append([]string(nil), r.LockPaths...)
	return d
}

// matchDepPattern reports whether rel (relative to the project root,
// forward slashes) matches a row pattern: over its base name, or over its
// last segments when the pattern holds a slash.
func matchDepPattern(pattern, rel string) bool {
	n := strings.Count(pattern, "/") + 1
	segs := strings.Split(rel, "/")
	if len(segs) < n {
		return false
	}
	ok, _ := path.Match(pattern, strings.Join(segs[len(segs)-n:], "/"))
	return ok
}

func depFileRow(rel string) (depFile, bool) {
	for _, r := range depFiles {
		if matchDepPattern(r.Pattern, rel) {
			return r, true
		}
	}
	return depFile{}, false
}

// DepFileFor returns the dependency-file row that rel (relative to the
// project root, forward slashes) matches, ok false when none does.
func DepFileFor(rel string) (DepFile, bool) {
	r, ok := depFileRow(rel)
	if !ok {
		return DepFile{}, false
	}
	return r.copyOut(), true
}

// DepFileDeclares reports whether a dependency file's body declares at
// least one dependency (or, for a name another tool may also use, is the
// kind of file its row means). A row with no content check, or a body
// that does not parse, declares: unknown is never treated as nothing to
// check. A path no row matches declares nothing.
func DepFileDeclares(rel string, body []byte) bool {
	r, ok := depFileRow(rel)
	if !ok {
		return false
	}
	if r.declares == nil {
		return true
	}
	return r.declares(body)
}

// UnreadFacts is what the coverage probe observed for one known dependency
// file. The zero value reads as a gap (no_extractor): a fact the probe did
// not establish never clears one.
type UnreadFacts struct {
	// Read: a linked extractor reads the file.
	Read bool
	// DeclaresNothing: the content check found nothing to check.
	DeclaresNothing bool
	// Locked: one of the row's lockfiles or lock paths is present in the
	// file's directory or above it.
	Locked bool
	// Online: the row is checked only by the online lookup.
	Online bool
	// NoAdvisoryData: the row's ecosystem has no advisory data anywhere.
	NoAdvisoryData bool
	// LockfileRead: a linked extractor reads one of the row's lockfiles, so
	// the file is a manifest whose lockfile is missing.
	LockfileRead bool
}

// unreadRule is one row of the unread-file table.
type unreadRule struct {
	Name string
	When func(UnreadFacts) bool
	// Reason is the gap reason; "" when the file is no gap.
	Reason string
}

// unreadRules is walked top-down; the first row that matches decides.
var unreadRules = []unreadRule{
	{Name: "read", When: func(f UnreadFacts) bool { return f.Read }},
	{Name: "declares_nothing", When: func(f UnreadFacts) bool { return f.DeclaresNothing }},
	{Name: "locked", When: func(f UnreadFacts) bool { return f.Locked }},
	{Name: "online_only", When: func(f UnreadFacts) bool { return f.Online }, Reason: ReasonNeedsOnline},
	{Name: "no_advisory_data", When: func(f UnreadFacts) bool { return f.NoAdvisoryData }, Reason: ReasonNoAdvisoryData},
	{Name: "lockfile_missing", When: func(f UnreadFacts) bool { return f.LockfileRead }, Reason: ReasonNoLockfile},
	{Name: "no_extractor", When: func(UnreadFacts) bool { return true }, Reason: ReasonNoExtractor},
}

// DecideUnread returns the gap reason of one known dependency file, ""
// when it is no gap.
func DecideUnread(f UnreadFacts) string {
	for _, r := range unreadRules {
		if r.When(f) {
			return r.Reason
		}
	}
	return ReasonNoExtractor
}

// UnreadRuleNames returns the unread-file table's rule names in order.
func UnreadRuleNames() []string {
	out := make([]string, 0, len(unreadRules))
	for _, r := range unreadRules {
		out = append(out, r.Name)
	}
	return out
}

// The content checks. Each is a cheap look at a capped body: enough to
// tell a file that declares dependencies from one that declares none (or
// is not the kind of file its name suggests), never a parser of the
// format.
var (
	pubspecDeps     = regexp.MustCompile(`(?m)^(?:dev_)?dependencies\s*:`)
	podfilePod      = regexp.MustCompile(`(?m)^\s*pod\s+['"]`)
	mixDepTuple     = regexp.MustCompile(`\{\s*:\w+\s*,\s*(?:"|path:|git:|github:|in_umbrella:)`)
	rebarDeps       = regexp.MustCompile(`\{\s*deps\s*,\s*\[\s*[^\]\s]`)
	cabalDepends    = regexp.MustCompile(`(?im)^\s*build-depends\s*:`)
	opamDepends     = regexp.MustCompile(`(?m)^\s*depends\s*:`)
	gradleDepsBlock = regexp.MustCompile(`\bdependencies\s*\{`)
	cpmVersion      = regexp.MustCompile(`(?i)<PackageVersion\b`)
	gitSubmodule    = regexp.MustCompile(`(?m)^\s*\[submodule\s`)
	conanRequires   = regexp.MustCompile(`(?m)^\s*\[(?:requires|tool_requires|build_requires|test_requires)\]\s*$`)
)

func pubspecDeclares(b []byte) bool      { return pubspecDeps.Match(b) }
func swiftPackageDeclares(b []byte) bool { return bytes.Contains(b, []byte(".package(")) }
func podfileDeclares(b []byte) bool      { return podfilePod.Match(b) }
func mixDeclares(b []byte) bool          { return mixDepTuple.Match(b) }
func rebarDeclares(b []byte) bool        { return rebarDeps.Match(b) }
func cabalDeclares(b []byte) bool        { return cabalDepends.Match(b) }
func opamDeclares(b []byte) bool         { return opamDepends.Match(b) }
func gradleDeclares(b []byte) bool       { return gradleDepsBlock.Match(b) }
func cpmDeclares(b []byte) bool          { return cpmVersion.Match(b) }
func gitmodulesDeclares(b []byte) bool   { return gitSubmodule.Match(b) }
func conanTxtDeclares(b []byte) bool     { return conanRequires.Match(b) }
func conanPyDeclares(b []byte) bool      { return bytes.Contains(b, []byte("requires")) }

// decodeTOML decodes a TOML body; ok false when it does not parse.
func decodeTOML(b []byte) (map[string]any, bool) {
	var doc map[string]any
	if _, err := toml.Decode(string(b), &doc); err != nil {
		return nil, false
	}
	return doc, true
}

// juliaProjectDeclares: a [deps] table with an entry.
func juliaProjectDeclares(b []byte) bool {
	doc, ok := decodeTOML(b)
	if !ok {
		return true
	}
	return nonEmpty(doc["deps"])
}

// juliaManifestDeclares: a Julia manifest (a julia_version or
// manifest_format key, or a deps table); another tool's Manifest.toml is
// not one.
func juliaManifestDeclares(b []byte) bool {
	doc, ok := decodeTOML(b)
	if !ok {
		return true
	}
	_, version := doc["julia_version"]
	_, format := doc["manifest_format"]
	return version || format || nonEmpty(doc["deps"])
}

// versionCatalogDeclares: a [libraries] or [plugins] table with an entry.
func versionCatalogDeclares(b []byte) bool {
	doc, ok := decodeTOML(b)
	if !ok {
		return true
	}
	return nonEmpty(doc["libraries"]) || nonEmpty(doc["plugins"])
}

// vcpkgDeclares: a manifest whose "dependencies" array has an entry.
func vcpkgDeclares(b []byte) bool {
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		return true
	}
	return nonEmpty(doc["dependencies"])
}

// rDescriptionDeclares: an R package DESCRIPTION (a Package: field) whose
// Depends, Imports or LinkingTo field names a package other than R itself.
func rDescriptionDeclares(b []byte) bool {
	fields := dcfFields(b)
	if strings.TrimSpace(fields["Package"]) == "" {
		return false
	}
	for _, f := range []string{"Depends", "Imports", "LinkingTo"} {
		for _, dep := range strings.Split(fields[f], ",") {
			name := strings.TrimSpace(dep)
			if i := strings.IndexAny(name, " (\t\n"); i >= 0 {
				name = name[:i]
			}
			if name != "" && name != "R" {
				return true
			}
		}
	}
	return false
}

// dcfFields reads a Debian-control-style body (R's DESCRIPTION): "Field:
// value" lines, a line that starts with white space continuing the field
// above.
func dcfFields(b []byte) map[string]string {
	out := map[string]string{}
	last := ""
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		if (line[0] == ' ' || line[0] == '\t') && last != "" {
			out[last] += "\n" + strings.TrimSpace(line)
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok || strings.ContainsAny(k, " \t") {
			last = ""
			continue
		}
		last = k
		out[k] = strings.TrimSpace(v)
	}
	return out
}
