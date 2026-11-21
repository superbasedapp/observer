package osvshardkey

import "strings"

// names.go is the per-ecosystem table of WHICH name is hashed and at how
// many bits a set is published (RM-0 R1 and R2, plan section 13.11 items 1
// and 2). The publisher hashes every affected entry's package.name of the
// set's base ecosystem as the record writes it; the node must hash the
// name osvlocal compares against it (SCALIBR's osvutil.ParsePackage form)
// and, per section 13.11 item 1, the raw extractor name as well.

// NameRule is one base ecosystem's row.
type NameRule struct {
	// Base is the OSV base ecosystem, spelled as OSV spells it.
	Base string
	// DefaultBits is the prefix length the publisher uses for every set of
	// this base (RM-0's recommendation: median shard about 8 KB, p95 under
	// about 64 KB, floor 8). A set's descriptor carries its own bits, so a
	// change here is a new epoch of that set, never a format change.
	DefaultBits int
	// NodeName says which of a package's names the node hashes.
	NodeName string
}

// NameRules is THE table, one row per base ecosystem the publisher shards.
// The OS rows cover every release of the distribution (osvdb.OSReleases):
// RM-0 measured one release each (Debian 12, Ubuntu 24.04 LTS, Alpine
// v3.20, RHEL 9, Rocky 9) and the bits carry over to the others.
//
// The last six rows (Pub, SwiftURL, Hex, Hackage, Julia, CRAN) joined the
// mirror on 2026-11-06, sized by RM-0's rule from their exports of that
// day: 14 to 1,717 records over 10 to 168 names each, far under crates.io's
// 3,036 records at the floor, so all six sit at the floor of 8 bits (the
// estimated shard sizes are in docs/dependency-scanning.md, "Remote
// lookup", "The sets"). For all six SCALIBR v0.5.3 builds a PURL with no
// namespace, so the name osvlocal compares is the extractor's name itself
// and the node hashes that one spelling (osvshard.Spellings); Canon
// lower-cases it, as for every base.
var NameRules = []NameRule{
	{Base: "npm", DefaultBits: 13, NodeName: "the lockfile name; a scoped package carries its scope (@scope/name)"},
	{Base: "PyPI", DefaultBits: 10, NodeName: "the project name; Canon applies PEP 503 itself, so either spelling hashes alike"},
	{Base: "Go", DefaultBits: 9, NodeName: "the module path, raw AND as ParsePackage rebuilds it (SCALIBR v0.5.3 lower-cases a PURL namespace; SECP-43); the toolchain module go is stdlib"},
	{Base: "Maven", DefaultBits: 9, NodeName: "group:artifact (MavenName)"},
	{Base: "crates.io", DefaultBits: 8, NodeName: "the crate name"},
	{Base: "RubyGems", DefaultBits: 8, NodeName: "the gem name"},
	{Base: "Packagist", DefaultBits: 9, NodeName: "vendor/name"},
	{Base: "NuGet", DefaultBits: 9, NodeName: "the package id"},
	{Base: "GitHub Actions", DefaultBits: 8, NodeName: "owner/repo of the uses: reference (Canon lower-cases it, as the facade's matcher compares)"},
	{Base: "Debian", DefaultBits: 9, NodeName: "the dpkg SOURCE package name (OSPackageName)"},
	{Base: "Ubuntu", DefaultBits: 11, NodeName: "the dpkg SOURCE package name (OSPackageName)"},
	{Base: "Alpine", DefaultBits: 8, NodeName: "the apk origin (source) name (OSPackageName)"},
	{Base: "Red Hat", DefaultBits: 11, NodeName: "the BINARY rpm name (ParsePackage has no rpm source rule)"},
	{Base: "Rocky Linux", DefaultBits: 8, NodeName: "the BINARY rpm name (ParsePackage has no rpm source rule)"},
	{Base: "Pub", DefaultBits: 8, NodeName: "the package name, the pubspec.lock key"},
	{Base: "SwiftURL", DefaultBits: 8, NodeName: "the normalized repository location (github.com/apple/swift-nio), as the Package.resolved extractor writes it"},
	{Base: "Hex", DefaultBits: 8, NodeName: "the package name, the mix.lock key"},
	{Base: "Hackage", DefaultBits: 8, NodeName: "the package name"},
	{Base: "Julia", DefaultBits: 8, NodeName: "the package name, the Manifest.toml key (Canon lower-cases HTTP and its kin)"},
	{Base: "CRAN", DefaultBits: 8, NodeName: "the package name (renv.lock's Package)"},
}

// RuleFor returns base's row.
func RuleFor(base string) (NameRule, bool) {
	for _, r := range NameRules {
		if r.Base == base {
			return r, true
		}
	}
	return NameRule{}, false
}

// MavenName is the name a Maven package is hashed under: group and artifact
// joined by ':' (how ParsePackage joins a Maven PURL's namespace and name,
// and how OSV records spell it).
func MavenName(group, artifact string) string {
	if group == "" {
		return artifact
	}
	return group + ":" + artifact
}

// PackageFormat is an OS package database's format.
type PackageFormat string

// The OS package formats.
const (
	FormatDpkg PackageFormat = "dpkg"
	FormatApk  PackageFormat = "apk"
	FormatRPM  PackageFormat = "rpm"
)

// OSPackageName is the name an OS package is hashed under: for dpkg and apk
// the source package name when the database names one (osvlocal compares
// the source name ParsePackage substitutes), else the binary name; for rpm
// always the binary name. An unknown format hashes the binary name.
func OSPackageName(format PackageFormat, binary, source string) string {
	switch format {
	case FormatDpkg, FormatApk:
		if s := strings.TrimSpace(source); s != "" {
			return s
		}
	}
	return binary
}
