package secfeed

import (
	"regexp"
	"strings"
)

// Ecosystem is the install gate's closed ecosystem vocabulary.
type Ecosystem string

// The ecosystems.
const (
	EcoNpm       Ecosystem = "npm"
	EcoPyPI      Ecosystem = "pypi"
	EcoGo        Ecosystem = "go"
	EcoCargo     Ecosystem = "cargo"
	EcoNuGet     Ecosystem = "nuget"
	EcoRubyGems  Ecosystem = "rubygems"
	EcoPackagist Ecosystem = "packagist"
)

// EcosystemSpec is one row of the ecosystem table.
type EcosystemSpec struct {
	Eco Ecosystem
	// OSV is the ecosystem's name in OSV records and queries.
	OSV string
	// PublicHost is the public default registry host, exact; a registry
	// address is public only when it is https on this host, default port,
	// no user info (IsPublicDefault).
	PublicHost string
	// MetadataHost is the host of the registry metadata API the online
	// client may ask (exists, first published).
	MetadataHost string
	// Normalize maps a name to the form the index and the cache key on.
	Normalize func(string) string
	// NearMissMin is the shortest name the near-miss check considers:
	// shorter names are one edit from too many others to say anything.
	NearMissMin int
}

var pep503 = regexp.MustCompile(`[-_.]+`)

func lower(s string) string { return strings.ToLower(s) }

// ecosystems is THE ecosystem table, one test case per row.
//
// The remote package lookup classifies names through this table and
// privname.go's classifier, so an OSV ecosystem with no row here has every
// name withheld from it. Maven, GitHub Actions, Pub, SwiftURL, Hex,
// Hackage, Julia and CRAN have no row on purpose (reviewed 2026-11-06): the
// registry configuration and environment the classifier reads do not prove
// one of their names public (Maven's reactor and local repository resolve
// before any remote; a private repository on github.com has an action's or
// a Swift package's shape; the Pub, Hex, Hackage and Julia extractors emit
// git and path packages under plain names; a private package manager is
// often configured under the repository name CRAN). Pub, Hex and CRAN
// lockfiles record each package's registry, so a classifier reading them
// could prove a name; none is built. docs/dependency-scanning.md, "Remote
// lookup", "Which ecosystems can send names", has the reasons and the
// honest options; a row is added only with a classifier that proves the
// name public.
var ecosystems = []EcosystemSpec{
	{Eco: EcoNpm, OSV: "npm", PublicHost: "registry.npmjs.org", MetadataHost: "registry.npmjs.org", Normalize: lower, NearMissMin: 4},
	{Eco: EcoPyPI, OSV: "PyPI", PublicHost: "pypi.org", MetadataHost: "pypi.org", Normalize: func(s string) string { return lower(pep503.ReplaceAllString(s, "-")) }, NearMissMin: 4},
	{Eco: EcoGo, OSV: "Go", PublicHost: "proxy.golang.org", MetadataHost: "proxy.golang.org", Normalize: func(s string) string { return s }, NearMissMin: 8},
	{Eco: EcoCargo, OSV: "crates.io", PublicHost: "crates.io", MetadataHost: "crates.io", Normalize: func(s string) string { return strings.ReplaceAll(lower(s), "_", "-") }, NearMissMin: 4},
	{Eco: EcoNuGet, OSV: "NuGet", PublicHost: "api.nuget.org", MetadataHost: "api.nuget.org", Normalize: lower, NearMissMin: 4},
	{Eco: EcoRubyGems, OSV: "RubyGems", PublicHost: "rubygems.org", MetadataHost: "rubygems.org", Normalize: lower, NearMissMin: 4},
	{Eco: EcoPackagist, OSV: "Packagist", PublicHost: "repo.packagist.org", MetadataHost: "repo.packagist.org", Normalize: lower, NearMissMin: 6},
}

// Ecosystems returns a copy of the ecosystem table.
func Ecosystems() []EcosystemSpec {
	out := make([]EcosystemSpec, len(ecosystems))
	copy(out, ecosystems)
	return out
}

// EcosystemOf returns the row for eco.
func EcosystemOf(eco Ecosystem) (EcosystemSpec, bool) {
	for _, e := range ecosystems {
		if e.Eco == eco {
			return e, true
		}
	}
	return EcosystemSpec{}, false
}

// EcosystemFromOSV maps an OSV ecosystem name to the table's id.
func EcosystemFromOSV(osv string) (Ecosystem, bool) {
	for _, e := range ecosystems {
		if e.OSV == osv {
			return e.Eco, true
		}
	}
	return "", false
}

// Normalize returns name in eco's index form, or "" for an unknown
// ecosystem.
func Normalize(eco Ecosystem, name string) string {
	e, ok := EcosystemOf(eco)
	if !ok {
		return ""
	}
	return e.Normalize(strings.TrimSpace(name))
}
