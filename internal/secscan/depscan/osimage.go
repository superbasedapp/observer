package depscan

import (
	"fmt"
	"sort"
	"strings"
)

// osimage.go is the pure core of route A of phase OS-2 (OS and CI
// vulnerability scanning plan sections 6.3 and 6.6.1, spike JSP-OS): an
// image's OS packages (dpkg, apk, rpm) matched against one release's
// stripped OSV export in the scan child. One image is one release, so an
// image run has exactly one ecosystem: the release's (an OSImageRequest's
// Ecosystem, "Debian:12", "Ubuntu:24.04:LTS"). It holds, as tables:
//
//   - the per-release canary table (a release with no row is "not
//     scanned: no_canary", never clean);
//   - the kernel rule (kernelRules): kernel packages are left out of the
//     match, counted and named;
//   - the release outcome table (DecideOSRelease) and the run notes.

// KindOSImage is ChildRequest.Kind for an image's OS packages.
const KindOSImage = "os_image"

// KindSBOM is ChildRequest.Kind for the packages an SBOM file lists
// (ChildRequest.Packages), matched without extraction.
const KindSBOM = "sbom"

// SBOMID is the driver id an SBOM-file run is recorded under: never
// ScalibrID, so a supplied SBOM never reads as the project's own scan in
// the coverage views (an empty SBOM proves nothing about the project).
const SBOMID = "sbom-import"

// OSImageRequest names the one release an image run matches.
type OSImageRequest struct {
	// Ecosystem is the release's OSV ecosystem label, the one findings and
	// coverage carry ("Debian:12", "Ubuntu:24.04:LTS", "Alpine:v3.20",
	// "Red Hat:enterprise_linux:9", "Rocky Linux:9").
	Ecosystem string `json:"ecosystem"`
	// Base is the OSV base ecosystem the release's file is linked under
	// ("Debian", "Ubuntu", "Alpine", "Red Hat", "Rocky Linux").
	Base string `json:"base"`
	// RPM: the release's packages come from an rpm database, which the
	// rpm extractor cannot read on Windows.
	RPM bool `json:"rpm,omitempty"`
	// Epoch is the installed release database's epoch ("" when none is
	// installed: the release is then not matched).
	Epoch string `json:"epoch,omitempty"`
}

// The OS image reasons (EcoResult.Reason and run reasons), beside the
// shared vocabulary in types.go.
const (
	// ReasonNoOSCanary: the release has no canary row, so no run can prove
	// its database loaded.
	ReasonNoOSCanary = "no_canary"
	// ReasonRPMOnWindows: an rpm-based release on a Windows node, where the
	// rpm extractor is not built (upstream `//go:build !windows`).
	ReasonRPMOnWindows = "not_supported_on_windows"
	// ReasonNoOSRelease: the image has no os-release, so its release (and
	// the database that answers for it) is unknown.
	ReasonNoOSRelease = "no_os_release"
	// ReasonDistroNotSupported: os-release names a distribution outside the
	// release table.
	ReasonDistroNotSupported = "distribution_not_supported"
	// ReasonReleaseNotSupported: a supported distribution's release outside
	// the release table (an Ubuntu interim release, an end-of-life one).
	ReasonReleaseNotSupported = "release_not_supported"
	// ReasonFeedUnavailable and ReasonReleaseNotPublished: the release's
	// database could not be fetched (the feed is unreachable or
	// unverifiable), or the feed publishes no file for the release.
	ReasonFeedUnavailable     = "feed_unavailable"
	ReasonReleaseNotPublished = "release_not_published"
	// ReasonOtherRelease: a gap, an OS package of another release.
	ReasonOtherRelease = "other_release_package"
	// ReasonImageEntryRefused: a gap, a package database in the image the
	// layer reader could not use (a link, an unresolved hard link).
	ReasonImageEntryRefused = "image_entry_refused"
	// ReasonNoImagePackages: the image holds no package database the OS
	// extractors read.
	ReasonNoImagePackages = "no_os_packages"
	// ReasonDatabaseLinkFailed: the release's export could not be linked
	// into the scan's run directory (never copied), so nothing ran.
	ReasonDatabaseLinkFailed = "database_link_failed"
)

// KernelDropRule is the drop rule that leaves kernel packages out.
const KernelDropRule = "kernel_package"

// OSCanary is one release's self-test package: a binary package (with its
// source or origin name) at a version a well-known advisory of the
// release's own data flags, matched in the same run; a database that does
// not flag it did not load, or the facade's ecosystem repair did not hold,
// so the release is not scanned.
type OSCanary struct {
	// Kind is the package database it stands for: "deb", "apk" or "rpm".
	Kind string
	// Name is the binary package name.
	Name string
	// Source is the dpkg source or apk origin name the matcher uses (""
	// for rpm, whose advisories name binary packages).
	Source  string
	Version string
	// Advisory is the advisory it is known for (documentation and tests).
	Advisory string
}

// osCanaries is the per-release canary table, keyed by the release's
// ecosystem label. Each row matched the release's stripped file in the
// JSP-OS spike (2026-11-04): Debian 12 libc6 (glibc) at deb12u2 by
// DSA-5514-1 (fixed in 2.36-9+deb12u3, which proves backports: deb12u3 is
// not flagged); Ubuntu 24.04 libpcre2-8-0 (pcre2) at 10.42-4ubuntu2.1 by
// USN-8974-1 (fixed in 10.42-4ubuntu2.2), the row that also proves the
// facade's ":LTS" repair, since SCALIBR's own "Ubuntu:24.04" matches
// nothing; Alpine 3.20 libcrypto3 (openssl) at 3.3.0-r0 by
// ALPINE-CVE-2024-5535 (fixed in 3.3.1-r1); RHEL 9 and Rocky 9 glib2 at
// 2.68.4-11.el9 by RHSA-2024:6464 and RLSA-2024:6464 (fixed in
// 2.68.4-14.el9_4.1). A release with no row reads "not scanned:
// no_canary" until the publisher lane grounds one against its file.
var osCanaries = map[string]OSCanary{
	"Debian:12":                  {Kind: "deb", Name: "libc6", Source: "glibc", Version: "2.36-9+deb12u2", Advisory: "DSA-5514-1"},
	"Ubuntu:24.04:LTS":           {Kind: "deb", Name: "libpcre2-8-0", Source: "pcre2", Version: "10.42-4ubuntu2.1", Advisory: "USN-8974-1"},
	"Alpine:v3.20":               {Kind: "apk", Name: "libcrypto3", Source: "openssl", Version: "3.3.0-r0", Advisory: "ALPINE-CVE-2024-5535"},
	"Red Hat:enterprise_linux:9": {Kind: "rpm", Name: "glib2", Version: "2.68.4-11.el9", Advisory: "RHSA-2024:6464"},
	"Rocky Linux:9":              {Kind: "rpm", Name: "glib2", Version: "2.68.4-11.el9", Advisory: "RLSA-2024:6464"},
}

// OSCanaryFor returns a release's canary.
func OSCanaryFor(ecosystem string) (OSCanary, bool) {
	c, ok := osCanaries[ecosystem]
	return c, ok
}

// OSCanaryEcosystems returns the releases that have a canary, sorted.
func OSCanaryEcosystems() []string { return SortedEcosystems(osCanaries) }

// IsOSPackage reports whether p came from an OS package extractor
// (SCALIBR's os/dpkg, os/apk, os/rpm).
func IsOSPackage(p Package) bool { return strings.HasPrefix(p.Extractor, "os/") }

// binaryName is an OS package's binary name.
func binaryName(p Package) string {
	if p.Binary != "" {
		return p.Binary
	}
	return p.Name
}

// kernelRule is one row of the kernel table: a package it matches is a
// kernel package.
type kernelRule struct {
	Name  string
	Match func(binary, source string) bool
}

func prefix(p string) func(string, string) bool {
	return func(b, _ string) bool { return strings.HasPrefix(b, p) }
}

// kernelRules: a container image runs its host's kernel, so its kernel
// headers, images and modules are not the image's vulnerabilities, and
// one of them (linux-libc-dev, source linux, about 10,000 kernel records)
// drove a stripped Ubuntu match past 3.5 GB (spike JSP-OS S6).
var kernelRules = []kernelRule{
	{Name: "linux-libc-dev", Match: func(b, _ string) bool { return b == "linux-libc-dev" }},
	{Name: "linux-headers-*", Match: prefix("linux-headers-")},
	{Name: "linux-image-*", Match: prefix("linux-image-")},
	{Name: "linux-modules-*", Match: prefix("linux-modules-")},
	{Name: "source linux", Match: func(_, s string) bool { return s == "linux" }},
	{Name: "kernel (rpm)", Match: func(b, _ string) bool { return b == "kernel" || strings.HasPrefix(b, "kernel-") }},
}

// KernelPackage reports whether an OS package is a kernel package
// (kernelRules); never true for a language package.
func KernelPackage(p Package) bool {
	if !IsOSPackage(p) {
		return false
	}
	b := binaryName(p)
	// Name is the match name: the source (or origin) when it differs from
	// the binary, else the binary itself.
	src := p.Name
	for _, r := range kernelRules {
		if r.Match(b, src) {
			return true
		}
	}
	return false
}

// KernelNotePrefix starts the run note naming the kernel packages left out.
const KernelNotePrefix = "Kernel packages"

// maxNamedKernel caps the names a kernel note lists.
const maxNamedKernel = 20

// KernelNote is the run note for the kernel packages of pkgs the drop table
// left out: their count and binary names (sorted, at most 20, "and N
// more"), "" when there are none. Never silent: a left-out package is
// always counted here.
func KernelNote(pkgs []Package) string {
	seen := map[string]bool{}
	for _, p := range pkgs {
		if KernelPackage(p) {
			seen[binaryName(p)] = true
		}
	}
	if len(seen) == 0 {
		return ""
	}
	names := SortedEcosystems(seen)
	more := ""
	if len(names) > maxNamedKernel {
		more = fmt.Sprintf(" and %d more", len(names)-maxNamedKernel)
		names = names[:maxNamedKernel]
	}
	n := 0
	for _, p := range pkgs {
		if KernelPackage(p) {
			n++
		}
	}
	noun := "kernel packages"
	if n == 1 {
		noun = "kernel package"
	}
	return fmt.Sprintf("%s: %d %s left out: a container does not run its own kernel (%s%s).", KernelNotePrefix, n, noun, strings.Join(names, ", "), more)
}

// The OS release notes' fixed prefixes (RunLabels reads them).
const (
	// FixedOnlyPrefix: the distribution publishes fixed issues only.
	FixedOnlyPrefix = "Fixed issues only"
	// KnownGapPrefix: advisories OSV does not carry for the release.
	KnownGapPrefix = "Known gap"
)

// OSReleaseNotes are an image run's release notes: "fixed issues only" for
// a distribution that publishes fixed issues only (Alpine, the Red Hat
// family), and the release row's known-gap sentence (a fixed sentence of
// the release table, never engine text).
func OSReleaseNotes(fixedOnly bool, knownGap string) []string {
	var out []string
	if fixedOnly {
		out = append(out, FixedOnlyPrefix+": this distribution publishes fixed issues only, so a clean result says nothing about unfixed ones.")
	}
	if knownGap != "" {
		out = append(out, KnownGapPrefix+": "+strings.TrimSuffix(knownGap, ".")+".")
	}
	return out
}

// OSFacts is what an image run observed for its release.
type OSFacts struct {
	// RPMOnWindows: an rpm-based release on a Windows node.
	RPMOnWindows bool
	// Compiled: the OS extractors are linked into this build.
	Compiled bool
	// HasCanary: the release has a canary row.
	HasCanary bool
	// DatabaseInstalled: the release's database is installed (an epoch).
	DatabaseInstalled bool
	// NoDatabase: the matcher reported no database for the base.
	NoDatabase bool
	// MatchError: the matcher failed for another reason.
	MatchError bool
	// CanaryHit: the canary matched at least one advisory.
	CanaryHit bool
}

// osRules is the release outcome table, walked top-down.
var osRules = []struct {
	When    func(OSFacts) bool
	Outcome EcoOutcome
	Reason  string
}{
	{func(f OSFacts) bool { return !f.Compiled }, EcoNotScanned, ReasonNotCompiled},
	{func(f OSFacts) bool { return f.RPMOnWindows }, EcoNotScanned, ReasonRPMOnWindows},
	{func(f OSFacts) bool { return !f.HasCanary }, EcoNotScanned, ReasonNoOSCanary},
	{func(f OSFacts) bool { return !f.DatabaseInstalled || f.NoDatabase }, EcoNotScanned, ReasonNoDatabase},
	{func(f OSFacts) bool { return f.MatchError }, EcoNotScanned, ReasonMatchFailed},
	{func(f OSFacts) bool { return !f.CanaryHit }, EcoNotScanned, ReasonSelfTestFailed},
	{func(OSFacts) bool { return true }, EcoScanned, ""},
}

// DecideOSRelease returns an image run's release outcome and reason.
func DecideOSRelease(f OSFacts) (EcoOutcome, string) {
	for _, r := range osRules {
		if r.When(f) {
			return r.Outcome, r.Reason
		}
	}
	return EcoNotScanned, ReasonMatchFailed
}

// osEcosystemOf returns the longest OS release label that prefixes an
// evidence string ("Red Hat:enterprise_linux:9 glib2@..."), "" for none.
func osEcosystemOf(evidence string) string {
	best := ""
	for eco := range osCanaries {
		if strings.HasPrefix(evidence, eco+" ") && len(eco) > len(best) {
			best = eco
		}
	}
	return best
}

// osFixHint is an OS package finding's fix hint.
const osFixHint = "Rebuild the image on an updated base image, or upgrade the package with the distribution's package manager to a version the advisory lists as fixed."

// SortedOSPackages returns the image's OS packages for the node-local
// inventory record: binary name, match name and version, sorted, kernel
// packages included (the record is the image's inventory, not the match).
func SortedOSPackages(pkgs []Package) []Package {
	out := make([]Package, 0, len(pkgs))
	for _, p := range pkgs {
		if IsOSPackage(p) {
			out = append(out, Package{Ecosystem: p.Ecosystem, Name: p.Name, Binary: p.Binary, Version: p.Version, Extractor: p.Extractor})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if binaryName(a) != binaryName(b) {
			return binaryName(a) < binaryName(b)
		}
		return a.Version < b.Version
	})
	return out
}
