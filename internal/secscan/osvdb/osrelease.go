package osvdb

import (
	"strings"
)

// osrelease.go is the ONE table of the operating system releases whose OS
// package databases Observer publishes and installs (OS and CI
// vulnerability scanning plan sections 6.4 and 6.6.1, spike JSP-OS). The
// publisher (scripts/vendorsign) strips each release's file out of its
// distribution's whole OSV export by Keep; the node maps an image's
// os-release onto a row with ReleaseFor, installs the release's file from
// the security.osv_os_export content kind under its Artifact name, and
// hands it to the matcher as <Base>/all.zip. The bucket's own per-release
// exports are never used: they stopped updating in October 2024.

// OSRelease is one operating system release.
type OSRelease struct {
	// Distro is the os-release ID this row answers ("debian", "ubuntu",
	// "alpine", "rhel", "rocky").
	Distro string
	// Version is the release as ReleaseFor normalises os-release
	// VERSION_ID ("12", "24.04", "3.20", "9").
	Version string
	// Base is the OSV base ecosystem the matcher opens <Base>/all.zip for.
	Base string
	// Ecosystem is the OSV ecosystem string the release's records carry
	// ("Debian:12", "Ubuntu:24.04:LTS"); for the Red Hat family it is a
	// prefix (KeepPrefix).
	Ecosystem string
	// KeepPrefix: keep every affected entry whose ecosystem starts with
	// Ecosystem (Red Hat's per-stream "Red Hat:enterprise_linux:9::baseos",
	// "::appstream", "::crb"), not only an equal one. Red Hat 10 has no
	// streams but per-minor strings ("Red Hat:enterprise_linux:10.0",
	// "10.1", and "10::fastdatapath"), so its one file holds every minor.
	KeepPrefix bool
	// Artifact is the release's artifact base name in the
	// security.osv_os_export kind (letters, digits, '.', '-', '_').
	Artifact string
	// ApproxBytes is the stripped file's size, rounded up, as lane OS-2 P's
	// publisher run measured it on 2026-11-04, for the accept's text; the
	// signed manifest states the exact size.
	ApproxBytes int64
	// FixedOnly: the distribution publishes fixed issues only (Alpine, the
	// Red Hat family), so a clean result says nothing about unfixed ones.
	FixedOnly bool
	// KnownGap is a fixed sentence naming advisories OSV does not carry for
	// the release ("" for none).
	KnownGap string
	// RPM: the release's packages are read from an rpm database, which the
	// matcher cannot read on Windows.
	RPM bool
}

const (
	gapDebianLTS = "Debian LTS advisories (DLA) are not in OSV for this release"
	gapUbuntuPro = "Ubuntu Pro (ESM) fixes are not in OSV"
)

// OSReleases is THE release table, in display order.
var OSReleases = []OSRelease{
	{Distro: "debian", Version: "11", Base: "Debian", Ecosystem: "Debian:11", Artifact: "Debian-11", ApproxBytes: 3 << 20, KnownGap: gapDebianLTS},
	{Distro: "debian", Version: "12", Base: "Debian", Ecosystem: "Debian:12", Artifact: "Debian-12", ApproxBytes: 62 << 20, KnownGap: gapDebianLTS},
	{Distro: "debian", Version: "13", Base: "Debian", Ecosystem: "Debian:13", Artifact: "Debian-13", ApproxBytes: 57 << 20},
	{Distro: "ubuntu", Version: "20.04", Base: "Ubuntu", Ecosystem: "Ubuntu:20.04:LTS", Artifact: "Ubuntu-20.04-LTS", ApproxBytes: 194 << 20, KnownGap: gapUbuntuPro},
	{Distro: "ubuntu", Version: "22.04", Base: "Ubuntu", Ecosystem: "Ubuntu:22.04:LTS", Artifact: "Ubuntu-22.04-LTS", ApproxBytes: 220 << 20, KnownGap: gapUbuntuPro},
	{Distro: "ubuntu", Version: "24.04", Base: "Ubuntu", Ecosystem: "Ubuntu:24.04:LTS", Artifact: "Ubuntu-24.04-LTS", ApproxBytes: 130 << 20, KnownGap: gapUbuntuPro},
	{Distro: "ubuntu", Version: "26.04", Base: "Ubuntu", Ecosystem: "Ubuntu:26.04:LTS", Artifact: "Ubuntu-26.04-LTS", ApproxBytes: 35 << 20, KnownGap: gapUbuntuPro},
	{Distro: "alpine", Version: "3.20", Base: "Alpine", Ecosystem: "Alpine:v3.20", Artifact: "Alpine-v3.20", ApproxBytes: 6 << 20, FixedOnly: true},
	{Distro: "alpine", Version: "3.21", Base: "Alpine", Ecosystem: "Alpine:v3.21", Artifact: "Alpine-v3.21", ApproxBytes: 6 << 20, FixedOnly: true},
	{Distro: "alpine", Version: "3.22", Base: "Alpine", Ecosystem: "Alpine:v3.22", Artifact: "Alpine-v3.22", ApproxBytes: 7 << 20, FixedOnly: true},
	{Distro: "alpine", Version: "3.23", Base: "Alpine", Ecosystem: "Alpine:v3.23", Artifact: "Alpine-v3.23", ApproxBytes: 7 << 20, FixedOnly: true},
	{Distro: "rhel", Version: "8", Base: "Red Hat", Ecosystem: "Red Hat:enterprise_linux:8::", KeepPrefix: true, Artifact: "Red-Hat-EL8", ApproxBytes: 4 << 20, FixedOnly: true, RPM: true},
	{Distro: "rhel", Version: "9", Base: "Red Hat", Ecosystem: "Red Hat:enterprise_linux:9::", KeepPrefix: true, Artifact: "Red-Hat-EL9", ApproxBytes: 3 << 20, FixedOnly: true, RPM: true},
	{Distro: "rhel", Version: "10", Base: "Red Hat", Ecosystem: "Red Hat:enterprise_linux:10", KeepPrefix: true, Artifact: "Red-Hat-EL10", ApproxBytes: 1 << 20, FixedOnly: true, RPM: true},
	{Distro: "rocky", Version: "8", Base: "Rocky Linux", Ecosystem: "Rocky Linux:8", Artifact: "Rocky-Linux-8", ApproxBytes: 3 << 20, FixedOnly: true, RPM: true},
	{Distro: "rocky", Version: "9", Base: "Rocky Linux", Ecosystem: "Rocky Linux:9", Artifact: "Rocky-Linux-9", ApproxBytes: 2 << 20, FixedOnly: true, RPM: true},
	{Distro: "rocky", Version: "10", Base: "Rocky Linux", Ecosystem: "Rocky Linux:10", Artifact: "Rocky-Linux-10", ApproxBytes: 1 << 20, FixedOnly: true, RPM: true},
}

// Keep reports whether an affected entry of the given OSV ecosystem belongs
// in the release's stripped file.
func (r OSRelease) Keep(ecosystem string) bool {
	if r.KeepPrefix {
		// "Red Hat:enterprise_linux:10" must not keep ":100"-style
		// neighbours: a prefix ending in a digit needs a ':' or the end
		// after it.
		if !strings.HasPrefix(ecosystem, r.Ecosystem) {
			return false
		}
		rest := ecosystem[len(r.Ecosystem):]
		return strings.HasSuffix(r.Ecosystem, ":") || rest == "" || strings.HasPrefix(rest, ":") || strings.HasPrefix(rest, ".")
	}
	return ecosystem == r.Ecosystem
}

// ExportArtifact is the release's base artifact name ("Debian-12.zip").
func (r OSRelease) ExportArtifact() string { return r.Artifact + ".zip" }

// DeltaArtifact is the release's cumulative delta artifact name.
func (r OSRelease) DeltaArtifact() string { return r.Artifact + ".delta.zip" }

// ReleaseFor maps an image's os-release ID and VERSION_ID onto its row. An
// Ubuntu release is only an LTS row (ok false for an interim release);
// Alpine and the Red Hat family match on major.minor and major. ok is false
// for a distribution or release the table does not hold: the image is then
// "not scanned", never clean.
func ReleaseFor(id, versionID string) (OSRelease, bool) {
	id = strings.ToLower(strings.TrimSpace(id))
	v := strings.Trim(strings.TrimSpace(versionID), `"'`)
	switch id {
	case "alpine":
		v = majorMinor(v)
	case "rhel", "rocky", "debian":
		v, _, _ = strings.Cut(v, ".")
	}
	for _, r := range OSReleases {
		if r.Distro == id && r.Version == v {
			return r, true
		}
	}
	return OSRelease{}, false
}

// ReleaseByArtifact returns the row whose artifact base is name.
func ReleaseByArtifact(name string) (OSRelease, bool) {
	for _, r := range OSReleases {
		if r.Artifact == name {
			return r, true
		}
	}
	return OSRelease{}, false
}

func majorMinor(v string) string {
	parts := strings.SplitN(v, ".", 3)
	if len(parts) < 2 {
		return v
	}
	return parts[0] + "." + parts[1]
}
