package trivyimage

import "slices"

// canary.go is the image driver's self-test (plan 6.7 "Honest coverage per
// driver"): a root filesystem Observer writes into a temporary directory,
// scanned with `trivy rootfs` in the same run and against the same
// database before the image. Its one package is Debian 12's libc6 at
// 2.36-9+deb12u2 (source glibc), which Debian's DSA-5514-1 (CVE-2023-4911,
// fixed in 2.36-9+deb12u3) flags; the same package route A's Debian 12
// canary uses. Trivy detects Debian from etc/debian_version, so the canary
// carries it beside etc/os-release.
//
// What a hit proves: Trivy ran, read the installed database and matched a
// dpkg package with backported versions. It does not prove each
// distribution's data loaded; per-distribution canaries are a follow-up,
// and the run's coverage note says so.

// The canary's package and the advisory it is known for.
const (
	CanaryPackage  = "libc6"
	CanarySource   = "glibc"
	CanaryVersion  = "2.36-9+deb12u2"
	CanaryCVE      = "CVE-2023-4911"
	CanaryAdvisory = "DSA-5514-1"
	// CanaryRelease is the release the canary stands for.
	CanaryRelease = "Debian:12"
)

// CanaryFiles is the canary root filesystem, by slash-separated relative
// path; the caller writes it into the canary directory.
func CanaryFiles() map[string]string {
	return map[string]string{
		"etc/os-release": "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nNAME=\"Debian GNU/Linux\"\nVERSION_ID=\"12\"\n" +
			"VERSION=\"12 (bookworm)\"\nVERSION_CODENAME=bookworm\nID=debian\n",
		"etc/debian_version": "12.2\n",
		"var/lib/dpkg/status": "Package: " + CanaryPackage + "\nStatus: install ok installed\nPriority: optional\nSection: libs\n" +
			"Installed-Size: 12000\nMaintainer: Observer canary <canary@invalid>\nArchitecture: amd64\nMulti-Arch: same\n" +
			"Source: " + CanarySource + "\nVersion: " + CanaryVersion + "\nDescription: superbased-observer canary\n\n",
	}
}

// CanaryHit reports whether a canary report flags the canary package with
// its known advisory.
func CanaryHit(r Report) bool {
	if !r.Metadata.OS.Detected() || r.Metadata.OS.Family != "debian" {
		return false
	}
	for _, res := range r.OSResults() {
		for _, v := range res.Vulnerabilities {
			if v.PkgName != CanaryPackage || v.InstalledVersion != CanaryVersion {
				continue
			}
			if v.VulnerabilityID == CanaryCVE || slices.Contains(v.VendorIDs, CanaryAdvisory) {
				return true
			}
		}
	}
	return false
}
