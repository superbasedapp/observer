package sandboxmxc

import (
	"strconv"
	"strings"
)

// ContractVersion is the exact MXC configuration contract every document
// this driver writes carries ("version": "1.0.0"). MXC 1.0.1 keeps the
// stable schema at 1.0.0 (its release notes); a library that refuses the
// contract is refused with backend_version_untested.
const ContractVersion = "1.0.0"

// Pins are the library version pins of the mxc-process row (sandbox plan
// v2 section 4.2: a required minimum below which the driver cannot work,
// and the tested range). The version is the one mxc_version() returns
// from a library whose hash matched the manifest, so it is read from an
// authenticated identity.
var Pins = VersionPins{RequiredMin: "1.0.0", TestedLow: "1.0.0", TestedHigh: "1.0.1"}

// VersionPins is a required minimum and a tested range.
type VersionPins struct {
	RequiredMin string
	TestedLow   string
	TestedHigh  string
}

// VersionStatus is how a library version sits against the pins.
type VersionStatus string

// The VersionStatus values.
const (
	// VersionTested: inside the tested range.
	VersionTested VersionStatus = "tested"
	// VersionBeta: at or above the minimum but outside the tested range;
	// usable and labelled beta (backend_version_beta, informational).
	VersionBeta VersionStatus = "beta"
	// VersionUntested: below the minimum or unreadable; refused.
	VersionUntested VersionStatus = "untested"
)

// CheckVersion places v (mxc_version()'s string, for example "1.0.1")
// against p. A version that does not parse as major.minor.patch (an empty
// string from a library that failed) is untested.
func CheckVersion(v string, p VersionPins) VersionStatus {
	got, ok := parseSemver(v)
	if !ok {
		return VersionUntested
	}
	minV, _ := parseSemver(p.RequiredMin)
	if compare(got, minV) < 0 {
		return VersionUntested
	}
	lo, _ := parseSemver(p.TestedLow)
	hi, _ := parseSemver(p.TestedHigh)
	if compare(got, lo) < 0 || compare(got, hi) > 0 {
		return VersionBeta
	}
	return VersionTested
}

// parseSemver reads major.minor.patch, ignoring a pre-release or build
// suffix ("1.0.1-rc1" reads as 1.0.1; a pre-release of the minimum is
// therefore accepted only through the contract check, which it must pass).
func parseSemver(v string) ([3]int, bool) {
	var out [3]int
	v = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(v), "v"))
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return out, false
	}
	for i, s := range parts {
		n, err := strconv.Atoi(s)
		if err != nil || n < 0 || s == "" {
			return out, false
		}
		out[i] = n
	}
	return out, true
}

// compare orders two versions.
func compare(a, b [3]int) int {
	for i := range a {
		switch {
		case a[i] < b[i]:
			return -1
		case a[i] > b[i]:
			return 1
		}
	}
	return 0
}
