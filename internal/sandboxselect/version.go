package sandboxselect

import (
	"fmt"
	"strconv"
	"strings"
)

// parseVersion reads a dotted numeric version ("0.4.0", "v1.44",
// "bubblewrap 0.13.1"): the last whitespace-separated field, an optional
// leading "v", up to three numeric parts, and a trailing pre-release or
// build suffix ignored. Anything else is an error, never a guess.
func parseVersion(s string) ([3]int, error) {
	var out [3]int
	f := strings.Fields(s)
	if len(f) == 0 {
		return out, fmt.Errorf("empty version")
	}
	v := strings.TrimPrefix(f[len(f)-1], "v")
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}
	parts := strings.Split(v, ".")
	if len(parts) == 0 || len(parts) > 3 {
		return out, fmt.Errorf("version %q", s)
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return out, fmt.Errorf("version %q", s)
		}
		out[i] = n
	}
	return out, nil
}

// compareVersions returns -1, 0 or 1.
func compareVersions(a, b [3]int) int {
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

// versionStatus is what a version means against a row's pins.
type versionStatus int

const (
	versionTested versionStatus = iota
	// versionBeta: at or above the required minimum but outside the tested
	// range (either direction): usable, labelled beta.
	versionBeta
	// versionRefused: below the required minimum, or unreadable.
	versionRefused
)

// classifyVersion judges an installed version against the pins.
func classifyVersion(installed, requiredMin, testedLow, testedHigh string) versionStatus {
	v, err := parseVersion(installed)
	if err != nil {
		return versionRefused
	}
	if requiredMin != "" {
		m, err := parseVersion(requiredMin)
		if err != nil || compareVersions(v, m) < 0 {
			return versionRefused
		}
	}
	if testedLow != "" {
		if lo, err := parseVersion(testedLow); err != nil || compareVersions(v, lo) < 0 {
			return versionBeta
		}
	}
	if testedHigh != "" {
		if hi, err := parseVersion(testedHigh); err != nil || compareVersions(v, hi) > 0 {
			return versionBeta
		}
	}
	return versionTested
}
