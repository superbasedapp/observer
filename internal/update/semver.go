package update

import (
	"strconv"
	"strings"
)

// Semver is a parsed X.Y.Z core. Pre-release and build metadata are
// deliberately NOT modelled: this package mirrors the shipped frontend
// rule (web/src/lib/version.ts:293-322), which strips the suffix before
// comparing, and a second, subtly different ordering on the node would
// be the bug — the dashboard would say "up to date" while the updater
// said "behind".
type Semver struct {
	// Major, Minor, Patch are the three non-negative core numbers.
	Major, Minor, Patch int
}

// ParseSemver parses "vX.Y.Z", "X.Y.Z", or either with a pre-release /
// build suffix ("v1.8.2-rc.1", "1.8.2+build"), returning the core only.
//
// It is a line-for-line port of parseSemver in
// web/src/lib/version.ts:308-322: strip a leading "v", cut at the first
// "-" or "+", require at least three dot-separated parts, and require
// every one of the first three to be a finite, non-negative number.
// Extra parts beyond the third are ignored exactly as the TS
// implementation ignores them.
func ParseSemver(v string) (Semver, bool) {
	if v == "" {
		return Semver{}, false
	}
	core := strings.TrimPrefix(v, "v")
	if i := strings.IndexAny(core, "-+"); i >= 0 {
		core = core[:i]
	}
	parts := strings.Split(core, ".")
	if len(parts) < 3 {
		return Semver{}, false
	}
	out := make([]int, 3)
	for i := 0; i < 3; i++ {
		n, err := strconv.Atoi(parts[i])
		if err != nil || n < 0 {
			return Semver{}, false
		}
		out[i] = n
	}
	return Semver{Major: out[0], Minor: out[1], Patch: out[2]}, true
}

// CompareSemver returns -1 / 0 / +1 for a < b / a == b / a > b, and
// ok=false when either side is unparseable. It is the Go twin of
// compareSemver (version.ts:293-306), including the "pre-release
// suffixes are stripped, not ordered" rule.
func CompareSemver(a, b string) (int, bool) {
	pa, oka := ParseSemver(a)
	pb, okb := ParseSemver(b)
	if !oka || !okb {
		return 0, false
	}
	for _, pair := range [3][2]int{
		{pa.Major, pb.Major},
		{pa.Minor, pb.Minor},
		{pa.Patch, pb.Patch},
	} {
		if pair[0] < pair[1] {
			return -1, true
		}
		if pair[0] > pair[1] {
			return 1, true
		}
	}
	return 0, true
}

// HasPreRelease reports whether v carries a pre-release or build
// suffix ("v1.8.2-rc.1"). Such a build is never nagged about an update
// (it is effectively ahead of the stable it would be pointed at) —
// the same judgement isUpdateAvailable makes at version.ts:334-337.
func HasPreRelease(v string) bool {
	return strings.ContainsAny(strings.TrimPrefix(v, "v"), "-+")
}

// IsDevBuild reports whether v is the unstamped development version.
// cmd/observer/main.go:46 sets `version = "dev"` and the release
// pipeline replaces it with -X main.version=; a dev build has no
// meaningful position in the ordering and is never told it is behind.
func IsDevBuild(v string) bool { return v == "" || v == "dev" }

// IsUpdateAvailable reports whether latest is a strict semver ahead of
// current, defaulting to false on ANY uncertainty (dev build,
// pre-release current, malformed either side).
//
// It is the Go twin of isUpdateAvailable (version.ts:328-340) and is
// the ONLY place this package decides "behind": verify rule 7 calls it
// so a manifest can never be applied on a comparison the dashboard
// would have called a no-op.
func IsUpdateAvailable(current, latest string) bool {
	if current == "" || latest == "" {
		return false
	}
	if IsDevBuild(current) {
		return false
	}
	if HasPreRelease(current) {
		return false
	}
	cmp, ok := CompareSemver(current, latest)
	return ok && cmp == -1
}
