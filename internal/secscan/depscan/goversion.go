package depscan

import (
	"regexp"
	"strconv"
	"strings"
)

// goversion.go reads the Go release a binary was built with, from the
// version string its build info carries (OS and CI vulnerability scanning
// plan section 14.6, item 4, operator ruling 2026-11-05 "Item 4 Go stdlib"
// (a)). SCALIBR's gobinary extractor already cuts the string at its first
// space and drops a leading "go", so the input is "1.22.3" for
// "go1.22.3 X:boringcrypto" and "devel" for "devel go1.23-abc +def"; the
// raw forms are accepted too, so a change in the extractor cannot move a
// binary from a release to "unknown" or the reverse.
//
// The result is the semantic-version spelling the Go vulnerability
// database uses for the "stdlib" package (1.22.3, 1.22.0, 1.22.0-rc.1),
// or "" when the string is not a release: a development build ("devel",
// a "-preN" snapshot) or anything unparseable. "" is never a clean
// result: the caller leaves the binary's standard library unmatched and
// reports a gap (ReasonGoVersionUnknown).

// goVersionRelease is a Go release or pre-release: go1.22, go1.22.3,
// go1.22rc1, go1.21beta2 (the "go" prefix already removed, a trailing
// vendor or experiment suffix already cut).
var goVersionRelease = regexp.MustCompile(`^1\.(\d{1,3})(?:\.(\d{1,3}))?(?:(rc|beta|alpha)(\d{1,3}))?$`)

// goVersionStep is one row of the normalization table, walked top-down on
// the working string; the first row whose Apply reports done decides.
type goVersionStep struct {
	Name string
	// Apply rewrites s. done true ends the walk with result (which may be
	// "" for unknown).
	Apply func(s string) (next string, result string, done bool)
}

// goVersionSteps is the normalization ladder; one test case per row in
// goversion_test.go.
var goVersionSteps = []goVersionStep{
	// A build info string is the release, then optional free text: an
	// experiment ("go1.21.0 X:boringcrypto"), a toolchain revision ("devel
	// go1.23-abc +def"), a distro note ("go1.21.9 (Red Hat 1.21.9-1.el9)").
	{"first_field", func(s string) (string, string, bool) {
		f := strings.Fields(s)
		if len(f) == 0 {
			return "", "", true
		}
		return f[0], "", false
	}},
	// A development build of the toolchain is not a release.
	{"devel", func(s string) (string, string, bool) {
		if s == "devel" || strings.HasPrefix(s, "devel+") || strings.HasPrefix(s, "devel:") || strings.HasPrefix(s, "devel-") {
			return s, "", true
		}
		return s, "", false
	}},
	{"go_prefix", func(s string) (string, string, bool) { return strings.TrimPrefix(s, "go"), "", false }},
	// Build metadata ("1.22.3+build5") is not part of the release.
	{"build_metadata", func(s string) (string, string, bool) { s, _, _ = strings.Cut(s, "+"); return s, "", false }},
	// An experiment glued on with a colon ("1.21.0:boringcrypto").
	{"experiment_colon", func(s string) (string, string, bool) { s, _, _ = strings.Cut(s, ":"); return s, "", false }},
	// A hyphen suffix: "-preN" and "-devel" mark a snapshot of the next
	// release (not a release); any other is a distro or vendor tag
	// ("1.22.3-bookworm", "1.21.9-1.el9") on a real release.
	{"hyphen_suffix", func(s string) (string, string, bool) {
		head, tail, ok := strings.Cut(s, "-")
		if !ok {
			return s, "", false
		}
		if strings.HasPrefix(tail, "pre") || strings.HasPrefix(tail, "devel") {
			return s, "", true
		}
		return head, "", false
	}},
	{"release", func(s string) (string, string, bool) {
		m := goVersionRelease.FindStringSubmatch(s)
		if m == nil {
			return s, "", true
		}
		minor, _ := strconv.Atoi(m[1])
		patch := 0
		if m[2] != "" {
			patch, _ = strconv.Atoi(m[2])
		}
		out := "1." + strconv.Itoa(minor) + "." + strconv.Itoa(patch)
		if m[3] != "" {
			n, _ := strconv.Atoi(m[4])
			out += "-" + m[3] + "." + strconv.Itoa(n)
		}
		return out, out, true
	}},
}

// IsBinaryStdlib reports the package a Go binary's build info yields for
// the standard library it embeds: Go, "stdlib", read out of an artifact.
func IsBinaryStdlib(p Package) bool {
	return p.Artifact && p.Ecosystem == "Go" && p.Name == "stdlib"
}

// NormalizeGoVersion returns the Go release a build info version string
// names in the Go vulnerability database's spelling, "" when it names no
// release (a development build, an unparseable string).
func NormalizeGoVersion(raw string) string {
	s := raw
	for _, step := range goVersionSteps {
		next, result, done := step.Apply(s)
		if done {
			return result
		}
		s = next
	}
	return ""
}
