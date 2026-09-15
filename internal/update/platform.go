package update

import (
	"fmt"
	"runtime"
	"strings"
)

// Archive types the release pipeline really emits
// (.github/workflows/npm-release.yml:1181-1189). There is no third
// shape and an unknown one is a validation failure, because "unpack it
// somehow" is exactly the kind of guess an updater must not make.
const (
	// ArchiveTarGz is the POSIX tarball, which carries the alias as a
	// relative SYMLINK (superbased -> observer).
	ArchiveTarGz = "tar.gz"
	// ArchiveZip is the win32 zip, which carries the alias as a byte
	// COPY (superbased.exe beside observer.exe) because zip symlink
	// support is unreliable across extractors.
	ArchiveZip = "zip"
)

// KnownArchiveType reports whether t is an archive shape the extractor
// understands.
func KnownArchiveType(t string) bool {
	return t == ArchiveTarGz || t == ArchiveZip
}

// DefaultArchiveTypeFor returns the archive shape the pipeline emits
// for a GOOS. It is a convenience for building a manifest, never a
// substitute for the manifest's own archive_type: the document decides
// what the extractor does, not the platform.
func DefaultArchiveTypeFor(goos string) string {
	if NormalizeOS(goos) == "windows" {
		return ArchiveZip
	}
	return ArchiveTarGz
}

// BinaryName returns the agent's executable name on a GOOS.
func BinaryName(goos string) string {
	if NormalizeOS(goos) == "windows" {
		return "observer.exe"
	}
	return "observer"
}

// AliasName returns the `superbased` alias name on a GOOS. The alias is
// skipped by the extractor; it is named here so a caller building a
// manifest names it the same way the pipeline does.
func AliasName(goos string) string {
	if NormalizeOS(goos) == "windows" {
		return "superbased.exe"
	}
	return "superbased"
}

// ArtifactKey identifies one artifact row inside a manifest.
type ArtifactKey struct {
	// Kind is the artifact family (KindAgent).
	Kind string
	// OS and Arch are NORMALIZED (see NormalizeOS / NormalizeArch), so
	// a manifest written with release-asset spellings ("win32", "x64")
	// keys the same as one written with Go spellings.
	OS, Arch string
}

// String renders the key as "kind/os/arch" for error messages.
func (k ArtifactKey) String() string { return fmt.Sprintf("%s/%s/%s", k.Kind, k.OS, k.Arch) }

// KeyOf returns the normalized key of an artifact row.
func KeyOf(a Artifact) ArtifactKey {
	return ArtifactKey{Kind: a.Kind, OS: NormalizeOS(a.OS), Arch: NormalizeArch(a.Arch)}
}

// osAliases maps every spelling seen across the release pipeline, the
// VS Code extension's asset names and Go itself onto a GOOS value.
// Table, not a switch ladder (CLAUDE.md #5).
var osAliases = map[string]string{
	"linux":   "linux",
	"darwin":  "darwin",
	"macos":   "darwin",
	"mac":     "darwin",
	"osx":     "darwin",
	"windows": "windows",
	"win32":   "windows",
	"win":     "windows",
}

// archAliases maps release-asset arch spellings onto GOARCH values.
var archAliases = map[string]string{
	"amd64":   "amd64",
	"x64":     "amd64",
	"x86_64":  "amd64",
	"arm64":   "arm64",
	"aarch64": "arm64",
}

// NormalizeOS folds an OS spelling onto its GOOS value, returning the
// lowercased input unchanged when it is not a known alias (an unknown
// platform must stay visible in errors, not become "linux").
func NormalizeOS(s string) string {
	l := strings.ToLower(strings.TrimSpace(s))
	if v, ok := osAliases[l]; ok {
		return v
	}
	return l
}

// NormalizeArch folds an arch spelling onto its GOARCH value, returning
// the lowercased input unchanged when it is not a known alias.
func NormalizeArch(s string) string {
	l := strings.ToLower(strings.TrimSpace(s))
	if v, ok := archAliases[l]; ok {
		return v
	}
	return l
}

// CurrentPlatform returns this binary's normalized (goos, goarch).
func CurrentPlatform() (string, string) {
	return NormalizeOS(runtime.GOOS), NormalizeArch(runtime.GOARCH)
}

// SelectArtifact returns the artifact row for one kind/os/arch, matching
// on NORMALIZED values so a manifest may spell a platform either way.
//
// A missing row is not an error shape the caller invents: verify rule 9
// turns it into blocked{no_artifact}, which is what the org board shows
// for a platform this release did not build.
func SelectArtifact(m Manifest, kind, goos, goarch string) (Artifact, bool) {
	want := ArtifactKey{Kind: kind, OS: NormalizeOS(goos), Arch: NormalizeArch(goarch)}
	for _, a := range m.Artifacts {
		if KeyOf(a) == want {
			return a, true
		}
	}
	return Artifact{}, false
}
