package update

import (
	"errors"
	"fmt"
	"regexp"
)

// ErrUnrecognizedArtifact is returned by ParseArtifactName for a filename
// that is not an agent release archive. Callers that scan a whole release
// directory (SHA256SUMS, provenance, SBOMs, the observer-org archives ride
// beside the agent archives) skip on it; callers handed one file refuse.
var ErrUnrecognizedArtifact = errors.New("update: unrecognized artifact filename")

// ErrArchiveTypeMismatch wraps ErrUnrecognizedArtifact for a name that IS an
// agent archive but pairs a target with the wrong archive type (a zip for a
// POSIX target, a tarball for windows). A directory scanner must NOT skip
// this one silently: it is a mis-built release, not a foreign file.
var ErrArchiveTypeMismatch = errors.New("update: archive type does not match the target")

// artifactNameRe parses a release archive name into version / target /
// extension: `observer-v1.33.0-linux-x64.tar.gz`,
// `observer-v1.33.0-win32-x64.zip`, `observer-v1.34.0-rc.2-linux-x64.tar.gz`.
//
// THE ONE OWNER of this rule (tests/invariant pins it). Until 2026-09-17 the
// org server's importer and the release pipeline's manifest producer
// (scripts/vendorsign) each carried a copy; the first rc tag ever cut broke
// on the pre-release suffix, the copy in the importer was fixed, and the
// second rc broke on the copy the pipeline actually runs.
//
// A regexp rather than a split ladder because the target itself contains
// the separator, and because a name that does NOT match must be refused,
// not guessed at. The version group is a semver core with an optional
// pre-release suffix whose class excludes "-", so the os/arch tokens that
// follow can never be swallowed by it, and a plain core backtracks to no
// suffix. `observer-org-v1.33.0-linux-x64.tar.gz` fails at the `v[0-9]`
// group, which is what keeps the org-server archives out of the agent
// manifest.
var artifactNameRe = regexp.MustCompile(`^observer-(v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.]+)?)-([a-z0-9]+)-([a-z0-9_]+)\.(tar\.gz|zip)$`)

// ParseArtifactName derives the manifest facts a release archive's filename
// encodes: the version tag, the normalized GOOS / GOARCH (the pipeline's
// `win32`/`x64` spellings and Go's `windows`/`amd64` key identically) and
// the archive type, which must be the one DefaultArchiveTypeFor emits for
// that target.
func ParseArtifactName(name string) (version, goos, goarch, archiveType string, err error) {
	m := artifactNameRe.FindStringSubmatch(name)
	if m == nil {
		return "", "", "", "", fmt.Errorf("%w: %q (want observer-<version>-<os>-<arch>.tar.gz|zip)", ErrUnrecognizedArtifact, name)
	}
	version, goos, goarch, archiveType = m[1], NormalizeOS(m[2]), NormalizeArch(m[3]), m[4]
	if want := DefaultArchiveTypeFor(goos); want != archiveType {
		return "", "", "", "", fmt.Errorf("%w: %w: %q is a %s but the pipeline emits %s for %s",
			ErrUnrecognizedArtifact, ErrArchiveTypeMismatch, name, archiveType, want, goos)
	}
	return version, goos, goarch, archiveType, nil
}
