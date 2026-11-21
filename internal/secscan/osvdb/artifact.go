package osvdb

import "strings"

// artifact.go is the ONE owner of how an OSV ecosystem name is spelled
// where a plain name is needed: the store's directory names
// (osv-scalibr/<Ecosystem>/all.zip, which may hold a space) and the
// artifact names of the security.osv_export content kind, which the feed
// host serves only as plain names (letters, digits, '.', '-', '_'). The
// publisher (scripts/vendorsign osvexport) and the node (the content
// remote, cmd/observer) both name the artifacts through ExportArtifact and
// DeltaArtifact, so the two can never drift.

// MaxEcosystemName caps an ecosystem name.
const MaxEcosystemName = 64

// ValidEcosystem reports a name that can only be one directory element and
// one URL path segment once escaped: letters, digits, '.', '-', '_', ':'
// and single spaces between words (OSV's "GitHub Actions", "Red Hat"),
// never "." or "..", never a separator, never a leading, trailing or
// doubled space.
func ValidEcosystem(eco string) bool {
	if eco == "" || len(eco) > MaxEcosystemName || eco == "." || eco == ".." {
		return false
	}
	if strings.HasPrefix(eco, " ") || strings.HasSuffix(eco, " ") || strings.Contains(eco, "  ") {
		return false
	}
	for _, r := range eco {
		if !(r == ' ' || r == '-' || r == '_' || r == '.' || r == ':' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}

// ArtifactBase is an ecosystem's name in the security.osv_export artifact
// names: the OSV name with each space spelled '-' ("GitHub Actions" ->
// "GitHub-Actions"; every other mirrored language ecosystem holds no
// space and is unchanged ("npm", "SwiftURL", "CRAN"), so every feed
// published before this rule keeps its names). ok is false for a name ValidEcosystem refuses and for one with
// ':' (no artifact name may carry it).
//
// The mapping is injective over the OSV ecosystem names: of the 48 at
// osv-schema's pinned version, the only one with a '-' is "OSS-Fuzz", and
// no name differs from another only by a space where the other has a '-'
// (TestArtifactBaseInjective holds this over the whole list).
func ArtifactBase(eco string) (string, bool) {
	if !ValidEcosystem(eco) || strings.Contains(eco, ":") {
		return "", false
	}
	return strings.ReplaceAll(eco, " ", "-"), true
}

// ExportArtifact is the artifact name of one ecosystem's base export in the
// security.osv_export kind ("npm.zip", "GitHub-Actions.zip"); "" for a name
// ArtifactBase refuses.
func ExportArtifact(eco string) string {
	b, ok := ArtifactBase(eco)
	if !ok {
		return ""
	}
	return b + ".zip"
}

// DeltaArtifact is the artifact name of one ecosystem's cumulative delta
// ("npm.delta.zip", "GitHub-Actions.delta.zip"); "" for a name ArtifactBase
// refuses.
func DeltaArtifact(eco string) string {
	b, ok := ArtifactBase(eco)
	if !ok {
		return ""
	}
	return b + ".delta.zip"
}
