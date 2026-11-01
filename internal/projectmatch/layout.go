package projectmatch

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
)

// Layout is where the project audience's node files live: one directory
// beside the org bundle cache ([guard.rules].org_bundle).
//
//	<dir>/mapping.json                    the signed mapping (MappingFile)
//	<dir>/envelopes/<project hash>.json   one signed envelope per project
//	<dir>/match/<project root hash>.json  the daemon's match record (MatchFile)
//	<dir>/resolved/<project hash>.json    an envelope the resolve call returned
//
// The org client is the one writer of the mapping and the envelopes; the
// daemon's matcher is the one writer of the match records; the guard reads.
type Layout struct {
	Dir string
}

// DirName is the directory's name beside the org bundle cache.
const DirName = "org-project-policy"

// LayoutFor returns the layout beside the org bundle cache at orgBundlePath
// (the zero Layout for an empty path).
func LayoutFor(orgBundlePath string) Layout {
	if orgBundlePath == "" {
		return Layout{}
	}
	return Layout{Dir: filepath.Join(filepath.Dir(orgBundlePath), DirName)}
}

// MappingPath is the signed mapping's file.
func (l Layout) MappingPath() string { return filepath.Join(l.Dir, "mapping.json") }

// EnvelopesDir holds the per-project envelopes.
func (l Layout) EnvelopesDir() string { return filepath.Join(l.Dir, "envelopes") }

// EnvelopePath is one project's envelope file. The file name is a hash of the
// org project id, so an id never becomes a path component.
func (l Layout) EnvelopePath(orgProjectID string) string {
	return filepath.Join(l.EnvelopesDir(), idHash(orgProjectID)+".json")
}

// ResolvedDir holds the envelopes of projects the resolve call matched (an
// above-cap member's projects have no envelope in the delivery). The matcher
// is their one writer; the org client's delivery never removes them. The
// guard checks each against the composed bundle in force like a delivered
// one, so a file of an older version or epoch is refused, never loaded.
func (l Layout) ResolvedDir() string { return filepath.Join(l.Dir, "resolved") }

// ResolvedEnvelopePath is one resolved project's envelope file.
func (l Layout) ResolvedEnvelopePath(orgProjectID string) string {
	return filepath.Join(l.ResolvedDir(), idHash(orgProjectID)+".json")
}

// MatchDir holds the daemon's match records.
func (l Layout) MatchDir() string { return filepath.Join(l.Dir, "match") }

// MatchPath is the match record of one project root, keyed by its root hash
// (secposture.ProjectRootHash's value, so the posture writer and the guard
// name the same file).
func (l Layout) MatchPath(projectRootHash string) string {
	return filepath.Join(l.MatchDir(), projectRootHash+".json")
}

// idHash names an envelope file.
func idHash(id string) string {
	sum := sha256.Sum256([]byte(id))
	return hex.EncodeToString(sum[:16])
}

// RootHash keys a project root's match record: the hex SHA-256 of the root
// path, the same recipe secposture.ProjectRootHash uses, so the security
// posture writer finds a root's record by the hash it already holds.
func RootHash(root string) string {
	if root == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(root))
	return hex.EncodeToString(sum[:])
}
