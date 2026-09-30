package orgcontract

import (
	"crypto/sha256"
	"encoding/hex"
)

// Tombstone table names: the only values PushDeletion.Table carries. They
// name the four cursor-wire families (the org tables of the same name).
const (
	DeletionSessions   = "sessions"
	DeletionActions    = "actions"
	DeletionAPITurns   = "api_turns"
	DeletionTokenUsage = "token_usage"
)

// PushDeletion is one TOMBSTONE: the WIRE IDENTITY of a cursor-wire row the
// node deleted as a correction after pushing it (agent migration 141, lane
// R2-TOMB). It carries only identity fields every row of that family already
// ships in every posture - a session id, a source-file HASH (never the raw
// path), a source event id, a request id and timestamp - so a tombstone can
// never disclose more than the row it retires did.
//
// Identity per Table (the key the org dedups that family by):
//
//   - sessions:    SessionID
//   - actions:     SourceFileHash + SourceEventID (an empty hash matches the
//     org's empty source_file key of a row that shipped with no source file)
//   - token_usage: SourceFileHash + SourceEventID
//   - api_turns:   RequestID + Timestamp across sessions (the org relocates a
//     moved turn by that identity); a request-less turn is SessionID +
//     Timestamp
//
// NodeRev is the node's change sequence AT THE DELETE. The org deletes its
// copy only when the copy's node_rev is strictly older, so a row re-inserted
// under the same identity after the delete (which always ships with a NodeRev
// >= this one) survives the tombstone whatever order the two arrive in.
type PushDeletion struct {
	Table          string `json:"table"`
	NodeRev        int64  `json:"node_rev"`
	SessionID      string `json:"session_id,omitempty"`
	SourceFileHash string `json:"source_file_hash,omitempty"`
	SourceEventID  string `json:"source_event_id,omitempty"`
	RequestID      string `json:"request_id,omitempty"`
	Timestamp      string `json:"timestamp,omitempty"`
}

// SessionManifest is the HEAL for rows the node deleted before tombstones
// existed (`observer org resync --deletions`): for ONE session, a digest of
// every row identity the node still holds, per family. The org deletes the
// rows it holds for (pusher, SessionID) whose identity digest is absent and
// whose node_rev is older than NodeRev.
//
// A nil list means "not described" and the org leaves that family alone; an
// empty non-nil list means the node holds no row of that family in the
// session. The node sends all three lists, always non-nil.
//
// Digests are ManifestDigest(family, key) with key = the row's source event
// id (actions, token_usage; a row without one is never listed and never
// deleted) or ManifestAPITurnKey (api_turns). The key deliberately leaves the
// source file out: the org's copy of that column depends on the node's share
// posture when it shipped, and a key that could differ between the two sides
// would delete a row the node still has. Coarser keys can only make the heal
// KEEP a row (a collision), never delete one the node holds.
type SessionManifest struct {
	SessionID string `json:"session_id"`
	NodeRev   int64  `json:"node_rev"`
	// NotBefore (RFC3339) is the oldest row time the org may delete through
	// this manifest: the node sets it inside its own retention horizon, so a
	// row the node aged out (node-local ageing, never a correction) can never
	// look deleted. The org deletes only rows whose timestamp parses and is at
	// or after it, and ignores a manifest without one.
	NotBefore  string   `json:"not_before"`
	Actions    []string `json:"actions"`
	TokenUsage []string `json:"token_usage"`
	APITurns   []string `json:"api_turns"`
}

// ManifestMaxRowsPerFamily bounds one SessionManifest family list and
// ManifestMaxRows the three together (about 19 wire bytes per digest, so a
// full manifest stays well inside half the default 1 MiB envelope). The node
// never sends a larger manifest (the session is reported and skipped) and the
// org ignores one over either bound.
const (
	ManifestMaxRowsPerFamily = 20000
	ManifestMaxRows          = 20000
)

// ManifestDigest is the 16-hex identity digest a SessionManifest lists for
// one row of family (a Deletion* table name) with identity key.
func ManifestDigest(family, key string) string {
	sum := sha256.Sum256([]byte("sbo-session-manifest-v1\x00" + family + "\x00" + key))
	return hex.EncodeToString(sum[:8])
}

// ManifestAPITurnKey is the api_turns manifest key: request id and timestamp
// (a request-less turn has an empty request id; its session is the manifest's
// own).
func ManifestAPITurnKey(requestID, timestamp string) string {
	return requestID + "\x00" + timestamp
}
