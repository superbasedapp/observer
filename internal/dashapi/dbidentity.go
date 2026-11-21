package dashapi

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"runtime"
	"strings"
)

// dbidentity.go is the one rule for "does this daemon serve my database"
// (decisions log L-125, "push-now reaches another daemon"). A CLI that hands
// work to the running daemon over its owner-local dashboard routes (push-now,
// the live-run question and its end, the live sandbox apply, the update
// apply, the config reload poke) used to dial whatever answered the
// dashboard address, and with no listen record beside its database that was
// the default 127.0.0.1:8081: a throwaway node with its own HOME had its
// push run by the operator's live daemon, against that daemon's database.
//
// The CLI now sends the identity of its database in DBIdentityRequestHeader;
// a daemon that knows its own database answers with its identity in
// DBIdentityHeader and refuses (409, DBMismatchCode) any request whose
// identity differs. DaemonHandoff is the table the CLI decides on.

// DBIdentityHeader is the response header in which a daemon names the
// identity of the database it serves. It is set only on a response to a
// request that carried DBIdentityRequestHeader, so a browser's responses are
// unchanged.
const DBIdentityHeader = "X-Observer-DB-Identity"

// DBIdentityRequestHeader is the request header in which a CLI names the
// identity of the database it acts on. A daemon serving another database
// refuses the request; a daemon that predates the header ignores it.
const DBIdentityRequestHeader = "X-Observer-Expect-DB-Identity"

// DBMismatchCode is the JSON error code of the 409 a daemon answers when
// the request names another database.
const DBMismatchCode = "db_identity_mismatch"

// DBIdentity is the identity of the database at dbPath: the first 16 bytes
// of the SHA-256 of its absolute, cleaned, slash-separated path (symlinks
// resolved when the file exists; case-folded on Windows, whose paths are
// case-insensitive), hex encoded. "" for an empty path. The path itself never
// leaves the process.
func DBIdentity(dbPath string) string {
	p := strings.TrimSpace(dbPath)
	if p == "" {
		return ""
	}
	if abs, err := filepath.Abs(p); err == nil {
		p = abs
	}
	if resolved, err := filepath.EvalSymlinks(p); err == nil {
		p = resolved
	}
	p = filepath.ToSlash(filepath.Clean(p))
	if runtime.GOOS == "windows" {
		p = strings.ToLower(p)
	}
	sum := sha256.Sum256([]byte(p))
	return hex.EncodeToString(sum[:16])
}

// DBMatch is what a CLI learned about the daemon at the dashboard address.
type DBMatch int

const (
	// DBNoDaemon: nothing listens at the address.
	DBNoDaemon DBMatch = iota
	// DBUnknown: something answered (or did not answer in time) without
	// naming its database: a daemon that predates the identity, or one
	// started without a database path.
	DBUnknown
	// DBSame: the daemon named this database.
	DBSame
	// DBOther: the daemon named another database, or refused this one.
	DBOther
)

// ClassifyDBIdentity turns the identity a daemon named (served, "" when it
// named none) into a DBMatch against want, this CLI's own identity.
func ClassifyDBIdentity(want, served string) DBMatch {
	switch {
	case served == "":
		return DBUnknown
	case want != "" && served == want:
		return DBSame
	default:
		return DBOther
	}
}

// daemonHandoffRule is one row of the handoff table. recordEvidence is
// whether this database carries local evidence of a daemon at that address:
// the listen record the daemon writes beside its database AND a live start
// lock for that database.
type daemonHandoffRule struct {
	match          DBMatch
	recordEvidence bool
	handoff        bool
	reason         string
}

// daemonHandoffRules is walked top-down; the first row whose match and
// evidence fit decides.
var daemonHandoffRules = []daemonHandoffRule{
	{DBNoDaemon, false, false, "no daemon listens"},
	{DBNoDaemon, true, false, "no daemon listens"},
	{DBSame, false, true, "the daemon serves this database"},
	{DBSame, true, true, "the daemon serves this database"},
	{DBOther, false, false, "the daemon there serves another database"},
	{DBOther, true, false, "the daemon there serves another database"},
	// An older daemon names no database. Its listen record beside this
	// database, with this database's start lock live, is the evidence the
	// CLI relied on before the identity existed, so it still hands off.
	{DBUnknown, true, true, "the daemon recorded beside this database does not name its database (an older build)"},
	// Without that evidence an unnamed daemon may serve any database (the
	// default port fallback): never hand it a mutation.
	{DBUnknown, false, false, "the daemon there does not name its database and none is recorded beside this one"},
}

// DaemonHandoff reports whether a CLI may hand work on its database to the
// daemon it found, and why.
func DaemonHandoff(match DBMatch, recordEvidence bool) (bool, string) {
	for _, r := range daemonHandoffRules {
		if r.match == match && r.recordEvidence == recordEvidence {
			return r.handoff, r.reason
		}
	}
	return false, "unrecognised daemon answer"
}
