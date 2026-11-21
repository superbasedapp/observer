package openshellorg

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
)

// Request ids of every mutating gateway RPC (lane G3). OpenShell 0.1.6
// answers InvalidArgument "must be a nonzero hyphenated UUID (36
// characters)" to any other value (live checks G-L1 and G-L2, decision log
// OB-077 to OB-079), so every id the front and the worker send is an
// RFC 4122 version 4 UUID. RequestID (boxname.go) is the ledger's own
// derived id and is never sent to the gateway.

// uuidRE is the shape the gateway accepts: hyphenated, lowercase hex, the
// version nibble 4 and the RFC 4122 variant.
var uuidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// IsRequestUUID reports whether s is a version 4 UUID the gateway accepts.
func IsRequestUUID(s string) bool { return uuidRE.MatchString(s) }

// formatUUID stamps the version and variant bits into b and renders it.
func formatUUID(b [16]byte) string {
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// RandomRequestUUID is a fresh random version 4 UUID, for a mutation whose
// retry needs no replay (a stop, a start, a delete with allow_missing).
func RandomRequestUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:]) // never returns an error since Go 1.24
	return formatUUID(b)
}

// RunRequestUUID is the deterministic version 4 UUID of one operation of
// one run (for example "create"): a retried create carries the same id, so
// the gateway's 24 hour receipt replay makes it at most once (design 3.2
// step 5). It is derived from the org id, the box's ledger key and the
// operation, under its own domain tag.
func RunRequestUUID(orgID, boxRunID, op string) string {
	return derivedUUID("sbo-openshell-request-uuid-v1", orgID, boxRunID, op)
}

// BoxRequestUUID is the deterministic version 4 UUID of one operation on
// one box named by its workspace and box name: what the front holds (a
// decision carries no org id or ledger key). The box name is derived from
// the org and the run, so it is as unique as RunRequestUUID's pair; its
// own domain tag keeps the two families apart (G3-A16).
func BoxRequestUUID(workspace, boxName, op string) string {
	return derivedUUID("sbo-openshell-box-request-uuid-v1", workspace, boxName, op)
}

func derivedUUID(domain, a, b, op string) string {
	sum := sha256.Sum256([]byte(domain + "\n" + a + "\n" + b + "\n" + op))
	var u [16]byte
	copy(u[:], sum[:16])
	return formatUUID(u)
}
