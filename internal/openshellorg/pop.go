package openshellorg

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Domain tags of the signed messages (sections 4.6, 5.4 and 7.7). Each is
// distinct from every other signed message in Observer (the push signature,
// the intel rail, Agent Access), so a proof minted for one never verifies on
// another.
const (
	// DomainMint signs a mint, login, poll, logout, ended, hold, discard and
	// held request from a node.
	DomainMint = "sbo-openshell-mint-v1"
	// DomainFetch signs a member's fetch of their own collect.
	DomainFetch = "sbo-openshell-fetch-v1"
	// DomainFront signs the front's internal decide and event calls.
	DomainFront = "sbo-openshell-front-v1"
)

// Header names of the proofs.
const (
	// HeaderProof carries base64url(Ed25519 signature) by the node's agent
	// key over [NodeMessage].
	HeaderProof = "X-SBO-OpenShell-Proof"
	// HeaderProofTS carries the Unix-seconds time the node signed.
	HeaderProofTS = "X-SBO-OpenShell-TS"
	// HeaderFrontSignature carries the front's service-key signature over
	// [FrontMessage].
	HeaderFrontSignature = "X-SBO-OpenShell-Front-Signature"
	// HeaderFrontKey carries the base64 public key the front signed with.
	HeaderFrontKey = "X-SBO-OpenShell-Front-Key"
	// HeaderFrontTS carries the front's signing time.
	HeaderFrontTS = "X-SBO-OpenShell-Front-TS"
)

// ProofWindow is the accepted clock difference for every proof (120 s).
const ProofWindow = 120 * time.Second

// SafeID reports whether s can be a field of a signed message: non-empty, at
// most 128 bytes, and no control character or the field separator.
func SafeID(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for _, r := range s {
		if r < 0x21 || r == 0x7f || r == '|' {
			return false
		}
	}
	return true
}

func bodyDigest(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// NodeMessage is the canonical message a node signs with its agent key for a
// mint (purpose one of the mint purposes) or another node route (purpose the
// route's verb: login, poll, logout, ended, hold, discard, held):
// domain || org id || run id || purpose || ts || sha256(body), joined by "\n".
// The node and the server derive it through this one helper.
func NodeMessage(domain, orgID, runID, purpose string, ts int64, body []byte) []byte {
	return []byte(strings.Join([]string{domain, orgID, runID, purpose, strconv.FormatInt(ts, 10), bodyDigest(body)}, "\n"))
}

// FrontMessage is the canonical message the front signs with its service key
// for an internal call: domain || method || path || replica || ts ||
// sha256(body).
func FrontMessage(method, path, replica string, ts int64, body []byte) []byte {
	return []byte(strings.Join([]string{DomainFront, method, path, replica, strconv.FormatInt(ts, 10), bodyDigest(body)}, "\n"))
}

// Fresh reports whether a signing time ts is within ProofWindow of now.
func Fresh(ts int64, now time.Time) bool {
	d := now.Unix() - ts
	if d < 0 {
		d = -d
	}
	return d <= int64(ProofWindow/time.Second)
}

// VerifyProof checks an Ed25519 signature over msg by pub. A malformed key or
// signature is a failure, never a panic.
func VerifyProof(pub ed25519.PublicKey, msg, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, msg, sig)
}

// ReplayCache remembers the proofs seen inside the window so a captured
// request cannot be replayed (rule T0). It is the one owner of that state; the
// zero value is ready.
type ReplayCache struct {
	mu   sync.Mutex
	seen map[string]int64
}

// Seen records key at ts and reports whether it was already present. Entries
// older than twice the window are dropped on each call.
func (c *ReplayCache) Seen(key string, ts int64, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.seen == nil {
		c.seen = make(map[string]int64)
	}
	cut := now.Add(-2 * ProofWindow).Unix()
	for k, v := range c.seen {
		if v < cut {
			delete(c.seen, k)
		}
	}
	if _, ok := c.seen[key]; ok {
		return true
	}
	c.seen[key] = ts
	return false
}

// ReplayKey is the replay-cache key of a node proof (G2-A3): the caller's
// scope (org, member and node), the run id, the purpose, the time and the
// body digest. Two members, or two nodes of one member, signing in the same
// second never collide; a byte-identical request replayed inside the window
// is refused.
func ReplayKey(org, member, node, runID, purpose string, ts int64, body []byte) string {
	return strings.Join([]string{org, member, node, runID, purpose, strconv.FormatInt(ts, 10), bodyDigest(body)}, "\n")
}
