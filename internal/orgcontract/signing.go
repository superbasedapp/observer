package orgcontract

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"sort"
	"strconv"
)

// Per-push proof headers. In addition to the possession-based bearer, every
// push carries an Ed25519 signature made with the agent's private key (whose
// public half was bound to the user record at enrolment). The server verifies
// the signature against that bound key, which defends against a stolen bearer
// being replayed by a party that does not also hold the agent's private key.
const (
	// HeaderAgentSignature carries base64url(Ed25519 signature) over the
	// canonical message from [PushSigningMessage].
	HeaderAgentSignature = "X-SBO-Agent-Signature"
	// HeaderTimestamp carries the Unix-seconds time the push was signed. The
	// server rejects pushes whose timestamp is outside ±[PushSignatureSkewSeconds]
	// to bound replay.
	HeaderTimestamp = "X-SBO-Timestamp"
	// PushSignatureSkewSeconds is the allowed clock skew for HeaderTimestamp.
	PushSignatureSkewSeconds int64 = 300
)

// PushSigningMessage returns the canonical bytes the agent signs and the
// server verifies: the signing timestamp (Unix seconds) and the SHA-256 of
// the exact body bytes on the wire (the gzip-compressed payload). Binding the
// signature to both the body hash and the timestamp makes a captured push
// non-replayable and tamper-evident. Client and server MUST derive the message
// identically — this single helper is the shared source of truth.
func PushSigningMessage(unixTimestamp int64, wireBody []byte) []byte {
	sum := sha256.Sum256(wireBody)
	return []byte(strconv.FormatInt(unixTimestamp, 10) + "\n" + hex.EncodeToString(sum[:]))
}

// Org-served Cloud Intelligence result-rail signing
// (docs/plans/org-served-cloud-intelligence-plan-2026-09-10.md §2.5; adversarial
// finding 1). The intel RESULT rail reuses the judge-relay AUTH SHAPE (enrolment
// bearer + per-request Ed25519 proof + skew + audience) but MUST NOT reuse its
// signing MESSAGE: JudgeRelay signs PushSigningMessage(ts, body), so a captured
// judge-relay proof inside the skew window could otherwise be replayed as an
// intel GET (and vice versa). This rail's proof is DOMAIN-SEPARATED and binds
// the request's method, path, canonical query and the org (audience) id, so a
// signature minted for one rail can never verify on the other. Client and
// server MUST derive it through these shared helpers — the PushSigningMessage
// precedent.

// intelRailSigningDomain domain-separates intel-rail proofs from every other
// Ed25519 use in the protocol, most importantly PushSigningMessage (which binds
// only ts + body hash and is what the judge relay signs).
const intelRailSigningDomain = "sbo-intel-rail-v1"

// IntelResultsPath is the fixed path of the agent RESULT rail. BOTH the node
// signer and the server verifier bind this CONSTANT (not the received
// r.URL.Path) into the proof, so a reverse proxy that rewrites the path cannot
// break verification and the two sides can never disagree on the bound value.
const IntelResultsPath = "/api/agent/intel/results"

// IntelRailCanonicalQuery returns the canonical, order-independent encoding of
// the intel rail's query parameters (since, limit) that BOTH the node and the
// server bind into the signing message, and that the node also uses to build
// the request URL — so the signed bytes and the wire query derive from one
// function and can never drift. An empty since and a non-positive limit yield
// the empty string (the no-cursor first page).
func IntelRailCanonicalQuery(since string, limit int) string {
	v := url.Values{}
	if since != "" {
		v.Set("since", since)
	}
	if limit > 0 {
		v.Set("limit", strconv.Itoa(limit))
	}
	return v.Encode()
}

// IntelRailSigningMessage returns the canonical bytes signed over one intel
// RESULT-rail request: SHA-256 over
//
//	domain || 0x00 || decimal(ts) || 0x00 || method || 0x00 || path ||
//	0x00 || canonicalQuery || 0x00 || orgID
//
// The NUL separators make the encoding unambiguous. Binding method/path/query/
// org domain-separates this proof from PushSigningMessage, which is exactly the
// replay the adversarial review flagged: a judge-relay proof (ts + body hash)
// can never satisfy this message, and this proof can never satisfy the judge
// relay's.
func IntelRailSigningMessage(ts int64, method, path, canonicalQuery, orgID string) []byte {
	h := sha256.New()
	h.Write([]byte(intelRailSigningDomain))
	h.Write([]byte{0})
	h.Write([]byte(strconv.FormatInt(ts, 10)))
	h.Write([]byte{0})
	h.Write([]byte(method))
	h.Write([]byte{0})
	h.Write([]byte(path))
	h.Write([]byte{0})
	h.Write([]byte(canonicalQuery))
	h.Write([]byte{0})
	h.Write([]byte(orgID))
	return h.Sum(nil)
}

// Policy-bundle signing (guard spec §14.2). The org server signs every
// published bundle with a dedicated Ed25519 policy key (distinct from the
// bearer signing key — different rotation and exposure profiles); the agent
// verifies against the public key pinned at enrolment before any rule from
// the bundle can join its policy. Client and server MUST derive the canonical
// message identically — these helpers are the shared source of truth, exactly
// like PushSigningMessage above.

// policyBundleSigningPrefix domain-separates bundle signatures from every
// other Ed25519 use in the protocol (bearer envelopes, push proofs): a
// signature minted for one purpose can never verify for another.
const policyBundleSigningPrefix = "sbo-policy-bundle-v1"

// PolicyBundleSigningMessage returns the canonical bytes signed over a policy
// bundle: a fixed domain prefix, the bundle version, and the SHA-256 of the
// exact TOML bytes. Binding the version into the message means a captured
// signature for version N can never be replayed as a different version — a
// downgrade must present version N itself, which the agent's monotonic
// version check rejects.
func PolicyBundleSigningMessage(version int64, bundleTOML []byte) []byte {
	sum := sha256.Sum256(bundleTOML)
	return []byte(policyBundleSigningPrefix + "\n" +
		strconv.FormatInt(version, 10) + "\n" + hex.EncodeToString(sum[:]))
}

// SignPolicyBundle signs the canonical bundle message and returns the
// base64url signature in the wire encoding PolicyBundle.Signature carries.
// The server's publish path is the only caller.
func SignPolicyBundle(priv ed25519.PrivateKey, version int64, bundleTOML []byte) string {
	sig := ed25519.Sign(priv, PolicyBundleSigningMessage(version, bundleTOML))
	return base64.RawURLEncoding.EncodeToString(sig)
}

// VerifyPolicyBundle checks a bundle envelope's signature against its own
// embedded public key: it decodes PublicKey and Signature from their wire
// encodings and verifies over the canonical message. It deliberately does NOT
// decide whether the embedded key is TRUSTED — callers compare
// sha256hex(decoded key) against their pinned hash (the agent's
// guard_policy_state pin row) before or after this check; the two checks
// together are the §14.2 acceptance gate. Returns the decoded public key so
// callers can hash-pin it without re-decoding.
func VerifyPolicyBundle(b PolicyBundle) (ed25519.PublicKey, error) {
	pub, err := base64.RawURLEncoding.DecodeString(b.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("orgcontract.VerifyPolicyBundle: decode public key: %w", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("orgcontract.VerifyPolicyBundle: public key is %d bytes, want %d", len(pub), ed25519.PublicKeySize)
	}
	sig, err := base64.RawURLEncoding.DecodeString(b.Signature)
	if err != nil {
		return nil, fmt.Errorf("orgcontract.VerifyPolicyBundle: decode signature: %w", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), PolicyBundleSigningMessage(b.Version, []byte(b.BundleTOML)), sig) {
		return nil, errors.New("orgcontract.VerifyPolicyBundle: signature verification failed")
	}
	return ed25519.PublicKey(pub), nil
}

// PublicKeyPinHash returns the sha256 hex of raw Ed25519 public-key bytes —
// the value pinned in the agent's guard_policy_state key-pin row and compared
// on every fetched bundle. One helper so enrolment pinning, fetch-time
// checking, and tests can never disagree on the hash recipe.
func PublicKeyPinHash(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])
}

// Org-announcement signing (rail R3 of
// docs/plans/dashboard-announcements-banner-plan-2026-07-31.md §4).
// Same discipline as the policy bundle above and for the same reasons:
// the signature covers a DOMAIN-SEPARATED, VERSION-BOUND message, never
// the bare body bytes. Client and server derive it through this one
// helper.

// announcementSigningDomain domain-separates announcement signatures
// from every other Ed25519 use in the protocol — and specifically from
// the routing-policy rail, which is signed by the SAME org key
// (orgserver/routingpolicy.SigningKey). Without the tag, a captured
// routing-policy document could be presented as an announcement (its
// signature is over the bare body there), so this constant is what
// makes one signing identity safe across two rails.
const announcementSigningDomain = "superbased-org-announcement"

// AnnouncementSigningMessage returns the canonical bytes signed over an
// org announcement document: SHA-256 over
//
//	domain || 0x00 || decimal(version) || 0x00 || body
//
// The NUL separators make the encoding unambiguous (the version is
// decimal digits, so no body can shift the boundary), and binding the
// version means a captured signature for version N can never be
// replayed as version N+1 — which is the whole attack the agent's
// monotonic-version short-circuit would otherwise hand an eavesdropper:
// bump the version on any captured signed document and the node caches
// it, freezing (or clearing) the fleet's banner.
//
// The rail is UNRELEASED, which is why this could be fixed in place
// rather than carried as a compat wart the way the routing rail's
// body-only signature is (docs/security.md open ledger).
func AnnouncementSigningMessage(version int64, body string) []byte {
	h := sha256.New()
	h.Write([]byte(announcementSigningDomain))
	h.Write([]byte{0})
	h.Write([]byte(strconv.FormatInt(version, 10)))
	h.Write([]byte{0})
	h.Write([]byte(body))
	return h.Sum(nil)
}

// Routing-policy signing, VERSION 2 (docs/security.md ledger
// ROUTING-SIG-1, closed 2026-08-20). The v1 signature on this rail
// covers the BODY BYTES ALONE ([VerifySignedBody]) — not the version,
// not the rail — which let a party able to serve
// GET /api/agent/routing-policy replay a genuinely signed OLD body under
// an INFLATED version and freeze a node's cache against every later
// genuine publish (the agent's monotonic `cached.Version >= doc.Version`
// short-circuit does the rest).
//
// The rail is RELEASED, so v1 could not be changed in place: a new agent
// would reject every old server's policy and vice versa. v2 is therefore
// CARRIED ALONGSIDE — the server mints both, the agent prefers v2 when
// the document offers one — exactly the versioned migration the ledger
// row prescribed.
//
// The message shape mirrors [AnnouncementSigningMessage] byte-for-byte
// in composition style, with a DIFFERENT domain tag, so a signature
// minted on either rail can never verify on the other even though ONE
// org key (orgserver/routingpolicy.SigningKeyWith — the org's configured
// key file when there is one, the database row otherwise) signs both.

// routingPolicySigningV2Domain domain-separates v2 routing-policy
// signatures from every other Ed25519 use in the protocol — including
// this rail's own v1 (bare body bytes) and the announcement rail
// ([announcementSigningDomain]).
const routingPolicySigningV2Domain = "sbo-routing-policy-v2"

// RoutingPolicySigningMessageV2 returns the canonical bytes signed over a
// routing-policy document on the v2 rail: SHA-256 over
//
//	domain || 0x00 || decimal(version) || 0x00 || body
//
// The NUL separators make the encoding unambiguous (the version is
// decimal digits, so no body can shift the boundary), and binding the
// VERSION is the whole point: a signature minted for version N cannot be
// presented at version N+1, which is precisely the cache-freezing replay
// ROUTING-SIG-1 recorded.
func RoutingPolicySigningMessageV2(version int64, body string) []byte {
	h := sha256.New()
	h.Write([]byte(routingPolicySigningV2Domain))
	h.Write([]byte{0})
	h.Write([]byte(strconv.FormatInt(version, 10)))
	h.Write([]byte{0})
	h.Write([]byte(body))
	return h.Sum(nil)
}

// SignRoutingPolicyV2 signs the canonical v2 message and returns the
// base64 (std encoding, matching this rail's v1 field) signature the
// RoutingPolicyDoc.SignatureV2 field carries. The org server's publish
// path is the only caller.
func SignRoutingPolicyV2(priv ed25519.PrivateKey, version int64, body string) string {
	return base64.StdEncoding.EncodeToString(
		ed25519.Sign(priv, RoutingPolicySigningMessageV2(version, body)),
	)
}

// DecodeCapped decodes exactly ONE JSON value from r into v under a hard
// byte cap, refusing both anything past that value and a document that
// reaches the cap.
//
// It exists because `json.NewDecoder(io.LimitReader(body, cap)).Decode`
// — the shape both org-announcement endpoints used — enforces neither
// property it looks like it enforces:
//
//   - Trailing bytes: Decode stops at the end of the first JSON value,
//     so a document followed by a second document, or by megabytes of
//     padding, decodes "successfully". Here the token stream must end
//     at EOF. Trailing whitespace is fine (json.Encoder writes a
//     newline); anything else is an error.
//   - Cap exhaustion: io.LimitReader simply stops producing bytes,
//     which a decoder can read as a clean end of input. Here the budget
//     is cap+1 bytes and exhausting it is an explicit error, so the cap
//     is a document cap and not merely a read cap.
func DecodeCapped(r io.Reader, maxBytes int64, v any) error {
	if maxBytes <= 0 {
		return fmt.Errorf("orgcontract.DecodeCapped: cap must be positive, got %d", maxBytes)
	}
	limited := &io.LimitedReader{R: r, N: maxBytes + 1}
	dec := json.NewDecoder(limited)
	err := dec.Decode(v)
	if limited.N <= 0 {
		return fmt.Errorf("orgcontract.DecodeCapped: document exceeds the %d-byte cap", maxBytes)
	}
	if err != nil {
		return fmt.Errorf("orgcontract.DecodeCapped: %w", err)
	}
	if _, terr := dec.Token(); !errors.Is(terr, io.EOF) {
		return fmt.Errorf("orgcontract.DecodeCapped: trailing bytes after the document")
	}
	return nil
}

// Policy-resource signing (Plane-A P0-5 unified policy resource,
// docs/plane-a/unified-policy-resource.md §6;
// docs/plans/plane-a-p0-5-unified-policy-resource-v1-plan.md §4.2). Domain-
// separated from every other Ed25519 use in this file, including
// PolicyBundle's dedicated policy-signing key use above: the message
// SHAPES differ (length-prefixed multi-field vs newline-delimited
// version+hash), so a signature minted for one rail can never verify on
// the other even if an operator ever pointed both rails at the same key
// bytes.

// policyResourceSigningDomain is the fixed prefix opening every
// PolicyResourceSigningMessage.
const policyResourceSigningDomain = "sbo-policy-resource-v1"

// policyResourceCapabilityPattern is the v1 capability-token grammar (plan
// §4.2): lowercase, starts with a letter, then letters/digits/underscore/dot,
// at most 64 characters total. It structurally excludes newlines and every
// other framing-hostile byte, so a malformed token is rejected before it
// ever reaches the signing message.
var policyResourceCapabilityPattern = regexp.MustCompile(`^[a-z][a-z0-9_.]{0,63}$`)

const (
	// MaxPolicyResourceCapabilities bounds the capability list to a small,
	// reviewable set (plan §4.2).
	MaxPolicyResourceCapabilities = 32
	// MaxPolicyResourceCapabilitiesBytes bounds the AGGREGATE size of the
	// capability list (plan §4.2) — a defense-in-depth cap independent of
	// the per-token length limit the grammar already implies.
	MaxPolicyResourceCapabilitiesBytes = 2048
	// MaxPolicyResourceDescriptionBytes is the dedicated publish-time
	// description size cap (plan §4.2 "description size cap at publish";
	// Codex SF8). Description is unsigned display metadata — still bounded
	// so a publish request cannot park unbounded text in org_policy_resources.
	MaxPolicyResourceDescriptionBytes = 4096
)

// NormalizeCapabilities validates, deduplicates, and sorts a capability list
// under the v1 grammar + size caps (plan §4.2). PolicyResourceSigningMessage
// calls this so the signer and every verifier always derive the IDENTICAL
// canonical capability list from the same logical set, regardless of the
// order or duplication the caller passed in — and so a capability
// containing a newline (or any other grammar violation) is rejected before
// it can ever reach the signed message.
func NormalizeCapabilities(caps []string) ([]string, error) {
	if len(caps) == 0 {
		return nil, nil
	}
	seen := make(map[string]bool, len(caps))
	out := make([]string, 0, len(caps))
	total := 0
	for _, c := range caps {
		if !policyResourceCapabilityPattern.MatchString(c) {
			return nil, fmt.Errorf("orgcontract.NormalizeCapabilities: capability %q fails the grammar ^[a-z][a-z0-9_.]{0,63}$", c)
		}
		if seen[c] {
			continue
		}
		seen[c] = true
		out = append(out, c)
		total += len(c)
	}
	if len(out) > MaxPolicyResourceCapabilities {
		return nil, fmt.Errorf("orgcontract.NormalizeCapabilities: %d distinct capabilities exceeds the %d-capability cap", len(out), MaxPolicyResourceCapabilities)
	}
	if total > MaxPolicyResourceCapabilitiesBytes {
		return nil, fmt.Errorf("orgcontract.NormalizeCapabilities: capability list is %d bytes, exceeds the %d-byte aggregate cap", total, MaxPolicyResourceCapabilitiesBytes)
	}
	sort.Strings(out)
	return out, nil
}

// writeLPField appends a length-prefixed field to buf: an 8-byte big-endian
// length followed by the raw bytes. Every field in
// PolicyResourceSigningMessage is framed this way so no field's content —
// including SelectorsJSON, which may contain arbitrary JSON — can shift a
// later field's boundary. This is stricter than PolicyBundleSigningMessage's
// newline-delimited encoding because SelectorsJSON is not grammar-constrained
// the way a bundle version number is.
func writeLPField(buf *bytes.Buffer, s string) {
	var lenBuf [8]byte
	binary.BigEndian.PutUint64(lenBuf[:], uint64(len(s)))
	buf.Write(lenBuf[:])
	buf.WriteString(s)
}

// PolicyResourceSigningMessage returns the canonical, length-prefixed,
// domain-separated bytes signed over a policy resource (plan §4.2). It
// binds ID, Version, Family, CompilerVersion, BodyHash (not Body itself —
// callers separately verify SHA-256(Body)==BodyHash, design §6),
// SelectorsJSON, and the NORMALIZED capability list. Binding Version means a
// captured signature for version N can never be replayed as a different
// version; binding the capability list and selectors means neither can be
// tampered post-signature without invalidating the signature (design §6:
// "the signing message covers targeting and capabilities, not just Body").
func PolicyResourceSigningMessage(id string, version int64, family, compilerVersion, bodyHash, selectorsJSON string, capabilities []string) ([]byte, error) {
	normCaps, err := NormalizeCapabilities(capabilities)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	buf.WriteString(policyResourceSigningDomain)
	writeLPField(&buf, id)
	writeLPField(&buf, strconv.FormatInt(version, 10))
	writeLPField(&buf, family)
	writeLPField(&buf, compilerVersion)
	writeLPField(&buf, bodyHash)
	writeLPField(&buf, selectorsJSON)
	writeLPField(&buf, strconv.Itoa(len(normCaps)))
	for _, c := range normCaps {
		writeLPField(&buf, c)
	}
	return buf.Bytes(), nil
}

// SignPolicyResource signs r's canonical message with priv and returns the
// base64url signature in the wire encoding SignedPolicyResource.Signature
// carries. The caller must set r.BodyHash = hex(SHA-256(r.Body)) beforehand
// — this function signs the message as given; it does not recompute or
// verify BodyHash (that is VerifyPolicyResource's job on the other end).
func SignPolicyResource(priv ed25519.PrivateKey, r SignedPolicyResource) (string, error) {
	msg, err := PolicyResourceSigningMessage(r.ID, r.Version, r.Family, r.CompilerVersion, r.BodyHash, r.SelectorsJSON, r.RequiredCapabilities)
	if err != nil {
		return "", fmt.Errorf("orgcontract.SignPolicyResource: %w", err)
	}
	sig := ed25519.Sign(priv, msg)
	return base64.RawURLEncoding.EncodeToString(sig), nil
}

// VerifyPolicyResource checks a resource's BodyHash against its own Body and
// its signature against its own embedded PublicKey. Like VerifyPolicyBundle,
// it deliberately does NOT decide whether the embedded key is TRUSTED —
// callers compare PublicKeyPinHash(decoded key) against their pinned hash
// before or after this check (the four-gate accept's gates 1+2, design §7).
// Returns the decoded public key so callers can hash-pin it without
// re-decoding.
func VerifyPolicyResource(r SignedPolicyResource) (ed25519.PublicKey, error) {
	sum := sha256.Sum256([]byte(r.Body))
	if hex.EncodeToString(sum[:]) != r.BodyHash {
		return nil, errors.New("orgcontract.VerifyPolicyResource: body hash mismatch")
	}
	pub, err := base64.RawURLEncoding.DecodeString(r.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("orgcontract.VerifyPolicyResource: decode public key: %w", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("orgcontract.VerifyPolicyResource: public key is %d bytes, want %d", len(pub), ed25519.PublicKeySize)
	}
	sig, err := base64.RawURLEncoding.DecodeString(r.Signature)
	if err != nil {
		return nil, fmt.Errorf("orgcontract.VerifyPolicyResource: decode signature: %w", err)
	}
	msg, err := PolicyResourceSigningMessage(r.ID, r.Version, r.Family, r.CompilerVersion, r.BodyHash, r.SelectorsJSON, r.RequiredCapabilities)
	if err != nil {
		return nil, fmt.Errorf("orgcontract.VerifyPolicyResource: %w", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), msg, sig) {
		return nil, errors.New("orgcontract.VerifyPolicyResource: signature verification failed")
	}
	return ed25519.PublicKey(pub), nil
}

// PolicyResourceMessageDigest returns
// hex(SHA-256(PolicyResourceSigningMessage(...))) — the "full message
// digest" the equal-version replay rule and the distribution ETag are keyed
// on (plan §4.2/§4.4/§6.3: "Equal-version short-circuit iff full message
// digest matches cached digest; else reject version_replay"). Binding the
// WHOLE signed message (not just Body) means a same-version republish that
// changes only capabilities/selectors is also caught, not just a changed
// Body.
func PolicyResourceMessageDigest(r SignedPolicyResource) (string, error) {
	msg, err := PolicyResourceSigningMessage(r.ID, r.Version, r.Family, r.CompilerVersion, r.BodyHash, r.SelectorsJSON, r.RequiredCapabilities)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(msg)
	return hex.EncodeToString(sum[:]), nil
}
