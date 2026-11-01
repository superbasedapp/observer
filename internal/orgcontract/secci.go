package orgcontract

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// secci.go is the wire contract of org.security.ci (security plan 7.9 F2
// and 7.10, lane SEC-F2B): node key enrolment over the enrolled channel,
// the org's countersign on a change record it received, the signed CI
// policy a CI job fetches with the scoped CI credential, and the signed
// change record lookup answer. Every signed message is domain separated
// and length prefixed (writeLPField), so no signature here can be replayed
// as another kind, another org or another version. The key certificate
// itself is internal/secchange.Certificate (domain sbo-change-key-cert-v1),
// carried here as raw JSON so this package stays free of it.

// The domain tags of the org's signatures.
const (
	// CIPolicyDomain signs the CI policy document.
	CIPolicyDomain = "sbo-ci-policy-v1"
	// CILookupDomain signs a change record lookup answer.
	CILookupDomain = "sbo-ci-lookup-v1"
	// ChangeCountersignDomain signs the org's receipt of a change record.
	ChangeCountersignDomain = "sbo-change-countersign-v1"
	// ChangeKeyEnrolDomain is what a node signs with the key it enrols
	// (proof of possession).
	ChangeKeyEnrolDomain = "sbo-change-key-enrol-v1"
)

// The org.security.ci routes. The agent route sits behind the enrolment
// bearer; the CI routes behind a CI credential (an ingest credential whose
// only resource is CIScopeVerify).
const (
	AgentChangeKeyPath = "/api/agent/security/change-key"
	CIPolicyPath       = "/api/ci/security/policy"
	CILookupPath       = "/api/ci/security/change-records"
	// CIContentPath + "{kind}/{file}" serves the org's mirrored security
	// content (a pinned CI driver) to a CI credential.
	CIContentPath = "/api/ci/security/content/"
	// CIScopeVerify is the CI credential's one resource.
	CIScopeVerify = "ci:verify"
)

// Caps.
const (
	// MaxChangeEnvelopeBytes caps an envelope on the wire.
	MaxChangeEnvelopeBytes = 64 << 10
	// MaxCILookupCommits caps the commits one lookup asks for.
	MaxCILookupCommits = 500
	// MaxCIRecordsPerCommit caps the records one commit's answer carries.
	MaxCIRecordsPerCommit = 8
	// MaxCIVerifyPolicyBytes caps the verify policy text in the CI policy.
	MaxCIVerifyPolicyBytes = 64 << 10
	// MaxCIDocumentBytes caps a signed CI document.
	MaxCIDocumentBytes = 32 << 20
	// CIKeyCertificateDays is a node key certificate's validity.
	CIKeyCertificateDays = 90
)

// ChangePatchFPHash is the wire's opaque patch fingerprint: a domain
// separated digest a CI job computes from the commit it checks, the lookup
// key when the node did not ship the commit sha. "" for no fingerprint.
func ChangePatchFPHash(fp string) string {
	if fp == "" {
		return ""
	}
	sum := sha256.Sum256([]byte("sbo-change-patch-v1\x00" + fp))
	return hex.EncodeToString(sum[:])
}

// changeEnvelopeShape is the DSSE envelope's JSON shape, checked only for
// form on the wire (the org verifies the signature itself).
type changeEnvelopeShape struct {
	PayloadType string `json:"payloadType"`
	Payload     string `json:"payload"`
	Signatures  []struct {
		KeyID string `json:"keyid"`
		Sig   string `json:"sig"`
	} `json:"signatures"`
}

// NormalizeChangeEnvelope keeps an envelope that is one JSON object of the
// DSSE shape within the cap, compacted; anything else is "".
func NormalizeChangeEnvelope(env string) string {
	if env == "" || len(env) > MaxChangeEnvelopeBytes || !utf8.ValidString(env) {
		return ""
	}
	var e changeEnvelopeShape
	dec := json.NewDecoder(strings.NewReader(env))
	if dec.Decode(&e) != nil || dec.More() || e.PayloadType == "" || e.Payload == "" || len(e.Signatures) == 0 || len(e.Signatures) > 4 {
		return ""
	}
	// Re-encode from the known shape, so an unknown top-level (or
	// signature) field never reaches the server's store (lane SEC-F2B audit
	// finding 7). The DSSE signature is over the payload, not these bytes.
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if enc.Encode(e) != nil {
		return ""
	}
	return strings.TrimSuffix(buf.String(), "\n")
}

// ChangeKeyEnrolRequest registers a node's change record signing key with
// the org (security plan 7.10 "Key enrolment"). Proof is the key's own
// Ed25519 signature over ChangeKeyEnrolMessage, so only the key's holder
// can enrol it.
type ChangeKeyEnrolRequest struct {
	KeyID           string `json:"key_id"`
	PublicKey       string `json:"public_key"`
	MachineIdentity string `json:"machine_identity"`
	At              string `json:"at"`
	Proof           string `json:"proof"`
}

// ChangeKeyEnrolMessage is what the enrolling key signs.
func ChangeKeyEnrolMessage(orgID, keyID, publicKey, machine, at string) []byte {
	var b bytes.Buffer
	b.WriteString(ChangeKeyEnrolDomain)
	b.WriteByte(0)
	for _, f := range []string{orgID, keyID, publicKey, machine, at} {
		writeLPField(&b, f)
	}
	return b.Bytes()
}

// ChangeKeyOrgRoot is the org root a certificate was issued under.
type ChangeKeyOrgRoot struct {
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"`
}

// ChangeKeyEnrolResponse carries the signed key certificate
// (internal/secchange.Certificate as JSON) and the org root that issued it.
type ChangeKeyEnrolResponse struct {
	Certificate json.RawMessage  `json:"certificate"`
	OrgRoot     ChangeKeyOrgRoot `json:"org_root"`
}

// The countersign key states.
const (
	CountersignKeyCertified   = "org_certified"
	CountersignKeyNotEnrolled = "key_not_enrolled"
)

// ChangeCountersign is the org's signed receipt of one change record: an
// enrolled node reported this record at ReceivedAt (plan 7.10 "Time and
// receipt"; it never proves the record is true, TAMPER-3). Envelope says
// whether the org held the signed envelope and checked it ("checked") or
// only the digest ("missing").
type ChangeCountersign struct {
	OrgID              string `json:"org_id"`
	KeyID              string `json:"key_id"`
	RecordDigest       string `json:"record_digest"`
	CommitIdentityHash string `json:"commit_identity_hash"`
	PatchFPHash        string `json:"patch_fp_hash"`
	ReceivedAt         string `json:"received_at"`
	KeyStatus          string `json:"key_status"`
	Envelope           string `json:"envelope"`
	IssuerKeyID        string `json:"issuer_key_id"`
	Signature          string `json:"signature,omitempty"`
}

// The countersign envelope states.
const (
	CountersignEnvelopeChecked = "checked"
	CountersignEnvelopeMissing = "missing"
)

// ChangeCountersignMessage is what the org signs for a countersign.
func ChangeCountersignMessage(c ChangeCountersign) []byte {
	var b bytes.Buffer
	b.WriteString(ChangeCountersignDomain)
	b.WriteByte(0)
	for _, f := range []string{c.OrgID, c.KeyID, c.RecordDigest, c.CommitIdentityHash, c.PatchFPHash, c.ReceivedAt, c.KeyStatus, c.Envelope, c.IssuerKeyID} {
		writeLPField(&b, f)
	}
	return b.Bytes()
}

// CIKeyID is the key id of an org key: the first 16 bytes of SHA-256 of the
// public key, in hex (the change record key id convention).
func CIKeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:16])
}

// SignChangeCountersign signs c with the org key.
func SignChangeCountersign(c ChangeCountersign, priv ed25519.PrivateKey) ChangeCountersign {
	pub, _ := priv.Public().(ed25519.PublicKey)
	c.IssuerKeyID, c.Signature = CIKeyID(pub), ""
	c.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, ChangeCountersignMessage(c)))
	return c
}

// ErrCISignature is wrapped by every signature check here.
var ErrCISignature = errors.New("orgcontract: org signature does not verify")

// VerifyChangeCountersign checks c against the org key pub.
func VerifyChangeCountersign(c ChangeCountersign, pub ed25519.PublicKey) error {
	if c.IssuerKeyID != CIKeyID(pub) {
		return fmt.Errorf("%w: countersign issued by another key", ErrCISignature)
	}
	sig, err := base64.StdEncoding.Strict().DecodeString(c.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("%w: countersign signature encoding", ErrCISignature)
	}
	c.Signature = ""
	if !ed25519.Verify(pub, ChangeCountersignMessage(c), sig) {
		return fmt.Errorf("%w: countersign", ErrCISignature)
	}
	return nil
}

// CIPolicy is the org's CI policy body (plan 7.9 "Policy from a protected
// rail"): the verify policy text (the F1 TOML), the provenance floor, the
// bounded wait for records, and the keys file (internal/secchange.TrustFile
// as JSON: the org root, the live key certificates and the revocation
// list). Version is monotonic per org; ExpiresAt bounds a fetched copy.
type CIPolicy struct {
	OrgID           string          `json:"org_id"`
	Version         int64           `json:"version"`
	IssuedAt        string          `json:"issued_at"`
	ExpiresAt       string          `json:"expires_at"`
	ProvenanceFloor string          `json:"provenance_floor"`
	WaitSeconds     int             `json:"wait_seconds"`
	VerifyPolicy    string          `json:"verify_policy,omitempty"`
	Keys            json.RawMessage `json:"keys"`
}

// CISignedDocument is a signed CI document: the body bytes as sent (JSON),
// the issuing org key and its signature over CIDocumentMessage.
type CISignedDocument struct {
	Body        json.RawMessage `json:"body"`
	IssuerKeyID string          `json:"issuer_key_id"`
	Signature   string          `json:"signature"`
}

// CIDocumentMessage is what the org signs for a CI document: the domain,
// the org, a version (the policy version; 0 for a lookup answer) and the
// digest of the body bytes.
func CIDocumentMessage(domain, orgID string, version int64, body []byte) []byte {
	sum := sha256.Sum256(body)
	var b bytes.Buffer
	b.WriteString(domain)
	b.WriteByte(0)
	writeLPField(&b, orgID)
	writeLPField(&b, strconv.FormatInt(version, 10))
	writeLPField(&b, hex.EncodeToString(sum[:]))
	return b.Bytes()
}

// SignCIDocument signs body under domain.
func SignCIDocument(domain, orgID string, version int64, body []byte, priv ed25519.PrivateKey) CISignedDocument {
	pub, _ := priv.Public().(ed25519.PublicKey)
	return CISignedDocument{
		Body: append(json.RawMessage(nil), body...), IssuerKeyID: CIKeyID(pub),
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, CIDocumentMessage(domain, orgID, version, body))),
	}
}

// VerifyCIDocument checks d under domain, orgID and version against pub.
func VerifyCIDocument(domain, orgID string, version int64, d CISignedDocument, pub ed25519.PublicKey) error {
	if len(d.Body) > MaxCIDocumentBytes {
		return fmt.Errorf("%w: document over its cap", ErrCISignature)
	}
	if d.IssuerKeyID != CIKeyID(pub) {
		return fmt.Errorf("%w: issued by another key", ErrCISignature)
	}
	sig, err := base64.StdEncoding.Strict().DecodeString(d.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("%w: signature encoding", ErrCISignature)
	}
	if !ed25519.Verify(pub, CIDocumentMessage(domain, orgID, version, d.Body), sig) {
		return fmt.Errorf("%w: %s", ErrCISignature, domain)
	}
	return nil
}

// CILookupRequest asks for the change records of up to MaxCILookupCommits
// commits: by commit sha (matched where the node shipped it) and by patch
// fingerprint hash (ChangePatchFPHash; matched otherwise, and after a
// rebase).
type CILookupRequest struct {
	Commits []CILookupCommit `json:"commits"`
}

// CILookupCommit is one commit asked about.
type CILookupCommit struct {
	SHA         string `json:"sha"`
	PatchFPHash string `json:"patch_fp_hash,omitempty"`
}

// CILookupAnswer is the lookup answer's body.
type CILookupAnswer struct {
	OrgID      string                 `json:"org_id"`
	AnsweredAt string                 `json:"answered_at"`
	Commits    []CILookupCommitAnswer `json:"commits"`
}

// CILookupCommitAnswer is one commit's records.
type CILookupCommitAnswer struct {
	SHA         string           `json:"sha"`
	PatchFPHash string           `json:"patch_fp_hash,omitempty"`
	Records     []CILookupRecord `json:"records"`
}

// The lookup match kinds.
const (
	CIMatchCommitSHA = "commit_sha"
	CIMatchPatchFP   = "patch_fp_hash"
)

// The ingest states of a stored record (ChangeIngestStates).
const (
	ChangeIngestCountersigned = "countersigned"
	ChangeIngestPending       = "pending_countersign"
	ChangeIngestReplay        = "refused_replay"
	ChangeIngestBinding       = "refused_binding"
	ChangeIngestSignature     = "refused_signature"
	ChangeIngestRevoked       = "refused_revoked_key"
	// ChangeIngestClaimConflict: a VERIFIED record from another certified
	// key for a commit that already has one (lane SEC-P4 decision 8,
	// SECP-31). It is not a replay: either key may be the commit's own
	// (an insider's certified key can claim a colleague's sha first), so
	// it is kept without a countersign and the CI step picks between the
	// two by the commit's committer or author (CILookupRecord.MemberHash).
	ChangeIngestClaimConflict = "claim_conflict"
)

// ChangeKeyMachineNotOnRecord is the key enrolment's error code for a
// member with no machine on record yet (no managed bind and no push): the
// node retries after its first push (lane SEC-P4 decision 8).
const ChangeKeyMachineNotOnRecord = "machine_not_on_record"

// ChangeIngestStates is the closed state vocabulary.
var ChangeIngestStates = []string{ChangeIngestCountersigned, ChangeIngestPending, ChangeIngestReplay, ChangeIngestBinding, ChangeIngestSignature, ChangeIngestRevoked, ChangeIngestClaimConflict}

// CILookupRecord is one stored record that may speak for a commit.
type CILookupRecord struct {
	RecordDigest string `json:"record_digest"`
	KeyID        string `json:"key_id"`
	MatchedBy    string `json:"matched_by"`
	State        string `json:"state"`
	// Envelope is the DSSE envelope the node shipped ("" when it did not:
	// the CI step then reads envelope_missing).
	Envelope    string             `json:"envelope,omitempty"`
	Countersign *ChangeCountersign `json:"countersign,omitempty"`
	// MemberHash is ChangeMemberEmailHash of the email of the member the
	// record's key is certified to ("" for a key the org did not certify,
	// or a member with no email on record). The answer is org-signed, so
	// the CI step reads it as the org's word (lane SEC-P4 decision 8; on a
	// managed node the member is already known to the org, P-089, so no
	// new privacy class).
	MemberHash string `json:"member_hash,omitempty"`
}

// changeMemberHashDomain separates the member email hash from every other
// hash of an email.
const changeMemberHashDomain = "sbo-change-member-v1\x00"

// ChangeMemberEmailHash is the hex SHA-256 of an email, trimmed and lower
// case, under the change-record member domain: the org hashes the certified
// key's member, the CI step a commit's committer and author, and the two
// compare equal for the same address. "" for an empty email.
func ChangeMemberEmailHash(email string) string {
	e := strings.ToLower(strings.TrimSpace(email))
	if e == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(changeMemberHashDomain + e))
	return hex.EncodeToString(sum[:])
}

// ciSHAShape is a full commit sha.
var ciSHAShape = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)

// NormalizeCILookupRequest bounds a lookup request: shaped shas and hashes
// only, at most MaxCILookupCommits, duplicates dropped. ok=false for an
// empty or oversized request.
func NormalizeCILookupRequest(r CILookupRequest) (CILookupRequest, bool) {
	if len(r.Commits) == 0 || len(r.Commits) > MaxCILookupCommits {
		return CILookupRequest{}, false
	}
	out := CILookupRequest{Commits: make([]CILookupCommit, 0, len(r.Commits))}
	seen := map[string]bool{}
	for _, c := range r.Commits {
		sha := strings.ToLower(strings.TrimSpace(c.SHA))
		if !ciSHAShape.MatchString(sha) || seen[sha] {
			continue
		}
		seen[sha] = true
		out.Commits = append(out.Commits, CILookupCommit{SHA: sha, PatchFPHash: secShaped(c.PatchFPHash, secHexShape, maxSecIDLen)})
	}
	return out, len(out.Commits) > 0
}
