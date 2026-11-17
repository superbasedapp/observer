package platformcontract

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
)

// This file is the additive M6.3 part of the v1 contract: the signed
// DOCUMENTS the control plane's document signer issues (plan 06 5.8.4 and
// 18.3.5; design docs/plans/managed-saas/m6.0-control-plane-design-2026-11-13.md
// 3.3 and 4.5). It fixes the envelope of each document - its domain tag, the
// signing input, the version rule and the key id - and the verification the
// tenant host calls. The entitlements body stays opaque here (its schema is
// M7b.1's); the availability body's three typed sections live in
// availability.go.
//
// Signing input, shared by every document kind and identical in layout to the
// pricing and display-policy rails (internal/orgcontract):
//
//	SHA-256( domain || 0x00 || scope || 0x00 || decimal(version) || 0x00 || body )
//
// signed with Ed25519. The domain tag is the kind's own, so a signature on one
// kind never verifies as another, nor as a host-API envelope (whose signing
// input is newline-joined, unhashed and starts with its own tag). The scope is
// the org id for an entitlements document and the fixed AvailabilityScope for
// the one platform-wide availability envelope. The version is bound
// explicitly, so a reader comparing versions compares a signed value.

// Document signing domains. Each is distinct from SigningDomain,
// ResponseSigningDomain and every orgcontract rail tag.
const (
	// EntitlementsSigningDomain tags an org's entitlements document (DR-71;
	// the same document is the self-hosted licence).
	EntitlementsSigningDomain = "sbo-entitlements-v1"
	// AvailabilitySigningDomain tags the platform availability envelope.
	AvailabilitySigningDomain = "sbo-availability-v1"
)

// AvailabilityScope is the scope an availability envelope is signed for: it is
// one platform-wide document, and its per-org rows live inside the body.
const AvailabilityScope = "platform"

// MaxDocumentBody bounds a document body (bytes).
const MaxDocumentBody = 128 << 10

// maxScopeLen bounds a document scope (an org id).
const maxScopeLen = 128

// DocumentKind is the closed vocabulary of signed documents.
type DocumentKind string

// Document kinds.
const (
	// KindEntitlements is an org's entitlements document.
	KindEntitlements DocumentKind = "entitlements"
	// KindAvailability is the platform availability envelope.
	KindAvailability DocumentKind = "availability"
)

// KnownDocumentKinds lists every DocumentKind.
func KnownDocumentKinds() []DocumentKind {
	return []DocumentKind{KindEntitlements, KindAvailability}
}

// Valid reports whether k is a known kind.
func (k DocumentKind) Valid() bool {
	_, ok := documentKindRuleFor(k)
	return ok
}

// documentKindRule is one row of the kind table: the domain tag and, for a
// platform-wide kind, the one scope it may be signed for ("" = an org id).
type documentKindRule struct {
	kind       DocumentKind
	domain     string
	fixedScope string
}

func documentKindRules() []documentKindRule {
	return []documentKindRule{
		{kind: KindEntitlements, domain: EntitlementsSigningDomain},
		{kind: KindAvailability, domain: AvailabilitySigningDomain, fixedScope: AvailabilityScope},
	}
}

func documentKindRuleFor(k DocumentKind) (documentKindRule, bool) {
	for _, r := range documentKindRules() {
		if r.kind == k {
			return r, true
		}
	}
	return documentKindRule{}, false
}

// Domain returns the kind's signing domain, or "" for an unknown kind.
func (k DocumentKind) Domain() string {
	r, _ := documentKindRuleFor(k)
	return r.domain
}

// Document errors.
var (
	// ErrDocumentKind means the kind is not a known DocumentKind.
	ErrDocumentKind = errors.New("platformcontract: unknown document kind")
	// ErrDocumentScope means the scope does not fit the kind.
	ErrDocumentScope = errors.New("platformcontract: document scope does not fit its kind")
	// ErrDocumentBody means the body is empty or over MaxDocumentBody.
	ErrDocumentBody = errors.New("platformcontract: document body empty or too large")
	// ErrDocumentVersion means a version is not positive (or a last-seen
	// version is negative).
	ErrDocumentVersion = errors.New("platformcontract: document version must be positive")
	// ErrVersionNotNewer means the version is not above the last one signed
	// or accepted for the same (kind, scope): an equal or older version.
	ErrVersionNotNewer = errors.New("platformcontract: document version is not newer than the last")
	// ErrUnknownDocumentKey means the key id is not in the verifier's key set.
	ErrUnknownDocumentKey = errors.New("platformcontract: document key id is not pinned")
)

// ValidateDocumentScope checks scope against kind: the fixed scope for a
// platform-wide kind; otherwise an org id of 1 to 128 printable ASCII
// characters with no space.
func ValidateDocumentScope(kind DocumentKind, scope string) error {
	r, ok := documentKindRuleFor(kind)
	if !ok {
		return fmt.Errorf("platformcontract.ValidateDocumentScope: %w", ErrDocumentKind)
	}
	if r.fixedScope != "" {
		if scope != r.fixedScope {
			return fmt.Errorf("platformcontract.ValidateDocumentScope: %s wants scope %q: %w", kind, r.fixedScope, ErrDocumentScope)
		}
		return nil
	}
	if scope == "" || len(scope) > maxScopeLen || scope == AvailabilityScope {
		return fmt.Errorf("platformcontract.ValidateDocumentScope: %w", ErrDocumentScope)
	}
	for i := 0; i < len(scope); i++ {
		if c := scope[i]; c <= ' ' || c > '~' {
			return fmt.Errorf("platformcontract.ValidateDocumentScope: %w", ErrDocumentScope)
		}
	}
	return nil
}

// versionRule is one row of the version table, walked top-down.
type versionRule struct {
	name   string
	refuse func(last, next int64) bool
	err    error
}

func versionRules() []versionRule {
	return []versionRule{
		{name: "next-positive", refuse: func(_, next int64) bool { return next <= 0 }, err: ErrDocumentVersion},
		{name: "last-non-negative", refuse: func(last, _ int64) bool { return last < 0 }, err: ErrDocumentVersion},
		{name: "strictly-newer", refuse: func(last, next int64) bool { return next <= last }, err: ErrVersionNotNewer},
	}
}

// CheckDocumentVersion is the monotonic version rule both the signer and every
// verifier apply: next must be positive and strictly above last (0 = nothing
// seen yet). An equal version is refused as firmly as an older one.
func CheckDocumentVersion(last, next int64) error {
	for _, r := range versionRules() {
		if r.refuse(last, next) {
			return fmt.Errorf("platformcontract.CheckDocumentVersion: %s (last %d, next %d): %w", r.name, last, next, r.err)
		}
	}
	return nil
}

// DocumentSigningMessage returns the 32 bytes signed for a document (see the
// file comment). It refuses an unknown kind, a scope that does not fit it, a
// non-positive version and an empty or oversized body.
func DocumentSigningMessage(kind DocumentKind, scope string, version int64, body []byte) ([]byte, error) {
	if err := ValidateDocumentScope(kind, scope); err != nil {
		return nil, fmt.Errorf("platformcontract.DocumentSigningMessage: %w", err)
	}
	if version <= 0 {
		return nil, fmt.Errorf("platformcontract.DocumentSigningMessage: %w", ErrDocumentVersion)
	}
	if len(body) == 0 || len(body) > MaxDocumentBody {
		return nil, fmt.Errorf("platformcontract.DocumentSigningMessage: %w", ErrDocumentBody)
	}
	h := sha256.New()
	h.Write([]byte(kind.Domain()))
	h.Write([]byte{0})
	h.Write([]byte(scope))
	h.Write([]byte{0})
	h.Write([]byte(strconv.FormatInt(version, 10)))
	h.Write([]byte{0})
	h.Write(body)
	return h.Sum(nil), nil
}

// DocumentKeyID returns the key id of a document-signing public key: the
// unpadded base64url SHA-256 of the raw 32-byte key (43 characters). Deriving
// the id from the key means a pinned id can never name a different key.
func DocumentKeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// DocumentKey is one pinned verification key.
type DocumentKey struct {
	// KeyID is DocumentKeyID(Public).
	KeyID string
	// Public is the Ed25519 public key.
	Public ed25519.PublicKey
}

// NewDocumentKey pins pub under its derived id.
func NewDocumentKey(pub ed25519.PublicKey) DocumentKey {
	return DocumentKey{KeyID: DocumentKeyID(pub), Public: pub}
}

// KeySet is the set of keys a verifier accepts for one kind. During a
// rollover it holds two keys; a host pins both ids.
type KeySet []DocumentKey

// Lookup returns the key named id. A key whose id is not its derived id is
// never returned.
func (ks KeySet) Lookup(id string) (ed25519.PublicKey, bool) {
	for _, k := range ks {
		if k.KeyID == id && len(k.Public) == ed25519.PublicKeySize && DocumentKeyID(k.Public) == id {
			return k.Public, true
		}
	}
	return nil, false
}

// SignDocument signs a document with priv and returns the signature and the
// key id. It applies DocumentSigningMessage's checks; the version rule
// against the last signed version is the caller's (the signer's) job.
func SignDocument(priv ed25519.PrivateKey, kind DocumentKind, scope string, version int64, body []byte) (sig []byte, keyID string, err error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, "", fmt.Errorf("platformcontract.SignDocument: %w", ErrBadSignature)
	}
	msg, err := DocumentSigningMessage(kind, scope, version, body)
	if err != nil {
		return nil, "", fmt.Errorf("platformcontract.SignDocument: %w", err)
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, "", fmt.Errorf("platformcontract.SignDocument: %w", ErrBadSignature)
	}
	return ed25519.Sign(priv, msg), DocumentKeyID(pub), nil
}

// VerifyDocument checks a document's signature under the key keyID names in
// keys, then the version rule against lastVersion (0 = none accepted yet).
func VerifyDocument(kind DocumentKind, scope string, keys KeySet, keyID string, version int64, body, sig []byte, lastVersion int64) error {
	msg, err := DocumentSigningMessage(kind, scope, version, body)
	if err != nil {
		return fmt.Errorf("platformcontract.VerifyDocument: %w", err)
	}
	pub, ok := keys.Lookup(keyID)
	if !ok {
		return fmt.Errorf("platformcontract.VerifyDocument: %w", ErrUnknownDocumentKey)
	}
	if len(sig) != ed25519.SignatureSize || !ed25519.Verify(pub, msg, sig) {
		return fmt.Errorf("platformcontract.VerifyDocument: %w", ErrBadSignature)
	}
	if err := CheckDocumentVersion(lastVersion, version); err != nil {
		return fmt.Errorf("platformcontract.VerifyDocument: %w", err)
	}
	return nil
}

// AvailabilityDocument is the signed platform availability envelope
// (sbo-availability-v1). Its wire shape matches EntitlementDocument; Body is
// the JSON of an AvailabilityBody.
type AvailabilityDocument struct {
	// Version is the monotonic, platform-wide envelope version.
	Version int64 `json:"version"`
	// Body is the signed AvailabilityBody JSON (base64 in JSON).
	Body []byte `json:"body"`
	// Signature is the Ed25519 signature (base64 in JSON).
	Signature []byte `json:"signature"`
	// KeyID names the signer key (DocumentKeyID).
	KeyID string `json:"key_id"`
}

// SignEntitlements signs an org's entitlements body as an EntitlementDocument.
func SignEntitlements(priv ed25519.PrivateKey, orgID string, version int64, body []byte) (EntitlementDocument, error) {
	sig, kid, err := SignDocument(priv, KindEntitlements, orgID, version, body)
	if err != nil {
		return EntitlementDocument{}, fmt.Errorf("platformcontract.SignEntitlements: %w", err)
	}
	return EntitlementDocument{Version: version, Body: append([]byte(nil), body...), Signature: sig, KeyID: kid}, nil
}

// SignAvailability signs an availability body as an AvailabilityDocument.
func SignAvailability(priv ed25519.PrivateKey, version int64, body []byte) (AvailabilityDocument, error) {
	sig, kid, err := SignDocument(priv, KindAvailability, AvailabilityScope, version, body)
	if err != nil {
		return AvailabilityDocument{}, fmt.Errorf("platformcontract.SignAvailability: %w", err)
	}
	return AvailabilityDocument{Version: version, Body: append([]byte(nil), body...), Signature: sig, KeyID: kid}, nil
}

// VerifyEntitlements is what a tenant host calls on an entitlements document
// for org orgID: the signature under one of keys, then the version strictly
// above lastVersion (the version in force; 0 when none). The body is not
// interpreted here.
func VerifyEntitlements(doc EntitlementDocument, orgID string, keys KeySet, lastVersion int64) error {
	if err := VerifyDocument(KindEntitlements, orgID, keys, doc.KeyID, doc.Version, doc.Body, doc.Signature, lastVersion); err != nil {
		return fmt.Errorf("platformcontract.VerifyEntitlements: %w", err)
	}
	return nil
}

// VerifyAvailability is what a tenant host calls on an availability envelope:
// the signature under one of keys, then the version strictly above
// lastVersion. The caller then decodes Body into an AvailabilityBody and
// calls its Validate.
func VerifyAvailability(doc AvailabilityDocument, keys KeySet, lastVersion int64) error {
	if err := VerifyDocument(KindAvailability, AvailabilityScope, keys, doc.KeyID, doc.Version, doc.Body, doc.Signature, lastVersion); err != nil {
		return fmt.Errorf("platformcontract.VerifyAvailability: %w", err)
	}
	return nil
}
