package orgcontract

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// managedpull.go is the contract half of the module managed-pull kit
// (roadmap F0-7, lane SHR-KIT; design JSP-1). A module that lets an org
// switch something ON for a managed node (the security module's
// GET /api/agent/security, the sandbox module's GET /api/agent/sandbox)
// registers a rail here and adds only its own body type; the signing
// message, the document, the verification and the node apply ladder are
// shared.
//
// The signing message binds all five of domain, org, subject, version and
// expiry, which none of the three older signed per-caller rails does
// (JSP-1 R10: budget binds no version outside its body and no expiry;
// pricing and display bind no subject and no expiry). The node verifies
// against its OWN org and subject, never the document's, so a document for
// another node, another org, another rail, another version or another
// expiry never verifies.

// ManagedPullRail is one registration on the kit.
type ManagedPullRail struct {
	// Name is the short rail name used in logs, the node cache key and the
	// fetch-state report ("security", "sandbox").
	Name string
	// Domain is the signing domain tag and the document's schema value.
	Domain string
	// Path is the agent route the node fetches.
	Path string
	// Authority is the managed-only enforce token a node's honoured grant
	// must hold for the rail's body to apply.
	Authority string
}

// The two rails' authority tokens, spelled here rather than imported from
// internal/govern (orgcontract is the wire contract and imports nothing of
// the node's policy layer); TestManagedPullRailsNameRealAuthorities pins
// them to govern's constants.
const (
	managedPullSecurityAuthority = "enforce.security"
	managedPullSandboxAuthority  = "enforce.sandbox"
)

// ManagedPullRails is the CLOSED rail table. Separate domains, paths and
// authorities per module; only the machinery is shared.
var ManagedPullRails = []ManagedPullRail{
	{Name: "security", Domain: "sbo-security-managed-v1", Path: "/api/agent/security", Authority: managedPullSecurityAuthority},
	{Name: "sandbox", Domain: "sbo-sandbox-managed-v1", Path: "/api/agent/sandbox", Authority: managedPullSandboxAuthority},
}

// LookupManagedPullRail returns the rail registered under name.
func LookupManagedPullRail(name string) (ManagedPullRail, bool) {
	for _, r := range ManagedPullRails {
		if r.Name == name {
			return r, true
		}
	}
	return ManagedPullRail{}, false
}

// ManagedPullDoc is the wire document of every managed pull. Body is the
// module's closed body, opaque to the kit (each module decodes its own with
// DisallowUnknownFields). An empty Body ("{}" or "null") is a signed "none":
// the only thing that clears a node's managed values.
type ManagedPullDoc struct {
	Schema  string `json:"schema"`
	OrgID   string `json:"org_id"`
	Subject string `json:"subject"`
	Version int64  `json:"version"`
	// ExpiresAt is unix seconds and required: a body past it stops applying
	// and the node's local values return.
	ExpiresAt int64           `json:"expires_at"`
	Body      json.RawMessage `json:"body"`
	Signature string          `json:"signature"`
}

// ErrManagedPullHeader is a header field that cannot be framed: empty, or
// carrying the NUL the framing uses as its separator, or a version or expiry
// that is not positive.
var ErrManagedPullHeader = errors.New("orgcontract: managed pull header field cannot be framed")

// ErrManagedPullUnverified is a document that does not verify for this node.
var ErrManagedPullUnverified = errors.New("orgcontract: managed pull document does not verify")

// ManagedPullMessage is the signing message:
//
//	SHA-256( domain 0x00 orgID 0x00 subject 0x00 decimal(version) 0x00 decimal(expiresAt) 0x00 body )
//
// The body is last, so it needs no separator rule. A header field that is
// empty or contains NUL is refused rather than trusted.
func ManagedPullMessage(domain, orgID, subject string, version, expiresAt int64, body []byte) ([]byte, error) {
	for _, f := range []string{domain, orgID, subject} {
		if f == "" || strings.ContainsRune(f, 0) {
			return nil, ErrManagedPullHeader
		}
	}
	if version <= 0 || expiresAt <= 0 {
		return nil, ErrManagedPullHeader
	}
	h := sha256.New()
	for _, f := range []string{domain, orgID, subject, strconv.FormatInt(version, 10), strconv.FormatInt(expiresAt, 10)} {
		h.Write([]byte(f))
		h.Write([]byte{0})
	}
	h.Write(body)
	return h.Sum(nil), nil
}

// SignManagedPull builds a signed document for one caller (the server's
// sign-at-serve helper).
func SignManagedPull(priv ed25519.PrivateKey, rail ManagedPullRail, orgID, subject string, version, expiresAt int64, body []byte) (ManagedPullDoc, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return ManagedPullDoc{}, errors.New("orgcontract.SignManagedPull: bad private key size")
	}
	if !json.Valid(body) {
		return ManagedPullDoc{}, errors.New("orgcontract.SignManagedPull: body is not a JSON document")
	}
	msg, err := ManagedPullMessage(rail.Domain, orgID, subject, version, expiresAt, body)
	if err != nil {
		return ManagedPullDoc{}, err
	}
	return ManagedPullDoc{
		Schema: rail.Domain, OrgID: orgID, Subject: subject, Version: version, ExpiresAt: expiresAt,
		Body:      append(json.RawMessage(nil), body...),
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, msg)),
	}, nil
}

// VerifyManagedPull checks doc against the pinned key, this rail, this
// node's own org and its own subject. The document's org and subject fields
// are display only: the message is rebuilt from what the node knows itself.
func VerifyManagedPull(pub ed25519.PublicKey, rail ManagedPullRail, orgID, subject string, doc ManagedPullDoc) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: no usable signing key", ErrManagedPullUnverified)
	}
	if doc.Schema != rail.Domain {
		return fmt.Errorf("%w: schema %q is not %q", ErrManagedPullUnverified, doc.Schema, rail.Domain)
	}
	msg, err := ManagedPullMessage(rail.Domain, orgID, subject, doc.Version, doc.ExpiresAt, doc.Body)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrManagedPullUnverified, err)
	}
	sig, err := base64.StdEncoding.DecodeString(doc.Signature)
	if err != nil || !ed25519.Verify(pub, msg, sig) {
		return fmt.Errorf("%w: signature", ErrManagedPullUnverified)
	}
	return nil
}

// ManagedPullBodyIsEmpty reports a signed explicit "none" body.
func ManagedPullBodyIsEmpty(body []byte) bool {
	t := bytes.TrimSpace(body)
	return len(t) == 0 || bytes.Equal(t, []byte("{}")) || bytes.Equal(t, []byte("null"))
}

// ManagedPullBodyHash is the hex SHA-256 of a body, the node cache's and the
// server issuance table's body identity.
func ManagedPullBodyHash(body []byte) string {
	sum := sha256.Sum256(body)
	return fmt.Sprintf("%x", sum[:])
}
