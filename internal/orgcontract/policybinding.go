package orgcontract

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strconv"
)

// Signed-rail BINDING, version 2 (pass-2 review C156-14 / C156-15, D-272 F3).
//
// The policy-resource rail and the guard-bundle rail were signed over the
// document alone: version + content (+ selectors and capabilities for a
// resource). That was enough while every node received the same stored
// envelope, but delivery now COMPOSES and PROJECTS per member: node.governance
// carries the member's team and member dashboard layers and is projected onto
// what the fetching node compiles; the guard bundle carries the member's team
// and member bundles. A v1 signature on such a body says nothing about whose
// it is, so one member's composed body, or a projection onto an older target
// (a bearer holder can request one by sending lower `nodegov-*` tokens), is a
// validly signed document for every other node of the org at that version.
//
// A v2 signature additionally binds:
//
//   - the org id (the enrolment's org_id), so no document crosses orgs;
//   - the subject (the verified bearer's user id), so no member's composed
//     body verifies for another member;
//   - the projection target (node.governance only; "" on every other family
//     and on the guard bundle), so a projection onto an older target does not
//     verify on a node that advertised a newer one.
//
// The bound values ride IN the envelope (PolicyBinding), so a cached envelope
// re-verifies self-contained (the guard's hook path reads only the file). The
// ACCEPT gates compare them to the node's own enrolment and target.
//
// COMPAT. Both rails are released, so v1 stays exactly as it was and is what
// every request without the capability token gets. A node advertises
// PolicyBindingCapability in ?policy_caps; a server that predates it ignores
// the token and keeps serving v1, which such a node still accepts until it
// has once held a bound envelope for that rail (then an unbound one is
// refused as a signature downgrade, so an on-path party cannot strip the
// binding back off). A released node never sends the token and never sees a
// `binding` field.

// PolicyBindingCapability is the ?policy_caps token a node sends on
// GET /api/agent/policy/{family} and GET /api/v1/policy-bundle to ask for a
// v2 (bound) signature. Both the server and the node read this one constant.
const PolicyBindingCapability = "binding-v2"

// PolicyBinding is what a v2 signature binds besides the document: the org,
// the member and (node.governance only) the projection target the body was
// shaped for. Every field is part of the signed message.
type PolicyBinding struct {
	OrgID   string `json:"org_id"`
	Subject string `json:"subject"`
	Target  string `json:"target,omitempty"`
}

// policyResourceSigningV2Domain opens every bound policy-resource message.
// Distinct from v1's domain, so a v1 signature never verifies as v2 and the
// other way round.
const policyResourceSigningV2Domain = "sbo-policy-resource-v2"

// policyBundleSigningV2Domain opens every bound guard-bundle message.
const policyBundleSigningV2Domain = "sbo-policy-bundle-v2"

// PolicyResourceBoundSigningMessage is the v2 message: the v1 fields in the
// same length-prefixed framing under the v2 domain, then the org, the subject
// and the target, each length-prefixed.
func PolicyResourceBoundSigningMessage(r SignedPolicyResource, b PolicyBinding) ([]byte, error) {
	normCaps, err := NormalizeCapabilities(r.RequiredCapabilities)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	buf.WriteString(policyResourceSigningV2Domain)
	writeLPField(&buf, r.ID)
	writeLPField(&buf, strconv.FormatInt(r.Version, 10))
	writeLPField(&buf, r.Family)
	writeLPField(&buf, r.CompilerVersion)
	writeLPField(&buf, r.BodyHash)
	writeLPField(&buf, r.SelectorsJSON)
	writeLPField(&buf, strconv.Itoa(len(normCaps)))
	for _, c := range normCaps {
		writeLPField(&buf, c)
	}
	writeLPField(&buf, b.OrgID)
	writeLPField(&buf, b.Subject)
	writeLPField(&buf, b.Target)
	return buf.Bytes(), nil
}

// policyResourceSignedMessage is the message r's signature covers: v2 when r
// carries a binding, v1 otherwise. Sign and verify both dispatch here, so the
// two can never pick different messages for one envelope.
func policyResourceSignedMessage(r SignedPolicyResource) ([]byte, error) {
	if r.Binding != nil {
		return PolicyResourceBoundSigningMessage(r, *r.Binding)
	}
	return PolicyResourceSigningMessage(r.ID, r.Version, r.Family, r.CompilerVersion, r.BodyHash, r.SelectorsJSON, r.RequiredCapabilities)
}

// PolicyResourceDeliveryDigest is hex(SHA-256) of the message r's signature
// covers (v2 when bound). It names one DELIVERY: the same document bound to
// another member or target has another delivery digest, while
// PolicyResourceMessageDigest (the v1 content identity the replay floor, the
// withdrawal lookup and the publish row key on) stays the same.
func PolicyResourceDeliveryDigest(r SignedPolicyResource) (string, error) {
	msg, err := policyResourceSignedMessage(r)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(msg)
	return hex.EncodeToString(sum[:]), nil
}

// PolicyResourceETag is the agent fetch's strong validator for r. An unbound
// delivery keeps the released shape `"pr-<content digest>"`; a bound one
// appends `.<first 16 hex of the delivery digest>`, so a node that starts
// asking for a binding (or whose target moved) is not answered 304 into the
// envelope it already holds. The withdrawal path reads the content digest back
// with PolicyResourceETagContentDigest.
func PolicyResourceETag(r SignedPolicyResource) (string, error) {
	content, err := PolicyResourceMessageDigest(r)
	if err != nil {
		return "", err
	}
	if r.Binding == nil {
		return `"pr-` + content + `"`, nil
	}
	delivery, err := PolicyResourceDeliveryDigest(r)
	if err != nil {
		return "", err
	}
	return `"pr-` + content + "." + delivery[:16] + `"`, nil
}

// PolicyResourceETagContentDigest extracts the content digest from an
// If-None-Match the agent fetch issued (either PolicyResourceETag shape).
func PolicyResourceETagContentDigest(etag string) (string, bool) {
	const prefix, suffix = `"pr-`, `"`
	if len(etag) <= len(prefix)+len(suffix) || etag[:len(prefix)] != prefix || etag[len(etag)-1:] != suffix {
		return "", false
	}
	d := etag[len(prefix) : len(etag)-1]
	for i := 0; i < len(d); i++ {
		if d[i] == '.' {
			d = d[:i]
			break
		}
	}
	return d, d != ""
}

// PolicyBundleBoundSigningMessage is the guard bundle's v2 message: the v2
// domain, then the version, the hex SHA-256 of the TOML, the org and the
// subject, each length-prefixed (the bundle carries no projection target).
func PolicyBundleBoundSigningMessage(version int64, bundleTOML []byte, b PolicyBinding) []byte {
	sum := sha256.Sum256(bundleTOML)
	var buf bytes.Buffer
	buf.WriteString(policyBundleSigningV2Domain)
	writeLPField(&buf, strconv.FormatInt(version, 10))
	writeLPField(&buf, hex.EncodeToString(sum[:]))
	writeLPField(&buf, b.OrgID)
	writeLPField(&buf, b.Subject)
	writeLPField(&buf, b.Target)
	return buf.Bytes()
}

// policyBundleSignedMessage is the message b's signature covers: v3 when b
// carries a project binding, v2 when it carries a binding, v1 otherwise.
func policyBundleSignedMessage(b PolicyBundle) []byte {
	if b.ProjectBinding != nil {
		return PolicyBundleV3SigningMessage(b.Version, []byte(b.BundleTOML), *b.ProjectBinding)
	}
	if b.Binding != nil {
		return PolicyBundleBoundSigningMessage(b.Version, []byte(b.BundleTOML), *b.Binding)
	}
	return PolicyBundleSigningMessage(b.Version, []byte(b.BundleTOML))
}

// SignPolicyBundleEnvelope signs b over the message its own Binding selects
// (v2 when bound) and returns the base64url signature. The delivery path uses
// it for the bound guard bundle; SignPolicyBundle stays the v1 publish path.
func SignPolicyBundleEnvelope(priv ed25519.PrivateKey, b PolicyBundle) string {
	return base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, policyBundleSignedMessage(b)))
}

// CheckPolicyBinding reports whether an envelope's binding (nil = unbound)
// matches the binding the node expects. A nil binding passes here; whether an
// unbound envelope is acceptable at all is the caller's downgrade decision.
func CheckPolicyBinding(got *PolicyBinding, want PolicyBinding) bool {
	return got == nil || *got == want
}
