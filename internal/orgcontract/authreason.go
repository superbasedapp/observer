package orgcontract

import (
	"crypto/ed25519"
	"encoding/base64"
)

// Auth-failure discriminators for the per-push proof (POST /api/agent/push).
//
// Every one of these failures is a 401 with the same {"error":"unauthorized"}
// body the protocol has always returned. That collapse is what made the
// 2026-08-26/27 push-auth incident so hard to diagnose: a node whose member key
// had been rebound by a DIFFERENT machine looked exactly like a node with a
// clock skew, a corrupt signature, or no enrolment at all — from either end.
//
// The reason rides as an ADDITIVE `reason` field on that same body. A v1.8-class
// agent unmarshals {error, message} and ignores the extra key; a v1.8-class
// server omits it and a current agent falls back to the bare message. Neither
// side may ever require it.
//
// Nothing here is derived from key MATERIAL beyond a truncated hash of a PUBLIC
// key (see AgentKeyFingerprint), and no reason distinguishes "wrong signature"
// from "wrong key" in a way an attacker could not already determine by trying:
// the discriminators separate OPERATOR faults, which is the whole point.
const (
	// AuthReasonMissingBearer: no validated bearer claims reached the handler.
	AuthReasonMissingBearer = "missing_bearer"
	// AuthReasonMissingSignature: the X-SBO-Timestamp / X-SBO-Agent-Signature
	// pair was absent. Usually an agent that predates per-push signing, or a
	// proxy stripping unknown headers.
	AuthReasonMissingSignature = "missing_signature"
	// AuthReasonTimestampSkew: the signature timestamp fell outside
	// ±PushSignatureSkewSeconds. A CLOCK problem, not a credential problem.
	AuthReasonTimestampSkew = "timestamp_skew"
	// AuthReasonMalformedSignature: the signature header was not valid
	// base64url. A transport/encoding fault, not a rejected identity.
	AuthReasonMalformedSignature = "malformed_signature"
	// AuthReasonUnknownKey: the authenticated member has NO agent public key
	// bound at all. The enrolment never completed, or the member record was
	// rebuilt. Remedy: re-enrol.
	AuthReasonUnknownKey = "unknown_key"
	// AuthReasonBindingConflict: a key IS bound for this member, and it is
	// provably NOT the key this agent signed with — the agent advertised its own
	// fingerprint via HeaderAgentKeyFingerprint and it differs from the bound
	// one. This is the one-key-per-member collision: another machine enrolled
	// under the same member and took the binding. Remedy: give each machine its
	// own member, or re-enrol this one (which takes the binding back and strands
	// the other).
	AuthReasonBindingConflict = "binding_conflict"
	// AuthReasonSignatureMismatch: a key is bound and the signature did not
	// verify against it, with no fingerprint advertised to prove which case it
	// is. Covers both a genuine tampered/corrupt signature and a binding
	// conflict reported by an agent too old to advertise its fingerprint — the
	// server says only what it can prove, and the body's bound_key_fingerprint
	// lets the agent finish the diagnosis locally.
	AuthReasonSignatureMismatch = "signature_mismatch"
)

// HeaderAgentKeyFingerprint carries AgentKeyFingerprint(agent public key) on a
// push. It is OPTIONAL in both directions: the server uses it only to upgrade
// AuthReasonSignatureMismatch to the sharper AuthReasonBindingConflict, and
// never to authenticate anything (the Ed25519 signature is the only
// authenticator — a header an attacker can set must never gate access).
const HeaderAgentKeyFingerprint = "X-SBO-Agent-Key-Fingerprint"

// agentKeyFingerprintHexLen is the truncation of PublicKeyPinHash used as a
// key LABEL. 16 hex chars (64 bits) is far past accidental collision for the
// handful of keys one member ever holds, and short enough to read in a log
// line next to a user id.
const agentKeyFingerprintHexLen = 16

// AgentKeyFingerprint returns a short, stable, non-secret label for an agent's
// PUBLIC key — the first 16 hex chars of PublicKeyPinHash. Both ends derive it
// through this one helper so a fingerprint printed in a server log, returned in
// a 401 body, and computed by the agent from its own key can never disagree.
//
// It is a one-way truncated hash of a public key: it identifies WHICH key is
// bound without carrying the key, and it reveals nothing about the private half.
func AgentKeyFingerprint(pub ed25519.PublicKey) string {
	if len(pub) == 0 {
		return ""
	}
	h := PublicKeyPinHash(pub)
	if len(h) < agentKeyFingerprintHexLen {
		return h
	}
	return h[:agentKeyFingerprintHexLen]
}

// AgentKeyFingerprintEncoded is AgentKeyFingerprint over the base64url wire
// encoding the enrolment path posts and org_members.agent_public_key stores.
// An unparseable or empty value yields "" rather than an error: a fingerprint
// is a diagnostic label, and no code path should fail because a label could not
// be computed.
func AgentKeyFingerprintEncoded(encoded string) string {
	if encoded == "" {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return ""
	}
	return AgentKeyFingerprint(ed25519.PublicKey(raw))
}
