package platformcontract

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// This file is the additive M5.2 part of the v1 contract: the refusal body
// both sides agree on, the envelope's header form, the request target the
// signature covers, and the signed response envelope. It adds no verb and
// changes no existing type.

// ErrorCode is the closed vocabulary of a host-API refusal. A refusal body
// carries exactly one code, an optional field name and, for an unknown
// version, the versions the host serves. It never carries free text.
type ErrorCode string

// Refusal codes, in the order the host checks a request.
const (
	// CodeUnknownRoute: the path is not a host-API route.
	CodeUnknownRoute ErrorCode = "unknown_route"
	// CodeUnknownVersion: the path names a contract version the host does not
	// serve; SupportedVersions lists the ones it does.
	CodeUnknownVersion ErrorCode = "unknown_version"
	// CodeMethodNotAllowed: the route exists under another method.
	CodeMethodNotAllowed ErrorCode = "method_not_allowed"
	// CodeMTLSRequired: the host requires a verified client certificate.
	CodeMTLSRequired ErrorCode = "mtls_required"
	// CodeBodyTooLarge: the body is over the host's limit.
	CodeBodyTooLarge ErrorCode = "body_too_large"
	// CodeUnsigned: an envelope header is missing or malformed.
	CodeUnsigned ErrorCode = "unsigned"
	// CodeUnknownKey: the key id is not one the host pins.
	CodeUnknownKey ErrorCode = "unknown_key"
	// CodeStale: the timestamp is outside ReplayWindow.
	CodeStale ErrorCode = "stale"
	// CodeDigestMismatch: the body does not match the signed digest.
	CodeDigestMismatch ErrorCode = "digest_mismatch"
	// CodeBadSignature: the signature does not verify.
	CodeBadSignature ErrorCode = "bad_signature"
	// CodeReplayed: the (key id, nonce) pair was already accepted inside
	// ReplayWindow. A retry is a new request with a new nonce.
	CodeReplayed ErrorCode = "replayed"
	// CodeMalformed: the body is not the verb's JSON.
	CodeMalformed ErrorCode = "malformed"
	// CodeInvalid: the request failed Validate; Field names the field.
	CodeInvalid ErrorCode = "invalid"
	// CodeTenantMismatch: the body's tenant_id differs from the path id.
	CodeTenantMismatch ErrorCode = "tenant_mismatch"
	// CodeIdempotencyConflict: the idempotency key was already used for a
	// different intent (another tenant, or another member).
	CodeIdempotencyConflict ErrorCode = "idempotency_conflict"
	// CodeIdempotencyInProgress: the first call with this key is still
	// running; retry later.
	CodeIdempotencyInProgress ErrorCode = "idempotency_in_progress"
	// CodeUnknownTenant: the tenant is not held by this host.
	CodeUnknownTenant ErrorCode = "unknown_tenant"
	// CodeCapacityWaitlist: the host is at its capacity ceiling and has put a
	// create on its waitlist (lead decision W14-D4; plan 06 7.5's admission
	// thresholds). Nothing was created and nothing is wrong with the intent:
	// the control plane keeps it and sends it again later, slowly, and never
	// parks it. Answered with HTTP 503. A tenant the host already holds is
	// never waitlisted (a replay always passes).
	CodeCapacityWaitlist ErrorCode = "capacity_waitlist"
	// CodeUnavailable: the host could not act now (a store or service
	// failure); nothing was applied by this call and a retry is safe.
	CodeUnavailable ErrorCode = "unavailable"
	// CodeInternal: the host produced a result it may not send (for example a
	// health answer outside the enums).
	CodeInternal ErrorCode = "internal"
)

// KnownErrorCodes lists every ErrorCode in check order.
var KnownErrorCodes = []ErrorCode{
	CodeUnknownRoute, CodeUnknownVersion, CodeMethodNotAllowed, CodeMTLSRequired,
	CodeBodyTooLarge, CodeUnsigned, CodeUnknownKey, CodeStale, CodeDigestMismatch,
	CodeBadSignature, CodeReplayed, CodeMalformed, CodeInvalid, CodeTenantMismatch,
	CodeIdempotencyConflict, CodeIdempotencyInProgress, CodeUnknownTenant,
	CodeCapacityWaitlist, CodeUnavailable, CodeInternal,
}

// Valid reports whether c is a known code.
func (c ErrorCode) Valid() bool { return containsStr(KnownErrorCodes, c) }

// ErrorResponse is the body of every host-API refusal.
type ErrorResponse struct {
	// Code is the refusal code.
	Code ErrorCode `json:"code"`
	// Field is the JSON field at fault, for CodeInvalid.
	Field string `json:"field,omitempty"`
	// SupportedVersions lists the versions the host serves, for
	// CodeUnknownVersion.
	SupportedVersions []string `json:"supported_versions,omitempty"`
}

// ErrUnsigned means an envelope header is missing or malformed.
var ErrUnsigned = errors.New("platformcontract: envelope headers missing or malformed")

// ErrNonceMismatch means a response envelope does not echo the request nonce.
var ErrNonceMismatch = errors.New("platformcontract: response nonce does not echo the request")

// ResponseSigningDomain domain-separates a host's response signatures from
// the control plane's request signatures, so a signed response can never be
// presented as a request even if a key were misused for both.
const ResponseSigningDomain = "sbo-platform-host-api-response-v1"

// SigningTarget is the request target the signature covers: the escaped path
// exactly as sent, plus "?" and the raw query when there is one. Both sides
// build it from the request URL (net/url's EscapedPath and RawQuery).
func SigningTarget(escapedPath, rawQuery string) string {
	if rawQuery == "" {
		return escapedPath
	}
	return escapedPath + "?" + rawQuery
}

// ParseEnvelopeHeaders reads the envelope from the five header values that
// get returns (http.Header.Get on the transport side). Every header must be
// present and the timestamp a decimal integer; ErrUnsigned otherwise. It does
// not verify anything.
func ParseEnvelopeHeaders(get func(name string) string) (Envelope, error) {
	e := Envelope{
		KeyID:      get(HeaderKeyID),
		Nonce:      get(HeaderNonce),
		BodyDigest: get(HeaderDigest),
		Signature:  get(HeaderSignature),
	}
	ts := get(HeaderTimestamp)
	if e.KeyID == "" || e.Nonce == "" || e.BodyDigest == "" || e.Signature == "" || ts == "" {
		return Envelope{}, fmt.Errorf("platformcontract.ParseEnvelopeHeaders: %w", ErrUnsigned)
	}
	n, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return Envelope{}, fmt.Errorf("platformcontract.ParseEnvelopeHeaders: %w", ErrUnsigned)
	}
	e.Timestamp = n
	return e, nil
}

// HeaderPairs returns the envelope as (header name, value) pairs in a fixed
// order, for the transport to set.
func (e Envelope) HeaderPairs() [][2]string {
	return [][2]string{
		{HeaderKeyID, e.KeyID},
		{HeaderTimestamp, strconv.FormatInt(e.Timestamp, 10)},
		{HeaderNonce, e.Nonce},
		{HeaderDigest, e.BodyDigest},
		{HeaderSignature, e.Signature},
	}
}

// ResponseSigningInput is SigningInput with ResponseSigningDomain in place of
// SigningDomain. method and target are the REQUEST's; e.Nonce is the
// request's nonce, echoed, which binds the response to the one request.
func ResponseSigningInput(method, target string, e Envelope) ([]byte, error) {
	in, err := SigningInput(method, target, e)
	if err != nil {
		return nil, fmt.Errorf("platformcontract.ResponseSigningInput: %w", err)
	}
	return append([]byte(ResponseSigningDomain), in[len(SigningDomain):]...), nil
}

// NewResponseEnvelope signs a host response body. The nonce is the request's
// nonce (echoed); method and target are the request's.
func NewResponseEnvelope(priv ed25519.PrivateKey, keyID, requestNonce, method, target string, body []byte, now time.Time) (Envelope, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return Envelope{}, fmt.Errorf("platformcontract.NewResponseEnvelope: %w", ErrBadSignature)
	}
	e := Envelope{KeyID: keyID, Timestamp: now.Unix(), Nonce: requestNonce, BodyDigest: BodyDigest(body)}
	in, err := ResponseSigningInput(method, target, e)
	if err != nil {
		return Envelope{}, fmt.Errorf("platformcontract.NewResponseEnvelope: %w", err)
	}
	e.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, in))
	return e, nil
}

// VerifyResponse checks that a response envelope echoes requestNonce, is
// fresh, matches body and carries a valid response signature under pub.
func (e Envelope) VerifyResponse(pub ed25519.PublicKey, requestNonce, method, target string, body []byte, now time.Time) error {
	if e.Nonce != requestNonce || strings.TrimSpace(requestNonce) == "" {
		return fmt.Errorf("platformcontract.Envelope.VerifyResponse: %w", ErrNonceMismatch)
	}
	if err := e.CheckFreshness(now); err != nil {
		return fmt.Errorf("platformcontract.Envelope.VerifyResponse: %w", err)
	}
	if BodyDigest(body) != e.BodyDigest {
		return fmt.Errorf("platformcontract.Envelope.VerifyResponse: %w", ErrDigestMismatch)
	}
	in, err := ResponseSigningInput(method, target, e)
	if err != nil {
		return fmt.Errorf("platformcontract.Envelope.VerifyResponse: %w: %w", ErrBadSignature, err)
	}
	sig, err := base64.StdEncoding.DecodeString(e.Signature)
	if err != nil || len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, in, sig) {
		return fmt.Errorf("platformcontract.Envelope.VerifyResponse: %w", ErrBadSignature)
	}
	return nil
}
