package dpop

import (
	"errors"
	"fmt"
)

// ErrorCode is the CLOSED proof-rejection vocabulary.
type ErrorCode string

// Proof error codes.
const (
	ErrCodeMalformed         ErrorCode = "malformed"
	ErrCodeType              ErrorCode = "bad_type"
	ErrCodeAlg               ErrorCode = "bad_alg"
	ErrCodeSignature         ErrorCode = "bad_signature"
	ErrCodeClaims            ErrorCode = "bad_claims"
	ErrCodeHTM               ErrorCode = "htm_mismatch"
	ErrCodeHTU               ErrorCode = "htu_mismatch"
	ErrCodeIATFuture         ErrorCode = "iat_in_future"
	ErrCodeIATStale          ErrorCode = "iat_stale"
	ErrCodeATH               ErrorCode = "ath_mismatch"
	ErrCodeJKT               ErrorCode = "jkt_mismatch"
	ErrCodeUseNonce          ErrorCode = "use_dpop_nonce"
	ErrCodeReplay            ErrorCode = "replayed"
	ErrCodeReplayUnavailable ErrorCode = "replay_store_unavailable"
)

// ErrInvalidProof is matched (errors.Is) by every *Error.
var ErrInvalidProof = errors.New("dpop: invalid proof")

// Error is a typed proof rejection. Externally every code is
// `invalid_dpop_proof` except ErrCodeUseNonce (`use_dpop_nonce` + a fresh
// DPoP-Nonce header) - see OAuthError.
type Error struct {
	Code   ErrorCode
	Detail string
}

// Error implements error.
func (e *Error) Error() string { return "dpop: invalid proof: " + string(e.Code) + ": " + e.Detail }

// Is makes every *Error match ErrInvalidProof.
func (e *Error) Is(target error) bool { return target == ErrInvalidProof }

func perr(code ErrorCode, format string, a ...any) error {
	return &Error{Code: code, Detail: fmt.Sprintf(format, a...)}
}

// CodeOf returns the ErrorCode of err ("" if it is not a proof error).
func CodeOf(err error) ErrorCode {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

// OAuthError maps err to the RFC 9449 error code a server returns:
// "use_dpop_nonce" for a missing/stale nonce, "invalid_dpop_proof" otherwise.
func OAuthError(err error) string {
	if CodeOf(err) == ErrCodeUseNonce {
		return "use_dpop_nonce"
	}
	return "invalid_dpop_proof"
}
