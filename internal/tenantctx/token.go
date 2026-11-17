package tenantctx

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// DefaultTTL is how long a token stays valid after it is minted. The
// database compares the expiry with the transaction's start time (now()), so
// a context never lapses inside the transaction that set it; the TTL only
// bounds how long a token copied out of a session stays usable.
const DefaultTTL = 15 * time.Minute

// MaxTTL is the longest TTL a signer accepts.
const MaxTTL = 24 * time.Hour

// MinKeyBytes is the shortest key a signer, the encoder and the databases'
// key functions accept.
const MinKeyBytes = 32

// MaxKeyBytes is the longest key accepted. HMAC hashes a key longer than the
// 64-byte block first; the bound only refuses a misread secret file.
const MaxKeyBytes = 1024

// MaxTokenBytes mirrors the databases' length bound on the setting.
const MaxTokenBytes = 512

// macHexLen is the length of the token's hex HMAC-SHA256.
const macHexLen = 64

// maxExpiryDigits is the longest expiry the databases parse (a bigint is 19
// digits; 18 can never overflow).
const maxExpiryDigits = 18

// keyIDDomain prefixes the key-id hash, so a key id is never the hash of
// anything else a deployment hashes.
const keyIDDomain = "sbo-tenant-context-key-id-v1\n"

// ErrInvalidContext is the sentinel every refused kind, subject, key, TTL or
// token matches with errors.Is.
var ErrInvalidContext = errors.New("tenantctx: invalid tenant context")

// CheckKey returns nil when key may sign tokens, else an error matching
// ErrInvalidContext.
func CheckKey(key []byte) error {
	if len(key) < MinKeyBytes || len(key) > MaxKeyBytes {
		return fmt.Errorf("%w: the key must be %d to %d bytes, got %d", ErrInvalidContext, MinKeyBytes, MaxKeyBytes, len(key))
	}
	return nil
}

// KeyID returns the 16 lower-case hex digit id of key: the first 8 bytes of
// SHA-256 over a fixed domain and the key. Installing the same key twice
// names the same row, so an install is idempotent; the id reveals nothing a
// brute force of a 32-byte key could use.
func KeyID(key []byte) string {
	h := sha256.New()
	h.Write([]byte(keyIDDomain)) //nolint:errcheck // hash.Hash.Write never fails.
	h.Write(key)                 //nolint:errcheck // hash.Hash.Write never fails.
	return hex.EncodeToString(h.Sum(nil)[:8])
}

// Encode returns the token "<subject>.<expiry>.<mac>" of kind k for subject,
// valid until expiry (unix seconds), under key. mac is the lower-case hex
// HMAC-SHA256 of the kind's domain followed by "<subject>.<expiry>".
func Encode(k Kind, subject string, expiry time.Time, key []byte) (string, error) {
	s, err := k.spec()
	if err != nil {
		return "", fmt.Errorf("tenantctx.Encode: %w", err)
	}
	if err := k.CheckSubject(subject); err != nil {
		return "", fmt.Errorf("tenantctx.Encode: %w", err)
	}
	if err := CheckKey(key); err != nil {
		return "", fmt.Errorf("tenantctx.Encode: %w", err)
	}
	exp := expiry.Unix()
	if exp <= 0 || exp > 999_999_999_999_999_999 {
		return "", fmt.Errorf("tenantctx.Encode: %w: expiry %d is out of range", ErrInvalidContext, exp)
	}
	expText := strconv.FormatInt(exp, 10)
	return subject + "." + expText + "." + hex.EncodeToString(mac(key, s.macMessage(subject, expText))), nil
}

func mac(key []byte, message string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(message)) //nolint:errcheck // hash.Hash.Write never fails.
	return m.Sum(nil)
}

// Parse splits a token of kind k into its subject, expiry (unix seconds) and
// MAC, with the same shape rules as the databases' functions. It checks no
// MAC and no expiry.
func Parse(k Kind, token string) (subject string, expiry int64, macBytes []byte, err error) {
	bad := func(why string) (string, int64, []byte, error) {
		return "", 0, nil, fmt.Errorf("tenantctx.Parse: %w: %s", ErrInvalidContext, why)
	}
	if !k.Valid() {
		return bad("unknown kind")
	}
	if len(token) > MaxTokenBytes {
		return bad("token too long")
	}
	macDot := strings.LastIndexByte(token, '.')
	if macDot < 0 {
		return bad("no MAC")
	}
	macHex := token[macDot+1:]
	expDot := strings.LastIndexByte(token[:macDot], '.')
	if expDot < 0 {
		return bad("no expiry")
	}
	expText := token[expDot+1 : macDot]
	subject = token[:expDot]
	if len(macHex) != macHexLen || strings.ToLower(macHex) != macHex {
		return bad("the MAC is not 64 lower-case hex digits")
	}
	if macBytes, err = hex.DecodeString(macHex); err != nil {
		return bad("the MAC is not hex")
	}
	if expText == "" || len(expText) > maxExpiryDigits || strings.TrimLeft(expText, "0123456789") != "" {
		return bad("the expiry is not 1 to 18 digits")
	}
	if expiry, err = strconv.ParseInt(expText, 10, 64); err != nil {
		return bad("the expiry does not parse")
	}
	if err := k.CheckSubject(subject); err != nil {
		return "", 0, nil, fmt.Errorf("tenantctx.Parse: %w", err)
	}
	return subject, expiry, macBytes, nil
}

// Verify is the Go statement of the databases' current-subject functions
// (sbo_current_org(), sbci_current_account()): the token's subject when it
// parses as kind k, its expiry is after now and its MAC verifies under one
// of keys with k's domain. The database is the enforcement point; Verify
// exists so the contract is tested natively and stated in one place.
func Verify(k Kind, token string, keys [][]byte, now time.Time) (string, error) {
	s, err := k.spec()
	if err != nil {
		return "", fmt.Errorf("tenantctx.Verify: %w", err)
	}
	subject, expiry, got, err := Parse(k, token)
	if err != nil {
		return "", fmt.Errorf("tenantctx.Verify: %w", err)
	}
	if expiry <= now.Unix() {
		return "", fmt.Errorf("tenantctx.Verify: %w: expired", ErrInvalidContext)
	}
	message := s.macMessage(subject, strconv.FormatInt(expiry, 10))
	for _, key := range keys {
		if hmac.Equal(mac(key, message), got) {
			return subject, nil
		}
	}
	return "", fmt.Errorf("tenantctx.Verify: %w: no key verifies the MAC", ErrInvalidContext)
}
