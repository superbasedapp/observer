package hostclient

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	pc "github.com/marmutapp/superbased-observer/internal/platformcontract"
)

// EnvelopeSignFunc asks a remote signer to sign one host-API request
// envelope: the document signer's sign_request operation
// (internal/cloudserver/oidcissuer/signerd DocumentClient.SignRequest). The
// signer applies its own rules (method, target under the base path, digest
// shape, its own clock's replay window) and returns the whole envelope.
type EnvelopeSignFunc func(ctx context.Context, method, target, nonce, bodyDigest string, timestamp int64) (pc.Envelope, error)

// signingInputFields is the number of newline-joined fields of
// platformcontract.SigningInput: domain, method, target, timestamp, nonce,
// key id, body digest. No field may contain a newline, so a split is exact.
const signingInputFields = 7

// ErrSignerMismatch means the remote signer answered with an envelope that
// is not the one asked for, or a signature that does not verify under the
// pinned host-API public key.
var ErrSignerMismatch = errors.New("hostclient: the request signer's answer does not match the request")

// EnvelopeRequestSigner is a RequestSigner over a remote envelope signer
// (design 3.3: the host-API key lives in the document signer process on the
// worker VM, never in the worker). keyID and pub are the signer's current
// host-API key, read from its published keys; every answer is checked
// against them before the signature reaches the wire:
//
//   - the signing input the Sender built is parsed back into its fields
//     (domain, key id and timestamp included) and handed to the signer;
//   - the returned envelope must repeat the key id, timestamp, nonce and
//     digest asked for;
//   - its signature must verify under pub over the exact signing input.
//
// So a signer that rotated its key, or anything else answering on its
// socket, can make a request fail (not sent, retried) but can never put an
// unverifiable signature on the wire.
func EnvelopeRequestSigner(keyID string, pub ed25519.PublicKey, sign EnvelopeSignFunc) (RequestSigner, error) {
	switch {
	case strings.TrimSpace(keyID) == "" || strings.ContainsAny(keyID, "\r\n"):
		return RequestSigner{}, errors.New("hostclient.EnvelopeRequestSigner: a single-line key id is required")
	case len(pub) != ed25519.PublicKeySize:
		return RequestSigner{}, errors.New("hostclient.EnvelopeRequestSigner: an ed25519 public key is required")
	case sign == nil:
		return RequestSigner{}, errors.New("hostclient.EnvelopeRequestSigner: a sign function is required")
	}
	key := append(ed25519.PublicKey(nil), pub...)
	return RequestSigner{KeyID: keyID, Sign: func(ctx context.Context, in []byte) ([]byte, error) {
		f := strings.Split(string(in), "\n")
		if len(f) != signingInputFields || f[0] != pc.SigningDomain || f[5] != keyID {
			return nil, fmt.Errorf("hostclient.EnvelopeRequestSigner: %w: not a signing input for key %s", ErrSignerMismatch, keyID)
		}
		method, target, nonce, digest := f[1], f[2], f[4], f[6]
		ts, err := strconv.ParseInt(f[3], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("hostclient.EnvelopeRequestSigner: %w: timestamp", ErrSignerMismatch)
		}
		env, err := sign(ctx, method, target, nonce, digest, ts)
		if err != nil {
			return nil, fmt.Errorf("hostclient.EnvelopeRequestSigner: %w", err)
		}
		if env.KeyID != keyID || env.Timestamp != ts || env.Nonce != nonce || env.BodyDigest != digest {
			return nil, fmt.Errorf("hostclient.EnvelopeRequestSigner: %w: envelope fields", ErrSignerMismatch)
		}
		sig, err := base64.StdEncoding.DecodeString(env.Signature)
		if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(key, in, sig) {
			return nil, fmt.Errorf("hostclient.EnvelopeRequestSigner: %w: signature", ErrSignerMismatch)
		}
		return sig, nil
	}}, nil
}
