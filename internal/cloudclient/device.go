package cloudclient

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/marmutapp/superbased-observer/internal/cloudcred"
	"github.com/marmutapp/superbased-observer/internal/cloudpop"
)

// b64 is the padding-free base64url encoding used on the exchange wire.
var b64 = base64.RawURLEncoding

// exchangeSigningContext is the fixed domain-separation prefix over which the
// device key signs during registration/exchange. It stops an exchange signature
// from being replayable as any other Ed25519 signature the device makes.
const exchangeSigningContext = "sbo-device-exchange.v1"

// ExchangeSigningInput returns the exact bytes the device key signs for the
// /v1/auth/exchange call: the domain-separation context, the server nonce, and
// the base64url device public key, newline-joined. Binding the public key stops
// a man-in-the-middle from swapping in a different key under a captured nonce
// signature. The server recomputes and verifies this.
func ExchangeSigningInput(nonce string, pub ed25519.PublicKey) []byte {
	return []byte(exchangeSigningContext + "\n" + nonce + "\n" + b64.EncodeToString(pub))
}

// device bundles the loaded device key with its cloudpop thumbprint.
type device struct {
	priv       ed25519.PrivateKey
	pub        ed25519.PublicKey
	thumbprint string
}

// loadOrCreateDevice returns the device key, creating and persisting a fresh
// Ed25519 key on first use. The private key never leaves cloudcred except as
// the in-memory signer here.
func loadOrCreateDevice(cred cloudcred.Store) (device, error) {
	priv, err := cred.LoadDeviceKey()
	switch {
	case err == nil:
	case errors.Is(err, cloudcred.ErrNotFound):
		_, priv, err = ed25519.GenerateKey(nil)
		if err != nil {
			return device{}, fmt.Errorf("cloudclient: generate device key: %w", err)
		}
		if err := cred.SaveDeviceKey(priv); err != nil {
			return device{}, fmt.Errorf("cloudclient: persist device key: %w", err)
		}
	default:
		return device{}, fmt.Errorf("cloudclient: load device key: %w", err)
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return device{}, fmt.Errorf("cloudclient: device key has no ed25519 public half")
	}
	return device{priv: priv, pub: pub, thumbprint: cloudpop.Thumbprint(pub)}, nil
}

// idempotencyKey derives the client retry key (Sol SC10): a deterministic hash
// over device thumbprint + cloud session + feature + schema + upload digest.
// Retries of the same upload produce the same key; the SERVER derives the
// canonical job-uniqueness key (adding the account and resolved prompt/route
// versions). Regeneration is a distinct authorized operation with a different
// input and thus a different key.
func idempotencyKey(deviceThumbprint, cloudSessionID, feature, schemaVersion, uploadDigest string) string {
	h := sha256.New()
	for _, part := range []string{deviceThumbprint, cloudSessionID, feature, schemaVersion, uploadDigest} {
		h.Write([]byte(part))
		h.Write([]byte{0x1f}) // unit separator: unambiguous field boundary
	}
	return "sbo-idem-" + b64.EncodeToString(h.Sum(nil))
}
