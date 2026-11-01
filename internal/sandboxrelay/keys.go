package sandboxrelay

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// Purpose names which channel a key belongs to, so a box key can never
// authenticate on the helper-to-daemon link or the reverse.
type Purpose byte

// The closed Purpose vocabulary.
const (
	// PurposeBox is the box-to-host-helper channel (the hostile edge).
	PurposeBox Purpose = 1
	// PurposeLink is the host-helper-to-daemon link.
	PurposeLink Purpose = 2
)

func (p Purpose) valid() bool { return p == PurposeBox || p == PurposeLink }

// NonceSize is the per-connection nonce the server chooses.
const NonceSize = 32

// SecretSize is the per-run secret length callers mint.
const SecretSize = 32

// direction labels bound into the HKDF info.
const (
	dirHostToGuest = "h2g"
	dirGuestToHost = "g2h"
)

// hkdfSalt is the fixed protocol salt.
var hkdfSalt = []byte("sbo-sandbox-relay-v1")

// Keys holds the two direction keys of one epoch of one connection.
type Keys struct {
	Epoch uint32
	// HostToGuest seals what the host (server) sends.
	HostToGuest []byte
	// GuestToHost seals what the guest (client) sends.
	GuestToHost []byte
}

// DeriveKeys derives both direction keys for one epoch of one connection
// from the per-run secret. The HKDF info binds the purpose, the run id, the
// direction, the epoch and the server's nonce, so a frame sealed for any
// other value of any of them fails the MAC (JSP-3: measured for another
// run and a reflected host frame).
func DeriveKeys(secret []byte, purpose Purpose, runID string, nonce []byte, epoch uint32) (Keys, error) {
	if len(secret) < 16 {
		return Keys{}, fmt.Errorf("sandboxrelay.DeriveKeys: secret too short")
	}
	if !purpose.valid() {
		return Keys{}, fmt.Errorf("sandboxrelay.DeriveKeys: unknown purpose %d", purpose)
	}
	derive := func(dir string) ([]byte, error) {
		info := make([]byte, 0, 64+len(runID)+len(nonce))
		info = append(info, byte(purpose))
		info = append(info, dir...)
		info = binary.BigEndian.AppendUint32(info, epoch)
		info = append(info, byte(len(runID)))
		info = append(info, runID...)
		info = append(info, nonce...)
		return hkdf.Key(sha256.New, secret, hkdfSalt, string(info), 32)
	}
	h2g, err := derive(dirHostToGuest)
	if err != nil {
		return Keys{}, fmt.Errorf("sandboxrelay.DeriveKeys: %w", err)
	}
	g2h, err := derive(dirGuestToHost)
	if err != nil {
		return Keys{}, fmt.Errorf("sandboxrelay.DeriveKeys: %w", err)
	}
	return Keys{Epoch: epoch, HostToGuest: h2g, GuestToHost: g2h}, nil
}
