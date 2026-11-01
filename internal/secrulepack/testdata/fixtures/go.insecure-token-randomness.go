package auth

import (
	crand "crypto/rand"
	"encoding/hex"
	"math/rand"
)

const letters = "abcdefghijklmnopqrstuvwxyz0123456789"

func newResetToken() string {
	b := make([]byte, 16)
	for i := range b {
		// ruleid: go.insecure-token-randomness
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func issue() (int64, int) {
	// ruleid: go.insecure-token-randomness
	sessionID := rand.Int63()
	// ok: go.insecure-token-randomness
	jitter := rand.Intn(100)
	return sessionID, jitter
}

func secureToken() string {
	b := make([]byte, 16)
	// ok: go.insecure-token-randomness
	_, _ = crand.Read(b)
	return hex.EncodeToString(b)
}
