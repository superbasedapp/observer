package main

import (
	"crypto/ed25519"
	"crypto/sha256"

	"github.com/marmutapp/superbased-observer/internal/orgclient"
)

// fixtureSecrets is an in-memory orgclient.BearerStore. It never touches
// the OS keychain. Its method set is the union of every version's
// interface, so it satisfies each one. What it hands out are fixture
// placeholders the fake org never checks.
type fixtureSecrets struct {
	key ed25519.PrivateKey
}

// newFixtureSecrets returns a store holding a signing key derived from a
// constant, published seed (a fixture key, never a secret).
func newFixtureSecrets() *fixtureSecrets {
	seed := sha256.Sum256([]byte(fixturePlaceholder))
	return &fixtureSecrets{key: ed25519.NewKeyFromSeed(seed[:])}
}

// SaveBearer is a no-op (part of orgclient.BearerStore).
func (b *fixtureSecrets) SaveBearer(string) error { return nil }

// LoadBearer is part of orgclient.BearerStore; it returns the fixture
// placeholder.
func (b *fixtureSecrets) LoadBearer() (string, error) { return fixturePlaceholder, nil }

// SaveAgentKey implements orgclient.BearerStore.
func (b *fixtureSecrets) SaveAgentKey(ed25519.PrivateKey) error { return nil }

// LoadAgentKey implements orgclient.BearerStore.
func (b *fixtureSecrets) LoadAgentKey() (ed25519.PrivateKey, error) { return b.key, nil }

// SaveVirtualKey implements orgclient.BearerStore (newer versions).
func (b *fixtureSecrets) SaveVirtualKey(string, uint64) error { return nil }

// LoadVirtualKey implements orgclient.BearerStore (newer versions).
func (b *fixtureSecrets) LoadVirtualKey() (string, uint64, error) {
	return "", 0, orgclient.ErrNoSecret
}

// Clear implements orgclient.BearerStore.
func (b *fixtureSecrets) Clear() error { return nil }

// Backend implements orgclient.BearerStore.
func (b *fixtureSecrets) Backend() string { return "wirecompat-memory" }
