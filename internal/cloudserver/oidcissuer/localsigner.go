package oidcissuer

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"
)

// LocalSigner is a Signer over RSA private keys held in this process. The
// signer process (signerd) serves one over its unix socket; tests use one
// directly. It applies ValidateClaims to every request and signs only with a
// key it holds, so it refuses anything the claim rules refuse.
type LocalSigner struct {
	issuer string
	keys   map[string]*rsa.PrivateKey
	pubs   []PublicKey
	now    func() time.Time
	rand   io.Reader
}

// NewLocalSigner returns a signer for the fixed issuer over keys (each at
// least MinRSABits). now nil means time.Now.
func NewLocalSigner(issuer string, keys []*rsa.PrivateKey, now func() time.Time) (*LocalSigner, error) {
	if _, err := ValidateIssuerURL(issuer); err != nil {
		return nil, fmt.Errorf("oidcissuer.NewLocalSigner: %w", err)
	}
	if len(keys) == 0 {
		return nil, errors.New("oidcissuer.NewLocalSigner: no keys")
	}
	s := &LocalSigner{issuer: issuer, keys: make(map[string]*rsa.PrivateKey, len(keys)), now: now, rand: rand.Reader}
	if s.now == nil {
		s.now = time.Now
	}
	for _, k := range keys {
		if k == nil || k.N.BitLen() < MinRSABits {
			return nil, fmt.Errorf("oidcissuer.NewLocalSigner: every key must be RSA of at least %d bits", MinRSABits)
		}
		jwk := PublicJWK(&k.PublicKey)
		if _, dup := s.keys[jwk.Kid]; dup {
			return nil, fmt.Errorf("oidcissuer.NewLocalSigner: key %s given twice", jwk.Kid)
		}
		s.keys[jwk.Kid] = k
		s.pubs = append(s.pubs, PublicKey{KID: jwk.Kid, JWK: jwk})
	}
	sort.Slice(s.pubs, func(i, j int) bool { return s.pubs[i].KID < s.pubs[j].KID })
	return s, nil
}

// Issuer returns the fixed issuer this signer signs for.
func (s *LocalSigner) Issuer() string { return s.issuer }

// Sign implements Signer.
func (s *LocalSigner) Sign(_ context.Context, kid string, c Claims) (string, error) {
	key, ok := s.keys[kid]
	if !ok {
		return "", fmt.Errorf("oidcissuer.LocalSigner.Sign: kid %q not held: %w", kid, ErrClaimsRefused)
	}
	if err := ValidateClaims(c, s.issuer, s.now()); err != nil {
		return "", err
	}
	return SignRS256(s.rand, key, kid, c)
}

// PublicKeys implements Signer.
func (s *LocalSigner) PublicKeys(context.Context) ([]PublicKey, error) {
	return append([]PublicKey(nil), s.pubs...), nil
}
