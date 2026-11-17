package tenantctx

import (
	"errors"
	"fmt"
	"time"
)

// Signer mints tokens of one kind with one key. It is immutable after
// construction and safe for concurrent use. The key is copied; the signer
// never exposes it.
type Signer struct {
	kind  Kind
	key   []byte
	keyID string
	ttl   time.Duration
	now   func() time.Time
}

// NewSigner returns a signer of kind k for key (MinKeyBytes to MaxKeyBytes)
// whose tokens live ttl (0 means DefaultTTL; 1s to MaxTTL). now is the clock
// (nil means time.Now).
func NewSigner(k Kind, key []byte, ttl time.Duration, now func() time.Time) (*Signer, error) {
	if !k.Valid() {
		return nil, fmt.Errorf("tenantctx.NewSigner: %w: unknown kind %d", ErrInvalidContext, uint8(k))
	}
	if err := CheckKey(key); err != nil {
		return nil, fmt.Errorf("tenantctx.NewSigner: %w", err)
	}
	if ttl == 0 {
		ttl = DefaultTTL
	}
	if ttl < time.Second || ttl > MaxTTL {
		return nil, fmt.Errorf("tenantctx.NewSigner: %w: the TTL must be between 1s and %s", ErrInvalidContext, MaxTTL)
	}
	if now == nil {
		now = time.Now
	}
	return &Signer{kind: k, key: append([]byte(nil), key...), keyID: KeyID(key), ttl: ttl, now: now}, nil
}

// Kind returns the kind of the signer's tokens.
func (s *Signer) Kind() Kind {
	if s == nil {
		return 0
	}
	return s.kind
}

// KeyID returns the id of the signer's key (see KeyID).
func (s *Signer) KeyID() string {
	if s == nil {
		return ""
	}
	return s.keyID
}

// Token returns a token for subject that expires the signer's TTL from now.
func (s *Signer) Token(subject string) (string, error) {
	if s == nil {
		return "", errors.New("tenantctx.Signer.Token: nil signer")
	}
	token, err := Encode(s.kind, subject, s.now().Add(s.ttl), s.key)
	if err != nil {
		return "", fmt.Errorf("tenantctx.Signer.Token: %w", err)
	}
	return token, nil
}

// Step returns what an adopter executes as the context step of a tenant
// transaction: the kind's SetLocalSQL and the token to bind as its $1.
func (s *Signer) Step(subject string) (query, token string, err error) {
	token, err = s.Token(subject)
	if err != nil {
		return "", "", fmt.Errorf("tenantctx.Signer.Step: %w", err)
	}
	return s.kind.SetLocalSQL(), token, nil
}
