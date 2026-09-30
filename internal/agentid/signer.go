package agentid

import (
	"crypto"
	"errors"
	"fmt"
	"sort"

	"github.com/marmutapp/superbased-observer/internal/dpop/jose"
)

// JWK is the alg-tagged public JSON Web Key used across Agent Access.
type JWK = jose.JWK

// Signer is ONE signing key: an opaque crypto.Signer (possibly KMS-backed and
// non-exportable) plus its algorithm-tagged public JWK. Doc3 §2.4 sketched the
// accessor as Public(); it is PublicJWK here because crypto.Signer already
// owns Public() with a different signature.
type Signer interface {
	crypto.Signer
	// PublicJWK returns the signing algorithm and the alg-tagged public JWK
	// (kid set). It never returns private material.
	PublicJWK() (alg string, jwk JWK)
}

// ServerTokenSigner is the org key ring seam (LocalSealed | AzureKeyVault).
// It signs ACCESS TOKENS only and is never a node proof signer.
type ServerTokenSigner interface {
	// Active returns the single active signing key and its kid.
	Active() (kid string, s Signer, err error)
	// JWKS returns the public halves of every pending, active and retiring
	// key, so no verifier ever meets a kid it cannot resolve.
	JWKS() ([]JWK, error)
}

// NodeProofSigner is the node's dedicated `agent-access-key` seam: DPoP
// proofs and sbo-actor+jwt assertions. It is never the org key ring and never
// the push-signing key (R2 / B8).
type NodeProofSigner interface {
	ProofSigner() (Signer, error)
}

// ErrNoActiveKey is returned when the ring holds no active signer.
var ErrNoActiveKey = errors.New("agentid: no active signing key")

// keySigner adapts an in-memory or KMS crypto.Signer to Signer.
type keySigner struct {
	crypto.Signer
	alg string
	jwk JWK
}

// PublicJWK implements Signer.
func (k keySigner) PublicJWK() (string, JWK) { return k.alg, k.jwk }

// NewKeySigner wraps a crypto.Signer as a Signer. The algorithm is derived
// from the key type (Ed25519 -> EdDSA, P-256 -> ES256, RSA -> RS256). An
// empty kid defaults to the RFC 7638 thumbprint of the public key - the kid
// the node actor assertion uses (§4.3).
func NewKeySigner(s crypto.Signer, kid string) (Signer, error) {
	if s == nil {
		return nil, errors.New("agentid.NewKeySigner: nil signer")
	}
	alg, err := jose.AlgForPublicKey(s.Public())
	if err != nil {
		return nil, fmt.Errorf("agentid.NewKeySigner: %w", err)
	}
	jwk, err := jose.PublicJWK(s.Public(), alg, "")
	if err != nil {
		return nil, fmt.Errorf("agentid.NewKeySigner: %w", err)
	}
	if kid == "" {
		if kid, err = jwk.Thumbprint(); err != nil {
			return nil, fmt.Errorf("agentid.NewKeySigner: %w", err)
		}
	}
	jwk.Kid = kid
	return keySigner{Signer: s, alg: alg, jwk: jwk}, nil
}

// KeyState is a key-ring row state (doc3 §4.2).
type KeyState string

// Key-ring states.
const (
	KeyPending  KeyState = "pending"
	KeyActive   KeyState = "active"
	KeyRetiring KeyState = "retiring"
	KeyRetired  KeyState = "retired"
)

// Published reports whether a key in this state belongs in the JWKS.
func (s KeyState) Published() bool { return s == KeyPending || s == KeyActive || s == KeyRetiring }

// RingEntry is one loaded key-ring row. Signer is required for the active
// key only; published non-active keys need just their public JWK.
type RingEntry struct {
	Kid    string
	State  KeyState
	Public JWK
	Signer Signer
}

// StaticRing is an immutable ServerTokenSigner snapshot built from loaded
// ring rows (the store refreshes by building a new one).
type StaticRing struct {
	activeKid string
	active    Signer
	jwks      []JWK
}

// NewStaticRing validates entries and builds the snapshot. It enforces the
// single-active-signer invariant, that the active entry has a signer whose
// public key equals its row, and that kids are unique.
func NewStaticRing(entries []RingEntry) (*StaticRing, error) {
	r := &StaticRing{}
	seen := map[string]bool{}
	for _, e := range entries {
		if e.Kid == "" {
			return nil, errors.New("agentid.NewStaticRing: entry without kid")
		}
		if seen[e.Kid] {
			return nil, fmt.Errorf("agentid.NewStaticRing: duplicate kid %q", e.Kid)
		}
		seen[e.Kid] = true
		switch e.State {
		case KeyPending, KeyActive, KeyRetiring, KeyRetired:
		default:
			return nil, fmt.Errorf("agentid.NewStaticRing: kid %q has unknown state %q", e.Kid, e.State)
		}
		if !e.State.Published() {
			continue
		}
		pub := e.Public
		alg, err := pub.ImpliedAlg()
		if err != nil {
			return nil, fmt.Errorf("agentid.NewStaticRing: kid %q: %w", e.Kid, err)
		}
		pub.Kid, pub.Alg = e.Kid, alg
		if e.State == KeyActive {
			if r.active != nil {
				return nil, fmt.Errorf("agentid.NewStaticRing: more than one active key (%q, %q)", r.activeKid, e.Kid)
			}
			if e.Signer == nil {
				return nil, fmt.Errorf("agentid.NewStaticRing: active kid %q has no signer", e.Kid)
			}
			salg, sjwk := e.Signer.PublicJWK()
			a, _ := sjwk.Thumbprint()
			b, _ := pub.Thumbprint()
			if salg != alg || a == "" || a != b {
				return nil, fmt.Errorf("agentid.NewStaticRing: active kid %q signer does not match its public key", e.Kid)
			}
			r.active, r.activeKid = e.Signer, e.Kid
		}
		r.jwks = append(r.jwks, pub)
	}
	sort.Slice(r.jwks, func(i, j int) bool { return r.jwks[i].Kid < r.jwks[j].Kid })
	return r, nil
}

// Active implements ServerTokenSigner.
func (r *StaticRing) Active() (string, Signer, error) {
	if r == nil || r.active == nil {
		return "", nil, ErrNoActiveKey
	}
	return r.activeKid, r.active, nil
}

// JWKS implements ServerTokenSigner.
func (r *StaticRing) JWKS() ([]JWK, error) {
	if r == nil {
		return nil, nil
	}
	out := make([]JWK, len(r.jwks))
	copy(out, r.jwks)
	return out, nil
}
