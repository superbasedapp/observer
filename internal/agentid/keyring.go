package agentid

import (
	"errors"
	"fmt"
	"time"
)

// KeyOpKind is one key-ring transition the store applies transactionally
// (under the Postgres advisory lock / SQLite leader singleton, §4.2).
type KeyOpKind string

// Key-ring operations.
const (
	// OpCreatePending asks the caller to generate + seal a new key and insert
	// it as pending (published in the JWKS before it can sign).
	OpCreatePending KeyOpKind = "create_pending"
	// OpBeginRetire moves the current active key to retiring.
	OpBeginRetire KeyOpKind = "begin_retire"
	// OpActivate moves a pending key to active.
	OpActivate KeyOpKind = "activate"
	// OpRetire moves a retiring key to retired (removed from the JWKS).
	OpRetire KeyOpKind = "retire"
)

// KeyOp is one transition. When Advance emits OpBeginRetire and OpActivate
// together they MUST be applied in that order in ONE transaction, so the
// single-active invariant (partial unique index) is never violated.
type KeyOp struct {
	Kind KeyOpKind
	Kid  string
}

// RingKey is the rotation-relevant state of one ring row.
type RingKey struct {
	Kid         string
	State       KeyState
	CreatedAt   time.Time // when it became pending (published)
	ActivatedAt time.Time
	RetiringAt  time.Time
	RetiredAt   time.Time
	// Acked is true once every serving replica has ACKed a data-plane config
	// carrying this public key (the A1 xDS inline-JWKS gate; the A2 front's
	// in-process JWKS satisfies it on publish). Activation waits for it when
	// RequireAck is set.
	Acked bool
}

// KeyRingState is the pure rotation state machine
// pending -> active -> retiring -> retired (§4.2).
type KeyRingState struct {
	Keys []RingKey
	// RotateEvery is the active key's lifetime before a successor is created
	// (zero = manual rotation only).
	RotateEvery time.Duration
	// PublishLead is how long a pending key must be published before it may
	// activate (>= JWKS cache lifetime + clock skew).
	PublishLead time.Duration
	// Overlap is how long a retiring key stays published (>= max token TTL +
	// JWKS cache lifetime + clock skew - see MinOverlap).
	Overlap time.Duration
	// RequireAck gates activation on the data-plane ACK.
	RequireAck bool
}

// MinOverlap is the smallest legal retiring overlap: no verifier may ever
// meet a token whose kid it can no longer resolve.
func MinOverlap(maxTTL, jwksCache, skew time.Duration) time.Duration {
	return maxTTL + jwksCache + skew
}

// ValidateConfig checks the timing parameters against the overlap rule.
func (kr *KeyRingState) ValidateConfig(maxTTL, jwksCache, skew time.Duration) error {
	if kr.Overlap < MinOverlap(maxTTL, jwksCache, skew) {
		return fmt.Errorf("agentid: key-ring overlap %s < max TTL + JWKS cache + skew (%s)", kr.Overlap, MinOverlap(maxTTL, jwksCache, skew))
	}
	if kr.PublishLead < jwksCache+skew {
		return fmt.Errorf("agentid: key-ring publish lead %s < JWKS cache + skew (%s)", kr.PublishLead, jwksCache+skew)
	}
	return nil
}

// Validate checks the structural invariants: unique kids, known states, at
// most one active key.
func (kr *KeyRingState) Validate() error {
	seen := map[string]bool{}
	active := 0
	for _, k := range kr.Keys {
		if k.Kid == "" || seen[k.Kid] {
			return fmt.Errorf("agentid: key ring has an empty or duplicate kid %q", k.Kid)
		}
		seen[k.Kid] = true
		switch k.State {
		case KeyActive:
			active++
		case KeyPending, KeyRetiring, KeyRetired:
		default:
			return fmt.Errorf("agentid: key %q has unknown state %q", k.Kid, k.State)
		}
	}
	if active > 1 {
		return errors.New("agentid: key ring has more than one active key")
	}
	return nil
}

func (kr *KeyRingState) find(state KeyState) (RingKey, bool) {
	var best RingKey
	found := false
	for _, k := range kr.Keys {
		if k.State == state && (!found || k.CreatedAt.Before(best.CreatedAt)) {
			best, found = k, true
		}
	}
	return best, found
}

// eligible reports whether a pending key may activate at now.
func (kr *KeyRingState) eligible(k RingKey, now time.Time) bool {
	if now.Sub(k.CreatedAt) < kr.PublishLead {
		return false
	}
	return !kr.RequireAck || k.Acked
}

// ringRule is one row of the rotation table: when match holds, emit ops.
type ringRule struct {
	name  string
	match func(kr *KeyRingState, now time.Time) []KeyOp
}

// ringRules is the ORDERED rotation table. Each row contributes ops; a row
// that returns nil does not apply. Retirement is independent of activation,
// so every row runs.
var ringRules = []ringRule{
	{"bootstrap: no active and no pending -> create pending", func(kr *KeyRingState, _ time.Time) []KeyOp {
		if _, ok := kr.find(KeyActive); ok {
			return nil
		}
		if _, ok := kr.find(KeyPending); ok {
			return nil
		}
		return []KeyOp{{Kind: OpCreatePending}}
	}},
	{"eligible pending -> retire active (if any) then activate", func(kr *KeyRingState, now time.Time) []KeyOp {
		p, ok := kr.find(KeyPending)
		if !ok || !kr.eligible(p, now) {
			return nil
		}
		var ops []KeyOp
		if a, ok := kr.find(KeyActive); ok {
			ops = append(ops, KeyOp{Kind: OpBeginRetire, Kid: a.Kid})
		}
		return append(ops, KeyOp{Kind: OpActivate, Kid: p.Kid})
	}},
	{"active past its lifetime and no pending -> create pending", func(kr *KeyRingState, now time.Time) []KeyOp {
		a, ok := kr.find(KeyActive)
		if !ok || kr.RotateEvery <= 0 || now.Sub(a.ActivatedAt) < kr.RotateEvery {
			return nil
		}
		if _, ok := kr.find(KeyPending); ok {
			return nil
		}
		return []KeyOp{{Kind: OpCreatePending}}
	}},
	{"retiring past the overlap -> retire", func(kr *KeyRingState, now time.Time) []KeyOp {
		var ops []KeyOp
		for _, k := range kr.Keys {
			if k.State == KeyRetiring && now.Sub(k.RetiringAt) >= kr.Overlap {
				ops = append(ops, KeyOp{Kind: OpRetire, Kid: k.Kid})
			}
		}
		return ops
	}},
}

// Advance returns the transitions due at now, in apply order. A ring that
// violates its invariants yields NO ops - Advance never makes a broken ring
// worse; the caller surfaces Validate's error.
func (kr *KeyRingState) Advance(now time.Time) []KeyOp {
	if kr.Validate() != nil {
		return nil
	}
	var ops []KeyOp
	for _, r := range ringRules {
		ops = append(ops, r.match(kr, now)...)
	}
	return ops
}

// Emergency returns the ops for a compromise rotation: the named pending key
// jumps to active immediately (skipping PublishLead) after the forced ACK
// sweep - it must be Acked when RequireAck is set.
func (kr *KeyRingState) Emergency(kid string) ([]KeyOp, error) {
	if err := kr.Validate(); err != nil {
		return nil, err
	}
	for _, k := range kr.Keys {
		if k.Kid != kid {
			continue
		}
		if k.State != KeyPending {
			return nil, fmt.Errorf("agentid: emergency target %q is %s, want pending", kid, k.State)
		}
		if kr.RequireAck && !k.Acked {
			return nil, fmt.Errorf("agentid: emergency target %q is not ACKed by every replica", kid)
		}
		var ops []KeyOp
		if a, ok := kr.find(KeyActive); ok {
			ops = append(ops, KeyOp{Kind: OpBeginRetire, Kid: a.Kid})
		}
		return append(ops, KeyOp{Kind: OpActivate, Kid: kid}), nil
	}
	return nil, fmt.Errorf("agentid: emergency target %q not in the ring", kid)
}

// transitions is the closed from->to table for the state-changing ops.
var transitions = map[KeyOpKind][2]KeyState{
	OpBeginRetire: {KeyActive, KeyRetiring},
	OpActivate:    {KeyPending, KeyActive},
	OpRetire:      {KeyRetiring, KeyRetired},
}

// Apply performs one op on the in-memory state (the store's twin of the
// transactional update; used by tests and dry-runs). OpCreatePending adds a
// key with the supplied kid.
func (kr *KeyRingState) Apply(op KeyOp, now time.Time) error {
	if op.Kind == OpCreatePending {
		if op.Kid == "" {
			return errors.New("agentid: create_pending needs a kid")
		}
		kr.Keys = append(kr.Keys, RingKey{Kid: op.Kid, State: KeyPending, CreatedAt: now})
		return kr.Validate()
	}
	tr, ok := transitions[op.Kind]
	from, to := tr[0], tr[1]
	if !ok {
		return fmt.Errorf("agentid: unknown key op %q", op.Kind)
	}
	for i := range kr.Keys {
		k := &kr.Keys[i]
		if k.Kid != op.Kid {
			continue
		}
		if k.State != from {
			return fmt.Errorf("agentid: %s on %q in state %s", op.Kind, op.Kid, k.State)
		}
		k.State = to
		switch to {
		case KeyActive:
			k.ActivatedAt = now
		case KeyRetiring:
			k.RetiringAt = now
		case KeyRetired:
			k.RetiredAt = now
		}
		return kr.Validate()
	}
	return fmt.Errorf("agentid: key %q not in the ring", op.Kid)
}
