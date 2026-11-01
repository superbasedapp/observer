package projectmatch

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// Held is what the node remembers about the project audience rail: whether it
// ever accepted a v3 delivery, and the highest epoch it accepted.
type Held struct {
	HadV3 bool
	Epoch int64
}

// The v3 accept gate's refusals.
var (
	ErrDowngrade     = errors.New("projectmatch: a bundle without the project audience (v2 or v1) after a v3 one")
	ErrEpochLower    = errors.New("projectmatch: assignment epoch lower than one already accepted")
	ErrBindingOwner  = errors.New("projectmatch: the delivery is bound to another org or member")
	ErrMalformed     = errors.New("projectmatch: a v3 delivery carrying a v2 binding or no mapping")
	ErrMappingDigest = errors.New("projectmatch: the mapping does not match the signed digest or epoch")
	ErrEnvelope      = errors.New("projectmatch: a project envelope does not belong to this delivery")
)

// Identity is the enrolment the delivery must be bound to.
type Identity struct {
	OrgID   string
	Subject string
}

// AcceptDelivery is the node's v3 gate for one composed bundle whose own
// signature already verified under key (the pinned org key). Walked top-down:
//
//  1. no project binding: refused as a downgrade once a v3 delivery was held,
//     else accepted (no project layer);
//  2. a v3 bundle must carry no v2 binding and must carry a mapping;
//  3. the binding must name this org and member;
//  4. the epoch must not be lower than one accepted;
//  5. the mapping must verify under the same key, name this org, member and
//     epoch, and digest to the signed value;
//  6. every envelope must verify under the same key, carry a v3 binding for
//     this org, member and epoch, an empty mapping digest, the bundle's
//     version, and a project the mapping lists, once each; its family
//     members (lane sec-p3) must match the families digest it signs and name
//     its project.
//
// It returns the new Held on success.
func AcceptDelivery(held Held, b orgcontract.PolicyBundle, want Identity, key ed25519.PublicKey) (Held, error) {
	pb := b.ProjectBinding
	if pb == nil {
		if held.HadV3 {
			return held, ErrDowngrade
		}
		return held, nil
	}
	if b.Binding != nil || b.Projects == nil || len(b.Families) > 0 || pb.FamiliesDigest != "" {
		return held, ErrMalformed
	}
	if pb.OrgID != want.OrgID || pb.Subject != want.Subject || pb.OrgProjectID != "" {
		return held, ErrBindingOwner
	}
	if pb.Epoch < held.Epoch {
		return held, fmt.Errorf("%w: served %d after %d", ErrEpochLower, pb.Epoch, held.Epoch)
	}
	m := b.Projects.Mapping
	mkey, err := orgcontract.VerifyProjectMapping(m)
	if err != nil || !bytes.Equal(mkey, key) {
		return held, fmt.Errorf("%w: mapping signature", ErrMappingDigest)
	}
	if m.OrgID != want.OrgID || m.Subject != want.Subject || m.Epoch != pb.Epoch ||
		orgcontract.ProjectMappingDigest(m) != pb.MappingDigest {
		return held, ErrMappingDigest
	}
	listed := map[string]bool{}
	for _, e := range m.Projects {
		listed[e.OrgProjectID] = true
	}
	seen := map[string]bool{}
	for _, env := range b.Projects.Envelopes {
		if err := checkEnvelope(env, want, pb.Epoch, b.Version, key); err != nil {
			return held, err
		}
		id := env.ProjectBinding.OrgProjectID
		if !listed[id] || seen[id] {
			return held, fmt.Errorf("%w: project %q is not listed once in the mapping", ErrEnvelope, id)
		}
		seen[id] = true
	}
	return Held{HadV3: true, Epoch: pb.Epoch}, nil
}

// checkEnvelope is the per-envelope half of AcceptDelivery, and what the guard
// re-checks when it loads a cached envelope (CheckEnvelope).
func checkEnvelope(env orgcontract.PolicyBundle, want Identity, epoch, version int64, key ed25519.PublicKey) error {
	ekey, err := orgcontract.VerifyPolicyBundle(env)
	if err != nil || !bytes.Equal(ekey, key) {
		return fmt.Errorf("%w: signature", ErrEnvelope)
	}
	eb := env.ProjectBinding
	if eb == nil || env.Binding != nil || env.Projects != nil {
		return fmt.Errorf("%w: not a v3 project envelope", ErrEnvelope)
	}
	if eb.OrgID != want.OrgID || eb.Subject != want.Subject || eb.OrgProjectID == "" ||
		eb.MappingDigest != "" || eb.Epoch != epoch || env.Version != version {
		return fmt.Errorf("%w: bound to another delivery", ErrEnvelope)
	}
	// The family members (lane sec-p3): the signature above covers their
	// digest; this checks the members against it and against the envelope's
	// project, so a member moved from another project's envelope, or one
	// whose body was swapped, is refused.
	if err := orgcontract.CheckProjectFamilies(env); err != nil {
		return fmt.Errorf("%w: %w", ErrEnvelope, err)
	}
	return nil
}

// CheckEnvelope verifies one cached envelope against the composed bundle it
// must belong to (same key, org, member, epoch and version) and against the
// project it is loaded for.
func CheckEnvelope(env orgcontract.PolicyBundle, composed orgcontract.PolicyBundle, orgProjectID string, key ed25519.PublicKey) error {
	pb := composed.ProjectBinding
	if pb == nil {
		return fmt.Errorf("%w: the composed bundle carries no project audience", ErrEnvelope)
	}
	if err := checkEnvelope(env, Identity{OrgID: pb.OrgID, Subject: pb.Subject}, pb.Epoch, composed.Version, key); err != nil {
		return err
	}
	if env.ProjectBinding.OrgProjectID != orgProjectID {
		return fmt.Errorf("%w: envelope for another project", ErrEnvelope)
	}
	return nil
}

// The resolve call's refusals (AcceptResolve).
var (
	ErrResolveSignature = errors.New("projectmatch: the resolve answer does not verify under the org key")
	ErrResolveOwner     = errors.New("projectmatch: the resolve answer is bound to another org or member")
	ErrResolveDelivery  = errors.New("projectmatch: the resolve answer is of another epoch or bundle version than the delivery in force")
	ErrResolveReplay    = errors.New("projectmatch: the resolve answer is for another request (digest or nonce)")
	ErrResolveExpired   = errors.New("projectmatch: the resolve answer is expired or not yet valid")
)

// resolveClockSkew is how far in the future an answer's issue time may be.
const resolveClockSkew = 5 * time.Minute

// AcceptResolve is the node's gate for one resolve answer, checked against the
// request it sent and the composed bundle in force (whose own signature and
// key pin already verified). Walked top-down:
//
//  1. the answer must verify, under its own domain, with the composed
//     bundle's key (a forged answer, or one signed by another key, fails);
//  2. it must name this org and member;
//  3. its epoch and bundle version must be the delivery's in force (a lower
//     epoch is a downgrade, a higher one belongs to a delivery the node has
//     not accepted yet);
//  4. it must answer exactly the request sent: its request digest and its
//     nonce (a replayed answer for another request or an earlier call fails);
//  5. it must be issued no later than now plus a small skew and not expired;
//  6. every envelope must be a v3 project envelope of this delivery, for a
//     project the answer lists, once each.
func AcceptResolve(a orgcontract.ProjectResolveAnswer, req orgcontract.ProjectResolveRequest, composed orgcontract.PolicyBundle, key ed25519.PublicKey, now time.Time) error {
	pb := composed.ProjectBinding
	if pb == nil {
		return fmt.Errorf("%w: the composed bundle carries no project audience", ErrResolveDelivery)
	}
	akey, err := orgcontract.VerifyProjectResolveAnswer(a)
	if err != nil || !bytes.Equal(akey, key) {
		return ErrResolveSignature
	}
	if a.OrgID != pb.OrgID || a.Subject != pb.Subject {
		return ErrResolveOwner
	}
	if a.Epoch != pb.Epoch || a.BundleVersion != composed.Version {
		return fmt.Errorf("%w: answer epoch %d version %d, delivery epoch %d version %d", ErrResolveDelivery, a.Epoch, a.BundleVersion, pb.Epoch, composed.Version)
	}
	if a.Nonce == "" || a.Nonce != req.Nonce || a.RequestDigest != orgcontract.ProjectResolveRequestDigest(req) {
		return ErrResolveReplay
	}
	if time.Unix(a.IssuedAt, 0).After(now.Add(resolveClockSkew)) || !now.Before(time.Unix(a.ExpiresAt, 0)) {
		return ErrResolveExpired
	}
	listed := map[string]bool{}
	for _, id := range a.OrgProjectIDs {
		listed[id] = true
	}
	seen := map[string]bool{}
	want := Identity{OrgID: pb.OrgID, Subject: pb.Subject}
	for _, env := range a.Envelopes {
		if err := checkEnvelope(env, want, pb.Epoch, composed.Version, key); err != nil {
			return err
		}
		id := env.ProjectBinding.OrgProjectID
		if !listed[id] || seen[id] {
			return fmt.Errorf("%w: project %q is not listed once in the resolve answer", ErrEnvelope, id)
		}
		seen[id] = true
	}
	return nil
}
