package guard

import (
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

// Managed-node org lock, guard half (T-839 / D-672, T-844).
//
// The daemon records in its MAC'd org lock (internal/guardposture orglock.go)
// the tenancy it resolved, the enrolment key pin and the last org bundle
// envelope it verified under that pin. config.Load carries the verified lock
// on GuardConfig.Lock, and New reads it here, so EVERY guard construction (the
// daemon, each hook mechanism, each CLI surface) gets:
//
//   - the tenancy, when its caller did not wire one: a hook process no longer
//     reads an individual node as managed just because it cannot afford the
//     store read (the conservative "unresolved" reading stays for a node with
//     no valid lock);
//   - the key pin, so a hook process also checks the cached bundle's signing
//     key against the enrolment pin;
//   - the last verified org layer, which New falls back to when the cached
//     bundle file exists but no longer verifies (loadOrgLayer), so a broken or
//     edited bundle can no longer drop the org layer and with it the org lock
//     on local approvals (audit row a3b).

// applyOrgLock folds the config's verified org lock into a guard under
// construction. Explicit Options win: the daemon wires its own tenancy and
// pin from the store, which is the source the lock was written from.
func (g *Guard) applyOrgLock(opts Options) {
	lk := opts.Config.Lock
	if lk.State == "tampered" && lk.OrgExpected {
		// The lock does not verify, but the daemon's MAC'd posture (or an org
		// file on disk) says an organization holds this node: a missing
		// bundle is a deletion until the lock is repaired (T-864 gap 1, the
		// bundle and the lock deleted together).
		g.orgBundleExpected = true
	}
	// The tenancy rides every lock state that resolved one (FU-235). A
	// valid lock carries the daemon's tenancy; a TAMPERED lock carries one
	// only when the daemon's own verified posture vouches for an individual
	// node (config guardFloorFor), and before this fix that reading was
	// dropped here, so a hook on an individual node read its tenancy as
	// unresolved and locked EVERY rule while the daemon repaired the lock.
	// Both sources are MAC'd daemon records; the conservative unresolved
	// reading stays for a lock that resolved no tenancy.
	if opts.ManagedTenancy == nil && lk.TenancyKnown {
		managed := lk.Managed
		g.SetManagedTenancy(func() bool { return managed })
	}
	if lk.State != "valid" {
		return
	}
	if lk.BundleExpected || lk.Bundle != "" {
		g.orgBundleExpected = true
	}
	if g.orgKeyPinHash == "" {
		g.orgKeyPinHash = lk.KeyPinHash
	}
	if lk.Bundle != "" {
		g.orgLastVerified = []byte(lk.Bundle)
	}
}

// clearOrgBundleTamper records that the cached bundle verified again (a
// successful reload): the org layer in force is the file's, not a fallback.
func (g *Guard) clearOrgBundleTamper() {
	g.orgBundleRejected.Store(false)
	g.orgBundleTampered.Store(false)
	g.orgBundleCause.Store(int32(bundleCauseRejected))
	g.orgLKGInUse.Store(false)
}

// OrgLockInputs is what the daemon's org-lock writer needs from its live
// guard (cmd/observer guardposture_wire.go): the tenancy, the pin, the
// verified envelope and the org's prompt-rule pins.
type OrgLockInputs struct {
	// Managed / TenancyResolved are the tenancy (Resolved=false: this guard
	// was built without a tenancy lookup).
	Managed, TenancyResolved bool
	// KeyPinHash is the enrolment pin this guard verified the bundle under.
	KeyPinHash string
	// Envelope is the signed org bundle envelope in force, as verified. It is
	// set only when the guard verified it under a pin, so the lock never
	// records a bundle trusted on its own signature alone.
	Envelope []byte
	// OrgLayer reports an org layer in force.
	OrgLayer bool
	// BundleExpected reports that this node accepted a verified org bundle:
	// one is in force, or the guard was told so (Options.OrgBundleExpected,
	// from the daemon's store). The lock carries it so a hook process reads
	// a deleted bundle as tamper (T-864 gap 1).
	BundleExpected bool
	// PromptFloor / PromptFloorStops report an org-pinned prompt-rule
	// decision, and one that can stop a prompt.
	PromptFloor, PromptFloorStops bool
}

// OrgLockInputs reports the live guard's org-lock inputs off one snapshot.
func (g *Guard) OrgLockInputs() OrgLockInputs {
	es := g.set.Load()
	in := OrgLockInputs{KeyPinHash: g.orgKeyPinHash, BundleExpected: g.orgBundleExpected}
	if fn := g.managedTenancy.Load(); fn != nil {
		in.TenancyResolved, in.Managed = true, (*fn)()
	}
	if es == nil || !es.orgApplies() {
		return in
	}
	in.OrgLayer, in.BundleExpected = true, true
	if g.orgKeyPinHash != "" && len(es.orgLayer.envelope) > 0 {
		in.Envelope = append([]byte(nil), es.orgLayer.envelope...)
	}
	for _, id := range promptRuleIDs {
		if es.orgPromptFloorFor(id) != PromptModeOff {
			in.PromptFloor = true
		}
	}
	in.PromptFloorStops = es.orgPromptFloorStops()
	return in
}

// OrgLockStatus is the org-lock half of `observer guard status` and the
// doctor: whether the cached bundle verified, and whether the org layer in
// force is the last verified copy.
type OrgLockStatus struct {
	// BundleTampered: the cached bundle file did not verify at the last
	// load.
	BundleTampered bool
	// LastVerifiedInUse: the org layer in force is the daemon's last verified
	// copy.
	LastVerifiedInUse bool
	// Unverifiable: the bundle did not verify, no last verified copy covers
	// for it, and this node's org lock reaches every rule (managed, or
	// tenancy unresolved), so local approvals are refused for every rule.
	Unverifiable bool
	// BundleProblem completes "the cached bundle ..." with what is actually
	// wrong with the file while BundleTampered holds: "does not verify", "is
	// missing" or "could not be read" (orgBundleCauseWords, T-889). Empty
	// when the bundle is not tampered.
	BundleProblem string
}

// OrgLockStatus reports the guard's org-lock state.
func (g *Guard) OrgLockStatus() OrgLockStatus {
	st := OrgLockStatus{
		BundleTampered:    g.orgBundleTampered.Load(),
		LastVerifiedInUse: g.orgLKGInUse.Load(),
		Unverifiable:      g.orgUnverifiable(g.set.Load()),
	}
	if st.BundleTampered {
		st.BundleProblem = orgBundleCause(g.orgBundleCause.Load()).words().status
	}
	return st
}

// orgUnverifiable reports the fail-closed state of T-844: the cached org
// bundle exists but does not verify, no last verified layer covers for it,
// and the org's authority reaches every rule here. The org's floor is then
// UNKNOWN, not absent, so no local approval may soften anything.
func (g *Guard) orgUnverifiable(es *engineSet) bool {
	if es != nil && es.orgApplies() {
		return false
	}
	return g.orgBundleRejected.Load() && g.orgLocksEveryRule()
}

// orgPromptFloorFor is the strongest prompt-mode floor the org layer pins on
// ruleID (PromptModeOff when it pins none).
func (es *engineSet) orgPromptFloorFor(ruleID string) PromptMode {
	best := PromptModeOff
	for _, v := range es.base().RuleStances(ruleID) {
		if m := promptModeFloor(v); promptModeRank[m] > promptModeRank[best] {
			best = m
		}
	}
	return best
}

// promptClassRule maps a detector class onto the prompt rule that judges it
// (R-172 secrets, R-190 PII), the same split the rule catalog makes.
var promptClassRule = map[string]string{
	scrub.ClassSecret: "R-172",
	scrub.ClassPII:    "R-190",
}

// orgPromptReach returns, per detector CLASS, whether the organization's
// prompt pin reaches past the local [guard.prompt] tuning on this node:
// a local "off" (global or per-detector) cannot switch the class's detectors
// off, and a local allow-pattern cannot drop its findings (D-672). It is
// managed-only: on an individual node (lock reaches only the rules the bundle
// names, and the developer keeps full control) it returns nil, so the local
// tuning stands exactly as before. A process with an unresolved tenancy keeps
// the conservative reading every other org-lock path takes.
func (g *Guard) orgPromptReach() map[string]bool {
	es := g.set.Load()
	if es == nil || !es.orgApplies() || !g.orgLocksEveryRule() {
		return nil
	}
	var out map[string]bool
	for class, rule := range promptClassRule {
		if es.orgPromptFloorFor(rule) == PromptModeOff {
			continue
		}
		if out == nil {
			out = map[string]bool{}
		}
		out[class] = true
	}
	return out
}

// detectorReached reports whether the org's prompt pin reaches detector
// name (its class is in reach).
func detectorReached(reach map[string]bool, name string) bool {
	if len(reach) == 0 {
		return false
	}
	class, ok := scrub.DetectorClass(name)
	return ok && reach[class]
}
