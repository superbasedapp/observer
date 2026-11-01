package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/govern/sidecar"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/guardposture"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// The daemon half of the managed-node org lock (T-839 / D-672, T-844,
// T-845). The posture loop (guardposture_wire.go) is the ONE writer of
// guard-org-lock.json, beside guard-posture.json, signed with the same key and
// repaired + reported the same way. Every interval it also:
//
//   - repairs the governance sidecar (and its exceptions file) from the
//     verified copy of what the governance handle last wrote, reporting a
//     tamper (T-845: a strip loop no longer keeps the pins off, the readers
//     use the lock's copy and the file is restored within one interval);
//   - re-verifies the cached org policy bundle and reports a tamper when it
//     no longer verifies (T-844), while the guard keeps enforcing the last
//     verified org layer recorded in the lock.

// governanceCopy is the daemon's verified copy of the governance files the
// governance handle last wrote. It is the ONE owner of that copy: the handle
// fills it inside write (holding mu across its file writes), the posture loop
// reads it for the org lock and repairs the files from it under the same mu,
// so the two can never interleave.
type governanceCopy struct {
	mu   sync.Mutex
	path string
	// known: the handle wrote at least once in this process (or the copy was
	// seeded from a verified lock at start).
	known      bool
	sidecar    []byte
	exceptions []byte
}

// newGovernanceCopy returns an empty copy for the sidecar at path.
func newGovernanceCopy(path string) *governanceCopy {
	if path == "" {
		return nil
	}
	return &governanceCopy{path: path}
}

// processGovernanceCopy is the daemon's governance copy, published by start.go
// once the handle's sidecar is bound (nil in every other process).
var processGovernanceCopy struct {
	mu sync.Mutex
	c  *governanceCopy
}

func setProcessGovernanceCopy(c *governanceCopy) {
	processGovernanceCopy.mu.Lock()
	processGovernanceCopy.c = c
	processGovernanceCopy.mu.Unlock()
}

func currentGovernanceCopy() *governanceCopy {
	processGovernanceCopy.mu.Lock()
	defer processGovernanceCopy.mu.Unlock()
	return processGovernanceCopy.c
}

// write runs fn (the handle's two file writes) under the copy's lock and
// records the bytes when fn reports success. A nil copy just runs fn.
func (c *governanceCopy) write(fn func() (sidecarRaw, exceptionsRaw []byte, ok bool)) {
	if c == nil {
		fn()
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	s, e, ok := fn()
	if !ok {
		return
	}
	c.known = true
	c.sidecar = append([]byte(nil), s...)
	c.exceptions = append([]byte(nil), e...)
}

// snapshot returns the copy (known=false when the handle has not written).
func (c *governanceCopy) snapshot() (known bool, sidecarRaw, exceptionsRaw []byte) {
	if c == nil {
		return false, nil, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.known, append([]byte(nil), c.sidecar...), append([]byte(nil), c.exceptions...)
}

// seed fills an empty copy from the daemon's previous verified lock, so the
// first lock this process writes does not hand the governance files back to
// the disk before the handle's first write.
func (c *governanceCopy) seed(sidecarRaw, exceptionsRaw []byte) {
	if c == nil || len(sidecarRaw) == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.known {
		return
	}
	c.known, c.sidecar, c.exceptions = true, append([]byte(nil), sidecarRaw...), append([]byte(nil), exceptionsRaw...)
}

// repair restores the governance files from the copy when they no longer
// match it and returns one detail per repaired file (T-845).
func (c *governanceCopy) repair() []string {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.known || len(c.sidecar) == 0 {
		return nil
	}
	var out []string
	if disk, err := os.ReadFile(c.path); err != nil || !bytes.Equal(disk, c.sidecar) {
		f, derr := sidecar.Decode(c.sidecar)
		if derr == nil {
			if werr := writeGovernanceSidecarBytes(c.path, c.sidecar, f.EffectiveHash, f.State); werr == nil {
				out = append(out, sidecarChangeDetail(c.path, err))
			}
		}
	}
	exPath := sidecar.ExceptionsPath(c.path)
	disk, err := os.ReadFile(exPath)
	switch {
	case len(c.exceptions) == 0 && err == nil:
		if os.Remove(exPath) == nil {
			out = append(out, "governance-exceptions.json appeared outside the daemon (no exception is in force); removed")
		}
	case len(c.exceptions) > 0 && (err != nil || !bytes.Equal(disk, c.exceptions)):
		if writeGovernanceFileBytes(exPath, c.exceptions, ".governance-exceptions-*.tmp") == nil {
			out = append(out, "governance-exceptions.json was changed or removed outside the daemon; restored")
		}
	}
	return out
}

// sidecarChangeDetail names a repaired sidecar change for the tamper event.
func sidecarChangeDetail(path string, readErr error) string {
	if readErr != nil && errors.Is(readErr, os.ErrNotExist) {
		return "governance-effective.json was removed outside the daemon; restored (" + path + ")"
	}
	return "governance-effective.json was changed outside the daemon; restored (" + path + ")"
}

// Tamper kinds the posture loop reports beside the posture's own (closed
// set; CLAUDE.md rule 5: one row per kind).
const (
	tamperOrgLock    = orgcontract.GuardTamperOrgLock
	tamperGovernance = orgcontract.GuardTamperGovernance
	tamperOrgBundle  = orgcontract.GuardTamperOrgBundle
)

var tamperCopy = map[string]struct{ target, reason, advice string }{
	tamperOrgLock: {
		guardposture.OrgLockFilename,
		"org guard lock tampered: %s; the daemon restored it",
		"Something running as this user rewrote Observer's record of the organization's guard floor. Check which process edits ~/.observer.",
	},
	tamperGovernance: {
		config.GovernanceSidecarFilename,
		"governance settings tampered: %s",
		"Something running as this user edited the organization's governance settings file. Hooks used the daemon's verified copy meanwhile. Check which process edits the files beside observer.db.",
	},
	tamperOrgBundle: {
		"org-policy-bundle.json",
		"org policy bundle tampered: %s",
		"The cached organization guard policy no longer verifies; the guard keeps enforcing the last verified org layer and refuses local approvals for org-locked rules. The next accepted bundle from the organization replaces the file.",
	},
}

// guardTamper is one detected tamper of a file the org lock protects.
type guardTamper struct{ kind, detail string }

// tamperVerdict is the guard event for a tamper of kind: a high guard_error
// flag (nothing was blocked by the report itself), degraded_from = kind, so
// it reaches the org on the normal guard_events push.
func tamperVerdict(t guardTamper, at time.Time) guard.ActionVerdict {
	c := tamperCopy[t.kind]
	return guard.ActionVerdict{
		Input:    guard.ActionInput{Tool: "observer", Target: c.target, Timestamp: at.UTC()},
		Kind:     policy.KindConfigChange,
		Category: "guard",
		Verdict: policy.Verdict{
			Decision: policy.DecisionFlag,
			RuleID:   guard.GuardErrorRuleID,
			Severity: policy.SeverityHigh,
			Reason:   guardEventReason(fmt.Sprintf(c.reason, t.detail)),
			Advice:   c.advice,
			Source:   policy.SourceBuiltin,
		},
		GuardError:   true,
		DegradedFrom: t.kind,
	}
}

// guardEventHome resolves the developer's home for guardEventReason (a var
// so tests pin it without touching the process environment).
var guardEventHome = os.UserHomeDir

// guardEventReason is the ONE rendering every daemon-built guard_error
// reason goes through before it is recorded (and pushed to the org): a path
// under the developer's home reads "~/..." instead of the absolute path,
// which names the developer's account (D-704 gap 5). The local daemon log
// keeps the absolute path; only the recorded event text is rewritten.
func guardEventReason(s string) string {
	home, err := guardEventHome()
	if err != nil {
		return s
	}
	return guard.HomeTilde(s, home)
}

// orgLockGuard returns the guard whose org layer the lock describes: the
// daemon's own live guard, or, when that is off (an individual node with the
// guard disabled, or a managed node whose floor this process predates), a
// guard built from the same inputs only to read the org layer.
func orgLockGuard(ctx context.Context, cfg config.Config, gd *guard.Guard, st *store.Store) *guard.Guard {
	if gd != nil {
		return gd
	}
	return nodeGuard(ctx, cfg, st)
}

// computeOrgLock derives the lock from the live guard's org inputs and the
// verified governance copy (DeriveFloor is the one floor derivation).
func computeOrgLock(gd *guard.Guard, gc *governanceCopy, now time.Time) guardposture.OrgLock {
	var in guard.OrgLockInputs
	if gd != nil {
		in = gd.OrgLockInputs()
	}
	known, gov, ex := gc.snapshot()
	var pinned map[string]any
	if known {
		if f, _ := sidecar.ReadBytes(gov, now); f != nil {
			exceptions, _ := sidecar.ReadExceptionsBytes(ex, f.EffectiveHash)
			pinned, _ = sidecar.PinsInForce(f.Pinned, exceptions, now)
		}
	}
	managed := in.TenancyResolved && in.Managed
	return guardposture.OrgLock{
		Managed: managed,
		Floor: guardposture.DeriveFloor(guardposture.FloorInputs{
			Managed: managed, OrgLayer: in.OrgLayer,
			PromptFloor: in.PromptFloor, PromptFloorStops: in.PromptFloorStops,
			Pinned: pinned,
		}),
		KeyPinHash:           in.KeyPinHash,
		Bundle:               string(in.Envelope),
		BundleExpected:       in.BundleExpected,
		GovernanceKnown:      known,
		Governance:           string(gov),
		GovernanceExceptions: string(ex),
		WrittenAt:            now.UTC(),
	}
}

// publishLock writes the org lock beside the resolved config when its content
// (ignoring WrittenAt) changed, or when the file on disk is not the one this
// writer last wrote, which is queued as a tamper. Called after publish, so
// the key is loaded.
func (w *guardPostureWriter) publishLock(configPath string, l guardposture.OrgLock) (bool, error) {
	resolved, err := config.ResolveGlobalPath(configPath)
	if err != nil {
		return false, fmt.Errorf("guardPostureWriter.publishLock: %w", err)
	}
	path := guardposture.OrgLockPath(resolved)
	cmp := l
	cmp.WrittenAt, cmp.MAC = time.Time{}, ""
	semantic, err := guardposture.EncodeOrgLock(cmp)
	if err != nil {
		return false, err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.key == nil {
		return false, errors.New("guardPostureWriter.publishLock: no key yet")
	}
	disk, rerr := os.ReadFile(path)
	diskIsOurs := rerr == nil && w.lastLockBytes != nil && bytes.Equal(disk, w.lastLockBytes)
	if w.lastLockBytes != nil && !diskIsOurs {
		w.extra = append(w.extra, guardTamper{tamperOrgLock, "guard-org-lock.json was changed or removed outside the daemon"})
	}
	if diskIsOurs && bytes.Equal(semantic, w.lastLock) {
		return false, nil
	}
	written, err := guardposture.WriteOrgLock(path, l, w.key)
	if err != nil {
		return false, err
	}
	w.lastLock, w.lastLockBytes = semantic, written
	return true, nil
}

// noteTamper queues a tamper detected outside publish (governance repair,
// bundle re-verification).
func (w *guardPostureWriter) noteTamper(t guardTamper) {
	w.mu.Lock()
	w.extra = append(w.extra, t)
	w.mu.Unlock()
}

// The org bundle tamper incident (T-869). Two checks can find a tampered,
// deleted or displaced org bundle: the posture check (checkOrgBundle, every
// interval) and the policy poll, which re-downloads a cache that no longer
// verifies (orgclient.PolicyResult.RepairedCache / DisplacedTo). Whichever
// runs first, one incident is ONE org_bundle_tamper event. bundleIncident is
// the one record both consult, and bundleIncidentTable is the one decision.

// bundleIncidentState is where the current incident stands between the two
// checks.
type bundleIncidentState int

const (
	// bundleIncidentNone: no incident is on record.
	bundleIncidentNone bundleIncidentState = iota
	// bundleIncidentReported: the posture check recorded the incident and
	// the poll has not repaired it yet.
	bundleIncidentReported
	// bundleIncidentRepaired: the poll repaired the incident the posture
	// check recorded; the posture check has not seen the file verify since.
	bundleIncidentRepaired
	// bundleIncidentResolved: the posture check saw the file verify again
	// while the incident it recorded had no poll repair on record. The poll
	// writes the file before its result reaches the writer, so a repair
	// reported now is that same incident. Lasts one posture check.
	bundleIncidentResolved
)

// bundleIncidentEvent is one observation of the bundle by either check.
type bundleIncidentEvent int

const (
	// bundleSeenSame: the posture check found the unverifiable content it
	// last recorded.
	bundleSeenSame bundleIncidentEvent = iota
	// bundleSeenNew: the posture check found unverifiable content it has
	// not recorded.
	bundleSeenNew
	// bundleSeenVerified: the posture check found the file verifying.
	bundleSeenVerified
	// bundlePollRepair: the poll re-materialised a cache that was tampered,
	// missing or displaced.
	bundlePollRepair
)

// bundleIncident is the writer's record of the current incident: its state
// and the identity of the unverifiable content the posture check last
// recorded.
type bundleIncident struct {
	state bundleIncidentState
	id    string
}

// bundleIncidentStep is one row's outcome: the next state, and whether the
// event is a new incident to record.
type bundleIncidentStep struct {
	next   bundleIncidentState
	record bool
}

// bundleIncidentTable is the one dedup decision (CLAUDE.md rule 5): every
// (state, event) pair has exactly one row, pinned by a test.
var bundleIncidentTable = map[bundleIncidentState]map[bundleIncidentEvent]bundleIncidentStep{
	bundleIncidentNone: {
		bundleSeenSame:     {bundleIncidentReported, true},
		bundleSeenNew:      {bundleIncidentReported, true},
		bundleSeenVerified: {bundleIncidentNone, false},
		// The poll repaired the file before the posture check saw it: this
		// is the only record of the incident.
		bundlePollRepair: {bundleIncidentNone, true},
	},
	bundleIncidentReported: {
		bundleSeenSame:     {bundleIncidentReported, false},
		bundleSeenNew:      {bundleIncidentReported, true},
		bundleSeenVerified: {bundleIncidentResolved, false},
		bundlePollRepair:   {bundleIncidentRepaired, false},
	},
	bundleIncidentRepaired: {
		// The poll already wrote the org's bundle back: unverifiable content
		// now is a fresh edit.
		bundleSeenSame:     {bundleIncidentReported, true},
		bundleSeenNew:      {bundleIncidentReported, true},
		bundleSeenVerified: {bundleIncidentNone, false},
		bundlePollRepair:   {bundleIncidentNone, true},
	},
	bundleIncidentResolved: {
		bundleSeenSame:     {bundleIncidentReported, true},
		bundleSeenNew:      {bundleIncidentReported, true},
		bundleSeenVerified: {bundleIncidentNone, false},
		bundlePollRepair:   {bundleIncidentNone, false},
	},
}

// stepBundleIncidentLocked applies ev to the incident (w.mu held) and reports
// whether ev is a new incident to record.
func (w *guardPostureWriter) stepBundleIncidentLocked(ev bundleIncidentEvent) bool {
	step, ok := bundleIncidentTable[w.bundle.state][ev]
	if !ok {
		return false
	}
	w.bundle.state = step.next
	return step.record
}

// noteBundleRepair records the policy poll's repair of the org bundle cache
// (a tampered or deleted file re-downloaded, or a foreign entry moved aside,
// D-704) unless the posture check already recorded this incident. detail is
// the event's specifics (bundleRepairDetail). One org_bundle_tamper event per
// incident, whichever check saw it first.
func (w *guardPostureWriter) noteBundleRepair(detail string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.stepBundleIncidentLocked(bundlePollRepair) {
		w.extra = append(w.extra, guardTamper{tamperOrgBundle, detail})
	}
}

// bundleRepair is one poll result as the repair rows read it: the result,
// the cache path to name in the event, and whether a deletion is a tamper on
// this node (the posture check's own rule, guard.missingBundleIsTamper: the
// org lock reaches every rule, i.e. a managed node or an unresolved tenancy;
// on an individual node a missing bundle is simply no org layer).
type bundleRepair struct {
	res              orgclient.PolicyResult
	cachePath        string
	deletionIsTamper bool
}

// bundleRepairRows render the tamper detail for a poll repair, walked top
// down; the first row that applies wins (a displaced entry is the most
// specific account of a "missing" cache). No row applies to a clean upgrade,
// a first fetch, or a pre-fetch check an I/O fault left undecided.
var bundleRepairRows = []struct {
	applies func(bundleRepair) bool
	detail  func(bundleRepair) string
}{
	{
		func(r bundleRepair) bool { return r.res.DisplacedTo != "" },
		func(r bundleRepair) string {
			return "org-policy-bundle.json was replaced by something that is not the bundle file; the daemon moved it aside to " +
				filepath.Base(r.res.DisplacedTo) + " (nothing deleted) and restored the organization's bundle"
		},
	},
	{
		func(r bundleRepair) bool { return r.res.RepairedCache == orgclient.CacheRepairTampered },
		func(r bundleRepair) string {
			why := ""
			if r.res.RepairedCode != orgclient.RejectNone {
				why = " (" + string(r.res.RepairedCode) + ")"
			}
			return r.cachePath + " was changed outside the daemon and no longer verified" + why +
				"; the policy poll restored the organization's bundle"
		},
	},
	{
		func(r bundleRepair) bool {
			return r.res.RepairedCache == orgclient.CacheRepairMissing && r.deletionIsTamper
		},
		func(r bundleRepair) string {
			return r.cachePath + " was removed outside the daemon although this node had accepted a verified bundle; the policy poll restored the organization's bundle"
		},
	},
}

// bundleRepairDetail returns the tamper detail for a poll result that
// repaired the cache, and false when it repaired nothing that is a tamper
// here (a clean upgrade, a first fetch, a 304, a deletion on an individual
// node). The cache path is named in the event ("~/..." once guardEventReason
// renders it).
func bundleRepairDetail(r bundleRepair) (string, bool) {
	if r.res.Status != orgclient.PolicyApplied {
		return "", false
	}
	if r.cachePath == "" {
		r.cachePath = "org-policy-bundle.json"
	}
	for _, row := range bundleRepairRows {
		if row.applies(r) {
			return row.detail(r), true
		}
	}
	return "", false
}

// deletionIsTamper reports whether a missing org bundle is a tamper on the
// node gd runs on: the org lock reaches every rule (a managed node, or a
// tenancy not yet resolved, the conservative reading). A nil guard reads the
// conservative way too.
func deletionIsTamper(gd *guard.Guard) bool {
	if gd == nil {
		return true
	}
	in := gd.OrgLockInputs()
	return !in.TenancyResolved || in.Managed
}

// takeExtraTampers returns and clears the queued non-posture tampers.
func (w *guardPostureWriter) takeExtraTampers() []guardTamper {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := w.extra
	w.extra = nil
	return out
}

// bundleTamperSeen dedupes the bundle tamper report: one event per distinct
// unverifiable file content, so a broken bundle is reported once, not every
// interval, and an edit to a different broken content is reported again. It
// reports true when the incident is already on record (by this check, or by
// the poll's repair; bundleIncidentTable).
func (w *guardPostureWriter) bundleTamperSeen(issue string, raw []byte) bool {
	sum := sha256.Sum256(append([]byte(issue+"\x00"), raw...))
	id := hex.EncodeToString(sum[:])
	w.mu.Lock()
	defer w.mu.Unlock()
	ev := bundleSeenNew
	if w.bundle.id == id {
		ev = bundleSeenSame
	}
	if !w.stepBundleIncidentLocked(ev) {
		return true
	}
	w.bundle.id = id
	return false
}

// bundleSeenVerifying notes that the posture check found the cached bundle
// verifying (the incident, if any, is over).
func (w *guardPostureWriter) bundleSeenVerifying() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.stepBundleIncidentLocked(bundleSeenVerified)
}

// checkOrgBundle reports a cached org bundle that no longer verifies under
// the daemon's pin (T-844). The live guard is not changed: it keeps the last
// verified org layer, and hooks fall back to the copy in the lock.
func (w *guardPostureWriter) checkOrgBundle(gd *guard.Guard) {
	if gd == nil {
		return
	}
	issue, raw := gd.OrgBundleFileIssue()
	if issue == "" {
		w.bundleSeenVerifying()
		return
	}
	if w.bundleTamperSeen(issue, raw) {
		return
	}
	w.noteTamper(guardTamper{tamperOrgBundle, issue})
	// Re-fetch now (T-864 gap 1): an edited or deleted cache no longer
	// verifies, so the poll sends no If-None-Match and downloads the
	// organization's bundle again instead of waiting for the hourly poll.
	kickPolicyBundle()
}

// processPolicyBundleKick is the daemon's org policy poll wake-up, published
// by start.go when the poll loop starts (nil in every other process, and
// while the node is not enrolled).
var processPolicyBundleKick struct {
	mu sync.Mutex
	fn func()
}

// setProcessPolicyBundleKick publishes the poll wake-up (nil clears it).
func setProcessPolicyBundleKick(fn func()) {
	processPolicyBundleKick.mu.Lock()
	processPolicyBundleKick.fn = fn
	processPolicyBundleKick.mu.Unlock()
}

// kickPolicyBundle wakes the org policy poll when one runs in this process.
func kickPolicyBundle() {
	processPolicyBundleKick.mu.Lock()
	fn := processPolicyBundleKick.fn
	processPolicyBundleKick.mu.Unlock()
	if fn != nil {
		fn()
	}
}

// publishOrgLockState is the per-interval org-lock work of the posture loop:
// write the lock, repair the governance files, re-verify the bundle.
func publishOrgLockState(ctx context.Context, configPath string, cfg config.Config, gd *guard.Guard, st *store.Store, w *guardPostureWriter, now time.Time) error {
	gc := currentGovernanceCopy()
	w.seedGovernanceOnce(gc)
	lockGuard := orgLockGuard(ctx, cfg, gd, st)
	if _, err := w.publishLock(configPath, computeOrgLock(lockGuard, gc, now)); err != nil {
		return err
	}
	for _, d := range gc.repair() {
		w.noteTamper(guardTamper{tamperGovernance, d})
	}
	w.checkOrgBundle(lockGuard)
	return nil
}

// seedGovernanceOnce seeds the governance copy from the lock this daemon
// found at start (when it verified), once per process.
func (w *guardPostureWriter) seedGovernanceOnce(gc *governanceCopy) {
	w.mu.Lock()
	start := w.startLock
	w.startLock = nil
	w.mu.Unlock()
	if start == nil || start.State != guardposture.OrgLockValid || !start.Lock.GovernanceKnown {
		return
	}
	gc.seed([]byte(start.Lock.Governance), []byte(start.Lock.GovernanceExceptions))
}

// guardOrgLockLines renders the org-lock lines of `observer guard status`
// (D-672: the floor is visible locally). Empty on a node with no lock.
func guardOrgLockLines(l config.GuardOrgLock, st guard.OrgLockStatus) []string {
	var out []string
	switch {
	case l.State == "tampered":
		out = append(out, "Org lock:     UNVERIFIABLE ("+l.Detail+") - conservative floor in force until the daemon repairs it")
	case l.State == "valid" && l.Managed:
		out = append(out, "Org lock:     managed node - the organization's guard floor is in force")
	case l.State == "valid":
		out = append(out, "Org lock:     individual node - local guard settings are in full control")
	}
	// T-881: the values a governance pin replaced, then the ones the floor
	// raised, from the one list config.Load recorded.
	for _, o := range l.OverrideLines() {
		out = append(out, "OVERRIDDEN:   "+o+" (set by organization policy; the local value does not apply)")
	}
	// T-889: say what is actually wrong with the file (a deleted bundle is
	// "missing", not "does not verify").
	problem := st.BundleProblem
	if problem == "" {
		problem = "is missing or does not verify"
	}
	switch {
	case st.LastVerifiedInUse:
		out = append(out, "Org bundle:   the cached bundle "+problem+" - enforcing the last verified org layer")
	case st.Unverifiable:
		out = append(out, "Org bundle:   the cached bundle "+problem+" and no verified copy is held - local approvals are refused for every rule")
	}
	return out
}
