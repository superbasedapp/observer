package hook

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"sync"
	"time"
)

// reconcile.go - T-847 / T-849: hook tamper is loud per event.
//
// Auto-registration is idempotent, so running it again is also the repair
// path: a removed or weakened Observer hook is written back to its canonical
// form. Before T-847 that repair was silent (and the checksum registry was
// re-recorded against whatever was on disk). This file is the ONE owner of
// three facts the managed-integrity probe reports:
//
//   - Probe: what a registration WOULD change right now (a dry run through
//     the same writers), so missing or weakened wiring is visible even when
//     the checksum registry was deleted or re-baselined;
//   - Reconcile: a real registration, its outcome recorded in
//     hook_checksums.json, and whether the write was a REPAIR of an event
//     Observer had registered before (not a first install, not a new event a
//     newer Observer adds);
//   - RepairTracker: the daemon-lifetime memory that makes a repair
//     recognisable even after hook_checksums.json itself was deleted.
//
// Every writer is reached through Register, so all of it dispatches on the
// registration target's hook mechanism, never on a tool name.

// benignRewriteRules are the hook equivalence rules (hookEquivalenceRules)
// whose rewrite is maintenance, not a repair: an upgrade or reinstall that
// moved the observer binary leaves an entry naming a binary that no longer
// runs, and rewriting it is not a sign anyone weakened the hook.
var benignRewriteRules = map[string]bool{
	"binary-broken": true,
}

// DriftEvents returns the native events a registration result changed or,
// for a dry run, would change: every added event plus every rewritten one,
// de-duplicated and sorted. Empty means the target's wiring is canonical.
func DriftEvents(res RegistrationResult) []string {
	set := map[string]bool{}
	for _, e := range res.HooksAdded {
		set[e] = true
	}
	for _, rw := range res.Rewrites {
		set[rw.Event] = true
	}
	return sortedSet(set)
}

// repairCandidates is DriftEvents minus the events whose only change was a
// benign rewrite.
func repairCandidates(res RegistrationResult) []string {
	benign := map[string]bool{}
	for _, rw := range res.Rewrites {
		if benignRewriteRules[rw.Rule] {
			benign[rw.Event] = true
		}
	}
	for _, rw := range res.Rewrites {
		if !benignRewriteRules[rw.Rule] {
			delete(benign, rw.Event)
		}
	}
	set := map[string]bool{}
	for _, e := range DriftEvents(res) {
		if !benign[e] {
			set[e] = true
		}
	}
	return sortedSet(set)
}

// Probe dry-runs Register(tool) with this registry's options: nothing is
// written, and the result says what a real registration would change
// (DriftEvents) and which file it owns (ConfigPath).
func (r *Registry) Probe(tool string) RegistrationResult {
	dry := *r
	dry.opts.DryRun = true
	return dry.Register(tool)
}

// RepairTracker is the daemon-lifetime memory of which events each
// registration target was seen fully registered with. A registration that
// has to write one of those events again is a repair, even when the
// developer also deleted hook_checksums.json (audit c3). The zero value is
// ready to use; it is safe for concurrent use.
type RepairTracker struct {
	mu   sync.Mutex
	seen map[string]map[string]bool
	// registryLostAt is when a pass found hook_checksums.json missing after
	// this process had registered hooks (zero when it never did).
	registryLostAt time.Time
}

// knows reports whether target was seen registered with event.
func (t *RepairTracker) knows(target, event string) bool {
	if t == nil {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.seen[target][event]
}

// observe records that target is registered with events.
func (t *RepairTracker) observe(target string, events []string) {
	if t == nil || len(events) == 0 {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.seen == nil {
		t.seen = map[string]map[string]bool{}
	}
	if t.seen[target] == nil {
		t.seen[target] = map[string]bool{}
	}
	for _, e := range events {
		t.seen[target][e] = true
	}
}

// anySeen reports whether the tracker has seen any registration.
func (t *RepairTracker) anySeen() bool {
	if t == nil {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.seen) > 0
}

// RegistryLostSince reports when a pass last found hook_checksums.json
// missing after this process had registered hooks, if that was within window
// of now.
func (t *RepairTracker) RegistryLostSince(now time.Time, window time.Duration) (time.Time, bool) {
	if t == nil {
		return time.Time{}, false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.registryLostAt.IsZero() || now.Sub(t.registryLostAt) > window {
		return time.Time{}, false
	}
	return t.registryLostAt, true
}

// BeginPass is called once before a registration pass. It notes a missing
// hook_checksums.json on a node this process has already registered hooks
// for: the pass that follows recreates the file, so without this note the
// deletion itself would leave no trace.
func (r *Registry) BeginPass(t *RepairTracker, now time.Time) {
	if t == nil || !t.anySeen() {
		return
	}
	if _, err := os.Stat(r.checksumsPath()); errors.Is(err, os.ErrNotExist) {
		t.mu.Lock()
		t.registryLostAt = now.UTC()
		t.mu.Unlock()
	}
}

// ReconcileResult is the outcome of one Reconcile call.
type ReconcileResult struct {
	// Result is the real registration's result.
	Result RegistrationResult
	// Repaired names the events this registration wrote back after they had
	// been registered before (empty when it repaired nothing).
	Repaired []string
	// RecordErr is a failure to persist the outcome in hook_checksums.json.
	RecordErr error
}

// Reconcile registers tool for real (Register), records the outcome in
// hook_checksums.json (RecordRegistration) and classifies what it wrote: an
// event is REPAIRED when it was changed by this registration and had been
// registered before, according to the registry entry's recorded events or the
// tracker. A first install, and an event a newer Observer adds for the first
// time, are not repairs. A nil tracker uses the registry entry alone.
func (r *Registry) Reconcile(tool string, t *RepairTracker, now time.Time) ReconcileResult {
	prior := r.checksumEntries()
	res := r.Register(tool)
	out := ReconcileResult{Result: res}
	if !res.DryRun && res.Error == nil && !res.Skipped {
		recorded := entryEvents(prior[res.ConfigPath])
		for _, e := range repairCandidates(res) {
			if recorded[e] || t.knows(res.Tool, e) {
				out.Repaired = append(out.Repaired, e)
			}
		}
		t.observe(res.Tool, resultEvents(res))
	}
	if res.ConfigPath != "" && !res.DryRun {
		out.RecordErr = r.RecordRegistration(res, out.Repaired, now)
	}
	return out
}

// resultEvents is every event a successful registration left in place.
func resultEvents(res RegistrationResult) []string {
	set := map[string]bool{}
	for _, e := range res.AlreadySet {
		set[e] = true
	}
	for _, e := range res.HooksAdded {
		set[e] = true
	}
	return sortedSet(set)
}

// RecordRegistration persists one auto-registration outcome into the
// hook_checksums.json entry for res.ConfigPath, keeping every other field:
// the target label ("tool"), last_result / last_error / last_checked_at (as
// RecordAutoRegisterResult), the events the target is registered with
// ("events", successful registrations only) and, when repaired is non-empty,
// last_repaired_at / last_repaired_events (and last_repaired_copy, the kept
// pre-repair bytes, T-884), which the managed-integrity probe reports as
// hook_repaired for a day. A failed registration also stamps last_error_at,
// which a later successful pass keeps, so the probe can report a failure that
// has cleared as hook_registration_failed for a day (T-887). A zero now means
// time.Now.
func (r *Registry) RecordRegistration(res RegistrationResult, repaired []string, now time.Time) error {
	if res.ConfigPath == "" {
		return nil
	}
	if now.IsZero() {
		now = time.Now()
	}
	stamp := now.UTC().Format(time.RFC3339)
	err := r.updateChecksumEntry(res.ConfigPath, func(entry map[string]any) {
		entry["last_checked_at"] = stamp
		if res.Tool != "" {
			entry["tool"] = res.Tool
		}
		if res.Error != nil {
			entry["last_result"] = "error"
			entry["last_error"] = res.Error.Error()
			// T-887: the failure time outlives the error (a later "ok"
			// keeps it), so a failure fixed before the next accepted org
			// report is still reported, as hook_registration_failed.
			entry["last_error_at"] = stamp
			return
		}
		entry["last_result"] = "ok"
		delete(entry, "last_error")
		if ev := resultEvents(res); len(ev) > 0 && !res.Skipped {
			entry["events"] = ev
		}
		if len(repaired) > 0 {
			entry["last_repaired_at"] = stamp
			entry["last_repaired_events"] = repaired
			// T-884: where this repair kept the bytes it replaced. A
			// repair that kept none clears an older repair's copy, so
			// the three last_repaired_* fields always describe one repair.
			if res.RepairCopy != "" {
				entry[LastRepairedCopyKey] = res.RepairCopy
			} else {
				delete(entry, LastRepairedCopyKey)
			}
		}
	})
	if err != nil {
		return fmt.Errorf("hook.RecordRegistration: %w", err)
	}
	return nil
}

// LastRepairedCopyKey is the hook_checksums.json entry field naming where the
// newest managed repair kept the artifact's pre-repair bytes (T-884). The
// managed-integrity probe (internal/diag) reads it into the hook_repaired
// item.
const LastRepairedCopyKey = "last_repaired_copy"

// checksumEntries reads hook_checksums.json (nil when absent or unreadable).
func (r *Registry) checksumEntries() map[string]map[string]any {
	raw, err := os.ReadFile(r.checksumsPath())
	if err != nil {
		return nil
	}
	out := map[string]map[string]any{}
	if json.Unmarshal(raw, &out) != nil {
		return nil
	}
	return out
}

// entryEvents is the "events" list a registry entry recorded.
func entryEvents(entry map[string]any) map[string]bool {
	out := map[string]bool{}
	list, _ := entry["events"].([]any)
	for _, v := range list {
		if s, ok := v.(string); ok {
			out[s] = true
		}
	}
	return out
}

func sortedSet(set map[string]bool) []string {
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
