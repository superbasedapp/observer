package main

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"reflect"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/guardposture"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// guardPostureInterval is how often the daemon re-publishes the posture
// (only when it changed) and drains the hook failure spool.
const guardPostureInterval = 15 * time.Second

// computeGuardPosture derives guard-posture.json from the daemon's live
// guard, per gate family (guard.Guard.GateEnforcement, the same answer
// the live guard acts on): the tool gate is closed by global or per-rule
// enforcement, the prompt gate by active prompt enforcement (which
// includes the default independent prompt enforcement in observe mode,
// Sol A2-01). A nil guard (off, or not constructible) is not enforced.
func computeGuardPosture(g config.GuardConfig, gd *guard.Guard, now time.Time) guardposture.Posture {
	p := guardposture.Posture{Source: guardposture.SourceLocal, WrittenAt: now.UTC()}
	if gd != nil {
		// The tenancy anchor a hook falls back to while the org lock is
		// being repaired (T-864 gap 1). Recorded only when this guard
		// resolved it, so "not managed" always means "individual".
		if in := gd.OrgLockInputs(); in.TenancyResolved {
			p.Managed, p.TenancyRecorded = in.Managed, true
		}
	}
	// The organization's prompt judge (lane adm-2) is independent of the
	// local guard's own mode: the hook asks it whenever it is active here.
	p.PromptJudgeActive, p.PromptJudgeFailClosed = processPlaneBLane.hookPosture()
	if gd == nil || !g.Enabled || g.Mode == "off" {
		return p
	}
	for _, st := range gd.PolicyStates() {
		if st.Layer == "org" {
			p.Source = guardposture.SourceOrg
			p.Generation = st.Version
		}
	}
	ep := postureFromEnforcement(guardGateEnforcement(g, gd))
	p.Enforced, p.GateCaps, p.UserPolicyFailClosed = ep.Enforced, ep.GateCaps, ep.UserPolicyFailClosed
	return p
}

// guardGateEnforcement is the ONE gate-enforcement answer behind the hook
// failure posture, called by the daemon's posture writer
// (computeGuardPosture) and by the hook's fallback
// (hookFallbackGateEnforcement) on guards built from the same inputs
// (nodeGuardPolicyInputs): the guard's own GateEnforcement, which sees the
// org bundle, per-rule enforcement and an unverifiable bundle on a managed
// node. A nil guard or a guard that is off is not enforced.
func guardGateEnforcement(g config.GuardConfig, gd *guard.Guard) guard.GateEnforcement {
	if gd == nil || !g.Enabled || g.Mode == "off" {
		return guard.GateEnforcement{}
	}
	return gd.GateEnforcement()
}

// guardPostureWriter is the ONE writer of guard-posture.json in a daemon
// process (start, the periodic re-publish and the org-bundle reload all
// publish through it). It skips a rewrite when the content is unchanged.
//
// It also owns the posture's authentication (Sol A2-02): it holds the HMAC
// key in memory, signs every write, and on every publish re-checks the
// files on disk. A posture or key that differs from what it last wrote (or
// went missing) is repaired and queued as a tamper event, which the
// posture loop persists as a guard event so the org sees it.
type guardPostureWriter struct {
	mu sync.Mutex
	// key is the HMAC key this process signs with (nil until the first
	// publish loads or creates it).
	key []byte
	// last is the semantic encoding (no WrittenAt, no MAC) of the last
	// publish; lastBytes the exact bytes written.
	last, lastBytes []byte
	// lastWrittenAt is the WrittenAt of the last write: an unchanged
	// posture is re-signed once it is RefreshInterval old, so a reader can
	// tell a running daemon's posture from a stopped one's (T-050).
	lastWrittenAt time.Time
	// tampers are detected, not yet persisted, tamper details.
	tampers []string

	// The org lock (guardorglock_wire.go, T-839 / T-844 / T-845): the
	// semantic encoding and exact bytes of the last lock written, the lock
	// found on disk at the first publish (seeds the governance copy), the
	// queued non-posture tampers and the org bundle tamper incident (the ONE
	// record both the posture check and the policy poll consult, so one
	// incident is one event whichever finds it first; T-869).
	lastLock, lastLockBytes []byte
	startLock               *guardposture.OrgLockLoaded
	extra                   []guardTamper
	bundle                  bundleIncident
}

// daemonGuardPosture is the process's posture writer.
var daemonGuardPosture = &guardPostureWriter{}

// publish writes p to the posture file beside the resolved config when its
// content (ignoring WrittenAt) changed, or when the files on disk are not
// the ones this writer last wrote (repair).
func (w *guardPostureWriter) publish(configPath string, p guardposture.Posture) (bool, error) {
	resolved, err := config.ResolveGlobalPath(configPath)
	if err != nil {
		return false, fmt.Errorf("guardPostureWriter.publish: %w", err)
	}
	postPath, keyPath := guardposture.PosturePath(resolved), guardposture.KeyPath(resolved)
	cmp := p
	cmp.WrittenAt = time.Time{}
	cmp.MAC = ""
	semantic, err := guardposture.Encode(cmp)
	if err != nil {
		return false, err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.key == nil {
		// The org lock as this daemon found it, read BEFORE the first
		// posture write (which sets the posture's org_lock anchor): a lock
		// tampered with while no daemon ran is reported, and a verified one
		// seeds the governance copy (seedGovernanceOnce).
		start := guardposture.LoadOrgLock(resolved)
		w.startLock = &start
		if start.State == guardposture.OrgLockTampered {
			w.extra = append(w.extra, guardTamper{tamperOrgLock, "found at daemon start: " + start.Detail})
		}
	}
	force, err := w.ensureKeyLocked(postPath, keyPath)
	if err != nil {
		return false, err
	}
	disk, rerr := os.ReadFile(postPath)
	diskIsOurs := rerr == nil && w.lastBytes != nil && bytes.Equal(disk, w.lastBytes)
	if w.lastBytes != nil && !diskIsOurs {
		w.tampers = append(w.tampers, "guard-posture.json was changed or removed outside the daemon")
		force = true
	}
	changed := force || !diskIsOurs || !bytes.Equal(semantic, w.last)
	heartbeat := p.WrittenAt.Sub(w.lastWrittenAt) >= guardposture.RefreshInterval
	if !changed && !heartbeat {
		return false, nil
	}
	written, err := guardposture.Write(postPath, p, w.key)
	if err != nil {
		return false, err
	}
	w.last, w.lastBytes, w.lastWrittenAt = semantic, written, p.WrittenAt
	// A heartbeat-only re-sign is not a change (no log line per minute).
	return changed, nil
}

// requestRefresh makes the next publish re-sign the posture even when its
// content is unchanged (the config file changed without touching [guard]:
// the new WrittenAt must postdate it, or readers would call it stale).
func (w *guardPostureWriter) requestRefresh() {
	w.mu.Lock()
	w.lastWrittenAt = time.Time{}
	w.mu.Unlock()
}

// ensureKeyLocked loads the signing key on the first publish (flagging a
// posture that was forged under an existing key while no daemon ran), and
// on later publishes repairs a key file that no longer holds this
// process's key. force reports that the posture must be rewritten.
func (w *guardPostureWriter) ensureKeyLocked(postPath, keyPath string) (force bool, err error) {
	if w.key == nil {
		prior, kerr := guardposture.ReadKey(keyPath)
		if kerr == nil && prior != nil {
			if pre := guardposture.Load(postPath, keyPath); pre.State == guardposture.StateTampered {
				w.tampers = append(w.tampers, "found at daemon start: "+pre.Detail)
			}
		}
		key, err := guardposture.LoadOrCreateKey(keyPath)
		if err != nil {
			return false, err
		}
		w.key = key
		return true, nil
	}
	disk, kerr := guardposture.ReadKey(keyPath)
	if kerr == nil && bytes.Equal(disk, w.key) {
		return false, nil
	}
	w.tampers = append(w.tampers, "guard-posture.key was changed or removed outside the daemon")
	if err := guardposture.WriteKey(keyPath, w.key); err != nil {
		return false, err
	}
	return true, nil
}

// takeTampers returns and clears the queued tamper details.
func (w *guardPostureWriter) takeTampers() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := w.tampers
	w.tampers = nil
	return out
}

// postureTamperVerdict is the guard event for a detected posture tamper:
// a guard_error flag (the daemon repaired the file; nothing was blocked),
// degraded_from "posture_tamper", so it reaches the org on the normal
// guard_events push.
func postureTamperVerdict(detail string, at time.Time) guard.ActionVerdict {
	return guard.ActionVerdict{
		Input:    guard.ActionInput{Tool: "observer", Target: guardposture.PostureFilename, Timestamp: at.UTC()},
		Kind:     policy.KindConfigChange,
		Category: "guard",
		Verdict: policy.Verdict{
			Decision: policy.DecisionFlag,
			RuleID:   guard.GuardErrorRuleID,
			Severity: policy.SeverityHigh,
			Reason:   guardEventReason("guard posture tampered: " + detail + "; the daemon restored it"),
			Advice:   "Something running as this user rewrote Observer's hook enforcement posture. Check which process edits ~/.observer.",
			Source:   policy.SourceBuiltin,
		},
		GuardError:   true,
		DegradedFrom: orgcontract.GuardTamperPosture,
	}
}

// recordPostureTampers persists the queued tamper events (best effort;
// they stay logged on failure).
func recordPostureTampers(ctx context.Context, w *guardPostureWriter, st *store.Store, logger *slog.Logger) int {
	details := w.takeTampers()
	extra := w.takeExtraTampers()
	if len(details) == 0 && len(extra) == 0 {
		return 0
	}
	now := time.Now()
	vs := make([]guard.ActionVerdict, 0, len(details)+len(extra))
	for _, d := range details {
		logger.Warn("guard posture: tamper detected and repaired", "detail", d)
		vs = append(vs, postureTamperVerdict(d, now))
	}
	for _, t := range extra {
		logger.Warn("guard org lock: tamper detected", "kind", t.kind, "detail", t.detail)
		vs = append(vs, tamperVerdict(t, now))
	}
	if st == nil {
		return 0
	}
	if _, err := st.PersistGuardVerdicts(ctx, vs); err != nil {
		logger.Warn("guard posture: persist tamper events", "err", err)
		return 0
	}
	return len(vs)
}

// publishGuardPosture computes and publishes the posture for gd, logging
// (never failing) on error.
func publishGuardPosture(configPath string, g config.GuardConfig, gd *guard.Guard, logger *slog.Logger) {
	p := computeGuardPosture(g, gd, time.Now())
	// This daemon writes guard-org-lock.json (publishOrgLockState), so a
	// missing lock reads as tampered, not as an older daemon.
	p.OrgLock = true
	// The security module's state, signed in so a hook reads a missing
	// security posture file as unknown only while the module is active
	// (security pillar plan section 4.3).
	p.SecurityRecorded, p.SecurityActive = true, daemonSecurityActive.Load()
	p.SecurityPacks = daemonSecurityPackSet()
	// A managed node's commit gate floor, signed in so the hook keeps it when
	// a project's own posture file cannot answer (audit SEC-P4 F2).
	p.CommitGateFloorHeld = securityCommitGateFloorHeld()
	changed, err := daemonGuardPosture.publish(configPath, p)
	if err != nil {
		logger.Warn("guard posture: publish failed", "err", err)
		return
	}
	if changed {
		logger.Info("guard posture: published", "enforced", p.Enforced, "source", p.Source,
			"generation", p.Generation, "gate_caps", p.GateCaps, "user_policy_fail_closed", p.UserPolicyFailClosed)
	}
}

// hookFailureOutcome is how one spool outcome is persisted (T-049): a
// fail-closed block is an enforced guard_error deny; a fail-open failure is
// a non-enforced guard_error flag (the call went through unevaluated).
type hookFailureOutcome struct {
	decision policy.Decision
	severity policy.Severity
	enforced bool
	reason   string // fmt: kind, tool, event
}

var hookFailureOutcomes = map[bool]hookFailureOutcome{
	false: {
		policy.DecisionDeny, policy.SeverityHigh, true,
		"hook failed closed (%s) on %s %s: guard enforcement is on, so the call was blocked unevaluated",
	},
	true: {
		policy.DecisionFlag, policy.SeverityWarn, false,
		"hook failed open (%s) on %s %s: guard enforcement is off for this gate, so the call went through unevaluated",
	},
}

// hookFailureVerdict turns one spooled hook failure into the guard_error
// verdict the one guard_events writer persists, with the failure kind in
// DegradedFrom, so it reaches the org on the normal guard_events push: an
// enforced deny for a fail-closed block, a non-enforced flag for a
// fail-open failure.
func hookFailureVerdict(r guardposture.Record) guard.ActionVerdict {
	kind, actionType := policy.KindToolCall, ""
	if r.Cap == string(integration.HookCapPromptGate) {
		kind, actionType = policy.KindUserPrompt, models.ActionUserPrompt
	}
	o := hookFailureOutcomes[r.FailedOpen()]
	reason := fmt.Sprintf(o.reason, r.Kind, r.Tool, r.Event)
	advice := "Check the hook's stderr and `observer doctor`; repeated failures mean the hook cannot evaluate calls on this node."
	if c, ok := hookCloseCopy[r.Kind]; ok {
		event := r.Event
		if r.Native != "" {
			event += " (tool " + r.Native + ")"
		}
		reason = fmt.Sprintf(c.reason, r.Tool, event)
		advice = c.advice
	}
	return guard.ActionVerdict{
		Input: guard.ActionInput{
			SessionID: r.SessionID, Tool: r.Tool, ActionType: actionType,
			Target: r.Event, Timestamp: r.At,
		},
		Kind:     kind,
		Category: "guard",
		Verdict: policy.Verdict{
			Decision: o.decision,
			RuleID:   guard.GuardErrorRuleID,
			Severity: o.severity,
			Reason:   guardEventReason(reason),
			Advice:   advice,
			Source:   policy.SourceBuiltin,
		},
		GuardError:   true,
		Enforced:     o.enforced,
		DegradedFrom: r.Kind,
	}
}

// hookCloseCopy is the per-kind wording for a spooled gate closure that is
// not a hook FAILURE (table-driven; a kind with no row keeps the generic
// failure copy). reason takes the tool and the event.
var hookCloseCopy = map[string]struct{ reason, advice string }{
	guardposture.KindUserPolicyFailClosed: {
		reason: "gate closed on %s %s: the organization requires gated hooks to fail closed while the user guard policy does not load",
		advice: "Fix ~/.observer/guard-policy.toml (Security > Rules > Advanced: policy layers, or `observer guard lint`); calls resume as soon as it loads.",
	},
	guardposture.KindUnclassified: {
		reason: "tool gate on %s %s could not classify the call (a tool name Observer does not know, or no operand), so it went through unjudged",
		advice: "Recorded at most once an hour per tool. If the tool is new or renamed, update Observer; `observer doctor --hooks` shows the gate's state.",
	},
}

// drainChunksPerTick bounds one tick's drain work; a larger spool is
// finished on later ticks (Commit keeps the unread tail).
const drainChunksPerTick = 8

// hookFailDrainCap is one chunk's byte bound (0 = the package default;
// tests lower it).
var hookFailDrainCap int64

// drainHookFailures moves the hook failure spool into guard_events, one
// bounded chunk at a time. A chunk is committed only after its persist
// succeeded; on failure it stays aside for the next tick. Bytes past a
// chunk are kept, never dropped (Sol A2-07).
func drainHookFailures(ctx context.Context, spoolPath string, st *store.Store, logger *slog.Logger) int {
	total := 0
	for i := 0; i < drainChunksPerTick; i++ {
		n, more, ok := drainHookFailureChunk(ctx, spoolPath, st, logger)
		total += n
		if !ok || !more {
			break
		}
	}
	return total
}

// drainHookFailureChunk drains and commits one chunk. more reports that
// the spool still holds data; ok is false when the chunk could not be
// drained or persisted (stop for this tick).
func drainHookFailureChunk(ctx context.Context, spoolPath string, st *store.Store, logger *slog.Logger) (n int, more, ok bool) {
	b, err := guardposture.Drain(spoolPath, hookFailDrainCap)
	if err != nil {
		logger.Warn("guard posture: hook failure spool drain", "err", err)
		return 0, false, false
	}
	if b == nil {
		return 0, false, true
	}
	if b.Dropped > 0 {
		logger.Warn("guard posture: hook failure spool had unreadable lines", "dropped", b.Dropped)
	}
	if len(b.Records) > 0 {
		vs := make([]guard.ActionVerdict, 0, len(b.Records))
		for _, r := range b.Records {
			vs = append(vs, hookFailureVerdict(r))
		}
		if _, err := st.PersistGuardVerdicts(ctx, vs); err != nil {
			logger.Warn("guard posture: persist hook failures", "err", err, "records", len(vs))
			return 0, false, false
		}
	}
	if err := b.Commit(); err != nil {
		logger.Warn("guard posture: commit hook failure spool", "err", err)
		return len(b.Records), false, false
	}
	return len(b.Records), true, true
}

// postureConfigState is what the config file says about the daemon's
// loaded guard config.
type postureConfigState int

const (
	// postureConfigCurrent: the file has not changed since the daemon loaded
	// it.
	postureConfigCurrent postureConfigState = iota
	// postureConfigTouched: the file changed but its [guard] section equals
	// the loaded one: keep publishing, re-signed after the change.
	postureConfigTouched
	// postureConfigGuardChanged: the file's [guard] section differs from
	// the one the daemon runs on (or the file no longer loads): the daemon's
	// posture would describe a config the hooks no longer read, so it stops
	// publishing until restarted (T-050).
	postureConfigGuardChanged
)

// postureConfigWatch tracks the global config file the daemon's guard was
// built from (one owner: guardPostureLoop).
type postureConfigWatch struct {
	path, configPath string
	guard            config.GuardConfig
	mod              time.Time
	warned           bool
}

// check stats the config file and classifies it against the loaded guard.
func (c *postureConfigWatch) check(logger *slog.Logger) postureConfigState {
	cur := fileModTime(c.path)
	if cur.Equal(c.mod) {
		return postureConfigCurrent
	}
	fresh, err := config.Load(config.LoadOptions{GlobalPath: c.configPath})
	// The org-lock record (GuardConfig.Lock) is the org's runtime state, not
	// the file's [guard] section: a lock rewrite must not read as a config
	// change.
	freshGuard, loaded := fresh.Guard, c.guard
	freshGuard.Lock, loaded.Lock = config.GuardOrgLock{}, config.GuardOrgLock{}
	if err == nil && reflect.DeepEqual(freshGuard, loaded) {
		c.mod, c.warned = cur, false
		return postureConfigTouched
	}
	if !c.warned {
		c.warned = true
		logger.Warn("guard posture: config.toml [guard] changed since the daemon started; not publishing the posture until restart, so hook failures follow the file")
	}
	return postureConfigGuardChanged
}

// guardPostureLoop is the daemon's posture owner: publish at start, then
// every guardPostureInterval re-publish (a no-op unless the live guard
// changed, e.g. an org bundle reload) and drain the hook failure spool.
// P1 like every sibling loop: never propagates an error.
func guardPostureLoop(ctx context.Context, configPath string) {
	cfg, database, cleanup, err := loadConfigAndDB(ctx, configPath)
	if err != nil {
		return
	}
	defer cleanup()
	logger := newLogger(cfg.Observer.LogLevel)
	st := store.New(database)
	resolved, _ := config.ResolveGlobalPath(configPath)
	spool := guardposture.SpoolPath(resolved)
	cfgWatch := &postureConfigWatch{path: resolved, configPath: configPath, guard: cfg.Guard, mod: fileModTime(resolved)}
	tick := func() {
		gd := acquireProcessGuard(ctx, cfg, st, logger)
		switch cfgWatch.check(logger) {
		case postureConfigCurrent:
			publishGuardPosture(configPath, cfg.Guard, gd, logger)
		case postureConfigTouched:
			daemonGuardPosture.requestRefresh()
			publishGuardPosture(configPath, cfg.Guard, gd, logger)
		case postureConfigGuardChanged:
			// Not published: the running guard no longer matches the file,
			// so the posture ages out and hooks follow the file (T-050).
		}
		// The org lock is the ORGANIZATION's hold, not the local [guard]
		// section, so it is written on every interval whatever the config
		// watch says (T-839 / T-844 / T-845).
		if err := publishOrgLockState(ctx, configPath, cfg, gd, st, daemonGuardPosture, time.Now()); err != nil {
			logger.Warn("guard org lock: publish failed", "err", err)
		}
		recordPostureTampers(ctx, daemonGuardPosture, st, logger)
		if n := drainHookFailures(ctx, spool, st, logger); n > 0 {
			logger.Info("guard posture: recorded fail-closed hook failures", "count", n)
		}
	}
	tick()
	t := time.NewTicker(guardPostureInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			tick()
		}
	}
}
