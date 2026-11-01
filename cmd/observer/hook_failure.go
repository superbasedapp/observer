package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/guardposture"
	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// Hook failure semantics (hook-parity audit section 5.7, Lane 0 step 10).
//
// A hook that fails (times out, panics, cannot load its config, cannot build
// its guard, cannot parse its payload) used to ALLOW on every path. That
// stays true everywhere except one place: a GATE capability (tool_gate,
// prompt_gate) whose binding Observer wires, on a node where guard
// enforcement is in force (guard-posture.json, written by the daemon). There
// a failure is answered with the dialect's BLOCK and a reason, and recorded
// (guard-hookfail.jsonl, drained by the daemon into guard_events, which
// reaches the org on the normal push). Everything else keeps its fail-open
// behaviour byte for byte.

// hookFailurePlan is this invocation's failure plan, resolved in newHookCmd's
// Run from the tool, the event and the posture BEFORE stdin is read. It is
// set once and never mutated afterwards, so the watchdog goroutine reads it
// without a lock.
type hookFailurePlan struct {
	// Tool / Event are the `observer hook <tool> <event>` arguments.
	Tool, Event string
	// Cap / Dialect / HostTimeout come from the resolved registry binding.
	Cap         integration.HookCap
	Dialect     string
	HostTimeout time.Duration
	// FailClosed is true when a failure must block.
	FailClosed bool
	// Gated is true when the binding is a gate capability an Observer
	// feature acts on: a failure there is recorded on the spool whichever
	// way it answers (fail closed, or fail open while enforcement is off),
	// T-049. Lifecycle and observe hooks are never recorded.
	Gated bool
	// UserPolicyFailClosed is the organization's T-327 choice for this
	// node (D-221): while the user guard-policy.toml does not load, a gate
	// whose plan fails closed is closed with a reason naming the file and
	// line (hookUserPolicyGate). Read from the same posture, or the same
	// fallback derivation, as FailClosed.
	UserPolicyFailClosed bool
	// SpoolPath is guard-hookfail.jsonl beside the global config.
	SpoolPath string
	// Started is when this invocation started (runHookInvocation's start):
	// the quick scan's clamp counts the time spent since (LEFT2 audit E4).
	Started time.Time
}

// hookPlanPtr is the current invocation's plan (nil = the zero, fail-open
// plan). An atomic pointer, because the watchdog may read it while it
// cannot take the reply lock (a stuck write) and the plan is replaced
// once, when the posture resolves (Sol A2-03).
var hookPlanPtr atomic.Pointer[hookFailurePlan]

// currentHookPlan returns the current invocation's plan.
func currentHookPlan() hookFailurePlan {
	if p := hookPlanPtr.Load(); p != nil {
		return *p
	}
	return hookFailurePlan{}
}

// setHookPlan replaces the current invocation's plan.
func setHookPlan(p hookFailurePlan) { hookPlanPtr.Store(&p) }

// hookPlanFailsClosed reports whether the current invocation fails closed.
func hookPlanFailsClosed() bool { return currentHookPlan().FailClosed }

// hookGuardNew is buildHookGuard's construction seam (tests inject a
// failing constructor to exercise the guard_init failure kind).
var hookGuardNew = guard.New

// hookReplyMu is the ONE lock over this invocation's reply: every stdout
// write (hookStdout), the verdict-tracking vars (hookReplied,
// hookPendingExitCode, hookExpectsStdoutReply), a failure reply and the
// failure exit all go through it, so the watchdog goroutine and the receiver
// can never both reply.
var hookReplyMu sync.Mutex

var (
	// hookStdoutWrote: some bytes of a reply went to stdout.
	hookStdoutWrote bool
	// hookFailureOwned: a fail-closed failure reply owns stdout; later
	// receiver writes are discarded and receiver exits are skipped.
	hookFailureOwned bool
	// hookFailureExited: the failure path already called its exit.
	hookFailureExited bool
	// hookReplyOut overrides the reply target (nil = os.Stdout, read at
	// write time so tests that swap os.Stdout keep working).
	hookReplyOut io.Writer
)

// hookWatchdogLockGrace bounds how long the watchdog waits for a receiver's
// in-flight stdout write before exiting anyway (a host that stopped reading
// must never pin the hook).
const hookWatchdogLockGrace = 2 * time.Second

func hookReplyTarget() io.Writer {
	if hookReplyOut != nil {
		return hookReplyOut
	}
	return os.Stdout
}

// hookStdoutWriter is the stdout every receiver writes its reply through.
type hookStdoutWriter struct{}

// Write forwards p to the reply target unless a failure reply already owns
// stdout.
func (hookStdoutWriter) Write(p []byte) (int, error) {
	hookReplyMu.Lock()
	defer hookReplyMu.Unlock()
	return writeReplyLocked(hookStdout, p)
}

// hookStdout is the receivers' stdout.
var hookStdout io.Writer = hookStdoutWriter{}

// writeReplyLocked writes p to w with hookReplyMu held: hookStdout resolves
// to the real target (never re-locking), any other writer is written as is.
func writeReplyLocked(w io.Writer, p []byte) (int, error) {
	if _, ok := w.(hookStdoutWriter); ok {
		if hookFailureOwned {
			return len(p), nil
		}
		hookStdoutWrote = true
		return hookReplyTarget().Write(p)
	}
	return w.Write(p)
}

// lockedReplyWriter adapts writeReplyLocked for code that already holds
// hookReplyMu and needs an io.Writer (recoverHookPanic's approve).
type lockedReplyWriter struct{ w io.Writer }

func (l lockedReplyWriter) Write(p []byte) (int, error) { return writeReplyLocked(l.w, p) }

// resetHookInvocationState restores every per-invocation reply var to its
// fresh state (newHookCmd's Run calls it first).
func resetHookInvocationState() {
	hookReplyMu.Lock()
	defer hookReplyMu.Unlock()
	hookReplied = false
	hookPendingExitCode = 0
	hookExpectsStdoutReply = true
	hookStdoutWrote = false
	hookFailureOwned = false
	hookFailureExited = false
	hookFailOpenRecorded = false
	hookPlanPtr.Store(nil)
	resetHookInvocationComponents()
}

// markHookDecided records, in ONE step under the reply lock, that the reply
// went out and which exit code carries the verdict, so the watchdog can never
// observe "replied" without the decided code (an exit-code block read as
// exit 0 would be an allow).
func markHookDecided(code int) {
	hookReplyMu.Lock()
	hookReplied = true
	hookPendingExitCode = code
	hookReplyMu.Unlock()
}

// setHookExpectsStdoutReply records whether the current dialect has a
// stdout reply channel at all (see hookExpectsStdoutReply).
func setHookExpectsStdoutReply(v bool) {
	hookReplyMu.Lock()
	hookExpectsStdoutReply = v
	hookReplyMu.Unlock()
}

// hookExit is the receivers' process exit for an already-decided verdict. It
// is skipped when a failure reply already owns this invocation (that path
// exits itself, with its own code).
func hookExit(code int) {
	hookReplyMu.Lock()
	defer hookReplyMu.Unlock()
	if hookFailureOwned {
		return
	}
	hookExitProcess(code)
}

// hookArgvSpelling maps a mechanism whose registered `observer hook` argv
// is NOT the vendor's native event name to the spelling function. Keyed on
// the mechanism (capability shape), never a tool.
var hookArgvSpelling = map[integration.HookMechanism]func(native string) string{
	integration.HookClaudeSettings: hook.ClaudeCodeEventArg,
}

// hookEventAliases maps a mechanism whose host ALSO invokes Observer under a
// second spelling of a native event to that spelling: Kiro CLI's V3
// standalone hooks file names the triggers in PascalCase (PreToolUse) where
// the 2.x agent JSON the bindings describe uses camelCase (preToolUse).
// Keyed on the mechanism (capability shape), never a tool.
var hookEventAliases = map[integration.HookMechanism]func(native string) string{
	integration.HookKiroAgentJSON: upperFirst,
}

// canonicalHookEvent folds an alias spelling of a native event (the
// mechanism's hookEventAliases entry) onto the binding's NativeEvent, so
// every receiver downstream sees one spelling. Any other event is returned
// unchanged.
func canonicalHookEvent(tool, event string) string {
	c, ok := integration.For(tool)
	if !ok {
		return event
	}
	if _, ok := c.Hook.Binding(event); ok {
		return event
	}
	alias, ok := hookEventAliases[c.Hook.Mechanism]
	if !ok {
		return event
	}
	for _, b := range c.Hook.Bindings {
		if alias(b.NativeEvent) == event {
			return b.NativeEvent
		}
	}
	return event
}

// resolveHookInvocationBinding returns the registry binding an `observer
// hook <tool> <event>` invocation serves: the native event first, then the
// mechanism's registered argv spelling.
func resolveHookInvocationBinding(tool, event string) (integration.HookBinding, bool) {
	c, ok := integration.For(tool)
	if !ok {
		return integration.HookBinding{}, false
	}
	if b, ok := c.Hook.Binding(event); ok {
		return b, true
	}
	if spell, ok := hookArgvSpelling[c.Hook.Mechanism]; ok {
		for _, b := range c.Hook.Bindings {
			if spell(b.NativeEvent) == event {
				return b, true
			}
		}
	}
	return integration.HookBinding{}, false
}

// resolveHookFailurePlan builds the invocation's final plan: the
// provisional plan, then the posture.
func resolveHookFailurePlan(tool, event, configPath string) hookFailurePlan {
	return finalizeHookFailurePlan(provisionalHookFailurePlan(tool, event, configPath), configPath)
}

// provisionalHookFailurePlan is the plan BEFORE any posture or config I/O:
// the registry binding only (a pure lookup). A wired gate whose dialect can
// block starts FAIL-CLOSED, because the posture is not known yet: a
// timeout or panic during posture resolution must not be answered by an
// uninitialized fail-open plan on a gated mechanism (Sol A2-03).
// finalizeHookFailurePlan then opens it when the posture says the family
// is not enforced.
func provisionalHookFailurePlan(tool, event, configPath string) hookFailurePlan {
	plan := hookFailurePlan{Tool: tool, Event: event}
	resolved, rerr := config.ResolveGlobalPath(configPath)
	if rerr == nil {
		plan.SpoolPath = guardposture.SpoolPath(resolved)
	}
	b, ok := resolveHookInvocationBinding(tool, event)
	if !ok {
		return plan
	}
	plan.Cap, plan.Dialect, plan.HostTimeout = b.Cap, b.Dialect, b.HostTimeout
	plan.Gated = b.Cap.IsGate() && b.Wired
	plan.FailClosed = rerr == nil && plan.Gated && hook.CanFailClosed(b.Dialect)
	return plan
}

// finalizeHookFailurePlan settles a provisional plan against the posture
// (hookPostureFailsClosedFn): it can only OPEN a provisionally closed plan,
// never close an open one. It publishes no interim plan
// (settleHookFailurePlan with a nil interim).
func finalizeHookFailurePlan(plan hookFailurePlan, configPath string) hookFailurePlan {
	return settleHookFailurePlan(plan, configPath, nil)
}

// settleHookFailurePlan is finalizeHookFailurePlan in two steps (T-381,
// D-188 / D-041 / D-150). The provisional plan is closed for every wired
// gate only until the cheap reads finish: the daemon's posture when it is
// trusted and fresh, else the config's own answer with every policy file
// that could raise it counted as enforcing
// (guard.PreliminaryGateEnforcement). That interim plan is published
// through interim (the watchdog and the panic guard read it) BEFORE the
// full derivation, which can cost a database open, runs. So on a node
// that is not enforcing, a slow or hung derivation fails OPEN, as D-041
// requires; on an enforcing node (or one whose policy files could make it
// enforcing) the interim plan stays closed. The final plan is the full
// derivation's answer, as before. The only window that still closes a
// gate on a non-enforcing node is the read of those two small files
// themselves (the posture and config.toml).
func settleHookFailurePlan(plan hookFailurePlan, configPath string, interim func(hookFailurePlan)) hookFailurePlan {
	if !plan.FailClosed {
		return plan
	}
	resolved, err := config.ResolveGlobalPath(configPath)
	if err != nil {
		plan.FailClosed = false
		return plan
	}
	if interim != nil {
		p := plan
		p.FailClosed = hookPreliminaryFailsClosed(resolved, configPath, plan.Cap)
		interim(p)
	}
	ans := hookPostureFailsClosedFn(resolved, configPath, plan.Cap)
	plan.FailClosed = ans.FailsClosed
	plan.UserPolicyFailClosed = ans.FailsClosed && ans.UserPolicyFailClosed
	return plan
}

// hookPreliminaryFailsClosed is the interim answer settleHookFailurePlan
// publishes: a trusted, fresh posture's answer; otherwise the config's
// with policy files counted as enforcing; false when the config cannot be
// read (D-150: neither readable fails open). It never opens the database.
func hookPreliminaryFailsClosed(resolvedConfig, configPath string, c integration.HookCap) bool {
	ld := guardposture.Load(guardposture.PosturePath(resolvedConfig), guardposture.KeyPath(resolvedConfig))
	if ld.State == guardposture.StateValid && ld.Posture.Stale(time.Now(), fileModTime(resolvedConfig)) == "" {
		return ld.Posture.FailsClosed(string(c))
	}
	cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
	if err != nil {
		return false
	}
	p := postureFromEnforcement(guard.PreliminaryGateEnforcement(cfg.Guard, userHomeOrEmpty(), pathExists))
	return p.FailsClosed(string(c))
}

// registrationToolGateFailsClosed answers hook.Options.ToolGateFailsClosed
// for a registration: whether a tool-gate failure on this node fails closed,
// the same interim answer an `observer hook` invocation starts from (a
// trusted fresh posture, else the config). False when the config path
// cannot be resolved. It never opens the database.
func registrationToolGateFailsClosed(configPath string) bool {
	resolved, err := config.ResolveGlobalPath(configPath)
	if err != nil {
		return false
	}
	return hookPreliminaryFailsClosed(resolved, configPath, integration.HookCapToolGate)
}

// registrationWindowsBridgeFailClosed answers hook.Options.
// WindowsBridgeFailClosed for a registration (surface-gap AW-37): the node
// reads as MANAGED (lockReadsManaged) and a tool-gate failure on it fails
// closed (registrationToolGateFailsClosed). An individual or non-enforcing
// node keeps today's bridge, which fails open when wsl.exe cannot run
// (docs/security.md HOOKFAIL-4). It never opens the database.
func registrationWindowsBridgeFailClosed(configPath string) bool {
	cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
	if err != nil || !lockReadsManaged(cfg.Guard.Lock) {
		return false
	}
	return registrationToolGateFailsClosed(configPath)
}

// lockReadsManaged is the managed reading of the org lock for the hook
// bridge: a verified lock recording managed tenancy, OR a tampered lock
// whose anchors say an organization is expected (OrgExpected, the same
// conservative reading the guard floor applies, internal/config
// guardfloor.go). Without the second half a same-user process that
// corrupts the lock would get the fail-open bridge written on the next
// registration (second audit of 4767d49c1, item 1).
func lockReadsManaged(l config.GuardOrgLock) bool {
	return (l.TenancyKnown && l.Managed) || l.OrgExpected
}

// pathExists reports whether path exists (any error but "not exist" counts
// as existing: the conservative reading for a file that could enforce).
func pathExists(path string) bool {
	_, err := os.Stat(path) //nolint:gosec // G703: a metadata read of the user's own local path; no privilege boundary is crossed
	return err == nil || !os.IsNotExist(err)
}

// hookPostureAnswer is the posture's answer for one gate capability: whether
// a failure there fails closed, and whether the organization's fail_closed
// choice for an invalid user policy applies to it (D-221).
type hookPostureAnswer struct {
	FailsClosed          bool
	UserPolicyFailClosed bool
}

// hookPostureFailsClosedFn is the posture-resolution seam (tests inject a
// slow resolver to exercise the bootstrap window).
var hookPostureFailsClosedFn = hookPostureFailsClosed

// hookRemaining is what is left of budget measured from start: one
// absolute deadline for the whole invocation, so time spent resolving the
// plan is never added on top of the budget (Sol A2-03). A non-positive
// budget (the watchdog disabled) passes through; an exhausted one fires
// at once.
func hookRemaining(start time.Time, budget time.Duration) time.Duration {
	if budget <= 0 {
		return budget
	}
	if r := budget - time.Since(start); r > 0 {
		return r
	}
	return time.Nanosecond
}

// hookPostureFailsClosed answers "is cap fail-closed on this node": the
// daemon's authenticated posture when it verifies; otherwise (no posture,
// or one that does not verify: written by a pre-authentication daemon still
// running through an upgrade, edited, or forged) the posture is IGNORED and
// the answer is computed from the config, exactly as when no daemon ever
// published (Sol A2-02 as corrected, D-040/D-041: fail closed ONLY under
// enforcement). A forged "not enforced" posture therefore cannot open a
// gate the config enforces, and an unverifiable posture never blocks a
// node whose config does not enforce. The daemon still repairs the file and
// records the tamper (guardposture_wire.go).
//
// A verifying posture is trusted only while it is FRESH (T-050,
// guardposture.Posture.Stale): re-signed by the daemon within MaxAge and not
// older than the config file. A stale one (the daemon stopped after
// enforcement was turned off in the config, or the config changed while the
// daemon kept running on the old one) is ignored the same way, so failures
// follow the config and the signed bundle, never a posture whose inputs
// moved.
func hookPostureFailsClosed(resolvedConfig, configPath string, c integration.HookCap) hookPostureAnswer {
	ld := guardposture.Load(guardposture.PosturePath(resolvedConfig), guardposture.KeyPath(resolvedConfig))
	var held hookPostureAnswer
	if ld.State == guardposture.StateValid {
		now, mod := time.Now(), fileModTime(resolvedConfig)
		postureAnswer := hookPostureAnswer{
			FailsClosed:          ld.Posture.FailsClosed(string(c)),
			UserPolicyFailClosed: ld.Posture.UserPolicyClosesGate(string(c)),
		}
		why := ld.Posture.Stale(now, mod)
		if why == "" {
			return postureAnswer
		}
		if ld.Posture.Managed && ld.Posture.StaleOnlyByConfig(now, mod) {
			// A managed node whose config.toml was just edited (T-864 gap
			// 2): the organization's last answer stays in force alongside
			// the (floored) config's until the daemon re-signs, so a local
			// edit cannot open a gate the organization holds closed.
			held = postureAnswer
			fmt.Fprintf(os.Stderr, "observer-hook: guard posture stale (%s); managed node, %s failures follow the stricter of the posture and the config\n", why, c)
		} else {
			fmt.Fprintf(os.Stderr, "observer-hook: guard posture stale (%s); ignored, %s failures follow the config\n", why, c)
		}
	}
	if ld.State == guardposture.StateTampered {
		fmt.Fprintf(os.Stderr, "observer-hook: guard posture unverifiable (%s); ignored, %s failures follow the config\n", ld.Detail, c)
	}
	cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
	if err != nil {
		return held
	}
	p := postureFromEnforcement(hookFallbackGateEnforcement(cfg))
	return hookPostureAnswer{
		FailsClosed:          held.FailsClosed || p.FailsClosed(string(c)),
		UserPolicyFailClosed: held.UserPolicyFailClosed || p.UserPolicyClosesGate(string(c)),
	}
}

// postureFromEnforcement is the ONE mapping from the shared gate-enforcement
// derivation (guardGateEnforcement, D-194) onto the posture fields both the
// daemon's writer and the hook's fallback act on, so the two can never
// disagree about which gates close or whether the org's invalid-user-policy
// choice applies.
func postureFromEnforcement(e guard.GateEnforcement) guardposture.Posture {
	return guardposture.Posture{
		Enforced:             e.Any(),
		GateCaps:             guardGateCaps(e),
		UserPolicyFailClosed: e.UserPolicyFailClosed,
	}
}

// hookUserPolicyGate closes this invocation's gate when the organization
// chose fail_closed for an invalid user guard policy (D-221 / T-327), the
// gate is enforced (the plan fails closed), and the user policy file does NOT
// load right now. The file is checked here, at invocation time, with the same
// guard.CheckUserPolicy the doctor, the daemon event and the Security banner
// use, so a fix takes effect on the very next call. The block names the file
// and line, is recorded in the hook spool (drained into guard_events), and
// returns true: the caller must not run the receiver. Every other case
// returns false and changes nothing (a config that cannot load is left to
// the receivers' own fail-closed path).
func hookUserPolicyGate(configPath string, stdin io.Reader) bool {
	plan := currentHookPlan()
	if !plan.FailClosed || !plan.UserPolicyFailClosed {
		return false
	}
	cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
	if err != nil || !guardEvaluates(cfg.Guard) {
		return false
	}
	st := guard.CheckUserPolicy(cfg.Guard, userHomeOrEmpty(), os.ReadFile)
	if !st.Invalid() {
		return false
	}
	body, _ := io.ReadAll(io.LimitReader(stdin, hookUserPolicyPeekBytes))
	hookReplyMu.Lock()
	defer hookReplyMu.Unlock()
	handled, code := answerFailureLocked(guardposture.KindUserPolicyFailClosed, guard.UserPolicyBlockReason(st), hookPayloadSessionID(body), os.Stderr)
	if handled && code != 0 {
		hookFailureExited = true
		hookExitProcess(code)
	}
	return handled
}

// fileModTime is path's modification time (zero when it cannot be stat'd).
func fileModTime(path string) time.Time {
	if path == "" {
		return time.Time{}
	}
	st, err := os.Stat(path) //nolint:gosec // G703: a metadata read of the user's own local path; no privilege boundary is crossed
	if err != nil {
		return time.Time{}
	}
	return st.ModTime()
}

// hookUserPolicyPeekBytes bounds the payload read for the session id when a
// gate is closed by the user-policy choice (the body is never evaluated).
const hookUserPolicyPeekBytes = 1 << 20

// hookFallbackDBTimeout bounds the fallback's store reads (the key pin and,
// only for an unverifiable bundle, the tenancy). The whole invocation stays
// under the watchdog's absolute deadline either way (Sol A2-03).
var hookFallbackDBTimeout = 2 * time.Second

// hookFallbackGateEnforcement computes enforcement when no daemon posture
// is trusted, from the SAME inputs the daemon uses: a guard built over the
// config, the cached org bundle verified under the enrolment key pin, the
// user policy (per-rule enforce), and the tenancy, through the shared
// guardGateEnforcement (Sol A2-02 follow-up: the config alone cannot see
// org or per-rule enforcement, which on a managed node is where it comes
// from). A guard that is off costs nothing (no DB, no guard). A store that
// cannot be opened gives no pin and unresolved tenancy; a guard that cannot
// be built degrades to the config-only answer.
func hookFallbackGateEnforcement(cfg config.Config) guard.GateEnforcement {
	if !cfg.Guard.Enabled || cfg.Guard.Mode == "off" {
		return guard.GateEnforcement{}
	}
	ctx, cancel := context.WithTimeout(context.Background(), hookFallbackDBTimeout)
	defer cancel()
	var st *store.Store
	if database, err := db.Open(ctx, db.Options{Path: cfg.Observer.DBPath}); err == nil {
		defer database.Close()
		st = store.New(database)
	}
	gd := nodeGuard(ctx, cfg, st)
	if gd == nil {
		return guard.ConfigGateEnforcement(cfg.Guard)
	}
	// Review M2-14: a store that cannot be opened gives no pin and no
	// tenancy; the shared derivation then withholds the org's
	// invalid-user-policy MODE (guard.Guard.GateEnforcement), so an
	// individual node never gets the org's fail_closed choice from a bundle
	// verified only on its own signature.
	return guardGateEnforcement(cfg.Guard, gd)
}

// nodeGuard builds a guard over cfg from the node's own policy inputs (the
// enrolment key pin and the tenancy, read through st, which may be nil) the
// way the daemon does. Shared by the hook fallback above and the CLI launch
// sandbox decision (launch_sandbox_gate.go). Nil when no guard can be built.
func nodeGuard(ctx context.Context, cfg config.Config, st *store.Store) *guard.Guard {
	pin, managed, bundleExpected := nodeGuardPolicyInputs(ctx, st, nil)
	home, err := os.UserHomeDir()
	if err != nil {
		home = ""
	}
	gd, err := hookGuardNew(guard.Options{Config: cfg.Guard, Home: home, OrgKeyPinHash: pin, ManagedTenancy: managed, OrgBundleExpected: bundleExpected})
	if err != nil {
		return nil
	}
	return gd
}

// guardGateCaps maps a per-family enforcement answer onto the gate
// capabilities that fail closed. Shared by the daemon's posture writer and
// the hook's config fallback (one definition), both fed by the guard's
// one enforcement helper.
func guardGateCaps(e guard.GateEnforcement) []string {
	var caps []string
	if e.Tool {
		caps = append(caps, string(integration.HookCapToolGate))
	}
	if e.Prompt {
		caps = append(caps, string(integration.HookCapPromptGate))
	}
	return caps
}

// hookGateBudget caps the watchdog budget for a gate event below the host's
// own hook timeout, so a fail-closed block is written before the host gives
// up on the hook (and applies its own failure policy).
func hookGateBudget(budget time.Duration, plan hookFailurePlan) time.Duration {
	if budget <= 0 || !plan.Cap.IsGate() || plan.HostTimeout <= 0 {
		return budget
	}
	margin := 2 * time.Second
	if plan.HostTimeout <= 2*margin {
		margin = plan.HostTimeout / 2
	}
	if c := plan.HostTimeout - margin; c < budget {
		return c
	}
	return budget
}

// failureReason picks the developer-facing reason for kind.
func failureReason(kind string) string {
	if kind == guardposture.KindTimeout {
		return hook.FailClosedTimeoutReason
	}
	return hook.FailClosedErrorReason
}

// answerFailureLocked writes the fail-closed BLOCK for kind when the plan
// fails closed and nothing has been replied yet, appends the spool record,
// and returns the exit code that carries the block. reason is the
// developer-facing text ("" = the generic failure reason for kind).
// handled=false leaves everything untouched (the caller keeps its fail-open
// path). The caller holds hookReplyMu.
func answerFailureLocked(kind, reason, sessionID string, stderr io.Writer) (handled bool, exitCode int) {
	plan := currentHookPlan()
	if hookFailureOwned || hookReplied || hookStdoutWrote {
		return false, 0
	}
	if !plan.FailClosed {
		recordFailOpenLocked(plan, kind, sessionID, stderr)
		return false, 0
	}
	if reason == "" {
		reason = failureReason(kind)
	}
	reply, ok := hook.BuildFailClosedReply(plan.Dialect, reason)
	if !ok {
		return false, 0
	}
	if len(reply.Stdout) > 0 {
		_, _ = hookReplyTarget().Write(reply.Stdout)
	}
	if reply.StderrReason || kind == guardposture.KindUserPolicyFailClosed {
		hook.WriteStderrBlockReason(stderr, reason)
	} else {
		fmt.Fprintf(stderr, "observer-hook: %s:%s failed closed (%s): guard enforcement is on\n", plan.Tool, plan.Event, kind)
	}
	hookFailureOwned = true
	hookReplied = true
	hookPendingExitCode = reply.ExitCode
	appendHookFailure(plan, kind, sessionID, guardposture.OutcomeFailClosed, stderr)
	return true, reply.ExitCode
}

// hookFailOpenRecorded: this invocation already spooled its fail-open
// failure (one record per invocation; the first failure kind wins, since a
// receiver that fails open keeps going and may hit a second one).
var hookFailOpenRecorded bool

// recordFailOpenLocked spools a gate hook's fail-open failure (T-049): the
// call is let through unevaluated, which the audit says is "recorded", so it
// lands on the same spool, labelled fail_open, and reaches guard_events as a
// non-enforced guard_error flag. Lifecycle / observe hooks are never
// recorded. The caller holds hookReplyMu.
func recordFailOpenLocked(plan hookFailurePlan, kind, sessionID string, stderr io.Writer) {
	if !plan.Gated || hookFailOpenRecorded {
		return
	}
	hookFailOpenRecorded = true
	appendHookFailure(plan, kind, sessionID, guardposture.OutcomeFailOpen, stderr)
}

// appendHookFailure appends one spool record (never blocking on the drain).
func appendHookFailure(plan hookFailurePlan, kind, sessionID, outcome string, stderr io.Writer) {
	if plan.SpoolPath == "" {
		return
	}
	if err := guardposture.Append(plan.SpoolPath, guardposture.Record{
		Tool: plan.Tool, Event: plan.Event, Cap: string(plan.Cap), SessionID: sessionID, Kind: kind, Outcome: outcome,
	}); err != nil {
		fmt.Fprintf(stderr, "observer-hook: hook failure spool: %v\n", err)
	}
}

// hookFailClosed is a receiver's failure exit: when the plan fails closed it
// writes the block (with the payload's session id when one is readable),
// records it, exits with the dialect's block code when that code is
// non-zero, and returns true (the receiver must return without replying).
// false = fail-open plan; the receiver continues its existing path.
func hookFailClosed(kind string, body []byte) bool {
	hookReplyMu.Lock()
	defer hookReplyMu.Unlock()
	handled, code := answerFailureLocked(kind, "", hookPayloadSessionID(body), os.Stderr)
	if handled && code != 0 {
		hookFailureExited = true
		hookExitProcess(code)
	}
	return handled
}

// loadGateConfig loads a gate receiver's config (FU-185): config.Load's
// answer, plus an explicit --config that names no file as a failure of its
// own. config.Load reads a missing file as the defaults, so a hook whose
// --config pointed at a moved or deleted file used to run on the defaults
// and approve. Now, under guard enforcement, a missing or unreadable
// explicit config is a "cannot evaluate" case: the call fails closed through
// hookFailClosed(KindConfig) (the hook-failure plan decides, so only an
// enforced gate blocks) and stop is true. Otherwise (enforcement off) a
// missing file is said on stderr and the hook runs on the defaults, and so
// does one that exists but cannot be read or parsed (FU-185 ruling): every
// caller then has a loaded config and cfgErr nil. Only when even the
// defaults cannot be loaded (the environment or the home is broken) is the
// error returned for the caller's own fallback. The load error's text is
// not printed: a parse error can quote the file.
func loadGateConfig(configPath string, body []byte, stderr io.Writer) (cfg config.Config, stop bool, cfgErr error) {
	cfg, cfgErr = config.Load(config.LoadOptions{GlobalPath: configPath})
	missing := cfgErr == nil && hookConfigMissing(configPath)
	if (cfgErr != nil || missing) && hookFailClosed(guardposture.KindConfig, body) {
		return cfg, true, cfgErr
	}
	if missing {
		fmt.Fprintf(stderr, "observer-hook: config %s does not exist; running on the defaults\n", configPath)
	}
	if cfgErr != nil {
		def, derr := config.Load(config.LoadOptions{NoGlobal: true})
		if derr != nil {
			fmt.Fprintf(stderr, "observer-hook: config %s could not be read or parsed, and the defaults could not be loaded either\n", configPath)
			return cfg, false, cfgErr
		}
		fmt.Fprintf(stderr, "observer-hook: config %s could not be read or parsed; running on the defaults\n", configPath)
		return def, false, nil
	}
	return cfg, false, cfgErr
}

// hookConfigMissing reports whether an explicit --config names no file.
func hookConfigMissing(path string) bool {
	if path == "" {
		return false
	}
	_, err := os.Stat(path) //nolint:gosec // G703: a metadata read of the hook's own --config path; no privilege boundary is crossed
	return errors.Is(err, os.ErrNotExist)
}

// hookReplyBarrier runs as newHookCmd's Run returns. Taking the reply lock
// waits out a watchdog that owns the reply (it holds the lock through its
// exit, so Run can never return and exit 0 underneath it); a failure reply
// whose block code was not yet delivered is delivered here.
func hookReplyBarrier() {
	hookReplyMu.Lock()
	defer hookReplyMu.Unlock()
	if hookFailureOwned && !hookFailureExited && hookPendingExitCode != 0 {
		hookFailureExited = true
		hookExitProcess(hookPendingExitCode)
	}
}

// hookPayloadUnparseable reports whether a gate payload is not JSON at all
// (after a UTF-8 BOM), which no guard can evaluate.
func hookPayloadUnparseable(body []byte) bool {
	return !json.Valid(bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF}))
}

// hookPayloadSessionID best-effort reads the session id a payload carries
// under any of the spellings the gate dialects use ("" when none), in the
// one precedence order hookliveness.PayloadSessionID states (FU-127):
// session_id, sessionId, conversation_id, conversationId, trajectory_id. It
// keeps the struct decode (so its encoding/json behaviour, pinned by the
// jsoncompat golden, is unchanged for every payload without the two new
// keys).
func hookPayloadSessionID(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	var p struct {
		SessionID           string `json:"session_id"`
		SessionIDCamel      string `json:"sessionId"`
		ConversationID      string `json:"conversation_id"`
		ConversationIDCamel string `json:"conversationId"`
		TrajectoryID        string `json:"trajectory_id"`
	}
	if json.Unmarshal(bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF}), &p) != nil {
		return ""
	}
	for _, s := range []string{p.SessionID, p.SessionIDCamel, p.ConversationID, p.ConversationIDCamel, p.TrajectoryID} {
		if s != "" {
			return s
		}
	}
	return ""
}

// hookWatchdogFire is the watchdog's timeout action. Under a fail-closed
// plan with nothing replied yet it writes the dialect's block and exits with
// the block code; when the receiver already replied it exits with the
// verdict the receiver decided. Under every other plan it is today's
// fail-open exit 0.
func hookWatchdogFire(maxRuntime time.Duration, exitFn func(int), stderr io.Writer) {
	deadline := time.Now().Add(hookWatchdogLockGrace)
	for !hookReplyMu.TryLock() {
		if time.Now().After(deadline) {
			// A receiver write is stuck (the host stopped reading).
			code := 0
			if plan := currentHookPlan(); plan.FailClosed {
				if r, ok := hook.BuildFailClosedReply(plan.Dialect, ""); ok {
					code = r.ExitCode
				}
			}
			fmt.Fprintf(stderr, "observer-hook: max-runtime %v exceeded with a reply write in flight; exiting %d\n", maxRuntime, code)
			exitFn(code)
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	defer hookReplyMu.Unlock()
	if plan := currentHookPlan(); !plan.FailClosed {
		if !hookReplied && !hookStdoutWrote {
			recordFailOpenLocked(plan, guardposture.KindTimeout, "", stderr)
		}
		fmt.Fprintf(stderr, "observer-hook: max-runtime %v exceeded; allowing the tool (fail-open, exit 0; see V3-1)\n", maxRuntime)
		exitFn(0)
		return
	}
	if handled, code := answerFailureLocked(guardposture.KindTimeout, "", "", stderr); handled {
		// A stderr-reason block owns stderr: the host shows it to the
		// developer as the reason, so no diagnostic line joins it (T-048).
		if r, ok := hook.BuildFailClosedReply(currentHookPlan().Dialect, ""); !ok || !r.StderrReason {
			fmt.Fprintf(stderr, "observer-hook: max-runtime %v exceeded; blocked (guard enforcement is on), exit %d\n", maxRuntime, code)
		}
		hookFailureExited = true
		exitFn(code)
		return
	}
	fmt.Fprintf(stderr, "observer-hook: max-runtime %v exceeded after the reply; exiting with the decided code %d\n", maxRuntime, hookPendingExitCode)
	exitFn(hookPendingExitCode)
}
