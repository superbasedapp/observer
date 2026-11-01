package integration

import (
	"sort"
	"time"
)

// Hook capability vocabulary (hook-parity audit 2026-10-02, section 2;
// docs/plans/hook-parity-lane0-brief.md step 0.1).
//
// A vendor's hook surface is described as a list of HookBinding rows: one
// native event of one mechanism, the abstract capability it provides, the
// reply dialect Observer speaks on it, the wire traits a feature needs
// (session key, process relation, host timeout and failure behaviour), and
// how that row is grounded. Every consumer (registration, the receiver, the
// guard conformance matrix, the coverage surfaces) reads these rows instead
// of re-deriving the same fact from a per-vendor list. All types here are
// DATA: closed string vocabularies and a value struct, no behaviour beyond
// lookups.

// HookCap is the abstract capability a native hook event provides. Closed
// set; see hookCapPhases for the phases each one admits.
type HookCap string

const (
	// HookCapToolGate: allow / ask / deny before a tool runs.
	HookCapToolGate HookCap = "tool_gate"
	// HookCapToolRewrite: replace the tool input before it runs.
	HookCapToolRewrite HookCap = "tool_rewrite"
	// HookCapPromptGate: warn / confirm / block / redact before the prompt
	// reaches the model.
	HookCapPromptGate HookCap = "prompt_gate"
	// HookCapPermissionGate: answer the host's own permission prompt.
	HookCapPermissionGate HookCap = "permission_gate"
	// HookCapStopGate: refuse a stop / force the agent to continue.
	// Documented so nobody wires it by accident; out of scope.
	HookCapStopGate HookCap = "stop_gate"
	// HookCapSessionLifecycle: session start / end.
	HookCapSessionLifecycle HookCap = "session_lifecycle"
	// HookCapTurnLifecycle: turn start / end (incl. turn failure).
	HookCapTurnLifecycle HookCap = "turn_lifecycle"
	// HookCapSubagentLifecycle: sub-agent start / stop.
	HookCapSubagentLifecycle HookCap = "subagent_lifecycle"
	// HookCapCompactLifecycle: context compaction pre / post.
	HookCapCompactLifecycle HookCap = "compact_lifecycle"
	// HookCapToolObserve: post-tool, with result.
	HookCapToolObserve HookCap = "tool_observe"
	// HookCapToolFailureObserve: a tool call failed.
	HookCapToolFailureObserve HookCap = "tool_failure_observe"
	// HookCapModelCallObserve: before / after a model request (usage).
	HookCapModelCallObserve HookCap = "model_call_observe"
	// HookCapPermissionObserve: the host asked for / denied a permission.
	HookCapPermissionObserve HookCap = "permission_observe"
	// HookCapEnvironmentObserve: cwd, config, instruction files, setup,
	// worktree changes.
	HookCapEnvironmentObserve HookCap = "environment_observe"
	// HookCapNotificationObserve: a host notification.
	HookCapNotificationObserve HookCap = "notification_observe"
	// HookCapTaskObserve: task created / completed.
	HookCapTaskObserve HookCap = "task_observe"
	// HookCapContextInject: text appended to the model context. The post
	// phase (text after a tool ran, security pillar plan section 4.7,
	// spike JSP-6) carries the security feedback line (lane SEC-H).
	HookCapContextInject HookCap = "context_inject"
	// HookCapUserMessage: non-blocking text the human sees.
	HookCapUserMessage HookCap = "user_message"
)

// Hook binding phases. The closed set each capability admits is
// hookCapPhases.
const (
	HookPhaseNone  = ""
	HookPhaseStart = "start"
	HookPhaseEnd   = "end"
	HookPhasePre   = "pre"
	HookPhasePost  = "post"
)

// hookCapPhases is the closed vocabulary of capabilities and, for each, the
// phases a binding may declare.
var hookCapPhases = map[HookCap][]string{
	HookCapToolGate:            {HookPhasePre},
	HookCapToolRewrite:         {HookPhasePre},
	HookCapPromptGate:          {HookPhasePre},
	HookCapPermissionGate:      {HookPhasePre},
	HookCapStopGate:            {HookPhaseEnd},
	HookCapSessionLifecycle:    {HookPhaseStart, HookPhaseEnd},
	HookCapTurnLifecycle:       {HookPhaseStart, HookPhaseEnd},
	HookCapSubagentLifecycle:   {HookPhaseStart, HookPhaseEnd},
	HookCapCompactLifecycle:    {HookPhasePre, HookPhasePost},
	HookCapToolObserve:         {HookPhasePost},
	HookCapToolFailureObserve:  {HookPhasePost},
	HookCapModelCallObserve:    {HookPhasePre, HookPhasePost},
	HookCapPermissionObserve:   {HookPhasePre, HookPhasePost},
	HookCapEnvironmentObserve:  {HookPhaseNone},
	HookCapNotificationObserve: {HookPhaseNone},
	HookCapTaskObserve:         {HookPhaseStart, HookPhaseEnd},
	HookCapContextInject:       {HookPhaseStart, HookPhasePre, HookPhasePost},
	HookCapUserMessage:         {HookPhaseNone, HookPhasePre},
}

// HookCaps returns the closed capability vocabulary, sorted.
func HookCaps() []HookCap {
	out := make([]HookCap, 0, len(hookCapPhases))
	for c := range hookCapPhases {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// IsGate reports whether the capability is a gate family member: a reply on
// it changes what the host does (audit section 2.1).
func (c HookCap) IsGate() bool {
	switch c {
	case HookCapToolGate, HookCapToolRewrite, HookCapPromptGate, HookCapPermissionGate, HookCapStopGate:
		return true
	}
	return false
}

// ValidPhase reports whether phase is in c's closed phase set. An unknown
// capability admits no phase.
func (c HookCap) ValidPhase(phase string) bool {
	for _, p := range hookCapPhases[c] {
		if p == phase {
			return true
		}
	}
	return false
}

// Known reports whether c is in the closed capability vocabulary.
func (c HookCap) Known() bool {
	_, ok := hookCapPhases[c]
	return ok
}

// Hook binding decisions: what a reply on the event can express. Closed set.
const (
	HookDecisionAllow   = "allow"
	HookDecisionAsk     = "ask"
	HookDecisionDeny    = "deny"
	HookDecisionModify  = "modify"
	HookDecisionContext = "context"
	HookDecisionMessage = "message"
)

var hookDecisions = map[string]bool{
	HookDecisionAllow: true, HookDecisionAsk: true, HookDecisionDeny: true,
	HookDecisionModify: true, HookDecisionContext: true, HookDecisionMessage: true,
}

// KnownHookDecision reports whether d is in the closed decision vocabulary.
func KnownHookDecision(d string) bool { return hookDecisions[d] }

// GroundingKind says how a binding's facts were established.
type GroundingKind string

const (
	// GroundingDoc: the vendor's own documentation or source, fetched on
	// Grounding.Date.
	GroundingDoc GroundingKind = "doc"
	// GroundingFixture: an in-repo test fixture or recorded payload.
	GroundingFixture GroundingKind = "fixture"
	// GroundingLive: a live test on a real install recorded in-repo. Only
	// live bindings join `observer start` auto-registration (audit
	// section 7 ruling 4).
	GroundingLive GroundingKind = "live"
	// GroundingInferred: unverified inference (a fork's inherited shape, a
	// third-party write-up).
	GroundingInferred GroundingKind = "inferred"
)

// Known reports whether k is in the closed grounding vocabulary.
func (k GroundingKind) Known() bool {
	switch k {
	case GroundingDoc, GroundingFixture, GroundingLive, GroundingInferred:
		return true
	}
	return false
}

// Grounding records the evidence behind a binding: its kind, a source (a
// URL, a doc path, or a test name) and the date it was established.
type Grounding struct {
	Kind   GroundingKind
	Source string
	Date   string
}

// ProcRelation is how the hook process relates to the agent process, which
// decides whether pidbridge can attribute proxy traffic to the session.
type ProcRelation string

const (
	// ProcDescendant: the hook runs as a descendant of the agent process,
	// so an ancestor walk reaches the agent.
	ProcDescendant ProcRelation = "descendant"
	// ProcInProcessPID: an in-process plugin passes its host's pid.
	ProcInProcessPID ProcRelation = "in_process_pid"
	// ProcNone: detached, remote, or unknown: no pid relation.
	ProcNone ProcRelation = "none"
)

// Known reports whether p is in the closed process-relation vocabulary
// (the zero value is not: every binding states one).
func (p ProcRelation) Known() bool {
	switch p {
	case ProcDescendant, ProcInProcessPID, ProcNone:
		return true
	}
	return false
}

// FailurePolicy is what the HOST does when the hook times out or errors.
type FailurePolicy string

const (
	// HostProceeds: the host treats a failed hook as a non-blocking error
	// and continues (fail open on the host side).
	HostProceeds FailurePolicy = "proceeds"
	// HostBlocks: the host blocks the action when the hook fails.
	HostBlocks FailurePolicy = "blocks"
	// HostFailureUnknown: the vendor does not document it.
	HostFailureUnknown FailurePolicy = "unknown"
)

// Known reports whether f is in the closed failure-policy vocabulary.
func (f FailurePolicy) Known() bool {
	switch f {
	case HostProceeds, HostBlocks, HostFailureUnknown:
		return true
	}
	return false
}

// HookBinding is one native event of one mechanism (audit section 5.2).
type HookBinding struct {
	// Cap is the abstract capability the event provides.
	Cap HookCap
	// Phase is the sub-role inside the capability (closed set per Cap).
	Phase string
	// NativeEvent is the vendor's own spelling of the event.
	NativeEvent string
	// Dialect is the internal/hook reply/extract dialect id Observer speaks
	// on this event; "" when Observer does not register it.
	Dialect string
	// Decisions is what a reply can express (closed set: allow, ask, deny,
	// modify, context, message). Empty for an observe-only event.
	Decisions []string
	// SessionKey is true when the payload carries a session or
	// conversation id (ask-once / confirm can be keyed on it).
	SessionKey bool
	// ProcRel is the hook process's relation to the agent process.
	ProcRel ProcRelation
	// HostTimeout is the host's own hook timeout; 0 = unknown.
	HostTimeout time.Duration
	// HostOnFailure is what the host does when the hook times out or
	// errors.
	HostOnFailure FailurePolicy
	// Registered is true when Observer writes the event into the vendor
	// config today.
	Registered bool
	// Wired is true when an Observer feature acts on the event today.
	// Implies Registered, except for plugin / tailer transports whose
	// "registration" is not a config entry per event.
	Wired bool
	// Grounding is the evidence behind this row.
	Grounding Grounding
	// Note is the verbatim conformance / coverage note, where one exists.
	Note string
	// GuardChannel, when non-empty, lists this binding in the guard
	// conformance matrix as the OBSERVE-ONLY channel "hook:<GuardChannel>"
	// (zero capabilities) even though it is not a gate: the two such rows
	// that exist today (codex notify, hermes plugin) are coverage facts the
	// Security page renders.
	GuardChannel string
	// ReplayedVia, when non-empty, names the tool whose OWN registered hook
	// config the host replays to reach this binding (Grok Build runs
	// ~/.claude/settings.json hooks: hook-parity Lane C3). Such a binding is
	// Wired without being Registered in this row's own config, even on a
	// per-event-config mechanism.
	ReplayedVia string
	// StandsInFor, on a ReplayedVia binding, names the NativeEvent of this
	// tool's OWN registered gate binding the replay stands in for: the
	// replayed call is the same call that registration sees, so the
	// receiver serves the replay only while that registration is absent
	// (the Copilot CLI runtime's Claude-compatible PreToolUse, internal/hook
	// foreignhost.go). Empty for a replay that is the tool's only gate on
	// those calls (Kimchi, DeepSeek). Cortex Code's replays name the events
	// its own hooks.json writer registers (built, behind live check LC18):
	// the own binding joins when that writer switches on, and until then
	// ReplayFallback is false (FU-141).
	StandsInFor string
	// WarnField, when non-empty, names the top-level field of this event's
	// ALLOW reply that the host shows the DEVELOPER as a pass-through notice
	// (Claude Code's common "systemMessage": "Warning message shown to the
	// user"). A tool gate sets it to the humanized reason of a record-worthy
	// flag, so a warn rule is visible without stopping the call. Empty means
	// the host documents no such field (or the allow is an empty stdout), so
	// a flag there stays silent to the developer and is only recorded.
	WarnField string
	// AdminCaveat, when non-empty, is a short admin-facing capability fact
	// about this gate that the per-tool rule coverage
	// (controlcoverage.RuleCoverage, rendered on the org guard form) shows
	// beside the outcome: something the developer does or does not see that
	// the decision ladder alone cannot say. One sentence; the long grounding
	// stays in Note.
	AdminCaveat string
	// RegisterWhen, when non-empty, is the component id that must be
	// SELECTED for Observer to write this binding's event into the vendor
	// config: the event is registered while the component is selected and
	// removed when it is not (internal/hook Options.Selected). Such a
	// binding is never Registered in the static sense, so every surface
	// that reads Registered (the parity matrices, `observer start`
	// auto-registration's live rule) is unchanged while nothing selects it.
	// Today only the security feedback rows (component security.feedback)
	// set it.
	RegisterWhen string
}

// HasDecision reports whether the binding's reply can express d.
func (b HookBinding) HasDecision(d string) bool {
	for _, x := range b.Decisions {
		if x == d {
			return true
		}
	}
	return false
}

// Provides reports whether any binding on the spec provides cap (vendor
// surface, whether or not Observer wires it).
func (h HookSpec) Provides(c HookCap) bool {
	for _, b := range h.Bindings {
		if b.Cap == c {
			return true
		}
	}
	return false
}

// WiredFor reports whether an Observer feature acts on cap today through
// this spec (some binding with Cap == c is Wired).
func (h HookSpec) WiredFor(c HookCap) bool {
	for _, b := range h.Bindings {
		if b.Cap == c && b.Wired {
			return true
		}
	}
	return false
}

// ReplayFallback reports whether b is reached through another tool's
// registration (ReplayedVia) only as a stand-in for a gate this spec
// registers in the tool's own config (StandsInFor names a registered, wired
// binding of the same capability). Such a replay runs only while that
// registration is absent, so the tool's gate does not ride the other
// tool's registration: a check or a coverage row that says it does would be
// wrong.
func (h HookSpec) ReplayFallback(b HookBinding) bool {
	if b.ReplayedVia == "" || b.StandsInFor == "" {
		return false
	}
	o, ok := h.Binding(b.StandsInFor)
	return ok && o.Cap == b.Cap && o.Wired && o.Registered && o.ReplayedVia == ""
}

// Binding returns the first binding whose NativeEvent is native (a native
// event that provides two capabilities carries two bindings; the first is
// its primary one). ok=false when the spec has no such event.
func (h HookSpec) Binding(native string) (HookBinding, bool) {
	for _, b := range h.Bindings {
		if b.NativeEvent == native {
			return b, true
		}
	}
	return HookBinding{}, false
}

// RegisteredEvents returns the distinct native events Observer registers on
// this spec, in binding order.
func (h HookSpec) RegisteredEvents() []string {
	return h.RegisteredEventsWith(nil)
}

// RegisteredEventsWith returns RegisteredEvents plus, after them in binding
// order, the events of every RegisterWhen binding whose component selected
// reports true. A nil selected adds nothing, so the result is exactly
// RegisteredEvents.
func (h HookSpec) RegisteredEventsWith(selected func(component string) bool) []string {
	var out []string
	seen := map[string]bool{}
	for _, b := range h.Bindings {
		if !b.Registered || seen[b.NativeEvent] {
			continue
		}
		seen[b.NativeEvent] = true
		out = append(out, b.NativeEvent)
	}
	if selected == nil {
		return out
	}
	for _, b := range h.Bindings {
		if b.RegisterWhen == "" || seen[b.NativeEvent] || !selected(b.RegisterWhen) {
			continue
		}
		seen[b.NativeEvent] = true
		out = append(out, b.NativeEvent)
	}
	return out
}

// OptInEvents returns the distinct native events that only RegisterWhen
// bindings name (no Registered binding shares the event) and whose
// component selected reports false: the events a writer removes when the
// component is not selected. A nil selected treats every component as not
// selected.
func (h HookSpec) OptInEvents(selected func(component string) bool) []string {
	static := map[string]bool{}
	for _, b := range h.Bindings {
		if b.Registered {
			static[b.NativeEvent] = true
		}
	}
	var out []string
	seen := map[string]bool{}
	for _, b := range h.Bindings {
		if b.RegisterWhen == "" || static[b.NativeEvent] || seen[b.NativeEvent] {
			continue
		}
		if selected != nil && selected(b.RegisterWhen) {
			continue
		}
		seen[b.NativeEvent] = true
		out = append(out, b.NativeEvent)
	}
	return out
}

// hookTransportNoEventConfig is the set of mechanisms whose transport is an
// in-process plugin or a log tailer: Observer does not write one config
// entry per event, so a binding there can be Wired without being
// Registered in the per-event sense.
var hookTransportNoEventConfig = map[HookMechanism]bool{
	HookHermesPlugin:     true,
	HookClineCLIJSONL:    true,
	HookCommandCodeMod:   true,
	HookBrowserExtension: true,
	HookPluginShimTS:     true,
}

// hookDialectServedElsewhere names the dialects whose wired bindings are
// served by a transport other than an `observer hook <tool> <event>`
// invocation written into the vendor config: a log tailer and the browser
// extension's native-messaging host. Keyed on the dialect (capability
// shape), so a row can mix such bindings with per-event registrations
// (cline-cli: the ~/.cline/hooks tool gate plus the hooks.jsonl tailer,
// T-342).
var hookDialectServedElsewhere = map[string]string{
	hookDialectClineCLITail:   "internal/adapter/clinecli hooks.jsonl tailer",
	hookDialectBrowserCapture: "`observer browser hook` (cmd/observer/browser.go)",
}

// ServedElsewhere names the receiver of a binding that `observer hook` does
// not serve ("" for every binding it does).
func (b HookBinding) ServedElsewhere() string { return hookDialectServedElsewhere[b.Dialect] }

// NeedsEventConfig reports whether wiring b on mechanism m takes its own
// per-event config entry: m writes one entry per event and b is not served
// by another transport.
func (b HookBinding) NeedsEventConfig(m HookMechanism) bool {
	return m.PerEventConfig() && b.ServedElsewhere() == ""
}

// PerEventConfig reports whether the mechanism's transport is a config file
// with one entry per native event (false for plugin / tailer / native
// messaging transports).
func (m HookMechanism) PerEventConfig() bool {
	return m != HookNone && !hookTransportNoEventConfig[m]
}

// RegisteredAllLive reports whether the spec registers at least one event
// and EVERY registered binding is live-grounded: the condition under which
// `observer start` may auto-register the mechanism without a consent step
// (hook-parity audit section 7, ruling 4). A mechanism with any doc- or
// fixture-grounded registered binding is written by `observer init` only,
// unless it is grandfathered (cmd/observer grandfatheredAutoRegister).
func (h HookSpec) RegisteredAllLive() bool {
	n := 0
	for _, b := range h.Bindings {
		if !b.Registered {
			continue
		}
		n++
		if b.Grounding.Kind != GroundingLive {
			return false
		}
	}
	return n > 0
}
