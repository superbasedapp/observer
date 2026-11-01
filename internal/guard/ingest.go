package guard

import (
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

// Watcher-path (post-hoc) evaluation seam (guard spec §3.2 seam 3,
// §7). store.Ingest calls EvaluateActions once per ingested batch
// with the actions that were ACTUALLY INSERTED (dedup-skipped rows
// never re-evaluate — idempotency for free), receives plain verdict
// records, and persists them through its own one-owner guard.go
// helpers. The guard layer holds the taint tracker; the store holds
// the rows: neither type leaks across (§17.2).

// ActionInput is one inserted action presented for post-hoc
// evaluation — plain data, built by the store from its own rows.
type ActionInput struct {
	// ActionID is the inserted actions.id (the guard_events anchor on
	// the post-hoc/watcher path).
	ActionID int64
	// APITurnID is the inserted api_turns.id, the guard_events anchor
	// on the PROXY response-inspection path (0 elsewhere). It lets the
	// obs trajectory enrichment join a verdict to the span by api_turn
	// id; the watcher/hook paths leave it 0 (they anchor via ActionID).
	APITurnID int64
	// SessionID / ProjectRoot / Tool / ActionType / Target /
	// Timestamp / TurnIndex mirror the action row.
	SessionID   string
	ProjectRoot string
	Tool        string
	ActionType  string
	Target      string
	Timestamp   time.Time
	TurnIndex   int
	// Success mirrors the action's success flag (web-fetch taint
	// marks only set on successful fetches — a failed fetch returned
	// no content to taint the session with).
	Success bool
	// ExternalChange is the freshness classifier's change-detected
	// signal on read-class actions: the file changed outside this
	// session since last observed (the §4.5 external_file taint
	// source).
	ExternalChange bool
	// PromptText is the developer's prompt for a user_prompt action: the
	// store's already-scrubbed raw_tool_input (the full text — Target is
	// a ~200-char excerpt), falling back to Target. Empty for every other
	// action type. IN-MEMORY ONLY: the post-hoc prompt lane
	// (posthocprompt.go) scans it and then clears it from the verdict it
	// returns; the persisted row carries a content-free fingerprint in
	// Target instead, exactly like the hook and proxy prompt lanes.
	PromptText string
	// PromptDigest is the pre-send mark (PromptPreSendDigest) a hook or
	// proxy prompt verdict carries: store.PersistGuardVerdicts records it
	// in guard_prompt_presend so the capture lane can recognise the same
	// prompt later. A one-way digest, node-local, never persisted on the
	// guard_events row itself. Empty everywhere else.
	PromptDigest string
}

// ActionVerdict pairs an evaluated action with its verdict — the
// plain result shape the store persists. Only decisions >= flag (and
// guard_error wrapper verdicts) are returned; allows stay silent.
type ActionVerdict struct {
	Input ActionInput
	// Kind is the classified event kind (persisted as
	// guard_events.event_kind).
	Kind policy.EventKind
	// Category is the winning rule's category (CategoryFor lookup),
	// persisted as guard_events.category.
	Category string
	// Verdict is the evaluation result.
	Verdict policy.Verdict
	// TaintOrigin is the winning taint mark's bounded description
	// when a taint-category rule won ("" otherwise) — persisted as
	// guard_events.taint_origin.
	TaintOrigin string
	// GuardError is true when the Q2 failure wrapper produced this
	// verdict (the caller persists it with rule_id=guard_error).
	GuardError bool
	// Enforced reports whether the emitted decision actually blocked
	// or deferred the action. Always false on the watcher path
	// (post-hoc by definition); the hook path sets it from the
	// resolved Emission. One result type, two feed paths — an
	// explicit design decision so the store keeps ONE translation
	// seam (PersistGuardVerdicts).
	Enforced bool
	// DegradedFrom records a §6.2 capability downgrade applied at
	// emission ("ask"/"deny" the verdict wanted but the channel
	// couldn't express). Empty on the watcher path.
	DegradedFrom string
	// ProxyAction, when non-empty, is the proxy-only enforcement
	// decision recorded on the audit row IN PLACE of the verdict's
	// decision string ("mask" — §8.2's proxy-specific decision).
	// policy.Decision stays the 4-value ordered enum so the layering
	// algebra is untouched; only the persisted decision column knows
	// "mask". Set exclusively by the proxy egress seam.
	ProxyAction string
	// SuppressAlert (FIX-3, phase-2 review) is true when the boundary
	// that built this verdict already showed the developer an
	// in-band, human-readable message for this exact outcome, so a
	// desktop toast on top would be a duplicate notification rather
	// than new information — e.g. the prompt-submit hook lane's
	// routine ask-once interrupt (the wire reply itself IS the
	// "reconsider once" message) or a warn/confirmed/approved
	// outcome (forwarded, non-blocking). It does NOT suppress a
	// genuine hard block/deny — see ActionVerdictFromPrompt's doc
	// comment for why "R-172 is Critical severity" alone was not
	// enough to make ask-once quiet (the original FIX-1 premise this
	// corrects). Every non-prompt channel leaves this false (zero
	// value) — MaybeAlert's existing severity-threshold behavior is
	// unchanged for them.
	SuppressAlert bool
	// SilentStop is true when the boundary STOPPED the action but its
	// channel showed the developer no reason in band (a prompt seam whose
	// block cannot carry a message: PromptSeamCaps.BlockSilent). The
	// desktop toast is then the only signal, so MaybeAlert sends it
	// whatever [guard.alerts].min_severity says. Zero value on every other
	// channel.
	SilentStop bool
	// Overridable / OrgLocked are the ORG-GRANTED OVERRIDE posture of
	// the winning rule at evaluation time (Track B, override.go).
	// Overridable: the org bundle marked this rule overridable, so the
	// developer may grant themselves a scoped exception and the
	// emission seam presents the deny as an ask where the channel can
	// prompt. OrgLocked: an org bundle applies and did NOT mark it, so
	// a local approval is inert. Both false on every individual node
	// (no bundle) and on flag-class verdicts, which never blocked.
	//
	// They are DERIVED state, not columns: guard_events is a
	// hash-CHAINED audit log whose row shape is fixed, so these ride
	// the in-memory verdict (alerts, emission text) and the node
	// dashboard re-derives them per rule from the live bundle. The
	// permanent record of an EXERCISED override stays the existing
	// degraded_from="approved" marker, and the permanent record of an
	// IGNORED one is the reason suffix applyApprovals writes.
	Overridable bool
	OrgLocked   bool
	// GrantID is the ORG access grant that changed this verdict (request-
	// grants G3, orggrant.go): set with DegradedFrom = DegradedFromOrgGrant
	// (lifted to flag) or DegradedFromOrgGrantSoften (deny softened to ask).
	// Persisted as guard_events.grant_id, which ships to the org on the
	// normal push and is part of the row's chain input (version 2). 0 = no
	// grant.
	GrantID int64
	// RequestBase is the node dashboard origin the org-locked deny line
	// links the request form under (request-grants G4; stamped by
	// stampOrgOverride from SetRequestAccessBase, "" = the CLI command
	// only). Derived state like Overridable/OrgLocked, never persisted.
	RequestBase string
	// softenedBy is a soften grant offered to the developer WITHOUT
	// counting a use (orggrant.go approvalOutcome); it steers the deny
	// text only. Derived state, never persisted.
	softenedBy int64
}

// watcherCaps are the post-hoc channel capabilities (spec §3.3): the
// watcher sees actions after execution; it can never block or ask.
var watcherCaps = policy.Capabilities{
	PreExecution: false,
	CanBlock:     false,
	CanAsk:       false,
}

// classifyKind maps the models action-type taxonomy onto policy event
// kinds AT THE BOUNDARY (Module rule 3 — the engine never sees
// adapter vocabulary). The bool reports whether the action is worth
// evaluating at all: lifecycle markers, prompts, and bookkeeping rows
// are skipped wholesale, which is most of what keeps the §7 ingest
// overhead budget (≤5%).
func classifyKind(actionType string) (policy.EventKind, bool) {
	switch actionType {
	case models.ActionRunCommand:
		return policy.KindShellExec, true
	case models.ActionReadFile, models.ActionWriteFile, models.ActionEditFile:
		return policy.KindFileAccess, true
	case models.ActionMCPCall:
		return policy.KindMCPCall, true
	case models.ActionConfigChange:
		return policy.KindConfigChange, true
	case models.ActionWebFetch, models.ActionWebSearch, models.ActionBrowserAction:
		// Evaluable as generic tool calls (url_domain user rules)
		// AND taint sources.
		return policy.KindToolCall, true
	default:
		return "", false
	}
}

// EvaluateActions evaluates one ingested batch in order: for each
// action it snapshots the session taint, evaluates through the Q2
// wrapper, then applies the action's taint side-effects (marks are
// recorded AFTER evaluation so an action that introduces taint is
// never its own sink). Returns only record-worthy results (decision
// >= flag, or wrapper errors).
//
// Mode off / guard disabled is handled by the caller not holding a
// Guard at all; a constructed Guard always evaluates (its engine
// returns allow immediately under ModeOff).
func (g *Guard) EvaluateActions(inputs []ActionInput) []ActionVerdict {
	// Load ONE snapshot for the whole batch so every Evaluate + its
	// paired CategoryFor read the exact same engineSet (the NIT
	// same-evaluation-snapshot contract); a concurrent ReloadOrgLayer
	// only affects the NEXT batch.
	es := g.set.Load()
	var out []ActionVerdict
	for i := range inputs {
		in := &inputs[i]
		// Compaction clears the session's taint (spec §4.5) — a
		// bookkeeping action otherwise skipped by classifyKind.
		if in.ActionType == models.ActionContextCompacted {
			g.taint.NoteCompaction(in.SessionID)
			continue
		}
		// The developer's own prompt, captured after it was sent: the
		// post-hoc prompt lane (posthocprompt.go). Before 2026-10-02 this
		// fell through to classifyKind, which skips prompts, so a tool
		// with no pre-send seam (agy, most of the fleet) recorded NOTHING
		// for a secret typed into a prompt.
		if in.ActionType == models.ActionUserPrompt {
			if av, ok := g.evaluateCapturedPrompt(es, in); ok {
				out = append(out, av)
			}
			continue
		}
		kind, evaluable := classifyKind(in.ActionType)
		if !evaluable {
			continue
		}
		taint := g.taint.Snapshot(in.SessionID, in.TurnIndex, in.Timestamp)
		ev := policy.Event{
			Kind:        kind,
			ActionType:  in.ActionType,
			Tool:        in.Tool,
			Target:      in.Target,
			ProjectRoot: in.ProjectRoot,
			SessionID:   in.SessionID,
			Caps:        watcherCaps,
			Taint:       taint,
			Now:         in.Timestamp,
			// §12 stamps: spend-so-far (TTL-cached lookup; zero when
			// no lookup is wired) and the A-610 consecutive-identical
			// run length.
			RepeatCount: g.repeats.Observe(in.SessionID, in.ActionType, in.Target),
		}
		g.stampBudgetIfRead(es, &ev, false, es.accountingContext(false))
		verdict, guardErr := g.evaluateWith(es, ev)
		if guardErr == nil {
			verdict = g.labelOrgBudgetVerdict(verdict)
		}
		// Post-hoc lane: org grants never apply here (lane ""), the gate
		// lane already decided and counted the call.
		verdict, appr := g.applyApprovals(verdict, &ev, "")
		if isBudgetRuleID(verdict.RuleID) && guardErr == nil &&
			g.budgetAlreadyRecorded(in.SessionID, verdict.RuleID) {
			// A budget breach records once per (session, rule) across
			// surfaces (budget.go) — cost only grows within a session,
			// so every later action would re-record the same fact. The
			// watcher channel can't block regardless (post-hoc).
			g.markTaint(in, kind, verdict)
			g.maybeConfigRescan(in)
			continue
		}
		if verdict.Decision >= policy.DecisionFlag || guardErr != nil {
			av := ActionVerdict{
				Input:       *in,
				Kind:        kind,
				Category:    g.categoryWith(es, verdict.RuleID),
				Verdict:     verdict,
				TaintOrigin: taintOriginFor(verdict, taint),
				GuardError:  guardErr != nil,
			}
			g.stampOrgOverride(es, &av)
			appr.stamp(&av)
			out = append(out, av)
		}
		eng := es.engineForEvent(g, ev.ProjectRoot, ev.Cwd)
		if ev, ok := g.evasionEvent(in, ev, verdict, guardErr, eng.RuleEnforceDenies); ok {
			if v := eng.EvaluateRule("A-613", ev); v.Decision >= policy.DecisionFlag {
				out = append(out, ActionVerdict{Input: *in, Kind: kind, Category: g.categoryWith(es, v.RuleID), Verdict: v})
			}
		}
		g.markTaint(in, kind, verdict)
		g.maybeConfigRescan(in)
	}
	return out
}

// markTaint applies an action's taint side-effects (spec §4.5
// sources, watcher-path subset):
//
//   - successful web fetch/search/browser results taint the session
//     (Imperative stays false post-hoc — content is not inspected
//     here; the proxy-side §8.4 heuristics set it in G9);
//   - MCP results taint as mcp_unpinned with the server as origin —
//     UNLESS the server is pinned and approved (the injected §9.2
//     lookup; G10 refines the G3 "every server is unpinned" note);
//   - reads of files changed outside the session taint as
//     external_file;
//   - a winning R-152 read / R-153 verdict marks secrets_read
//     (verdict-driven so the secret-file vocabulary stays in
//     rules_boundary.go).
func (g *Guard) markTaint(in *ActionInput, kind policy.EventKind, verdict policy.Verdict) {
	mark := func(source, origin string) {
		g.taint.Mark(in.SessionID, policy.TaintMark{
			Source: source,
			Origin: boundOrigin(origin),
			Turn:   in.TurnIndex,
			At:     in.Timestamp,
		})
	}
	switch kind {
	case policy.KindToolCall:
		if in.Success {
			mark(policy.TaintSourceWebFetch, in.Target)
		}
	case policy.KindMCPCall:
		if server := policy.MCPServerFromTarget(in.Target); server != "" && !g.mcpApproved(server) {
			mark(policy.TaintSourceMCPUnpinned, server)
		}
	case policy.KindFileAccess:
		if in.ActionType == models.ActionReadFile && in.ExternalChange {
			mark(policy.TaintSourceExternalFile, in.Target)
		}
	}
	if (verdict.RuleID == "R-153" || verdict.RuleID == "R-152") &&
		in.ActionType == models.ActionReadFile {
		mark(policy.TaintSourceSecretsRead, in.Target)
	}
}

// taintOriginFor extracts the audit-row taint origin: the first
// untrusted mark's "source:origin" when a taint-category rule won.
func taintOriginFor(verdict policy.Verdict, taint policy.TaintState) string {
	if len(verdict.RuleID) < 2 || verdict.RuleID[0] != 'T' {
		return ""
	}
	for _, m := range taint.Marks {
		if m.Origin != "" {
			return m.Source + ":" + m.Origin
		}
	}
	return ""
}

// boundOrigin caps an origin description at 128 bytes (origins are
// hosts/server names/paths — never content; the cap is belt-and-
// braces against a pathological target string).
func boundOrigin(s string) string {
	const maxOrigin = 128
	if len(s) <= maxOrigin {
		return s
	}
	return s[:maxOrigin]
}

// evasionEvent records a refusal in the A-613 tracker and, when the same
// rule already refused other shapes in this session within the window,
// returns the event stamped for the A-613 row (ok true). A-613 rides
// beside the refusal's own verdict, so it is evaluated on its own.
//
// A refusal is an ask or a deny, or, in observe mode, a flag from a rule
// whose enforce decision is deny (enforceDenies): observe mode never asks
// or denies, and A-613's row says it flags in observe mode too (plans
// decision log P-004).
func (g *Guard) evasionEvent(in *ActionInput, ev policy.Event, verdict policy.Verdict, guardErr error, enforceDenies func(ruleID string) bool) (policy.Event, bool) {
	window := time.Duration(g.cfg.Rules.EvasionWindowSeconds) * time.Second
	if window <= 0 || guardErr != nil || verdict.RuleID == "" || verdict.RuleID == "A-613" {
		return ev, false
	}
	refused := verdict.Decision >= policy.DecisionAsk ||
		(verdict.Decision == policy.DecisionFlag && enforceDenies != nil && enforceDenies(verdict.RuleID))
	if !refused {
		return ev, false
	}
	others := g.evasions.Observe(in.SessionID, verdict.RuleID, in.ActionType+"\x1f"+in.Target, in.Timestamp, window)
	if others < 1 {
		return ev, false
	}
	ev.EvasionOf, ev.EvasionShapes = verdict.RuleID, others
	return ev, true
}
