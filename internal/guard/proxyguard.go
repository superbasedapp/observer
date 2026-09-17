package guard

import (
	"encoding/json"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/guard/mcpsec"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

// Proxy-path evaluation seams (guard spec §3.2 seam 2, §8). The proxy
// is daemon-resident, so — unlike the short-lived hook process — its
// Guard instance holds LIVE taint state. cmd composition shares ONE
// Guard between the proxy and the watcher store (the cachetrack
// single-engine precedent), which is what finally arms T-501: the
// §8.4 injection heuristics here set Imperative taint that the
// watcher/hook seams consume on the next shell event.
//
// Three features, each gated by its own [guard.proxy] key:
//
//   - ScanProxyRequest / egress (§8.2, egress_scan): typed secret
//     detectors over the FINAL outbound body (post-compression — the
//     bytes the provider actually sees), resolved through the real
//     R-172 api_request row so mode/overrides/approvals all apply.
//     The proxy-side ACTION (forward / mask / deny) maps from the
//     verdict via [guard.proxy].egress_action — see the decision
//     table on resolveEgressAction.
//   - ScanProxyRequest / injection (§8.4, injection_heuristics): the
//     R-180 heuristics over NEW inbound tool-result / web / pasted
//     content segments; hits mark session taint with Imperative=true
//     and flag — they NEVER deny (gap F7).
//   - InspectProxyResponse (§8.3, response_scan): the response's
//     tool_use blocks are the model's intended next actions —
//     evaluated through the same engine a hook would use, a full
//     round-trip earlier. Flag/alert only in v1 (CanBlock=false; the
//     §6.2 degradation records what the verdict wanted).

// proxyRequestCaps are the egress-seam channel capabilities: the
// proxy sees the request BEFORE the provider does and can block it
// (synthetic 403, §8.5). No human in the loop → CanAsk=false (ask
// degrades to deny per §6.2 F5, then egress_action decides).
var proxyRequestCaps = policy.Capabilities{
	PreExecution: true,
	CanBlock:     true,
	CanAsk:       false,
	ProxyRouted:  true,
}

// proxyResponseCaps are the response-inspection capabilities:
// pre-execution intent, but v1 never rewrites model output (§8.3) —
// the channel cannot block, so deny/ask-class verdicts record with
// the §6.2 degradation marker.
var proxyResponseCaps = policy.Capabilities{
	PreExecution: true,
	CanBlock:     false,
	CanAsk:       false,
	ProxyRouted:  true,
}

// Proxy-action strings recorded on guard_events.decision for egress
// enforcement (the §8.2 "mask" decision exists ONLY at this seam —
// policy.Decision stays the 4-value ordered enum so the layering
// algebra is untouched).
const proxyActionMask = "mask"

// proxyActionRedact is the prompt-submit intervention PROXY LANE's own
// proxy_action value (contract §3.4) — distinct from proxyActionMask
// (the §8.2 egress scanner's own masking) even though both rewrite
// [REDACTED:type] markers into the body, because they run at different
// seams over different scopes (the single latest user turn vs the
// whole outbound body) and get separate audit rows.
const proxyActionRedact = "redact"

// maxProxySeenSessions bounds the per-session event-dedup map; the
// oldest-touched session evicts on overflow (same shape as the taint
// tracker bounds).
const maxProxySeenSessions = 256

// maxProxySeenSigs bounds signatures kept per session.
const maxProxySeenSigs = 128

// ProxyToolUse is one intended next action extracted from a provider
// response by the proxy (which owns wire-format parsing; this layer
// owns meaning). Input is the tool's JSON input object.
type ProxyToolUse struct {
	// Name is the tool name as the model emitted it.
	Name string
	// Input is the JSON-encoded input object ({"command": ...}).
	Input []byte
}

// ProxyRequestResult is what the egress seam hands back to the proxy
// adapter: record-worthy verdicts plus the action to take on the
// request.
type ProxyRequestResult struct {
	// Verdicts are the record-worthy results (egress + injection),
	// ready for store.PersistGuardVerdicts.
	Verdicts []ActionVerdict
	// MaskedBody, when non-nil, is the rewritten outbound body
	// ([REDACTED:type] markers in place of certain findings). The
	// proxy MUST forward it instead of the original.
	MaskedBody []byte
	// Deny reports the §8.5 synthetic-403 decision. DenyRuleID /
	// DenyReason feed the provider-shaped error body.
	Deny       bool
	DenyRuleID string
	DenyReason string
	// PromptDeny/PromptStatus/PromptRuleID/PromptReason (contract §3,
	// prompt-submit intervention PROXY LANE) carry the SAME decision as
	// Deny/DenyRuleID/DenyReason above — scanPrompt sets both pairs
	// together (never Deny alone for a prompt-lane block, so today's
	// cmd/observer/guardwire.go adapter, which only reads Deny/
	// DenyRuleID/DenyReason, already forwards a safe, never-429,
	// never-5xx 4xx response with zero changes on that side) — but
	// PromptStatus additionally distinguishes the two safe status codes
	// the contract calls for (§3.3): 400 for a fresh ask-once interrupt
	// (policy.DecisionAsk — "send it again to confirm") or the
	// session-less fail-closed degrade, 403 for an unconditional block
	// (policy.DecisionDeny — mode=block or another fail-closed degrade).
	// A caller that wants the precise status and
	// the developer-facing (not agent-facing) wording reads these three
	// fields instead of the generic Deny ones; see PromptReason's doc
	// comment on proxyPromptHouseMessage for why the wording differs
	// from guardDenyBody's egress framing.
	PromptDeny   bool
	PromptStatus int
	PromptRuleID string
	PromptReason string
	// MCPDecls are the request's MCP tool declarations when this is
	// the first time this session has shown this declaration set
	// (per-session dedup — request bodies re-send the whole tools
	// array every turn). The cmd adapter forwards them to the mcpsec
	// observation flow OFF the request path; the proxy package never
	// sees them.
	MCPDecls []mcpsec.ToolDecl
}

// proxySeen is the per-session record-dedup state: a request body
// carries the whole conversation, so without dedup the same finding
// signature would re-record on every subsequent turn of the session.
// Deny decisions are NEVER deduped (each enforced deny is an audit
// fact); flag/mask records dedup by signature.
type proxySeen struct {
	sigs      map[string]bool
	lastTouch time.Time
}

// ScanProxyRequest runs the §8.2 egress scan and the §8.4 injection
// heuristics over the final outbound request body. provider is the
// wire-format hint ("anthropic" | "openai" — a body shape, not a tool
// identity); sessionID may be empty (dedup and taint degrade to
// no-ops). now is injected for determinism; zero means time.Now().
//
// The call is synchronous on the request hot path — the §17.9 budget
// (≤10ms p99 added per request) is pinned by BenchmarkScanProxyRequest.
func (g *Guard) ScanProxyRequest(provider string, body []byte, sessionID string, now time.Time) ProxyRequestResult {
	return g.scanProxyRequest(provider, body, sessionID, now, true)
}

// ScanProxyPrompt is phase 1 of the two-phase proxy protocol (LIVE
// CORRECTION 2026-09-07): the prompt-submit lane ALONE, run by the proxy
// on the ORIGINAL request body BEFORE conversation compression. The
// compression pipeline forward-scrubs the outbound body
// (scrub.ScrubForward), so a prompt scan on the post-compression bytes
// sees [REDACTED] where the secret was and can never ask-once/block --
// two live Codex Desktop turns were silently redacted that way with no
// guard event and no message to the developer. Same gating as the
// prompt block inside scanProxyRequest; returns the prompt outcome only
// (PromptDeny/Deny/MaskedBody + the prompt verdict).
func (g *Guard) ScanProxyPrompt(provider string, body []byte, sessionID string, now time.Time) ProxyRequestResult {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	var res ProxyRequestResult
	if len(body) == 0 || !(g.cfg.Prompt.Enabled && g.cfg.Prompt.ProxyLane) {
		return res
	}
	parsed := parseProxyBody(provider, body, false)
	g.scanPrompt(&res, provider, body, parsed, sessionID, now)
	return res
}

// ScanProxyRequestAfterPrompt is phase 2: everything ScanProxyRequest
// does EXCEPT the prompt lane, for a proxy that already ran
// ScanProxyPrompt on the pre-compression body. Running the prompt lane
// here again would double-evaluate the same submission against the
// reconsider-once store (a PII finding surviving compression would read
// its own phase-1 "warned" row as the confirming resend).
func (g *Guard) ScanProxyRequestAfterPrompt(provider string, body []byte, sessionID string, now time.Time) ProxyRequestResult {
	return g.scanProxyRequest(provider, body, sessionID, now, false)
}

func (g *Guard) scanProxyRequest(provider string, body []byte, sessionID string, now time.Time, withPrompt bool) ProxyRequestResult {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	var res ProxyRequestResult
	if len(body) == 0 {
		return res
	}
	wantTools := g.cfg.MCP.Pinning || g.cfg.MCP.PoisoningHeuristics
	parsed := parseProxyBody(provider, body, wantTools)
	target := provider + ":" + parsed.model

	// Load ONE snapshot for the whole request scan (budget + egress +
	// injection), so every Evaluate + its paired CategoryFor read the
	// same engineSet (the NIT same-evaluation-snapshot contract).
	es := g.set.Load()

	// §12.1 budget check first (cheapest pass — a TTL-cached lookup +
	// one engine evaluation). A hard-mode deny short-circuits the
	// pipeline: the request never reaches the provider, so there is
	// nothing to egress-scan and no new content enters the session.
	g.scanBudget(es, &res, sessionID, target, now, parsed.model)
	if res.Deny {
		return res
	}

	// Prompt-submit intervention, PROXY LANE (contract §3; risk item 4
	// — "prompt-scan first, egress-scan second"): the developer's own
	// latest typed turn is judged BEFORE the egress scanner sees the
	// body, so a fresh ask-once/block interrupt reaches the developer
	// unmasked — masking the finding first would make the interrupt
	// unreachable. A prompt-lane block/ask short-circuits the rest of
	// this scan (mirrors the budget-deny short-circuit above): the
	// developer hasn't confirmed anything yet, so nothing downstream
	// should treat this content as sent. Gated on BOTH the feature
	// switch and the lane switch — an operator can run [guard.prompt]
	// hook-lane-only (ProxyLane=false) without paying this scan at all.
	//
	// egressBody starts as the original body and is upgraded to the
	// prompt lane's own redacted body when scanPrompt produced one
	// (F5, phase-3b review): scanEgress previously always re-scanned
	// the ORIGINAL body even after a redact, which (a) could un-redact
	// a finding the prompt lane already masked — anything covered by
	// [guard.proxy].egress_allow but not [guard.prompt].allow would
	// forward in the clear despite the operator having just asked for
	// it to be masked — and (b) recorded a SECOND verdict for the
	// exact same finding. Feeding the redacted body forward composes
	// the two lanes instead of one clobbering the other: a secret the
	// prompt lane already replaced with a [REDACTED:type] marker no
	// longer matches the egress detector at all, so it naturally
	// produces neither effect; any OTHER secret elsewhere in the
	// request still scans and masks/denies exactly as before.
	egressBody := body
	if withPrompt && g.cfg.Prompt.Enabled && g.cfg.Prompt.ProxyLane {
		g.scanPrompt(&res, provider, body, parsed, sessionID, now)
		if res.Deny {
			return res
		}
		if res.MaskedBody != nil {
			egressBody = res.MaskedBody
		}
	}

	if g.cfg.Proxy.EgressScan {
		g.scanEgress(es, &res, egressBody, sessionID, target, now)
	}
	if g.cfg.Proxy.InjectionHeuristics {
		g.scanInjection(es, &res, parsed, sessionID, now)
	}
	if len(parsed.mcpDecls) > 0 &&
		!g.proxyAlreadySeen(sessionID, mcpDeclsSignature(parsed.mcpDecls), now) {
		// First time this session shows this declaration set — hand it
		// out for the §9.2 observation flow (the cmd adapter runs the
		// pin diff off the request path).
		res.MCPDecls = parsed.mcpDecls
	}
	return res
}

// mcpDeclsSignature builds the per-session dedup key for a request's
// MCP declaration set: one ToolsHash per server, joined in sorted
// server order (ToolsHash itself sorts tools within a server).
func mcpDeclsSignature(decls []mcpsec.ToolDecl) string {
	byServer := map[string][]mcpsec.ToolDecl{}
	servers := make([]string, 0, 4)
	for _, d := range decls {
		if _, ok := byServer[d.Server]; !ok {
			servers = append(servers, d.Server)
		}
		byServer[d.Server] = append(byServer[d.Server], d)
	}
	sort.Strings(servers)
	var b strings.Builder
	b.WriteString("mcp_decls")
	for _, s := range servers {
		b.WriteByte('|')
		b.WriteString(s)
		b.WriteByte('=')
		b.WriteString(mcpsec.ToolsHash(byServer[s]))
	}
	return b.String()
}

// scanEgress implements the §8.2 half of ScanProxyRequest. es is the
// caller's already-Loaded snapshot so the Evaluate+CategoryFor pair
// stays consistent (NIT contract).
func (g *Guard) scanEgress(es *engineSet, res *ProxyRequestResult, body []byte, sessionID, target string, now time.Time) {
	// One detector pass produces both the findings and the candidate
	// masked body. Only certain, non-allowlisted findings mask (§8.2:
	// mask is for detector-certain types; entropy hits never mask).
	maskable := func(f scrub.TypedFinding) bool {
		return f.Certain && !g.egressAllowed(f.Value)
	}
	masked, findings := scrub.MaskSecrets(string(body), maskable)

	// Allowlist filter ([guard.proxy].egress_allow): a finding whose
	// VALUE matches an operator pattern (test fixtures, known-fake
	// keys) doesn't count at all.
	secrets := make([]policy.SecretFinding, 0, len(findings))
	anyCertain := false
	for _, f := range findings {
		if g.egressAllowed(f.Value) {
			continue
		}
		secrets = append(secrets, policy.SecretFinding{Type: f.Type, Certain: f.Certain})
		if f.Certain {
			anyCertain = true
		}
	}
	if len(secrets) == 0 {
		return
	}

	ev := policy.Event{
		Kind:      policy.KindAPIRequest,
		Target:    target,
		SessionID: sessionID,
		Caps:      proxyRequestCaps,
		Secrets:   secrets,
		Now:       now,
	}
	verdict, guardErr := g.evaluateWith(es, ev)
	verdict, approved := g.applyApprovals(verdict, &ev)
	if verdict.Decision < policy.DecisionFlag && guardErr == nil {
		return // R-172 disabled or overridden to allow
	}

	av := ActionVerdict{
		Input: ActionInput{
			SessionID: sessionID,
			Target:    target,
			Timestamp: now,
		},
		Kind:       policy.KindAPIRequest,
		Category:   g.categoryWith(es, verdict.RuleID),
		Verdict:    verdict,
		GuardError: guardErr != nil,
	}
	if approved {
		av.DegradedFrom = "approved"
	}

	em := ResolveEmission(verdict, proxyRequestCaps)
	action := g.resolveEgressAction(em, anyCertain)
	switch action {
	case "deny":
		av.Enforced = true
		res.Deny = true
		res.DenyRuleID = verdict.RuleID
		res.DenyReason = verdict.Reason
	case proxyActionMask:
		av.Enforced = true
		av.ProxyAction = proxyActionMask
		res.MaskedBody = []byte(masked)
	default: // forward, record as flag-class
		if em.Permission == "deny" && av.DegradedFrom == "" {
			// The verdict wanted to block but egress_action (or an
			// entropy-only finding set) capped the channel at
			// flag/mask — record the downgrade, never silently weaker
			// (§6.2 F5).
			av.DegradedFrom = verdict.Decision.String()
			av.Verdict.Decision = policy.DecisionFlag
		}
	}

	// Dedup flag/mask records per session (a deny always records).
	if !res.Deny && g.proxyAlreadySeen(sessionID, egressSignature(&av), now) {
		return
	}
	res.Verdicts = append(res.Verdicts, av)
}

// resolveEgressAction maps a resolved emission onto the proxy action
// per [guard.proxy].egress_action — the §8.2 decision table:
//
//	verdict (post-approval, post-§6.2) | egress_action | certain? | action
//	flag-class                         | *             | *        | forward (record flag)
//	deny                               | flag          | *        | forward (record flag, degraded_from=deny)
//	deny                               | mask          | yes      | mask    (record mask, enforced)
//	deny                               | mask          | no       | forward (record flag, degraded_from=deny — entropy-only never masks)
//	deny                               | deny          | *        | 403     (record deny, enforced)
func (g *Guard) resolveEgressAction(em Emission, anyCertain bool) string {
	if em.Permission != "deny" {
		return "flag"
	}
	switch g.cfg.Proxy.EgressAction {
	case "deny":
		return "deny"
	case proxyActionMask:
		if anyCertain {
			return proxyActionMask
		}
		return "flag"
	default:
		return "flag"
	}
}

// egressAllowed reports whether a matched value is covered by an
// [guard.proxy].egress_allow pattern.
func (g *Guard) egressAllowed(value string) bool {
	for _, re := range g.egressAllow {
		if re.MatchString(value) {
			return true
		}
	}
	return false
}

// proxyPromptCaps are the prompt-submit intervention PROXY LANE's
// channel capabilities (contract §3, the "proxy-lane conformance row"
// the build contract calls for — kept as a package-level literal here
// rather than an internal/guard/conformance.go row, matching how
// proxyRequestCaps/proxyResponseCaps above are ALSO literals local to
// this file rather than ConformanceMatrix entries: conformance.go's
// matrix is keyed per adapter×hook-channel, but the proxy lane is one
// uniform capability shared by every routed tool regardless of which
// adapter it is — CLAUDE.md rule 3, branch on capability shape, never
// tool identity).
//
// Unlike proxyRequestCaps (the §8.2 egress scan, which has no human in
// the loop and so sets CanAsk:false), CanAsk:true here is load-bearing:
// the reconsider-once state machine's "ask" IS the reject-once — a
// first-occurrence 4xx the developer reads and resends unchanged to
// confirm (contract §5). Setting CanAsk:false would make
// guard.ResolveEmission silently degrade every fresh ask-once
// interrupt straight to a permanent deny, defeating the resend-to-
// confirm UX the whole feature exists to provide.
var proxyPromptCaps = policy.Capabilities{
	PreExecution: true,
	CanBlock:     true,
	CanAsk:       true,
	ProxyRouted:  true,
}

// promptDenyStatus implements contract §3.3's status-code table: 400
// for a fresh ask-once interrupt (policy.DecisionAsk — "resend
// unchanged to confirm"), and for the session-less fail-closed degrade
// (the client may be able to recover by establishing a local scope); 403
// for an unconditional block (policy.DecisionDeny — mode=block or any
// other fail-closed degrade, including store_unwired). The decision stays
// a deny in every fail-closed case; this helper only selects the wire
// status. Never 429 (retried by every SDK's default backoff, which would
// silently auto-confirm an interrupt the developer never read) and never
// a 5xx (contract §3.3).
func promptDenyStatus(decision policy.Decision, degradedFrom string) int {
	if degradedFrom == "no_session" {
		return 400
	}
	if decision == policy.DecisionAsk {
		return 400
	}
	return 403
}

// proxyPromptBlockReasons mirrors the block-reason suffix table
// internal/hook/promptsubmit.go's promptHouseMessage renders for the
// hook lane (same wording, so a developer who trips the SAME finding
// on a hook-guarded and a proxy-guarded turn sees an identical
// message) — kept as a small independent copy here rather than an
// export from internal/hook, because internal/hook is this package's
// OWN dependent (hook imports guard, never the reverse — inverting
// that to share four lines of message text would be the wrong trade).
var proxyPromptBlockReasons = map[string]string{
	"": ". Edit it out before sending — mode=\"block\" has no resend override.",
	"unhashable": ". This finding type can't be fingerprinted for a resend override, so it blocks every time — " +
		"edit it out before sending.",
	"no_session": ". No session id was available to track a resend, so this blocks unconditionally — " +
		"edit it out before sending.",
	"store_unwired": ". The reconsider-once store isn't available right now, so this blocks unconditionally " +
		"(fail-closed) — edit it out before sending, or retry once observer is healthy.",
	"unscanned": "",
}

// proxyPromptRemediationDetector mirrors
// internal/hook/promptsubmit.go's own promptRemediationDetector — the
// first (alphabetically earliest) type from PromptVerdict.Detectors'
// sorted CSV, since a copy-pasteable command can only name one
// detector at a time. Kept as a small package-local duplicate rather
// than exporting the hook-lane helper: internal/guard must not import
// internal/hook (that dependency runs the other direction), and this
// is a one-line string split, not shared logic worth a new seam.
func proxyPromptRemediationDetector(csv string) string {
	if i := strings.IndexByte(csv, ','); i >= 0 {
		return csv[:i]
	}
	return csv
}

// proxyPromptHouseMessage renders the house-style, DEVELOPER-facing
// message (contract §7) for a proxy-lane PromptVerdict — deliberately
// NOT guardDenyBody's "[observer-guard %s] request blocked by the
// egress policy: %s" framing (internal/proxy/guard.go), which is
// written for the AGENT to read and self-correct (§3.1); the audience
// here is the human who just typed the prompt, so the wording matches
// internal/hook/promptsubmit.go's promptHouseMessage instead.
//
// FIXED (final-fix review, FIX cluster): the ask-once branch used to
// emit the literal, non-functional placeholder text "observer guard
// prompt allow <detector> --session" — no real detector id, no real
// session id, and missing the --session flag's own argument, exactly
// the bug the hook lane's promptHouseMessage already fixed under F6
// (phase-3a review). This now interpolates the REAL detector (from
// pv.Detectors, same promptRemediationDetector convention) and the
// REAL sessionID the caller already has in scope, so a developer on
// the proxy lane gets the same copy-pasteable command the hook lane
// gives.
func proxyPromptHouseMessage(pv PromptVerdict, sessionID string) string {
	reason := pv.Verdict.Reason
	switch pv.Outcome {
	case PromptOutcomeBlocked:
		if pv.Verdict.Decision == policy.DecisionAsk {
			detector := proxyPromptRemediationDetector(pv.Detectors)
			if detector == "" {
				detector = "<detector>"
			}
			sid := sessionID
			if sid == "" {
				sid = "<session>"
			}
			if pv.DegradedFrom == "retry_too_fast" {
				// Inside reconsider_min_delay: most likely the client's own
				// retry (Copilot CLI retried a 400 after 42 ms), but a fast
				// human gets the same verdict — say what to do (F2).
				return "observer: " + reason + ". That resend arrived too fast to count as your confirmation — wait a moment and send it again unchanged to confirm, or edit it out."
			}
			return "observer: " + reason + ". Send it again unchanged to confirm, or edit it out. " +
				"Run `observer guard prompt allow " + detector + " --session " + sid +
				"` to stop asking (this allows every detector in the same rule class, not just " + detector + ")."
		}
		suffix, ok := proxyPromptBlockReasons[pv.DegradedFrom]
		if !ok {
			suffix = proxyPromptBlockReasons[""]
		}
		return "observer: " + reason + suffix
	case PromptOutcomeWarned:
		return "observer: " + reason + " (forwarded; see `observer guard prompt status`)."
	default:
		return reason
	}
}

// scanPrompt implements the prompt-submit intervention PROXY LANE
// (contract §3): extract the LATEST user turn per wire shape, run it
// through the SAME BuildPromptFindings → EvaluatePrompt → ResolveEmission
// → ActionVerdictFromPrompt seam the hook lane uses
// (internal/hook/promptsubmit.go's HandlePromptSubmitGuarded), and
// translate the result onto res: a blocking outcome sets Deny (+ the
// PromptXxx fields — see ProxyRequestResult's doc comment for why both
// pairs are set) and short-circuits (never deduped — an enforced
// interrupt is always an audit fact, matching scanEgress's own deny
// posture); a non-blocking record-worthy outcome (warned/confirmed/
// approved) appends a dedup'd verdict for persistence + MaybeAlert,
// exactly like scanEgress's flag path.
//
// Cross-lane confirm (contract §10 item 6 / this build's item 2): the
// reconsider-once fingerprint is keyed on session_id + the finding
// set, not on which LANE evaluated it, so a hook-confirmed resend
// lands on the identical guard_prompt_reconsider row here too — this
// function does nothing special to make that true, it falls out of
// calling the same EvaluatePrompt seam over the same store. It DOES
// require the daemon's shared Guard (the one ScanProxyRequest runs on)
// to have SetPromptReconsiderStore wired to the same DB the hook
// lane's per-process Guard uses (cmd/observer/hook.go:836 wires it for
// the hook lane's short-lived Guard already); until
// cmd/observer/guardwire.go's buildGuardForStore also calls
// g.SetPromptReconsiderStore for the daemon-shared instance, every
// proxy-lane ask-once fails closed to an unconditional block
// (DegradedFrom="store_unwired", §5.4/§10 item 5's documented
// fail-closed posture) rather than allowing the resend-to-confirm —
// SAFE (never a silent allow), just not the full designed UX. See this
// build's own report for the exact follow-up needed there.
//
// PII-class findings under mode=redact still degrade to the ask-once/
// block handling below, same as the hook lane (RequestedMode is
// simply recorded, never acted on for PII): there is no exported
// PII-aware masking primitive outside internal/scrub
// (scrub.MaskSecrets is deliberately secrets-only, and reimplementing
// its Fernet-shielding-aware span bookkeeping here would risk a byte-
// offset bug against upstream JSON validity — the exact class of
// incident CLAUDE.md's Don'ts section documents). A genuine SECRET-only
// finding set under mode=redact DOES get real redact treatment: see
// the branch below.
//
// parsed is the SAME parseProxyBody view ScanProxyRequest already built
// for the §8.4 injection scan — F6 (phase-3b review): when
// parsed.latestUserTextOK is true (Anthropic/OpenAI, the common case),
// that extraction is reused instead of a second full-body
// extractLatestUserPromptText decode; the fallback below covers Gemini
// (never parsed by parseProxyBody) and any shape parseProxyBody's
// stricter structs failed to decode.
func (g *Guard) scanPrompt(res *ProxyRequestResult, provider string, body []byte, parsed proxyParsedBody, sessionID string, now time.Time) {
	text, ok := parsed.latestUserText, parsed.latestUserTextOK
	if !ok {
		text, ok = extractLatestUserPromptText(provider, body)
	}
	if !ok {
		return
	}
	secrets, pii, truncated := g.BuildPromptFindings(text)
	if len(secrets) == 0 && len(pii) == 0 && !truncated {
		return
	}

	ev := policy.Event{
		Kind:            policy.KindUserPrompt,
		Target:          provider,
		SessionID:       sessionID,
		Caps:            proxyPromptCaps,
		Secrets:         secrets,
		PIIFindings:     pii,
		PromptTruncated: truncated,
		Now:             now,
	}
	pv := g.EvaluatePrompt(ev)

	// Genuine redact (contract §3.4/item 3): the proxy IS a
	// modify-capability channel — it can rewrite the outbound body
	// before the provider ever sees it, unlike every hook dialect built
	// so far (none has redact wired; see promptguard.go's package doc
	// comment). Only reachable for a secret-only finding set — see the
	// doc comment above for why PII stays on the block path.
	if pv.RequestedMode == PromptModeRedact && len(pii) == 0 && len(secrets) > 0 {
		if newBody, masked := g.redactPromptSecrets(provider, body); masked {
			// F7 (phase-3b review): route through the SAME
			// PromptVerdict → ActionVerdict bridge every other outcome
			// uses instead of hand-building the ActionVerdict here —
			// see ActionVerdictFromRedactedPrompt's own doc comment for
			// why a redact needs its own (Emission-bypassing) branch of
			// that bridge, and for the SuppressAlert fix (the hand-built
			// version left SuppressAlert at its zero value, so a
			// redact-and-forward — which never blocks anything — was
			// toasting a desktop alert on every occurrence).
			av := g.ActionVerdictFromRedactedPrompt(pv, ActionInput{SessionID: sessionID, Target: provider, Timestamp: now})
			if !g.proxyAlreadySeen(sessionID, egressSignature(&av), now) {
				res.Verdicts = append(res.Verdicts, av)
			}
			res.MaskedBody = newBody
			return
		}
		// Masking/splicing failed for any reason (e.g. the body no
		// longer round-trips through the same shape) — fall through to
		// the tested ask-once/block path below rather than silently
		// forwarding the secret unmasked.
	}

	em := ResolveEmission(pv.Verdict, proxyPromptCaps)
	av := g.ActionVerdictFromPrompt(pv, em, ActionInput{SessionID: sessionID, Target: provider, Timestamp: now})

	if em.Permission != "allow" {
		reason := proxyPromptHouseMessage(pv, sessionID)
		res.Deny = true
		res.DenyRuleID = pv.Verdict.RuleID
		res.DenyReason = reason
		res.PromptDeny = true
		res.PromptStatus = promptDenyStatus(pv.Verdict.Decision, pv.DegradedFrom)
		res.PromptRuleID = pv.Verdict.RuleID
		res.PromptReason = reason
		res.Verdicts = append(res.Verdicts, av)
		return
	}
	if !pv.RecordWorthy() {
		return
	}
	if g.proxyAlreadySeen(sessionID, egressSignature(&av), now) {
		return
	}
	res.Verdicts = append(res.Verdicts, av)
}

// redactPromptSecrets masks every certain, non-allowlisted secret-class
// finding within the latest user turn's own TEXT ELEMENTS via
// scrub.MaskSecrets — the same [REDACTED:type] marker egress masking
// uses — then splices the masked text back in place, leaving every
// other message/field byte-for-byte untouched apart from object key
// ordering (encoding/json normalizes map key order; JSON object key
// order carries no semantic meaning, so no provider parses it
// positionally). masked=false means nothing needed masking, or the
// splice could not be performed safely — the caller then falls back to
// the ask-once/block path rather than forwarding an unmasked secret.
//
// FIX (B1, phase-3b review): the original implementation flattened the
// WHOLE message into one string (any tool_result/image_url/inlineData
// block lost on the way — anthropicUserPromptText and its OpenAI/
// Gemini siblings deliberately read ONLY text for the SCAN, which is
// correct there, but this function used to reuse that same flattened
// text as the REWRITE too), masked THAT, and rewrote the message as a
// single plain-text content field — silently deleting every non-text
// block. A last user message carrying a tool_result alongside pasted
// text (a normal mid-conversation shape, not just Claude Code's own
// system-reminder injections) would upstream-400 with "tool_use ids
// were found without tool_result blocks", breaking the live session —
// the exact JSON-structural-integrity class of incident CLAUDE.md's
// Don'ts section already documents for scrub.Scrubber.String. Masking
// now happens PER TEXT ELEMENT, in place, via maskOne below, and ONLY
// when the target content is a bare string or an array whose every
// element is a plain text block/part — any other shape (tool_result,
// image_url, inlineData, function/tool blocks, ...) makes the splice
// helpers below report ok=false, and this function then reports
// masked=false so the caller falls back to the tested ask-once/block
// path instead of dropping content.
func (g *Guard) redactPromptSecrets(provider string, body []byte) (newBody []byte, masked bool) {
	maskable := func(f scrub.TypedFinding) bool {
		return f.Certain && !g.promptAllowed(f.Value)
	}
	maskOne := func(s string) (string, bool) {
		out, _ := scrub.MaskSecrets(s, maskable)
		return out, out != s
	}
	return spliceLatestUserPromptText(provider, body, maskOne)
}

// spliceLatestUserPromptText rewrites JUST the latest user turn this
// package's own extractLatestUserPromptText would find, calling maskOne
// on each plain-text element of that message's content and writing the
// result back IN PLACE. Every other top-level field and every other
// message/content item is carried through UNTOUCHED as raw
// json.RawMessage; even within the target message, only text elements
// are touched — so a redact never touches earlier turns (contract §3.4)
// and never drops a non-text block (B1).
//
// ok=false (never partial) whenever the target content is anything
// other than a bare string or an array whose EVERY element is a plain
// text block/part — a tool_result, image_url, inlineData, tool_use, or
// any other block/part type anywhere in the message means the WHOLE
// message is left untouched and the caller treats this as "could not
// redact safely", falling back to the ask-once/block path (B1: the
// previous version instead rewrote the whole message to plain-string
// content, silently deleting whatever else was there — the class of
// bug that produces an upstream "tool_use ids were found without
// tool_result blocks" 400 and breaks the live session).
func spliceLatestUserPromptText(provider string, body []byte, maskOne func(string) (string, bool)) ([]byte, bool) {
	switch provider {
	case models.ProviderAnthropic:
		return spliceAnthropicLatestUser(body, maskOne)
	case models.ProviderOpenAI:
		return spliceOpenAILatestUser(body, maskOne)
	case models.ProviderGoogle:
		return spliceGeminiLatestUser(body, maskOne)
	default:
		return nil, false
	}
}

// spliceAnthropicLatestUser rewrites the last role:"user" entry of an
// Anthropic Messages request's messages[] IN PLACE (see
// maskAnthropicTextOnlyContent for the B1 safety rule), leaving every
// other message's raw bytes untouched.
func spliceAnthropicLatestUser(body []byte, maskOne func(string) (string, bool)) ([]byte, bool) {
	var raw map[string]json.RawMessage
	if json.Unmarshal(body, &raw) != nil {
		return nil, false
	}
	msgsRaw, ok := raw["messages"]
	if !ok {
		return nil, false
	}
	var msgs []json.RawMessage
	if json.Unmarshal(msgsRaw, &msgs) != nil {
		return nil, false
	}
	idx := lastUserMessageIndex(msgs, func(m json.RawMessage) bool {
		var am anthropicMessage
		return json.Unmarshal(m, &am) == nil && am.Role == "user"
	})
	if idx < 0 {
		return nil, false
	}
	var am anthropicMessage
	if json.Unmarshal(msgs[idx], &am) != nil {
		return nil, false
	}
	newContent, changed, safe := maskAnthropicTextOnlyContent(am.Content, maskOne)
	if !safe || !changed {
		return nil, false
	}
	rewritten, err := json.Marshal(struct {
		Role    string          `json:"role"`
		Content json.RawMessage `json:"content"`
	}{Role: "user", Content: newContent})
	if err != nil {
		return nil, false
	}
	msgs[idx] = rewritten
	newMsgs, err := json.Marshal(msgs)
	if err != nil {
		return nil, false
	}
	raw["messages"] = newMsgs
	out, err := json.Marshal(raw)
	if err != nil || !json.Valid(out) {
		return nil, false
	}
	return out, true
}

// maskAnthropicTextOnlyContent implements the B1 safety rule for one
// Anthropic message's content: a bare string masks directly; a block
// array masks only when EVERY block is type:"text" — a tool_use,
// tool_result, image, document, thinking, or any other/unrecognized
// block type anywhere in the array makes the whole array unsafe
// (safe=false, out/changed unusable). Non-"text"/"type" keys on a text
// block (e.g. Anthropic's own cache_control) are preserved untouched —
// this rewrites ONLY each block's "text" field, via a
// map[string]json.RawMessage decode rather than a narrow struct, so an
// unmodeled sibling key is never silently dropped.
func maskAnthropicTextOnlyContent(content json.RawMessage, maskOne func(string) (string, bool)) (out json.RawMessage, changed, safe bool) {
	var s string
	if json.Unmarshal(content, &s) == nil {
		newS, ch := maskOne(s)
		if !ch {
			return content, false, true
		}
		nb, err := json.Marshal(newS)
		if err != nil {
			return nil, false, false
		}
		return nb, true, true
	}
	var blocks []map[string]json.RawMessage
	if json.Unmarshal(content, &blocks) != nil {
		return nil, false, false
	}
	for i, b := range blocks {
		var typ string
		if json.Unmarshal(b["type"], &typ) != nil || typ != "text" {
			return nil, false, false
		}
		var text string
		if json.Unmarshal(b["text"], &text) != nil {
			return nil, false, false
		}
		newText, ch := maskOne(text)
		if !ch {
			continue
		}
		nt, err := json.Marshal(newText)
		if err != nil {
			return nil, false, false
		}
		b["text"] = nt
		blocks[i] = b
		changed = true
	}
	if !changed {
		return content, false, true
	}
	nb, err := json.Marshal(blocks)
	if err != nil {
		return nil, false, false
	}
	return nb, true, true
}

// spliceOpenAILatestUser rewrites the last role:"user" chat message
// (Chat Completions) — or, when the body has no messages[] array at
// all, the top-level `input` string (the Responses API's own
// bare-string shape) — IN PLACE (see maskOpenAITextOnlyContent for the
// B1 safety rule on the Chat Completions content-parts array). The
// Responses API's ARRAY input shape is deliberately NOT spliced: that
// shape is Codex's own request format (unavailable on Codex, not
// merely "rare" — every Responses-array-input caller falls through to
// the ask-once/block path for redact specifically); a later pass can
// add it following this function's own per-item pattern.
func spliceOpenAILatestUser(body []byte, maskOne func(string) (string, bool)) ([]byte, bool) {
	var raw map[string]json.RawMessage
	if json.Unmarshal(body, &raw) != nil {
		return nil, false
	}
	if msgsRaw, ok := raw["messages"]; ok {
		var msgs []json.RawMessage
		if json.Unmarshal(msgsRaw, &msgs) != nil {
			return nil, false
		}
		idx := lastUserMessageIndex(msgs, func(m json.RawMessage) bool {
			var cm openAIChatMessage
			return json.Unmarshal(m, &cm) == nil && cm.Role == "user"
		})
		if idx < 0 {
			return nil, false
		}
		var cm openAIChatMessage
		if json.Unmarshal(msgs[idx], &cm) != nil {
			return nil, false
		}
		newContent, changed, safe := maskOpenAITextOnlyContent(cm.Content, maskOne)
		if !safe || !changed {
			return nil, false
		}
		rewritten, err := json.Marshal(struct {
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		}{Role: "user", Content: newContent})
		if err != nil {
			return nil, false
		}
		msgs[idx] = rewritten
		newMsgs, err := json.Marshal(msgs)
		if err != nil {
			return nil, false
		}
		raw["messages"] = newMsgs
		out, err := json.Marshal(raw)
		if err != nil || !json.Valid(out) {
			return nil, false
		}
		return out, true
	}
	inputRaw, ok := raw["input"]
	if !ok {
		return nil, false
	}
	var s string
	if json.Unmarshal(inputRaw, &s) != nil {
		return nil, false // array-shaped input — see doc comment
	}
	newS, ch := maskOne(s)
	if !ch {
		return nil, false
	}
	newInput, err := json.Marshal(newS)
	if err != nil {
		return nil, false
	}
	raw["input"] = newInput
	out, err := json.Marshal(raw)
	if err != nil || !json.Valid(out) {
		return nil, false
	}
	return out, true
}

// maskOpenAITextOnlyContent mirrors maskAnthropicTextOnlyContent for
// Chat Completions content-parts arrays ([{"type":"text","text":...}]):
// safe only when every part is type:"text" — an image_url part (or any
// other type) anywhere in the array makes the whole array unsafe (B1).
func maskOpenAITextOnlyContent(content json.RawMessage, maskOne func(string) (string, bool)) (out json.RawMessage, changed, safe bool) {
	var s string
	if json.Unmarshal(content, &s) == nil {
		newS, ch := maskOne(s)
		if !ch {
			return content, false, true
		}
		nb, err := json.Marshal(newS)
		if err != nil {
			return nil, false, false
		}
		return nb, true, true
	}
	var parts []map[string]json.RawMessage
	if json.Unmarshal(content, &parts) != nil {
		return nil, false, false
	}
	for i, p := range parts {
		var typ string
		if json.Unmarshal(p["type"], &typ) != nil || typ != "text" {
			return nil, false, false
		}
		var text string
		if json.Unmarshal(p["text"], &text) != nil {
			return nil, false, false
		}
		newText, ch := maskOne(text)
		if !ch {
			continue
		}
		nt, err := json.Marshal(newText)
		if err != nil {
			return nil, false, false
		}
		p["text"] = nt
		parts[i] = p
		changed = true
	}
	if !changed {
		return content, false, true
	}
	nb, err := json.Marshal(parts)
	if err != nil {
		return nil, false, false
	}
	return nb, true, true
}

// spliceGeminiLatestUser rewrites the last role:"user" (or role-less —
// F4/§3.2's own single-turn allowance) entry of a Gemini generateContent
// request's contents[] IN PLACE: safe only when every part in parts[]
// carries NOTHING but a "text" field (checked via len(m)==1 — Gemini
// parts have no "type" discriminator the way Anthropic/OpenAI blocks
// do, so a part map with any other key present — inlineData,
// functionCall, functionResponse, fileData, ... — makes the whole
// message unsafe, since this function has no way to preserve those
// binary/structured shapes it does not decode).
func spliceGeminiLatestUser(body []byte, maskOne func(string) (string, bool)) ([]byte, bool) {
	var raw map[string]json.RawMessage
	if json.Unmarshal(body, &raw) != nil {
		return nil, false
	}
	contentsRaw, ok := raw["contents"]
	if !ok {
		return nil, false
	}
	var contents []json.RawMessage
	if json.Unmarshal(contentsRaw, &contents) != nil {
		return nil, false
	}
	idx := lastUserMessageIndex(contents, func(c json.RawMessage) bool {
		var gc geminiRequestContent
		return json.Unmarshal(c, &gc) == nil && (gc.Role == "" || gc.Role == "user")
	})
	if idx < 0 {
		return nil, false
	}
	var gc struct {
		Role  string            `json:"role"`
		Parts []json.RawMessage `json:"parts"`
	}
	if json.Unmarshal(contents[idx], &gc) != nil {
		return nil, false
	}
	changed := false
	for i, p := range gc.Parts {
		var m map[string]json.RawMessage
		if json.Unmarshal(p, &m) != nil || len(m) != 1 {
			return nil, false
		}
		textRaw, ok := m["text"]
		if !ok {
			return nil, false
		}
		var text string
		if json.Unmarshal(textRaw, &text) != nil {
			return nil, false
		}
		newText, ch := maskOne(text)
		if !ch {
			continue
		}
		nt, err := json.Marshal(newText)
		if err != nil {
			return nil, false
		}
		m["text"] = nt
		np, err := json.Marshal(m)
		if err != nil {
			return nil, false
		}
		gc.Parts[i] = np
		changed = true
	}
	if !changed {
		return nil, false
	}
	role := gc.Role
	if role == "" {
		role = "user"
	}
	rewritten, err := json.Marshal(struct {
		Role  string            `json:"role"`
		Parts []json.RawMessage `json:"parts"`
	}{Role: role, Parts: gc.Parts})
	if err != nil {
		return nil, false
	}
	contents[idx] = rewritten
	newContents, err := json.Marshal(contents)
	if err != nil {
		return nil, false
	}
	raw["contents"] = newContents
	out, err := json.Marshal(raw)
	if err != nil || !json.Valid(out) {
		return nil, false
	}
	return out, true
}

// lastUserMessageIndex returns the index of the last item in items for
// which isUser reports true, or -1 — the shared search both the
// extraction functions (proxysegments.go, by value) and the splice
// functions above (by index, since they need to REPLACE the entry)
// use, kept as one implementation so "which message is the latest user
// turn" can never quietly diverge between extraction and splicing.
func lastUserMessageIndex(items []json.RawMessage, isUser func(json.RawMessage) bool) int {
	for i := len(items) - 1; i >= 0; i-- {
		if isUser(items[i]) {
			return i
		}
	}
	return -1
}

// scanInjection implements the §8.4 half: the R-180 heuristics over
// the request's NEW inbound content segments (the trailing
// tool-result / user-paste run — earlier turns were scanned when they
// were new). Hits mark session taint with Imperative=true and record
// flag verdicts; they never deny (F7) — R-180's table row is flag in
// both modes, and nothing here consults egress_action.
func (g *Guard) scanInjection(es *engineSet, res *ProxyRequestResult, parsed proxyParsedBody, sessionID string, now time.Time) {
	for i := range parsed.segments {
		seg := &parsed.segments[i]
		ev := policy.Event{
			Kind:      policy.KindAPIRequest,
			Target:    seg.origin,
			SessionID: sessionID,
			Caps:      proxyRequestCaps,
			Raw:       []byte(seg.text),
			Now:       now,
		}
		verdict, guardErr := g.evaluateWith(es, ev)
		if verdict.Decision < policy.DecisionFlag && guardErr == nil {
			continue
		}
		if verdict.RuleID == policy.InjectionRuleID() &&
			!(seg.taintSource == policy.TaintSourceMCPUnpinned && g.mcpApproved(seg.mcpServer)) {
			// The arming move: untrusted content carrying
			// instruction-shaped patterns taints the session with the
			// Imperative bit T-501 consumes. A pinned-and-approved MCP
			// server's results skip the mark (§9.2 — approval is an
			// explicit operator trust grant); the R-180 flag verdict
			// still records below, so the content concern stays
			// visible either way.
			g.taint.Mark(sessionID, policy.TaintMark{
				Source:     seg.taintSource,
				Origin:     boundOrigin(seg.origin),
				Imperative: true,
				At:         now,
			})
		}
		av := ActionVerdict{
			Input: ActionInput{
				SessionID: sessionID,
				Target:    seg.origin,
				Timestamp: now,
			},
			Kind:       policy.KindAPIRequest,
			Category:   g.categoryWith(es, verdict.RuleID),
			Verdict:    verdict,
			GuardError: guardErr != nil,
		}
		if g.proxyAlreadySeen(sessionID, injectionSignature(&av), now) {
			continue
		}
		res.Verdicts = append(res.Verdicts, av)
	}
}

// InspectProxyResponse evaluates the response's tool_use blocks — the
// model's intended next actions (§8.3) — through the same engine the
// hook path uses, with the session's LIVE taint snapshot stamped, so
// an R-101-class command or a T-501 sequence flags a full round-trip
// before the client's own hook would see it. Flag/alert only in v1:
// the channel cannot block (proxyResponseCaps), so blocking verdicts
// record with the §6.2 degradation marker and Enforced=false.
//
// Returns record-worthy verdicts for the adapter to persist + alert.
// ProjectRoot is unknown at the proxy (the hook-path precedent) —
// boundary/cross-project rules stay watcher-path; Dialect is posix
// (Claude Code's Bash tool runs POSIX shells on every platform;
// nested powershell/cmd payloads switch dialect mid-parse anyway).
func (g *Guard) InspectProxyResponse(sessionID string, tools []ProxyToolUse, now time.Time) []ActionVerdict {
	if !g.cfg.Proxy.ResponseScan || len(tools) == 0 {
		return nil
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	// One snapshot for every tool_use in this response (NIT contract).
	es := g.set.Load()
	var out []ActionVerdict
	for i := range tools {
		ev, ok := buildToolUseEvent(&tools[i])
		if !ok {
			continue
		}
		ev.SessionID = sessionID
		ev.Caps = proxyResponseCaps
		ev.Now = now
		ev.Taint = g.taint.Snapshot(sessionID, 0, now)
		verdict, guardErr := g.evaluateWith(es, ev)
		verdict, approved := g.applyApprovals(verdict, &ev)
		if verdict.Decision < policy.DecisionFlag && guardErr == nil {
			continue
		}
		av := ActionVerdict{
			Input: ActionInput{
				SessionID:  sessionID,
				ActionType: ev.ActionType,
				Target:     ev.Target,
				Timestamp:  now,
			},
			Kind:        ev.Kind,
			Category:    g.categoryWith(es, verdict.RuleID),
			Verdict:     verdict,
			TaintOrigin: taintOriginFor(verdict, ev.Taint),
			GuardError:  guardErr != nil,
		}
		if approved {
			av.DegradedFrom = "approved"
		}
		// §6.2: the channel can't block — record what the verdict
		// wanted via the degradation marker (emission seams only
		// overwrite DegradedFrom when non-empty, preserving the
		// "approved" marker).
		if em := ResolveEmission(verdict, proxyResponseCaps); em.DegradedFrom != "" {
			av.DegradedFrom = em.DegradedFrom
		}
		out = append(out, av)
	}
	return out
}

// responseToolShape maps a lowercased tool name onto the policy event
// vocabulary — the response-side sibling of the hook layer's
// claudeToolShape table, covering the common tool vocabularies of the
// proxy-routed clients (a wire-format mapping, not tool-identity
// branching: unknown names simply don't evaluate). Table-driven per
// Module rule 5; extend here.
var responseToolShape = map[string]struct {
	kind       policy.EventKind
	actionType string
	fields     []string // input fields tried in order for the target
}{
	"bash":             {policy.KindShellExec, models.ActionRunCommand, []string{"command"}},
	"shell":            {policy.KindShellExec, models.ActionRunCommand, []string{"command", "cmd"}},
	"run_command":      {policy.KindShellExec, models.ActionRunCommand, []string{"command", "cmd"}},
	"run_terminal_cmd": {policy.KindShellExec, models.ActionRunCommand, []string{"command"}},
	"execute_command":  {policy.KindShellExec, models.ActionRunCommand, []string{"command"}},
	"write":            {policy.KindFileAccess, models.ActionWriteFile, []string{"file_path", "path", "target_file"}},
	"write_file":       {policy.KindFileAccess, models.ActionWriteFile, []string{"file_path", "path", "target_file"}},
	"write_to_file":    {policy.KindFileAccess, models.ActionWriteFile, []string{"path", "file_path"}},
	"create_file":      {policy.KindFileAccess, models.ActionWriteFile, []string{"file_path", "path"}},
	"edit":             {policy.KindFileAccess, models.ActionEditFile, []string{"file_path", "path", "target_file"}},
	"multiedit":        {policy.KindFileAccess, models.ActionEditFile, []string{"file_path", "path"}},
	"edit_file":        {policy.KindFileAccess, models.ActionEditFile, []string{"file_path", "path", "target_file"}},
	"apply_diff":       {policy.KindFileAccess, models.ActionEditFile, []string{"path", "file_path"}},
	"notebookedit":     {policy.KindFileAccess, models.ActionEditFile, []string{"notebook_path", "file_path"}},
	"str_replace_based_edit_tool": {
		policy.KindFileAccess, models.ActionEditFile, []string{"path", "file_path"},
	},
	"read":       {policy.KindFileAccess, models.ActionReadFile, []string{"file_path", "path", "target_file"}},
	"read_file":  {policy.KindFileAccess, models.ActionReadFile, []string{"file_path", "path", "target_file"}},
	"webfetch":   {policy.KindToolCall, models.ActionWebFetch, []string{"url"}},
	"web_fetch":  {policy.KindToolCall, models.ActionWebFetch, []string{"url"}},
	"websearch":  {policy.KindToolCall, models.ActionWebSearch, []string{"query"}},
	"web_search": {policy.KindToolCall, models.ActionWebSearch, []string{"query"}},
}

// buildToolUseEvent classifies one tool_use into a policy.Event.
// ok=false means the tool isn't an evaluable shape (unknown name,
// missing operand) — unknown is never a violation.
func buildToolUseEvent(tu *ProxyToolUse) (policy.Event, bool) {
	if strings.HasPrefix(tu.Name, "mcp__") {
		return policy.Event{
			Kind:       policy.KindMCPCall,
			ActionType: models.ActionMCPCall,
			Target:     tu.Name,
		}, true
	}
	shape, ok := responseToolShape[strings.ToLower(tu.Name)]
	if !ok {
		return policy.Event{}, false
	}
	target := jsonStringField(tu.Input, shape.fields)
	if target == "" {
		return policy.Event{}, false
	}
	return policy.Event{
		Kind:       shape.kind,
		ActionType: shape.actionType,
		Target:     target,
	}, true
}

// proxyAlreadySeen consults + updates the per-session signature set.
// Empty session IDs never dedup (no stable key to dedup on).
func (g *Guard) proxyAlreadySeen(sessionID, sig string, now time.Time) bool {
	if sessionID == "" {
		return false
	}
	g.proxyMu.Lock()
	defer g.proxyMu.Unlock()
	if g.proxySeen == nil {
		g.proxySeen = make(map[string]*proxySeen)
	}
	st := g.proxySeen[sessionID]
	if st == nil {
		if len(g.proxySeen) >= maxProxySeenSessions {
			g.evictOldestProxySeenLocked()
		}
		st = &proxySeen{sigs: make(map[string]bool)}
		g.proxySeen[sessionID] = st
	}
	st.lastTouch = now
	if st.sigs[sig] {
		return true
	}
	if len(st.sigs) >= maxProxySeenSigs {
		// Bounded: drop the whole set rather than tracking insert
		// order — worst case a signature re-records once per reset,
		// which errs toward recording.
		st.sigs = make(map[string]bool)
	}
	st.sigs[sig] = true
	return false
}

// evictOldestProxySeenLocked removes the least-recently-touched
// session. Caller holds proxyMu.
func (g *Guard) evictOldestProxySeenLocked() {
	var oldestID string
	var oldest time.Time
	first := true
	for id, st := range g.proxySeen {
		if first || st.lastTouch.Before(oldest) {
			oldestID, oldest, first = id, st.lastTouch, false
		}
	}
	if oldestID != "" {
		delete(g.proxySeen, oldestID)
	}
}

// egressSignature / injectionSignature build the dedup keys. Reason
// carries the stable type×count summary (egress) / heuristic names
// (injection), so a CHANGED finding set records again.
func egressSignature(av *ActionVerdict) string {
	return av.Verdict.RuleID + "|" + av.Verdict.Reason + "|" + av.Verdict.Decision.String() + "|" + av.ProxyAction
}

func injectionSignature(av *ActionVerdict) string {
	return av.Verdict.RuleID + "|" + av.Input.Target + "|" + av.Verdict.Reason
}

// compileEgressAllow compiles [guard.proxy].egress_allow patterns,
// recording invalid ones as load issues (degrade-don't-fail — the
// pattern is skipped, scanning continues).
func compileEgressAllow(patterns []string) ([]*regexp.Regexp, []string) {
	var out []*regexp.Regexp
	var issues []string
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err != nil {
			issues = append(issues, "egress_allow pattern "+p+": "+err.Error())
			continue
		}
		out = append(out, re)
	}
	return out, issues
}
