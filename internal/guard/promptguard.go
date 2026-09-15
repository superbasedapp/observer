package guard

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

// Prompt-submit intervention — the reconsider-once evaluation seam
// (docs/plans/prompt-submit-intervention-exploration-2026-09-07.md,
// PHASE 1: this file, plus the R-172/R-190 policy rows and the
// guard_prompt_reconsider store seam. NO hook/proxy wiring lands here
// — cmd/observer/hook.go and internal/proxy are untouched; a later
// phase calls into EvaluatePrompt from those boundaries).
//
// Two entry points, used together by a future hook/proxy adapter:
//
//  1. BuildPromptFindings(text) runs the typed detectors
//     (internal/scrub) over the developer's own prompt text (or the
//     latest user turn extracted on the proxy lane) and returns the
//     Secrets/PIIFindings ready to stamp onto a policy.Event. This is
//     the ONE place a raw scrub.TypedFinding.Value is read outside
//     internal/scrub itself — only to apply [guard.prompt].allow and
//     to compute PIIFinding.Hash; the value never survives past this
//     function.
//  2. EvaluatePrompt(ev) is THE single seam both the hook lane
//     (phase 2) and the proxy lane (phase 3) call once the Event is
//     built (Kind: policy.KindUserPrompt, Secrets/PIIFindings from
//     step 1, SessionID/Tool/Cwd/ProjectRoot/Caps/Now from the
//     boundary's own payload). It runs the same policy engine every
//     other event kind uses (R-190/R-172 supply RuleID/Category/
//     Severity/Reason/Source), then layers the [guard.prompt] mode
//     vocabulary (off/warn/ask-once/block/redact) and the
//     reconsider-once state machine on top — exactly the way
//     applyApprovals already layers grant downgrades onto a
//     policy.Verdict in EvaluateHook, rather than duplicating rule
//     logic here (CLAUDE.md module-boundary rule 2).
//
// PromptVerdict.Verdict is ResolveEmission-compatible: for a Decision
// of Ask or Deny, the caller resolves the actual wire-level permission
// via guard.ResolveEmission(pv.Verdict, ev.Caps) exactly as the hook
// lane already does for EvaluateHook's ActionVerdict — this engine
// does NOT call ResolveEmission itself, so a channel with CanAsk:false
// degrades a fresh ask-once interrupt from Ask to Deny with
// DegradedFrom="ask" at the EXISTING, already-correct ResolveEmission
// call site (contract §10 item 12), never a bespoke second copy of
// that degradation logic here.
//
// FIXED (round-2 review B1): the original phase-1 shape had
// policy.SecretFinding carry no per-span hash ("gains nothing" per the
// contract's own §4.4), which forced a secret-shaped ask-once/redact
// finding to STRICTEN to block-every-time — breaking the operator's
// core requirement of ask-once for API tokens. SecretFinding now
// carries the same SpanLen/Hash shape PIIFinding always has (populated
// by BuildPromptFindings below, from the same normalized-span hash),
// so a secret finding participates in the identical-resend fingerprint
// exactly like a PII finding. Only a finding whose Hash the boundary
// left EMPTY still degrades to block (see the loop in EvaluatePrompt)
// — that is now the general "cannot fingerprint" case, not a
// secret-specific one.
//
// FIXED (round-2 review F7): [guard.prompt].suppress_in_code and
// max_findings now thread through to scrub.DetectPromptFindings via
// PromptDetectOptions — previously suppress_in_code was a dead knob
// (PII detection applied code-context suppression unconditionally) and
// max_findings was ignored in favor of a fixed internal constant.

// PromptMode is the [guard.prompt] mode vocabulary (contract §5.1).
type PromptMode string

// PromptMode values, in the vocabulary [guard.prompt] and
// [guard.prompt.detectors] both use.
const (
	// PromptModeOff runs the detector nowhere; no findings, no rows.
	PromptModeOff PromptMode = "off"
	// PromptModeWarn records the finding (verdict flag) and forwards
	// the prompt unchanged; never interrupts.
	PromptModeWarn PromptMode = "warn"
	// PromptModeRedact forwards with the span masked and tells the
	// developer, on channels that can modify the prompt. Phase 1 has
	// no modify-capability wiring yet (no channel is wired at all),
	// so EvaluatePrompt degrades this to the same handling as
	// PromptModeAskOnce and records RequestedMode so a later phase
	// can honor the real redact behavior on capable channels — never
	// silently to warn (contract §5.1).
	PromptModeRedact PromptMode = "redact"
	// PromptModeAskOnce blocks the first occurrence with a reason;
	// the identical resend within the TTL is allowed through.
	PromptModeAskOnce PromptMode = "ask-once"
	// PromptModeBlock blocks every occurrence until the prompt text
	// changes; no resend override.
	PromptModeBlock PromptMode = "block"
)

// promptModeRank orders the mode vocabulary by strictness — used both
// to clamp a per-detector override so it never escalates past the
// global [guard.prompt].mode (contract §5.1) and to reduce several
// findings (each with their own effective mode) down to one worst-case
// outcome for the whole prompt. Table-driven per CLAUDE.md rule 5;
// never branch on the mode string anywhere else in this file.
var promptModeRank = map[PromptMode]int{
	PromptModeOff:     0,
	PromptModeWarn:    1,
	PromptModeRedact:  2,
	PromptModeAskOnce: 3,
	PromptModeBlock:   4,
}

// parsePromptMode reports whether s is a known mode string.
func parsePromptMode(s string) (PromptMode, bool) {
	m := PromptMode(s)
	_, ok := promptModeRank[m]
	return m, ok
}

// effectivePromptMode resolves one detector's mode: the global
// [guard.prompt].mode is the FLOOR every detector sits on, and a
// per-detector override in [guard.prompt.detectors][detector] wins
// whenever it ranks STRICTER than that floor (F7, phase-3a review —
// stricter-wins semantics: max(global, detector) by
// promptModeRank). A LOOSER override still clamps UP to the global
// floor — the "never below the floor the operator set globally"
// protection is unchanged, only the "never above" direction was
// reversed. This supersedes the original "a per-detector mode never
// escalates past the global mode" invariant (contract §5.1's original
// text, superseded — see GuardPromptConfig's doc comment for the full
// rationale): that invariant silently downgraded a detector explicitly
// marked stricter than the global default, which is not what an
// operator setting a per-detector override would expect. e.g. this
// repo's own shipped default has [guard.prompt].mode="ask-once" with
// Detectors["github_pat"]="block" — under the old clamp, "block" was
// silently capped down to "ask-once"; under stricter-wins it is
// honored.
//
// FIXED (final-fix review B1): an explicit per-detector "off" is an
// EXEMPTION, not a rank the floor clamp applies to. The floor ("a
// looser override clamps UP to the global floor") only ever applies
// AMONG non-off overrides — it exists so an operator can't quietly
// weaken a detector's strictness below the global posture (e.g. warn
// under a block floor), not so an operator can never fully exempt one
// detector. Off is the one mode that means "never scanned, never
// findable, never counted" (see activePromptDetectors), and the
// shipped default config relies on exactly this: [guard.prompt].mode
// defaults to "ask-once" with email/phone_e164/phone_nanp explicitly
// "off" — under the old floor-applies-to-everything reading, those
// three detectors clamped back UP to "ask-once" and the shipped
// default silently interrupted on "email me at a@b.com" and a plain
// phone number, which is not what an explicit "off" override could
// ever mean. A per-detector "off" is therefore honored unconditionally
// whenever the global mode itself is not off (see the kill-switch
// exception below for that case).
//
// The ONE exception (F7's explicit carve-out, unchanged by the above):
// when the GLOBAL mode itself is "off", a per-detector override can
// NEVER turn that detector back on — off means off, full stop, with
// no per-detector escalation past it. This is the feature's own kill
// switch: a per-detector override cannot resurrect a detector the
// operator globally disabled. This is orthogonal to the per-detector
// exemption above (which only ever narrows scanning further, never
// escalates it).
//
// An unparseable global or override value falls back to off — the
// config loader already rejects unknown mode strings at construction
// (internal/config validateGuard), so this only matters for hand-built
// Options in tests; fail-closed-to-off is deliberately NOT fail-open
// here because an unparseable mode is a construction bug the config
// layer should have caught, not a live signal to trust.
//
// EffectivePromptMode is the exported counterpart (F4, phase-3a
// review): `observer guard prompt status` needs to show the ACTUAL
// resolved per-detector mode (after this file's stricter-wins-with-
// floor clamp, F7, and the off-is-an-exemption fix above) rather than
// the raw, potentially-misleading [guard.prompt.detectors] config
// value, without a second copy of the resolution rule.
func EffectivePromptMode(global string, overrides map[string]string, detector string) PromptMode {
	return effectivePromptMode(global, overrides, detector)
}

func effectivePromptMode(global string, overrides map[string]string, detector string) PromptMode {
	g, ok := parsePromptMode(global)
	if !ok {
		return PromptModeOff
	}
	if g == PromptModeOff {
		// The kill-switch exception: off stays off regardless of any
		// per-detector override.
		return PromptModeOff
	}
	ov, hasOv := overrides[detector]
	if !hasOv {
		return g
	}
	d, ok := parsePromptMode(ov)
	if !ok {
		return g
	}
	if d == PromptModeOff {
		// An explicit per-detector "off" is an exemption, not a rank
		// the floor clamp applies to — it is honored unconditionally
		// (the global mode is not off here; that case returned above).
		return PromptModeOff
	}
	if promptModeRank[d] < promptModeRank[g] {
		// Looser than the global floor (but not "off") — clamp UP to
		// the floor.
		return g
	}
	// Stricter than (or equal to) the global floor — honored.
	return d
}

// PromptOutcome classifies how the reconsider-once state machine
// resolved one EvaluatePrompt call (contract §5.3).
type PromptOutcome string

// PromptOutcome values.
const (
	// PromptOutcomeAllowed: no non-off finding, or every finding's
	// effective mode resolved to off.
	PromptOutcomeAllowed PromptOutcome = "allowed"
	// PromptOutcomeWarned: mode=warn, the global [guard].mode is not
	// "enforce" (which caps every outcome at warned — D2, guard never
	// blocks outside enforce mode), OR the reconsider-store returned a
	// genuine ERROR (not a miss) mid ask-once/redact evaluation
	// (round-2 review F3 — DegradedFrom="store_error" on that row
	// distinguishes it from the other two, ordinary causes).
	PromptOutcomeWarned PromptOutcome = "warned"
	// PromptOutcomeBlocked: a fresh ask-once interrupt, an expired-
	// and-re-interrupted ask-once grant, mode=block, an unhashable
	// finding (the boundary left Hash empty), an empty session_id, or
	// an unwired reconsider store.
	PromptOutcomeBlocked PromptOutcome = "blocked"
	// PromptOutcomeConfirmed: the identical resend arrived within the
	// TTL — forwarded, flagged, not blocked.
	PromptOutcomeConfirmed PromptOutcome = "confirmed"
	// PromptOutcomeApproved: an operator's dashboard grant
	// (guard_approvals, via applyApprovals) downgraded what would
	// otherwise have blocked or asked.
	PromptOutcomeApproved PromptOutcome = "approved"
)

// PromptVerdict is EvaluatePrompt's result — the prompt-submit
// intervention counterpart of ActionVerdict, deliberately a separate,
// smaller type (module-boundary discipline: this feature's shape does
// not spread into the general hook-path result type).
type PromptVerdict struct {
	// Verdict is the underlying policy evaluation (RuleID "R-190" or
	// "R-172", Category, Severity, Reason, Source already carry the
	// standard audit shape every other rule gets). Decision is
	// Allow/Flag/Ask/Deny. For Ask or Deny the caller MUST resolve the
	// actual wire-level permission via
	// guard.ResolveEmission(pv.Verdict, ev.Caps) — this engine does
	// not call it itself (see the package doc comment above).
	Verdict policy.Verdict
	// Outcome names which branch of the reconsider-once state machine
	// produced Verdict — the guard_events audit row and any future
	// dashboard card render off this, not off Decision alone (Decision
	// alone can't distinguish "warned" from "confirmed", both flag).
	Outcome PromptOutcome
	// RequestedMode is non-empty only when the effective mode was
	// "redact" but Phase 1 degraded it to ask-once/block handling for
	// want of a modify-capability channel (see the package doc
	// comment). A later phase's redact wiring reads this to know the
	// developer's config actually asked for masking, not blocking.
	RequestedMode PromptMode
	// Fingerprint is the reconsider-once fingerprint (contract §5.2)
	// when Outcome required one (Blocked/Confirmed via ask-once or
	// redact); empty otherwise. Never derived from a raw value — see
	// promptFingerprint.
	Fingerprint string
	// Detectors is the sorted, comma-joined detector type list driving
	// this fresh ask-once/redact interrupt (F6, phase-3a review) — the
	// same CSV shape promptDetectorsCSV computes for the
	// guard_prompt_reconsider.detectors column, populated ONLY on the
	// one fresh-interrupt branch (Outcome=Blocked, Verdict.Decision=Ask)
	// evaluatePromptAskOnce returns. hook.promptHouseMessage reads this
	// to interpolate the ACTUAL detector id into its in-band
	// remediation text ("run `observer guard prompt allow <detector>
	// --session <id>`") instead of a literal, useless "<detector>"
	// placeholder. Empty on every other branch — a block/deny/warn
	// outcome either has no resend story at all (mode=block, an
	// unhashable/no_session/store_unwired degrade) or isn't the
	// interrupt this remediation text is offered for.
	Detectors string
	// DegradedFrom is set DIRECTLY by this engine (independent of
	// whatever guard.ResolveEmission separately reports for the
	// channel-capability case) for downgrades already resolved here:
	// "ask" when Outcome is Confirmed (an ask-once grant that would
	// have asked again was downgraded to flag by the identical
	// resend), "store_error" when Outcome is Warned because the
	// reconsider store returned a genuine error mid-evaluation (round-2
	// review F3), "approved" when an operator's dashboard grant applied
	// (mirrors ActionVerdict's own "approved" marker). Empty otherwise.
	// The caller ORs this with ResolveEmission's own DegradedFrom
	// output for Ask/Deny decisions, exactly as EvaluateHook's
	// "approved" marker and ResolveEmission's channel-capability
	// marker already coexist today.
	//
	// NOTE (N4, not yet actionable — no guard_events writer exists
	// until phase 2/3 wires a hook/proxy caller): "ask" is overloaded
	// between two distinct shapes — "confirmed by an identical resend"
	// (this engine, above) and "the channel cannot express ask at all"
	// (ResolveEmission's own degrade of Ask→Deny for CanAsk:false,
	// contract §10 item 12). Both currently render as DegradedFrom
	// "ask" on a guard_events row. When the phase 2/3 writer lands,
	// disambiguate via PromptOutcome (Confirmed vs Blocked) rather than
	// adding a second DegradedFrom string — Outcome already carries the
	// distinction this engine needs; only a future cross-cutting
	// consumer that reads DegradedFrom without Outcome would need more.
	DegradedFrom string
	// GuardError mirrors ActionVerdict.GuardError: true when the Q2
	// failure wrapper produced Verdict instead of a real evaluation.
	// When true, no mode/reconsider-once resolution ran — Verdict is
	// whatever the failure-mode policy (Strict / fail-open) produced.
	GuardError bool
}

// RecordWorthy reports whether the verdict should persist as a
// guard_events row — decision >= flag, or a guard-error wrapper
// verdict. Mirrors the inline expression EvaluateHook returns
// alongside ActionVerdict (guard/hook.go) so callers do not have to
// re-derive it.
func (pv PromptVerdict) RecordWorthy() bool {
	return pv.GuardError || pv.Verdict.Decision >= policy.DecisionFlag
}

// PromptReconsiderLookup reports whether an ACTIVE (non-expired, per
// now) reconsider-once row exists for fingerprint — the first half of
// the injected store seam (guard never imports store; mirrors
// ApprovalLookup, internal/guard/approvals.go). A "no row" or a
// genuinely expired row is reported as ok=false, err=nil — a MISS, not
// an error; fail-closed toward a fresh interrupt, never toward
// treating a stale grant as still live. err is non-nil ONLY for an
// actual store failure (round-2 review F3: previously this returned a
// bare bool, silently discarding a store error at the EvaluatePrompt
// call site) — EvaluatePrompt treats that case differently from a miss
// (see the doc comment on its ask-once branch). Wired to
// store.LookupPromptReconsider by cmd composition.
// Since the 2026-09-07 live correction it also returns WHEN the row was
// recorded (warnedAt): EvaluatePrompt needs that to tell a developer's
// confirming resend from the client's own automatic retry
// ([guard.prompt].reconsider_min_delay).
type PromptReconsiderLookup func(fingerprint string, now time.Time) (warnedAt time.Time, ok bool, err error)

// PromptReconsiderRecord persists a fresh (or expired-and-renewed)
// reconsider-once warning. Wired to store.RecordPromptWarned.
type PromptReconsiderRecord func(fingerprint, sessionID, tool, detectors string, warnedAt, expiresAt time.Time) error

// PromptReconsiderConfirm marks a reconsider-once row confirmed by an
// identical resend. found=false, err=nil means there was no ACTIVE
// (non-expired) row to confirm — the caller must treat this as a FRESH
// interrupt (fail-closed), never as an implicit allow — the row may
// have expired in the (tiny) window between the paired Lookup and this
// call, and EvaluatePrompt already treats that race as "start over",
// not "let it through". err is non-nil ONLY for an actual store
// failure (round-2 review F3), distinct from found=false. Wired to
// store.ConfirmPromptReconsider.
type PromptReconsiderConfirm func(fingerprint string, now time.Time) (found bool, err error)

// PromptReconsiderFuncs bundles the reconsider-once persistence seam.
// The zero value (every func nil) fails CLOSED: EvaluatePrompt treats
// every ask-once/redact finding as block until this is wired — never a
// silent allow (contract §5.4/§10 item 5). A STORE ERROR from any of
// the three funcs once wired is a DIFFERENT case (round-2 review F3):
// it degrades the whole-prompt decision to warn (forward + flag,
// DegradedFrom="store_error") rather than blocking a developer's work
// on a transient DB hiccup, and the error is surfaced via
// Guard.LoadIssues.
type PromptReconsiderFuncs struct {
	Lookup  PromptReconsiderLookup
	Record  PromptReconsiderRecord
	Confirm PromptReconsiderConfirm
}

// SetPromptReconsiderStore wires the reconsider-once persistence seam.
// Zero value disables confirm-by-resend entirely (see
// PromptReconsiderFuncs). Set once at composition, mirroring
// SetApprovalLookup.
func (g *Guard) SetPromptReconsiderStore(f PromptReconsiderFuncs) {
	g.promptReconsider = f
}

func (g *Guard) promptReconsiderWired() bool {
	return g.promptReconsider.Lookup != nil && g.promptReconsider.Record != nil && g.promptReconsider.Confirm != nil
}

// compilePromptAllow compiles [guard.prompt].allow once. Invalid
// patterns degrade to LoadIssues, the same posture as
// compileEgressAllow (proxyguard.go) for the sibling
// [guard.proxy].egress_allow key — a distinct compiled list because
// the two allowlists are configured, and may legitimately differ, per
// channel.
func compilePromptAllow(patterns []string) ([]*regexp.Regexp, []string) {
	var out []*regexp.Regexp
	var issues []string
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err != nil {
			issues = append(issues, "guard.prompt.allow pattern "+p+": "+err.Error())
			continue
		}
		out = append(out, re)
	}
	return out, issues
}

// promptAllowed reports whether a matched value is covered by a
// [guard.prompt].allow pattern.
func (g *Guard) promptAllowed(value string) bool {
	for _, re := range g.promptAllow {
		if re.MatchString(value) {
			return true
		}
	}
	return false
}

// BuildPromptFindings runs the typed detectors (internal/scrub) over
// prompt text and returns the Secrets/PIIFindings ready to stamp onto
// a policy.Event's Secrets/PIIFindings fields.
//
// This calls scrub.DetectPromptFindings — the ONE class-aware entry
// point into internal/scrub's detection table (round-2 review B2) —
// not the secret-only DetectSecrets every other consumer uses;
// BuildPromptFindings is DetectPromptFindings' documented only caller.
// It also threads [guard.prompt].max_findings and .suppress_in_code
// through as scrub.PromptDetectOptions (round-2 review F7 — previously
// dead knobs).
//
// [guard.prompt].allow is applied here (the only place outside
// internal/scrub that reads a raw scrub.TypedFinding.Value) — a
// finding whose VALUE matches an allow pattern is dropped entirely,
// never reaching policy or the audit row. The value itself never
// survives past this function: every returned finding (secret or PII)
// carries only Type/Class/SpanLen and a one-way Hash of the NORMALIZED
// span (see normalizedSpanHash) — SecretFinding gained this same
// SpanLen/Hash shape in round-2 review B1, closing the gap that used
// to force every ask-once/redact secret finding to degrade to block.
func (g *Guard) BuildPromptFindings(text string) (secrets []policy.SecretFinding, pii []policy.PIIFinding, truncated bool) {
	opts := scrub.PromptDetectOptions{
		MaxFindings:     g.cfg.Prompt.MaxFindings,
		SuppressInCode:  g.cfg.Prompt.SuppressInCode,
		ActiveDetectors: g.activePromptDetectors(),
	}
	findings, wasTruncated := scrub.DetectPromptFindings(text, opts)
	for _, f := range findings {
		if g.promptAllowed(f.Value) {
			continue
		}
		hash := normalizedSpanHash(f.Class, f.Value)
		spanLen := f.End - f.Start
		if f.Class == scrub.ClassPII {
			pii = append(pii, policy.PIIFinding{
				Type:    f.Type,
				Class:   f.Class,
				SpanLen: spanLen,
				Hash:    hash,
			})
			continue
		}
		// "secret" and any unclassified legacy row (pre-Class typed
		// detectors, if ever hand-constructed in a test) default to
		// the secret half.
		secrets = append(secrets, policy.SecretFinding{
			Type:    f.Type,
			Certain: f.Certain,
			SpanLen: spanLen,
			Hash:    hash,
		})
	}
	return secrets, pii, wasTruncated
}

// activePromptDetectors computes the round-2 re-review BLOCK-2 active
// set: every known detector id (scrub.DetectorNames — the same list
// internal/config's validateGuard already validates
// [guard.prompt.detectors] keys against, F5) whose EFFECTIVE mode
// (global [guard.prompt].mode clamped by any per-detector override,
// exactly the same resolution EvaluatePrompt applies per-finding)
// is anything other than off. Passed to scrub.DetectPromptFindings so
// an off-mode detector is never scanned in the first place — the fix
// half that stops it from silently consuming ANY detector's
// per-detector cap, paired with detect.go's own per-detector cap
// change (the other half of BLOCK-2).
func (g *Guard) activePromptDetectors() map[string]bool {
	active := make(map[string]bool, len(scrub.DetectorNames()))
	for _, name := range scrub.DetectorNames() {
		if effectivePromptMode(g.cfg.Prompt.Mode, g.cfg.Prompt.Detectors, name) != PromptModeOff {
			active[name] = true
		}
	}
	return active
}

// normalizedSpanHash is sha256 hex of the matched value with
// separators removed (contract §5.2's "normalized_span") — so
// "4242 4242 4242 4242" and "4242-4242-4242-4242" fingerprint
// identically. The value is hashed immediately; it is never stored,
// logged, or returned by this function in any other form.
//
// FIX-4 (round-2 re-review): case-folding is now CLASS-AWARE, not
// universal. The original always lowercased before hashing — correct
// for PII (a credit card or SSN has no case at all, and a phone/IBAN's
// letters are not case-sensitive identity), but wrong for secrets: a
// GitHub PAT, API key, or JWT is a case-SENSITIVE credential string —
// two keys differing only in case are two DIFFERENT keys. Lowercasing
// them onto the same fingerprint meant a developer who resent a
// genuinely NEW (case-changed) key was treated as confirming the OLD
// one, silently granting a fresh secret a pass it never earned.
// Separators are still stripped for both classes (that part of the
// normalization was never class-specific — "4242-4242…" vs
// "4242 4242…" is genuinely the same value either way).
func normalizedSpanHash(class, value string) string {
	normalized := strings.NewReplacer("-", "", " ", "", ".", "").Replace(value)
	if class == scrub.ClassPII || class == "" {
		// Empty class defaults to the PII (case-insensitive) side —
		// the more conservative choice for any legacy/hand-built
		// finding that predates the Class field, since folding case
		// only ever WIDENS what an existing grant covers for a
		// value class where case doesn't carry identity anyway; it
		// never narrows a secret's fingerprint.
		normalized = strings.ToLower(normalized)
	}
	sum := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(sum[:])
}

// promptFindingHash pairs a stable detector Type with its
// normalized-span Hash — the common shape both policy.SecretFinding
// and policy.PIIFinding now carry (round-2 review B1 added Hash to
// SecretFinding precisely so the fingerprint below can cover the WHOLE
// finding set, secrets and PII alike, not just the PII half).
type promptFindingHash struct {
	Type, Hash string
}

// promptFingerprint implements contract §5.2 exactly:
//
//	fp = sha256("v1" 0x1e session_id 0x1e join(sorted(type:hash), 0x1f))
//
// over the SORTED SET of findings, not the whole prompt — this is
// deliberate: a developer who resends the identical secret/PII value
// with extra surrounding prose has not changed the finding set, so the
// resend confirms; a developer who edits or removes the value produces
// a different (or empty) finding set, so the interrupt does not refire
// (contract §5.2). findings must already be filtered to the ones
// actually driving the ask-once/redact decision (off-mode findings,
// and any finding with no Hash at all, excluded) — see the caller in
// EvaluatePrompt.
func promptFingerprint(sessionID string, findings []promptFindingHash) string {
	parts := make([]string, 0, len(findings))
	for _, f := range findings {
		parts = append(parts, f.Type+":"+f.Hash)
	}
	sort.Strings(parts)
	var b strings.Builder
	b.WriteString("v1")
	b.WriteByte(0x1e)
	b.WriteString(sessionID)
	b.WriteByte(0x1e)
	b.WriteString(strings.Join(parts, "\x1f"))
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

// promptDetectorsCSV renders the sorted, de-duplicated detector type
// list for the guard_prompt_reconsider.detectors column ("comma-joined
// detector ids, no values").
func promptDetectorsCSV(findings []promptFindingHash) string {
	seen := map[string]bool{}
	var types []string
	for _, f := range findings {
		if !seen[f.Type] {
			seen[f.Type] = true
			types = append(types, f.Type)
		}
	}
	sort.Strings(types)
	return strings.Join(types, ",")
}

// promptFindingRef is one finding's (secret or PII) contribution to
// the whole-prompt mode resolution: its effective mode (already
// clamped to the global ceiling) and the type/hash pair the
// fingerprint needs when hasHash is true. hasHash is false ONLY when
// the boundary left Hash empty (round-2 review B1: this is now the
// SOLE remaining "cannot fingerprint" case — it no longer matters
// whether the finding came from ev.Secrets or ev.PIIFindings).
type promptFindingRef struct {
	mode    PromptMode
	typ     string
	hash    string
	hasHash bool
	// unhashableDegrade (FIX-5, phase-2 review) is true when this
	// ref's mode was force-changed from ask-once/redact to block
	// SOLELY because the boundary could not compute a fingerprint
	// hash (promptFindingRefFor) — as opposed to the operator's own
	// [guard.prompt] mode genuinely being "block". The caller needs
	// this to render an honest message: "this finding type can't be
	// fingerprinted for a resend override" is a different, more
	// useful fact than "you configured mode=block".
	unhashableDegrade bool
}

// EvaluatePrompt is THE single seam both the hook lane (phase 2) and
// the proxy lane (phase 3) call once a policy.Event is built for a
// KindUserPrompt evaluation (see the package doc comment for the full
// contract). ev.Secrets/ev.PIIFindings should already be populated,
// typically via BuildPromptFindings.
//
// FIX-1 (round-2 re-review): every branch of the underlying decision
// that resolves to policy.DecisionDeny is raised to SeverityHigh here,
// in this one wrapper, rather than duplicated per branch inside
// evaluatePromptDecide — R-190's own table row stays SeverityWarn
// (rules_exfil.go explains why: a routine ask-once must not ALSO ring
// a desktop toast under the default [guard.alerts] threshold), but a
// verdict that actually BLOCKS — mode=block, an unhashable finding
// degrading to block, an empty session_id, an unwired reconsider
// store, or FIX-2's oversize-prompt-under-mode=block case — is
// qualitatively different and must not under-rank alongside a routine
// flag on any severity-ordered surface. Both the guard_events writer
// and the Part-B MaybeAlert bridge read pv.Verdict.Severity AFTER this
// runs, so neither needs its own copy of the rule.
func (g *Guard) EvaluatePrompt(ev policy.Event) PromptVerdict {
	return raisePromptSeverityOnDeny(g.evaluatePromptDecide(ev))
}

// raisePromptSeverityOnDeny implements the FIX-1 severity bump
// described on EvaluatePrompt's doc comment.
//
// BLOCK-2 (phase-2 review): this must be a FLOOR, not an assignment.
// R-172 (secret exfiltration) is already SeverityCritical on its own
// rule row; a plain unconditional assignment here would DOWNGRADE a
// critical secret denial to SeverityHigh — ranking a leaked API token
// below a mere destructive-command ask. Only raise severity when the
// underlying rule scored BELOW SeverityHigh (e.g. R-190's PII row,
// which starts at SeverityWarn); never lower an already-higher
// severity.
func raisePromptSeverityOnDeny(pv PromptVerdict) PromptVerdict {
	if pv.Verdict.Decision == policy.DecisionDeny && pv.Verdict.Severity < policy.SeverityHigh {
		pv.Verdict.Severity = policy.SeverityHigh
	}
	return pv
}

// promptEnforceActive implements FIX-8's decision (phase-2 review,
// GuardPromptConfig.EnforceIndependent's doc comment carries the full
// rationale): the prompt-submit lane's own enforce/observe question,
// decoupled from D2's global [guard].mode gate by default. The ONE
// call site every block-vs-warn branch in this file reads, so the two
// producers (evaluatePromptDecide's early exit, degradedScanVerdict's
// mode=block branch) can never disagree about which posture is active.
func (g *Guard) promptEnforceActive() bool {
	if g.cfg.Prompt.EnforceIndependent {
		return true
	}
	return g.cfg.Mode == "enforce"
}

// evaluatePromptDecide is EvaluatePrompt's actual decision logic,
// unwrapped so the FIX-1 severity bump above applies uniformly to
// every return path without being duplicated inside each one.
func (g *Guard) evaluatePromptDecide(ev policy.Event) PromptVerdict {
	if ev.Now.IsZero() {
		ev.Now = time.Now().UTC()
	}
	if !g.cfg.Enabled || !g.cfg.Prompt.Enabled || g.cfg.Mode == "off" {
		return PromptVerdict{Verdict: policy.Verdict{Decision: policy.DecisionAllow}, Outcome: PromptOutcomeAllowed}
	}

	es := g.set.Load()
	verdict, guardErr := g.evaluateWith(es, ev)
	if guardErr != nil {
		outcome := PromptOutcomeAllowed
		if verdict.Decision >= policy.DecisionAsk {
			outcome = PromptOutcomeBlocked
		} else if verdict.Decision == policy.DecisionFlag {
			outcome = PromptOutcomeWarned
		}
		return PromptVerdict{Verdict: verdict, Outcome: outcome, GuardError: true}
	}
	if verdict.RuleID == "" {
		// No R-190/R-172 hit — no findings, or every finding was
		// filtered by [guard.prompt].allow before the Event was built.
		//
		// FIX-2 (round-2 re-review): this is ALSO the shape an oversize
		// prompt produces when the unbounded secret scan found nothing
		// either — ev.PromptTruncated means PII detection was SKIPPED,
		// not that it ran clean, and treating the two identically was
		// the silent-degrade FIX-2 closes. A genuine secret finding
		// still reaches R-172 normally (that scan is never bounded) and
		// is never touched by this branch. FIX-2 (phase-2 review) widens
		// the same degrade to ev.PromptFieldMissing: a dialect extractor
		// that found NONE of its known prompt-field names in the raw
		// payload (schema drift) must not look identical to "scanned
		// clean" either.
		if pv, degraded := g.degradedScanVerdict(ev); degraded {
			return pv
		}
		return PromptVerdict{Verdict: policy.Verdict{Decision: policy.DecisionAllow}, Outcome: PromptOutcomeAllowed}
	}

	// Resolve one effective mode per finding, then reduce to the
	// worst (strictest) mode across the whole prompt (contract §5.1:
	// a per-detector mode never escalates past the global mode; this
	// function does the opposite reduction — several already-clamped
	// per-detector modes collapse to one whole-prompt decision, and
	// the strictest one wins, mirroring policy.StricterOf's spirit).
	//
	// Round-2 review B1: a secret finding is treated EXACTLY like a
	// PII finding now — both carry Type/Hash, both degrade to block
	// ONLY when Hash is empty (the boundary could not compute one).
	// There is no longer a secret-specific stricten branch.
	var refs []promptFindingRef
	for i := range ev.Secrets {
		s := &ev.Secrets[i]
		refs = append(refs, promptFindingRefFor(g, s.Type, s.Hash))
	}
	for i := range ev.PIIFindings {
		p := &ev.PIIFindings[i]
		refs = append(refs, promptFindingRefFor(g, p.Type, p.Hash))
	}

	worst := PromptModeOff
	for _, r := range refs {
		if promptModeRank[r.mode] > promptModeRank[worst] {
			worst = r.mode
		}
	}
	if worst == PromptModeOff {
		return PromptVerdict{Verdict: policy.Verdict{Decision: policy.DecisionAllow}, Outcome: PromptOutcomeAllowed}
	}

	// FIX-8 (phase-2 review): D2 ("the guard never blocks outside
	// enforce mode") is the default for every OTHER guard channel,
	// but [guard.prompt].enforce_independent (default true) makes the
	// prompt-submit lane a deliberate, documented exception — see
	// GuardPromptConfig.EnforceIndependent's doc comment for the full
	// rationale. promptEnforceActive() is the ONE place this decision
	// is made; both this early-exit and degradedScanVerdict's own
	// mode=block branch read it, so they can never disagree.
	if !g.promptEnforceActive() {
		verdict.Decision = policy.DecisionFlag
		return PromptVerdict{Verdict: verdict, Outcome: PromptOutcomeWarned}
	}

	switch worst {
	case PromptModeWarn:
		verdict.Decision = policy.DecisionFlag
		return PromptVerdict{Verdict: verdict, Outcome: PromptOutcomeWarned}

	case PromptModeBlock:
		verdict.Decision = policy.DecisionDeny
		pv := PromptVerdict{Verdict: verdict, Outcome: PromptOutcomeBlocked, DegradedFrom: promptBlockDegradedFrom(refs)}
		return g.applyPromptApproval(pv, &ev)

	case PromptModeAskOnce, PromptModeRedact:
		return g.evaluatePromptAskOnce(ev, verdict, worst, refs)

	default: // PromptModeOff cannot reach here (handled above)
		return PromptVerdict{Verdict: policy.Verdict{Decision: policy.DecisionAllow}, Outcome: PromptOutcomeAllowed}
	}
}

// degradedScanReason is the table-driven (CLAUDE.md rule 5) mapping
// from a "detection didn't actually run" signal on ev to its
// house-style reason text. Order matters: PromptFieldMissing (the
// extractor found nothing to scan at all) is checked first because a
// field-missing payload is very often ALSO oversize-looking (an empty
// string never truncates) — but the two causes are honestly distinct,
// so a payload that manages to be both reports the more fundamental
// one (there was no recognizable prompt field to begin with).
func degradedScanReason(ev policy.Event) (reason string, degraded bool) {
	switch {
	case ev.PromptFieldMissing:
		return "the hook payload did not contain any of the prompt field names this dialect expects (schema drift); PII/secret detection did not run", true
	case ev.PromptTruncated:
		return "prompt exceeds the guard scan size limit; PII detection did not run over the full body", true
	default:
		return "", false
	}
}

// degradedScanVerdict implements FIX-2 (round-2 re-review, widened by
// the phase-2 review to cover PromptFieldMissing alongside the
// original PromptTruncated case): when detection could not actually
// run over the real prompt text, the caller must not treat "no
// findings" as "scanned clean" — see degradedScanReason and the
// PromptFieldMissing/PromptTruncated field doc comments
// (internal/policy/event.go). degraded=false when [guard.prompt]'s
// global mode itself resolves to off (mirrors the ordinary
// worst==PromptModeOff early return — nothing to degrade when the
// feature is off) or when neither signal is set. The degrade is warn
// everywhere except mode=block under guard enforce, which blocks —
// contract "warn (or block under mode=block)": there is no
// ask-once/redact treatment here, deliberately — a stable
// reconsider-once fingerprint needs the ACTUAL finding set, which is
// exactly what an unscanned body doesn't have.
func (g *Guard) degradedScanVerdict(ev policy.Event) (PromptVerdict, bool) {
	reason, degraded := degradedScanReason(ev)
	if !degraded {
		return PromptVerdict{}, false
	}
	mode, ok := parsePromptMode(g.cfg.Prompt.Mode)
	if !ok || mode == PromptModeOff {
		return PromptVerdict{}, false
	}
	verdict := policy.Verdict{
		RuleID:   "R-190",
		Severity: policy.SeverityWarn,
		Reason:   reason,
		Source:   policy.SourceBuiltin,
	}
	if g.promptEnforceActive() && mode == PromptModeBlock {
		verdict.Decision = policy.DecisionDeny
		// FIX-5 (phase-2 review): "unscanned" distinguishes this from
		// the operator's plain mode=block choice — the reason text
		// already explains WHY (truncated/field-missing), but
		// hook.promptHouseMessage needs the marker to avoid appending
		// the generic "edit it out — mode=block has no resend
		// override" suffix on top of an already-complete reason.
		pv := PromptVerdict{Verdict: verdict, Outcome: PromptOutcomeBlocked, DegradedFrom: "unscanned"}
		return g.applyPromptApproval(pv, &ev), true
	}
	verdict.Decision = policy.DecisionFlag
	return PromptVerdict{Verdict: verdict, Outcome: PromptOutcomeWarned}, true
}

// evaluatePromptAskOnce implements the ask-once/redact branch of
// EvaluatePrompt's mode switch (extracted to keep EvaluatePrompt's own
// cyclomatic complexity down — this branch is the reconsider-once
// state machine in full, contract §5.3).
func (g *Guard) evaluatePromptAskOnce(ev policy.Event, verdict policy.Verdict, worst PromptMode, refs []promptFindingRef) PromptVerdict {
	var requested PromptMode
	if worst == PromptModeRedact {
		requested = PromptModeRedact
	}
	// Fingerprint over every non-off, hashable finding — secret or
	// PII alike (round-2 review B1) — "the finding set", not
	// filtered further by ask-once-vs-redact (contract §5.2); a
	// finding whose OWN effective mode is off never reaches this
	// slice.
	var forFP []promptFindingHash
	for _, r := range refs {
		if r.hasHash && r.mode != PromptModeOff {
			forFP = append(forFP, promptFindingHash{Type: r.typ, Hash: r.hash})
		}
	}
	if ev.SessionID == "" || !g.promptReconsiderWired() {
		// Fail-closed (contract §5.2: empty session_id degrades to
		// block, never allow; an unwired store degrades the same
		// way, contract §10 item 5). FIX-5 (phase-2 review): the two
		// causes get DISTINCT DegradedFrom markers so
		// hook.promptHouseMessage can render an honest reason instead
		// of the generic "you configured mode=block" text neither
		// cause actually is.
		degradedFrom := "no_session"
		if ev.SessionID != "" {
			degradedFrom = "store_unwired"
		}
		verdict.Decision = policy.DecisionDeny
		pv := PromptVerdict{Verdict: verdict, Outcome: PromptOutcomeBlocked, RequestedMode: requested, DegradedFrom: degradedFrom}
		return g.applyPromptApproval(pv, &ev)
	}

	fp := promptFingerprint(ev.SessionID, forFP)
	ttl := 30 * time.Minute
	if d, err := g.cfg.Prompt.ReconsiderTTLDuration(); err == nil && d > 0 {
		ttl = d
	}

	// Round-2 review F3: a STORE ERROR (not a miss) at any of the
	// three steps below degrades the WHOLE prompt decision to warn
	// (forward + flag, DegradedFrom="store_error") rather than
	// blocking a developer's work on a transient DB hiccup — a
	// deliberately different posture from the fail-closed-to-block
	// cases above (empty session / unwired store), which are
	// static misconfigurations, not live operational blips. The
	// error is surfaced via Guard.LoadIssues so an operator can
	// still see it.
	warnedAt, active, lookupErr := g.promptReconsider.Lookup(fp, ev.Now)
	if lookupErr != nil {
		g.recordIssues([]string{"guard.prompt: reconsider lookup failed: " + lookupErr.Error()})
		return g.applyPromptApproval(g.promptStoreErrorVerdict(verdict, requested, fp), &ev)
	}
	if active {
		// Automatic-retry floor (LIVE CORRECTION 2026-09-07): Copilot
		// CLI retried the ask-once 400 byte-for-byte 42 ms later and the
		// retry read as the developer's confirmation — any client with
		// automatic retry would defeat confirm-by-resend. An identical
		// resend inside [guard.prompt].reconsider_min_delay is the
		// client, not a human: stay blocked with the SAME interrupt and
		// leave the existing row untouched (no re-record — warned_at
		// must not slide, or a retry storm could postpone the window
		// forever). DegradedFrom marks the outcome for the audit row;
		// the house message is unchanged (the human still resends).
		minDelay := g.cfg.Prompt.ReconsiderMinDelayDuration()
		if minDelay >= ttl {
			// A floor at/over the reconsider window would block forever;
			// ignore it rather than refuse the config at load (F1).
			minDelay = 0
		}
		if minDelay > 0 && !warnedAt.IsZero() && ev.Now.Sub(warnedAt) < minDelay {
			verdict.Decision = policy.DecisionAsk
			pv := PromptVerdict{
				Verdict: verdict, Outcome: PromptOutcomeBlocked, RequestedMode: requested,
				Fingerprint: fp, Detectors: promptDetectorsCSV(forFP), DegradedFrom: "retry_too_fast",
			}
			return g.applyPromptApproval(pv, &ev)
		}
		confirmed, confirmErr := g.promptReconsider.Confirm(fp, ev.Now)
		if confirmErr != nil {
			g.recordIssues([]string{"guard.prompt: reconsider confirm failed: " + confirmErr.Error()})
			return g.applyPromptApproval(g.promptStoreErrorVerdict(verdict, requested, fp), &ev)
		}
		if confirmed {
			verdict.Decision = policy.DecisionFlag
			pv := PromptVerdict{
				Verdict: verdict, Outcome: PromptOutcomeConfirmed,
				RequestedMode: requested, Fingerprint: fp, DegradedFrom: "ask",
			}
			return g.applyPromptApproval(pv, &ev)
		}
		// Race: the row expired between Lookup and Confirm — fall
		// through and treat this exactly like a fresh miss.
	}

	detectorsCSV := promptDetectorsCSV(forFP)
	if recordErr := g.promptReconsider.Record(fp, ev.SessionID, ev.Tool, detectorsCSV, ev.Now, ev.Now.Add(ttl)); recordErr != nil {
		g.recordIssues([]string{"guard.prompt: reconsider record failed: " + recordErr.Error()})
		return g.applyPromptApproval(g.promptStoreErrorVerdict(verdict, requested, fp), &ev)
	}
	verdict.Decision = policy.DecisionAsk
	pv := PromptVerdict{Verdict: verdict, Outcome: PromptOutcomeBlocked, RequestedMode: requested, Fingerprint: fp, Detectors: detectorsCSV}
	return g.applyPromptApproval(pv, &ev)
}

// promptFindingRefFor resolves one finding's (secret or PII, they are
// treated identically post round-2 review B1) effective mode and
// fingerprint ingredient. A finding with an empty hash cannot
// participate in the identical-resend refinement — its ask-once/redact
// mode degrades to block, the sole remaining "cannot fingerprint" case
// (previously secret-specific; now just "this finding has no hash").
func promptFindingRefFor(g *Guard, detectorType, hash string) promptFindingRef {
	m := effectivePromptMode(g.cfg.Prompt.Mode, g.cfg.Prompt.Detectors, detectorType)
	hasHash := hash != ""
	degraded := false
	if (m == PromptModeAskOnce || m == PromptModeRedact) && !hasHash {
		m = PromptModeBlock
		degraded = true
	}
	return promptFindingRef{mode: m, typ: detectorType, hash: hash, hasHash: hasHash, unhashableDegrade: degraded}
}

// promptBlockDegradedFrom implements FIX-5 (phase-2 review): reports
// "unhashable" when the whole-prompt PromptModeBlock outcome was
// reached ONLY because at least one finding degraded from ask-once/
// redact for lacking a hash — never because the operator actually
// configured mode=block. Returns "" (the operator's own mode=block
// choice) whenever no ref degraded this way, even if OTHER refs are
// independently mode=block by configuration — an honest message about
// "this finding type can't be fingerprinted" only applies when that
// is the ACTUAL reason the whole prompt hit block.
func promptBlockDegradedFrom(refs []promptFindingRef) string {
	for _, r := range refs {
		if r.unhashableDegrade {
			return "unhashable"
		}
	}
	return ""
}

// promptStoreErrorVerdict builds the degrade-to-warn PromptVerdict for
// a genuine reconsider-store error (round-2 review F3) — forward the
// prompt, record a flag, and mark DegradedFrom="store_error" so the
// distinction from a normal "warn"-mode or observe-mode outcome is
// visible on the audit row.
func (g *Guard) promptStoreErrorVerdict(verdict policy.Verdict, requested PromptMode, fp string) PromptVerdict {
	verdict.Decision = policy.DecisionFlag
	return PromptVerdict{
		Verdict: verdict, Outcome: PromptOutcomeWarned,
		RequestedMode: requested, Fingerprint: fp, DegradedFrom: "store_error",
	}
}

// applyPromptApproval layers the §5.5 dashboard-approval override
// channel onto a resolved (Ask/Deny) PromptVerdict, reusing the
// EXISTING guard_approvals machinery (applyApprovals,
// internal/guard/approvals.go) rather than a parallel implementation —
// the same audited-exception semantics every other rule already gets.
// A no-op for Allow/Flag verdicts (applyApprovals itself guards on
// Decision >= DecisionAsk).
func (g *Guard) applyPromptApproval(pv PromptVerdict, ev *policy.Event) PromptVerdict {
	v, approved := g.applyApprovals(pv.Verdict, ev)
	pv.Verdict = v
	if approved {
		pv.Outcome = PromptOutcomeApproved
		pv.DegradedFrom = "approved"
	}
	return pv
}
