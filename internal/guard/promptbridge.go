package guard

import "github.com/marmutapp/superbased-observer/internal/policy"

// Part B (prompt-submit intervention hook lane,
// docs/plans/prompt-submit-intervention-exploration-2026-09-07.md): the
// ONE bridge from a PromptVerdict (guard/promptguard.go's evaluation
// result) onto the general-purpose ActionVerdict shape the SINGLE
// guard_events store seam (store.PersistGuardVerdicts,
// internal/store/guard.go) already knows how to persist. No new table,
// no new writer — item 4's "guard_events writer for prompt verdicts"
// is this function plus the existing seam, deliberately, per CLAUDE.md
// module-boundary rule 4 (one owner per table).
//
// The bridge is ALSO the single place item 5's MaybeAlert bridge reads
// from: a hook/proxy caller builds one ActionVerdict via
// ActionVerdictFromPrompt and passes it to BOTH the persist callback
// and g.MaybeAlert.
//
// FIX-3 (phase-2 review) corrects an earlier, wrong premise here: the
// original claim was "a routine ask-once never double-notifies
// because its Severity stays Warn, below the alert threshold" — true
// for R-190 (PII, base SeverityWarn), but FALSE for R-172 (secrets,
// SeverityCritical on the rule row itself, independent of the FIX-1
// deny-floor raise). A fresh ask-once interrupt over a leaked token
// carries Decision=Ask, never touches the FIX-1 deny-only raise, and
// was ALREADY at Critical — well above the default "high" alert
// threshold — so the desktop toast fired right alongside the in-band
// "resend to confirm" reply the developer was already reading. That
// is a real double-notification, not a hypothetical one.
//
// The correct signal is em.Permission (the RESOLVED wire-level
// permission, post channel-capability degrade), not Severity and not
// pv.Verdict.Decision alone: SuppressAlert is set whenever
// em.Permission != "deny" — routine ask ("ask") and every
// non-blocking outcome (warn/confirmed/approved, "allow") already
// show the developer an in-band message, so a toast on top is a
// duplicate. A genuine hard block/deny DOES still toast, INCLUDING
// the channel-capability-degraded case (e.g. Devin's CanAsk:false,
// where ask silently becomes a wire-level deny with no explained
// "just resend" story and, per that vendor's own docs, no user-
// visible message channel at all for this event — the toast is the
// ONLY way the developer learns anything happened).

// ActionVerdictFromPrompt converts pv into an ActionVerdict ready for
// store.PersistGuardVerdicts / Guard.MaybeAlert.
//
// input.Target is OVERWRITTEN with pv.Fingerprint — already a one-way
// sha256 hex digest of the normalized finding set (never the matched
// value, never a raw prompt span, see promptFingerprint) — so the two
// generic columns PersistGuardVerdicts derives from Target stay
// content-free: TargetExcerpt becomes the opaque fingerprint hex
// itself (safe to store — it IS the audit anchor a later
// `observer guard prompt clear <fingerprint>` looks up by) and
// TargetHash a hash of that hash. This is the CANARY the tests pin:
// the matched value, any prefix/suffix, the span text, or a per-span
// hash never reaches reason/target_excerpt/target_hash — only
// detector TYPE names + span LENGTHS (already baked into
// pv.Verdict.Reason by matchPromptFindings/matchSecretsOnAPIRequest,
// which render "detected credit_card×1 ... " never the value) and the
// whole-finding-set fingerprint ever do.
//
// Reason gets pv.Outcome appended as a stable "[outcome=...]" suffix
// (item 4's disambiguation requirement): DegradedFrom="ask" is
// documented as overloaded between "confirmed by an identical resend"
// (PromptOutcomeConfirmed) and "the channel can't express ask at all,
// degraded to a hard block" (PromptOutcomeBlocked via
// ResolveEmission's own capability degrade) — guard_events has no
// dedicated outcome column, so this is the disambiguation without a
// migration. em's own DegradedFrom (the channel-capability
// degradation ResolveEmission computed) is OR'd with pv.DegradedFrom
// (the reconsider-engine's own marker) exactly as promptguard.go's
// package doc comment specifies; a rare case where BOTH differ
// concatenates them with "+" rather than silently picking one.
func (g *Guard) ActionVerdictFromPrompt(pv PromptVerdict, em Emission, input ActionInput) ActionVerdict {
	input.Target = pv.Fingerprint
	verdict := pv.Verdict
	if pv.Outcome != "" {
		verdict.Reason = verdict.Reason + " [outcome=" + string(pv.Outcome) + "]"
	}
	es := g.set.Load()
	return ActionVerdict{
		Input:         input,
		Kind:          policy.KindUserPrompt,
		Category:      g.categoryWith(es, verdict.RuleID),
		Verdict:       verdict,
		Enforced:      em.Enforced,
		DegradedFrom:  combineDegradedFrom(pv.DegradedFrom, em.DegradedFrom),
		GuardError:    pv.GuardError,
		SuppressAlert: em.Permission != "deny",
	}
}

// ActionVerdictFromRedactedPrompt builds the ActionVerdict for a
// SUCCESSFUL proxy-lane redact-and-forward (contract §3.4/item 3,
// internal/guard/proxyguard.go's scanPrompt redact branch). A genuine
// redact is a channel-capability action ResolveEmission's generic
// ask/deny algebra does not model: the request is ALWAYS forwarded —
// never blocked — regardless of whether pv.Verdict.Decision came back
// Ask (a fresh occurrence, reusing the ask-once state machine's own
// bookkeeping) or Flag (an already-confirmed one), because the proxy's
// modify capability means it never needs to ask in the first place. So
// this function fixes the persisted Decision at DecisionFlag
// (non-blocking) and Enforced=true (the body WAS rewritten) via a
// synthetic Emission{Permission:"allow", Enforced:true} rather than
// resolving pv.Verdict's real (possibly Ask) decision through the
// caller's actual channel capabilities, which would be the wrong
// question for an action that already succeeded.
//
// F7 (phase-3b review): the original call site hand-built this
// ActionVerdict inline (bypassing this bridge entirely, with its own
// separate g.set.Load() snapshot — see ScanProxyRequest's own es
// threading) and left SuppressAlert at its Go zero value (false) — so
// EVERY successful redact-and-forward toasted a desktop alert, even
// though nothing was blocked and the developer's request went through
// unmodified in shape. SuppressAlert is unconditionally true here: a
// redact already shows the developer their work wasn't interrupted (in
// contrast to ActionVerdictFromPrompt's own SuppressAlert rule, which
// still toasts on a genuine block/deny — there is no in-band signal to
// suppress there).
//
// Reuses ActionVerdictFromPrompt for the Fingerprint/Reason-suffix/
// Category/DegradedFrom handling rather than duplicating it, so this
// file stays the ONE place a PromptVerdict becomes an ActionVerdict
// (CLAUDE.md module-boundary rule 4).
func (g *Guard) ActionVerdictFromRedactedPrompt(pv PromptVerdict, input ActionInput) ActionVerdict {
	av := g.ActionVerdictFromPrompt(pv, Emission{Permission: "allow", Enforced: true}, input)
	av.Verdict.Decision = policy.DecisionFlag
	av.ProxyAction = proxyActionRedact
	av.SuppressAlert = true
	return av
}

// combineDegradedFrom ORs two DegradedFrom markers from independent
// sources (the reconsider-once engine's own marker, and
// ResolveEmission's channel-capability degrade) — see
// ActionVerdictFromPrompt's doc comment.
func combineDegradedFrom(pvFrom, emFrom string) string {
	switch {
	case pvFrom == "":
		return emFrom
	case emFrom == "" || emFrom == pvFrom:
		return pvFrom
	default:
		return pvFrom + "+" + emFrom
	}
}
