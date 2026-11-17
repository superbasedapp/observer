package guard

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

// Post-hoc prompt lane (prompt-guard coverage audit 2026-10-02,
// docs/audits/prompt-guard-coverage-audit-2026-10-02.md).
//
// The prompt rules (R-172 secrets, R-190 PII) act BEFORE a prompt reaches
// the model only where a pre-send seam exists: a verified prompt-submit
// hook (internal/hook/promptsubmit.go) or the proxy request path
// (proxyguard.go scanPrompt). Most of the fleet has neither — Antigravity
// CLI's hooks cannot see or block the user's prompt and its OAuth traffic
// is not proxy-routable — and until this lane existed the watcher path
// skipped user_prompt actions entirely (classifyKind), so a secret typed
// into such a tool produced no guard event, no node warning and nothing
// at the org. Silence is the one outcome the guard must never produce for
// a rule the operator turned on.
//
// This lane evaluates the captured prompt AFTER the fact, through the
// same detectors and the same R-172/R-190 rows as the pre-send lanes, and
// records a FLAG (the watcher can never block or ask). It deliberately
// does not run the reconsider-once state machine: there is nothing left
// to reconsider.
//
// Two inputs make it honest rather than noisy:
//
//   - Storage scrubbing ran first. Every adapter scrubs prompt text before
//     the store sees it, so the typed detectors run over SCRUBBED text: a
//     value the storage scrubber missed is still found, a typed marker
//     "[REDACTED:<detector>]" (scrub.TypedRedactedMarkers) counts as a
//     certain finding of that detector, and a "match" whose value is the
//     bare "[REDACTED]" marker is dropped — the generic storage rows also
//     redact prose ("Bearer token auth", "max token: 4096"), so a bare
//     marker is not evidence of a secret.
//   - A pre-send lane may already have judged THIS prompt. The hook and
//     proxy lanes leave a mark (session id + PromptCaptureDigest of the
//     prompt) when they judge one; when the capture lane finds a mark for
//     the same session AND the same digest near the capture time, it stays
//     silent, so the audit log carries one row per prompt, not two. A
//     DIFFERENT prompt in the same session (a second secret) has a
//     different digest and is still judged.

// PromptPreSendLookup reports whether a PRE-SEND prompt lane (the hook
// lane or the proxy lane) already judged the prompt whose
// PromptAlreadyJudged reports whether a pre-send lane already left a mark
// for this prompt in this session (the same per-prompt digest and window
// the capture lane dedupes on). A seam that fires many times per turn,
// such as Antigravity CLI's PreInvocation (before every model call),
// uses it to judge each prompt once. False when no lookup is wired.
func (g *Guard) PromptAlreadyJudged(sessionID, text string, at time.Time) bool {
	if g.promptPreSend == nil || sessionID == "" {
		return false
	}
	d := PromptCaptureDigest(text)
	return d != "" && g.promptPreSend(sessionID, d, at)
}

// PromptCaptureDigest is digest, in sessionID, close to at. Wired at
// composition to store.PreSendPromptJudged; guard never imports store (the
// ApprovalLookup precedent). A lookup failure must report false: a
// duplicate flag is recoverable noise, a missed one is the silent gap this
// lane exists to close.
type PromptPreSendLookup func(sessionID, digest string, at time.Time) bool

// PromptCaptureDigest is the per-prompt dedupe key shared by the pre-send
// lanes and the capture lane: sha256 hex of the prompt after the DEFAULT
// storage scrub (scrub.New) and whitespace normalisation. The pre-send side
// hashes the raw prompt, the capture side the already-scrubbed stored text;
// scrubbing is idempotent on its own output, so the same prompt yields the
// same digest on both sides. Best effort by construction: an adapter that
// stores the prompt in a different shape than the hook payload carries
// (wrapped, truncated, extra scrub patterns) yields a different digest, and
// the capture lane then records a duplicate flag - noise, never a miss. The
// digest is node-local (migration 150); it never leaves the node.
func PromptCaptureDigest(text string) string {
	normalized := strings.Join(strings.Fields(scrub.New().String(text)), " ")
	if normalized == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(sum[:])
}

// PromptPreSendDigest is what a pre-send lane records after judging prompt
// text: its PromptCaptureDigest when the capture lane would otherwise judge
// the same prompt again - the pre-send verdict was record-worthy, or the
// stored (scrubbed) form will carry a typed redaction marker the capture
// lane counts as a finding (the [guard.prompt].allow case: an allow-listed
// fixture the pre-send lane let through must not be flagged afterwards
// from its marker). "" means no mark is needed.
func PromptPreSendDigest(text string, recordWorthy bool) string {
	if !recordWorthy && len(scrub.TypedRedactedMarkers(scrub.New().String(text))) == 0 {
		return ""
	}
	return PromptCaptureDigest(text)
}

// SetPromptPreSendLookup wires the pre-send dedupe lookup. Nil (the
// default) records every post-hoc finding. Set once at composition.
func (g *Guard) SetPromptPreSendLookup(fn PromptPreSendLookup) {
	g.promptPreSend = fn
}

// postHocPromptNote is appended to a post-hoc row's reason so an admin
// reading the audit log (node or org) knows the prompt was NOT stopped and
// why — the honest counterpart of the pre-send lanes' "[outcome=asked]".
const postHocPromptNote = " (found in the captured transcript after the prompt was already sent; no pre-send guard lane judged it, so it could not be blocked or warned in time)"

// postHocMarkerCap bounds the typed-marker findings one prompt can add
// (a pathological paste of many redacted tokens still yields one row).
const postHocMarkerCap = 16

// evaluateCapturedPrompt is the post-hoc lane for one inserted
// user_prompt action. ok=false when there is nothing to record: the
// prompt lane is off, no finding, or a pre-send lane already judged it.
func (g *Guard) evaluateCapturedPrompt(es *engineSet, in *ActionInput) (ActionVerdict, bool) {
	if !g.postHocPromptEnabled() {
		return ActionVerdict{}, false
	}
	text := in.PromptText
	if text == "" {
		text = in.Target
	}
	if strings.TrimSpace(text) == "" {
		return ActionVerdict{}, false
	}
	secrets, pii, _ := g.buildPromptFindings(text, func(_, value string) bool { return isScrubMarkerValue(value) })
	secrets = append(secrets, g.typedMarkerFindings(text)...)
	if len(secrets) == 0 && len(pii) == 0 {
		return ActionVerdict{}, false
	}
	if g.promptPreSend != nil && g.promptPreSend(in.SessionID, PromptCaptureDigest(text), in.Timestamp) {
		return ActionVerdict{}, false
	}

	ev := policy.Event{
		Kind:        policy.KindUserPrompt,
		ActionType:  in.ActionType,
		Tool:        in.Tool,
		ProjectRoot: in.ProjectRoot,
		SessionID:   in.SessionID,
		Caps:        watcherCaps,
		Secrets:     secrets,
		PIIFindings: pii,
		Now:         in.Timestamp,
	}
	verdict, guardErr := g.evaluateWith(es, ev)
	if guardErr == nil && verdict.RuleID == "" {
		return ActionVerdict{}, false
	}
	// Captured after send: org grants never apply on this lane (lane "").
	verdict, appr := g.applyApprovals(verdict, &ev, "")
	// The decision a pre-send seam would have acted on (the org's
	// explicit enforce=false caps it at flag, exactly as on the pre-send
	// lanes), kept so the record says what the capture lane could not do.
	wanted := promptDecision(verdict)
	if verdict.EnforceCappedBy != "" && wanted > policy.DecisionFlag {
		wanted = policy.DecisionFlag
	}
	if guardErr == nil {
		// Post-hoc by definition: whatever the rule would have wanted
		// before send (ask/deny), the watcher can only record it.
		if verdict.Decision == policy.DecisionAllow {
			return ActionVerdict{}, false
		}
		verdict.Decision = policy.DecisionFlag
		verdict.Reason += postHocPromptNote
	}

	var forFP []promptFindingHash
	for _, s := range secrets {
		forFP = append(forFP, promptFindingHash{Type: s.Type, Hash: s.Hash})
	}
	for _, p := range pii {
		forFP = append(forFP, promptFindingHash{Type: p.Type, Hash: p.Hash})
	}
	pv := PromptVerdict{
		Verdict:     verdict,
		Outcome:     PromptOutcomeDetected,
		Fingerprint: promptFingerprint(in.SessionID, forFP),
		GuardError:  guardErr != nil,
	}
	if appr.approved() {
		pv.DegradedFrom = "approved"
	}
	pv.GrantProject = g.grantProject(&ev)
	pv.Lane = "capture"
	if wanted >= policy.DecisionFlag {
		pv.Action, pv.ActionDegradedFrom = ResolvePromptAction(wanted, PromptSeamCapture)
	}
	input := *in
	input.PromptText = "" // never carried past this lane
	// ONE PromptVerdict → ActionVerdict bridge (promptbridge.go): Target
	// becomes the content-free fingerprint there.
	// The action is flag-after, so the bridge leaves the desktop toast on:
	// nothing was shown before send, and the toast is the only signal the
	// developer gets (it follows the ordinary severity threshold).
	av := g.ActionVerdictFromPrompt(pv, Emission{Permission: "allow"}, input)
	av.SuppressAlert = false
	g.stampOrgOverride(es, &av)
	return av, true
}

// postHocPromptEnabled mirrors the gate the pre-send lanes apply
// (evaluatePromptDecide): guard on, [guard.prompt] on, and a global
// prompt mode other than off. The per-detector modes are applied by the
// active-detector set inside buildPromptFindings / typedMarkerFindings.
func (g *Guard) postHocPromptEnabled() bool {
	if !g.cfg.Enabled || !g.cfg.Prompt.Enabled || g.cfg.Mode == "off" {
		return false
	}
	mode, ok := parsePromptMode(g.cfg.Prompt.Mode)
	return ok && mode != PromptModeOff
}

// isScrubMarkerValue reports whether a detector's matched value is (or
// contains) a storage redaction marker — i.e. the detector matched the
// key context around a value the scrubber already removed, not a value.
func isScrubMarkerValue(value string) bool {
	return strings.Contains(value, "[REDACTED")
}

// typedMarkerFindings turns every "[REDACTED:<secret detector>]" marker in
// a stored prompt into a certain finding of that detector, honoring the
// operator's per-detector prompt modes (an off detector stays off) and the
// postHocMarkerCap bound. The hash is over the marker itself: the value is
// gone, so the fingerprint can only say "this detector, this many times".
func (g *Guard) typedMarkerFindings(text string) []policy.SecretFinding {
	markers := scrub.TypedRedactedMarkers(text)
	if len(markers) == 0 {
		return nil
	}
	active := g.activePromptDetectors()
	var out []policy.SecretFinding
	for _, typ := range markers {
		if !active[typ] {
			continue
		}
		marker := scrub.TypedRedactedMarker(typ)
		out = append(out, policy.SecretFinding{
			Type:    typ,
			Certain: true,
			SpanLen: len(marker),
			Hash:    normalizedSpanHash(scrub.ClassSecret, marker),
		})
		if len(out) >= postHocMarkerCap {
			break
		}
	}
	return out
}
