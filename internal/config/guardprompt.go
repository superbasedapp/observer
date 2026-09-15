package config

import (
	"time"

	"github.com/marmutapp/superbased-observer/internal/scrub"
)

// GuardPromptConfig is [guard.prompt] (prompt-submit intervention build
// contract, docs/plans/prompt-submit-intervention-exploration-2026-09-07.md
// §8.1). It configures the "reconsider-once" guardrail over the
// DEVELOPER'S OWN prompt text on their coding-agent tool — warning, asking
// to reconsider once, blocking, or redacting a prompt that contains a
// deterministic secret or PII value — evaluated on the hook lane
// (prompt-submit hook channels, §6) and/or the proxy lane (the latest user
// turn on an outbound API request, §3.2).
//
// This is Plane B (the developer's own prompt), distinct from the Plane-A
// [observability.admission] end-user guardrail in internal/obs.
//
// Org posture: [guard.prompt] is NODE-LOCAL, the same invariant as
// [org_client.share].full_content and the routing enabled/mode keys. An
// org can only TIGHTEN posture via the existing signed policy bundle
// (internal/guard/bundle.go); there is no remote force-enforce toggle.
type GuardPromptConfig struct {
	// Enabled gates the whole prompt-submit intervention feature. When
	// false, no detectors run over prompt text on either lane. Default
	// true.
	Enabled bool `toml:"enabled"`
	// Mode is the GLOBAL default verdict for every detector that has no
	// entry in Detectors: "off" | "warn" | "ask-once" | "block" |
	// "redact" (§5.1). Default "ask-once".
	//
	// INVARIANT (enforced by the guard-engine workstream, NOT here;
	// stricter-wins semantics as of F7, phase-3a review — this
	// supersedes the original "never escalate past global" text): Mode
	// is a FLOOR, not a ceiling. A per-detector override in Detectors
	// WINS whenever it ranks stricter than this global mode (e.g. this
	// repo's own shipped default is Mode="ask-once" with
	// Detectors["github_pat"]="block" — github_pat is honored at
	// "block", not silently capped down to "ask-once"); an override
	// LOOSER than Mode still clamps UP to it (the floor still holds in
	// that direction). The ONE exception: when Mode itself is "off", no
	// per-detector override can turn that detector back on — off is the
	// feature's kill switch, not just another rank on the ladder. The
	// config layer only validates that Mode and every Detectors value
	// are individually well-formed (one of the five strings); it does
	// not compute or clamp the effective per-detector mode. Callers
	// resolving the effective mode for a detector must apply that
	// resolution themselves — see
	// internal/guard/promptguard.go::effectivePromptMode, the one
	// implementation of this rule.
	Mode string `toml:"mode"`
	// HookLane gates evaluation on prompt-submit hook channels (the
	// vendor-native "block before the model sees it" protocols
	// catalogued in §2/§6). Default true. WIRED: read by
	// cmd/observer/hook.go's promptGuardEnabled, which every
	// prompt-submit hook receiver (the Claude Code / Codex / Cursor /
	// long-tail-vendor branches in that file) checks before calling
	// EvaluatePrompt on that lane. Because each `observer hook <tool>
	// <event>` invocation is a fresh short-lived process that loads
	// config itself, a change here takes effect on the very next
	// hook-triggered prompt — no daemon restart needed.
	HookLane bool `toml:"hook_lane"`
	// ProxyLane gates evaluation of the latest user turn on outbound
	// proxy requests (§3.2), for clients that don't expose a hook lane
	// or as a second net on ones that do. Default true. WIRED: read by
	// internal/guard/proxyguard.go's scanPrompt, which is composed onto
	// the real proxy request path by cmd/observer/guardwire.go +
	// cmd/observer/proxy.go. Because the proxy lane runs inside the
	// long-lived daemon process (config loaded once at startup), a
	// change here only reaches it after a daemon restart — see
	// `PUT /api/config/section/guard`'s restart_required response.
	ProxyLane bool `toml:"proxy_lane"`
	// ReconsiderTTL is the lifetime of an "ask-once" grant: an
	// identical resend of the same finding set within this window is
	// allowed through and recorded as confirmed (§5.2, §5.4). Parsed
	// via time.ParseDuration; see ReconsiderTTLDuration. Default
	// "30m".
	ReconsiderTTL string `toml:"reconsider_ttl"`
	// ReconsiderMinDelay is the shortest gap after an ask-once interrupt
	// at which an identical resend counts as the developer's
	// CONFIRMATION. A resend inside it is treated as the client's own
	// automatic retry and stays blocked (LIVE CORRECTION 2026-09-07:
	// Copilot CLI retried a 400 byte-for-byte 42 ms later and the retry
	// read as a confirmation). Go duration; "0s" disables the floor.
	// Default "3s".
	ReconsiderMinDelay string `toml:"reconsider_min_delay"`
	// Allow is a list of RE2 patterns matched against a finding's
	// MATCHED VALUE (never against the whole prompt): a finding whose
	// value matches any pattern is dropped entirely (test fixtures,
	// known-fake keys — mirrors [guard.proxy].egress_allow). Compiled
	// once via scrub.ValidatePatterns at config-validation time.
	Allow []string `toml:"allow"`
	// SuppressInCode gates the §4.3 code-context suppression: a
	// candidate value that appears inside a fenced code block / string
	// literal shaped like a variable assignment to a placeholder is
	// not reported. Default true.
	SuppressInCode bool `toml:"suppress_in_code"`
	// MaxFindings caps the number of findings recorded per scan (§4.5
	// bound) — a defensive limit against pathological inputs (e.g. a
	// CSV paste with thousands of digit runs), not a normal-case
	// ceiling. Default 64.
	MaxFindings int `toml:"max_findings"`
	// EnforceIndependent (FIX-8, phase-2 review) decides whether the
	// prompt-submit lane obeys the D2 global-mode gate every OTHER
	// guard channel does ("the guard never blocks outside enforce
	// mode" — docs/guard.md, [guard].mode defaults to "observe") or
	// acts on its OWN [guard.prompt].mode regardless of [guard].mode.
	// Default TRUE — the operator-friendly answer, and a deliberate,
	// DOCUMENTED exception to D2 for this one feature specifically:
	//
	//   - [guard.prompt] ships pre-configured for ask-once out of the
	//     box (Enabled:true, Mode:"ask-once") specifically because the
	//     contract's whole premise is "warn/ask/block a secret typed
	//     into a prompt, with zero setup". Gating that on the SAME
	//     [guard].mode="enforce" opt-in every other (much riskier)
	//     guard channel requires would make the shipped defaults
	//     silently inert — an operator who installs observer and
	//     pastes a live API key into Claude Code gets no protection at
	//     all until they separately discover and set [guard].mode.
	//   - The risk/reward shape is different from shell/MCP blocking:
	//     ask-once's cost of a false positive is a single confirmed
	//     resend (a few seconds); shell/destructive-action blocking
	//     can halt real work outright, which is why THAT stays gated
	//     behind an explicit enforce opt-in.
	//   - This is D2-COMPLIANT in spirit for the CANONICAL empty
	//     Event/other channels (shell, MCP, file) — this switch only
	//     affects policy.KindUserPrompt evaluation
	//     (guard.EvaluatePrompt), never the general EvaluateHook path
	//     every other channel uses.
	//
	// Set false to make prompt-submit inherit the D2 gate like every
	// other channel (observe mode caps every outcome at warn,
	// regardless of [guard.prompt].mode). [guard].enabled=false or
	// [guard].mode="off" still fully disables the prompt lane either
	// way — this knob only controls the observe/enforce distinction,
	// never the on/off one.
	EnforceIndependent bool `toml:"enforce_independent"`
	// Detectors holds per-detector mode overrides, keyed by the stable
	// detector id (the PII ids defined by the scrub-detector
	// workstream, e.g. "credit_card", "us_ssn", plus any secret
	// detector id from internal/scrub/detect.go, e.g. "github_pat").
	// A key naming an unknown detector id is a validation error (the
	// one place in [guard.prompt] where an unrecognized key is
	// rejected outright, since a typo here would silently leave a
	// detector at the global Mode instead of the operator's intended
	// override). Values use the same five-mode vocabulary as Mode.
	// Absent keys default to Mode.
	Detectors map[string]string `toml:"detectors"`
}

// ReconsiderTTLDuration parses ReconsiderTTL as a time.Duration. Callers
// needing the parsed value at runtime should use this rather than
// re-parsing ReconsiderTTL themselves; validateGuard has already rejected
// a config where this would fail (reconsider_ttl must parse and be > 0).
func (c GuardPromptConfig) ReconsiderTTLDuration() (time.Duration, error) {
	return time.ParseDuration(c.ReconsiderTTL)
}

// ReconsiderMinDelayDuration parses ReconsiderMinDelay. An empty value
// (a hand-built config that never went through the loader's defaults)
// or an unparseable one — which validateGuard rejects at load — yields
// 0, i.e. no retry floor, so the field is purely additive.
func (c GuardPromptConfig) ReconsiderMinDelayDuration() time.Duration {
	if c.ReconsiderMinDelay == "" {
		return 0
	}
	d, err := time.ParseDuration(c.ReconsiderMinDelay)
	if err != nil || d < 0 {
		return 0
	}
	return d
}

// knownPromptDetectors is the full vocabulary of detector ids a
// [guard.prompt.detectors] key is allowed to name, DERIVED from
// scrub.DetectorNames() (F5, round-2 review — this used to be a
// hand-duplicated map kept in sync by hand with internal/scrub's
// typedDetectors table; internal/config already imports internal/scrub
// for scrub.ValidatePatterns, so there was never a real dependency
// reason for the duplication, only historical accident). A detector
// added to or removed from internal/scrub's table is reflected here
// automatically — no second edit, no drift.
var knownPromptDetectors = promptDetectorNameSet()

func promptDetectorNameSet() map[string]bool {
	names := scrub.DetectorNames()
	set := make(map[string]bool, len(names))
	for _, name := range names {
		set[name] = true
	}
	return set
}

// guardPromptModes is the five-value mode vocabulary shared by
// [guard.prompt].mode and every [guard.prompt.detectors] value (§5.1).
var guardPromptModes = map[string]bool{
	"off":      true,
	"warn":     true,
	"ask-once": true,
	"block":    true,
	"redact":   true,
}
