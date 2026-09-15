// Package scrub redacts secrets (Bearer tokens, API keys, AWS keys,
// connection-string passwords, env-var assignments) from tool inputs before
// they reach storage. See spec §8.
//
// Scrubbing runs at the adapter boundary — original unscrubbed data is never
// written to disk.
//
// # Typed detection and the two finding classes
//
// Beside the destructive Scrubber (String/ScrubForward, which redact
// into "[REDACTED]" for storage), this package also exposes a typed
// detection surface (detect.go) that names WHAT kind of sensitive
// content appears WHERE, without destroying it: TypedFinding.Class is
// either ClassSecret (a credential — API keys, tokens, PEM blocks;
// case-sensitive identity) or ClassPII (a personally-identifiable
// value — credit cards, SSNs, email addresses; no case identity, only
// separator normalization). Every EXISTING consumer of this surface
// (DetectSecrets, CertainSecretTypes, MaskSecrets — the proxy egress
// scanner, the R-172 shell-arg rule, the Plane-A admission gate, the
// process-argv masker) is secret-only by design: none of them should
// ever treat a developer's own email or phone number as a leaked
// credential.
//
// DetectPromptFindings is the ONE class-aware entry point, added for
// the prompt-submit intervention feature
// (docs/plans/prompt-submit-intervention-exploration-2026-09-07.md):
// its only caller is internal/guard's BuildPromptFindings, which reads
// BOTH classes off the developer's own typed prompt text. Its
// PromptDetectOptions.ActiveDetectors restricts scanning to detectors
// whose [guard.prompt] effective mode isn't "off" (so an off-mode
// detector's volume can never exhaust another's finding budget —
// contract round-2 re-review BLOCK-2), and its MaxFindings caps each
// detector's OWN budget independently, not one budget shared across
// every detector in table order.
//
// # Span privacy contract
//
// TypedFinding.Value (and the Start/End byte offsets that bound it)
// are IN-MEMORY ONLY: they exist so a caller can apply an allowlist
// ([guard.proxy].egress_allow / [guard.prompt].allow) and compute a
// one-way hash of the matched span. Neither the value nor the offsets
// are ever persisted, logged, or placed on a policy.Verdict.Reason —
// downstream callers keep only Type/Class/SpanLen and a sha256 hash of
// the NORMALIZED span (separators stripped; case folded for PII only,
// preserved for secrets — a case change is a DIFFERENT credential).
// See internal/guard/promptguard.go's normalizedSpanHash for the exact
// normalization rule and internal/policy's SecretFinding/PIIFinding
// for the shape that crosses the package boundary.
package scrub
