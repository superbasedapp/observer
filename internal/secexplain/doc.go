// Package secexplain builds the judge prompt that explains one security
// finding and labels the judge's answer (security pillar plan
// docs/plans/security-pillar-plan-2026-10-19.md sections 5.11 (b), 6.2 step
// 3 and 9 T7, T8; ledger SECP-15; lane sec-h).
//
// The prompt is built from rule data (the rule id, category, severity,
// confidence, status and the quoted location) plus the finding's already
// redacted evidence, capped at MaxEvidenceBytes and passed through the
// injected scrubber (scrub.ScrubForward at the wiring point) before it is
// fenced as untrusted repository text. The judge's answer is cut to
// MaxAnswerBytes, stripped of control characters and returned as an
// advisory Explanation: it carries no field that could set a verdict, a
// status or a posture, and the caller writes nothing from it (PR1, SECP-15).
//
// Pure: no SQL, HTTP, filesystem watcher or process execution
// (imports_test.go). The judge call itself is the caller's, through
// internal/judgeclient.
package secexplain
