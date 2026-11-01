// Package secdetect is the security pillar's native secret detection over
// proposed or written content (security pillar plan
// docs/plans/security-pillar-plan-2026-10-19.md sections 4.7 item 3.1,
// 5.3 and 6.1; security Phase C).
//
// It runs only the secret-class rows of internal/scrub (scrub.DetectSecrets)
// and never Scrubber.String, under fixed limits per caller:
//
//   - the hook (HookLimits): a fixed 16 KiB and a per-call deadline. A scan
//     that reaches its deadline, or content over the cap, ends
//     ScanIncomplete and is left to the post-write seam and the commit gate
//     [JSP-2]. The cap is not configurable in the hook.
//   - the post-write seam and the commit quick scan (PostWriteLimits): the
//     larger caps (64 or 256 KiB), never on the hook path.
//
// The entropy heuristic is reported at low confidence and never blocks.
// Hits carry the detector type, the line and the confidence; the matched
// value is used in memory only (the known-example list) and never leaves
// this package. DenyText renders the templated line an agent sees, quoting
// and capping every piece of repository-controlled text.
//
// The package is pure: no SQL, no HTTP, no filesystem watcher, no clock of
// its own (the caller injects one).
package secdetect
