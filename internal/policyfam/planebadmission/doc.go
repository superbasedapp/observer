// Package planebadmission is the Plane-B judged-admission policy FAMILY body
// (Plane B dual-mode gateway design 2026-08-29 §4.6, operator-ruled IN; gap
// register 2026-09-02 G1-JUDGED-ADM). It is its OWN policy object — "Coding
// Agents · Policies · Admission" — that shares the admission engine as a
// library (internal/policyfam/admission compiles the inner spec; internal/obs/
// admission evaluates it) but never Plane A's policy objects, UI surface, or
// event stream.
//
// Two consumers read a compiled spec:
//
//   - the org AI Gateway runs it on Gateway-Mode requests as request-path
//     step "judged admission" (gwhttp.Handler.Admission), with the judge routed
//     ONLY through an org-configured gateway upstream (JudgeUpstreamID) — the
//     surviving lesson of the 2026-08-13 incident: never an unreviewed
//     third-party default and never the personal plane's route;
//   - the node proxy lane, ONLY when NodeLane is true AND the node is
//     managed and holds the enforce.admission authority (P-228). Default OFF
//     is byte-identical to the hardcoded exclusion (obsUpstreamLane); the flip
//     rides this signed body and nothing else, so it can never happen by
//     accident, and an individual node never runs it.
//
// Scope (P-228) says which requests the judge reads: user_prompts (the
// default, also for a body with no scope key) judges only a request whose
// newest turn is the developer's own prompt; all_calls judges every
// request's new trailing segment, tool results included. Both seams classify
// through internal/promptturn and decide through internal/promptadmit.
//
// Pure package: wire shape + compile/validate only; no SQL/HTTP/fsnotify.
package planebadmission
