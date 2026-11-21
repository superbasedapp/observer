// Package promptadmit is the pure decision layer of the Plane-B coding-agent
// prompt admission judge (P-228, docs/plans/discovery-admission-2026-11-03.md,
// docs/guard.md "Org prompt admission judge"). Two seams consult it with the
// same answers: the org AI gateway's planeb.admission gate
// (internal/orgserver/planebadmit) and the node proxy's managed-node lane
// (cmd/observer).
//
// It owns three tables and one cache, each walked top-down:
//
//   - Plan: given the policy's scope (user_prompts, the default, or
//     all_calls) and a promptturn classification, what text is judged, or
//     why nothing is (a tool-loop continuation under user_prompts, no user
//     turn, empty text). Empty text never reaches the judge.
//   - Decide: given the policy's mode (enforce or observe), its strict flag
//     and the admission engine's verdict, whether the request is admitted,
//     admitted and flagged, or refused. An ask verdict is never silently
//     admitted: no prompt seam here can ask, so it is refused under enforce
//     and flagged under observe. A judge that could not answer follows the
//     strict flag (refused under enforce when strict, else admitted and
//     flagged).
//   - Cache: a bounded, TTL verdict cache keyed by the policy identity and
//     the judged text's digest, so the same prompt under the same policy is
//     judged once. A verdict built on an unavailable judge is never cached.
//
// Pure package: no database/sql, net/http or fsnotify (imports_test.go).
package promptadmit
