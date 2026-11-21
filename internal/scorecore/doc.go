// Package scorecore is the one owner of what a valid score is (Plane A
// build-out W3-1, lane B7; contract
// docs/plans/plane-a-sdk-buildout/contracts/scores.md).
//
// A score is one judgement about one trace or span: a name, a value of one of
// three kinds, the source that produced it, and an optional comment. The
// machine (internal/obs/store, obs_eval_scores) and the org
// (internal/orgserver/annotation, org_trace_annotation) both store scores and
// both validate them here, so the two sides can never disagree on a value
// kind, a bound, the author key or the public score id.
//
// Everything is table-driven (CLAUDE.md rule 5): the value kinds, the source
// vocabulary (and which sources a client may set), and the author-key rule
// per source are each one ordered table with one test case per row.
//
// The package is pure (rule 1): no SQL, no HTTP, no fsnotify, never
// internal/obs. Its only in-repo import is internal/genaiattr, the attribute
// vocabulary that names the gen_ai.evaluation.result keys. Scrubbing the
// comment is the caller's job (scrub.ScrubForward), because the caller knows
// whether the comment will be stored at all.
package scorecore
