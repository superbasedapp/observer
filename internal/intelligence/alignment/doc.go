// Package alignment builds and parses LLM-judge prompts that grade whether
// a git commit delivered what a developer asked an AI coding tool for
// (docs/plans/projects-page-roi-and-commit-alignment-plan-2026-09-21.md §2
// R6, §3.6 tier J — "the judge the operator already configured for
// [observability], which MAY be remote").
//
// It is a PURE package per CLAUDE.md module-boundary rule #1: no
// database/sql, no net/http, no fsnotify, no os/exec, and no import of
// internal/store. All I/O is injected — the actual model call goes through
// the caller-supplied Judge interface, and the host binds a concrete
// implementation (cmd/observer/alignment_wire.go, over the SAME
// chatCompletionsJudge the eval/admission judges already use). Purity is
// pinned by imports_test.go.
//
// Three entry points:
//
//   - BuildPrompt turns an Input (the developer's prompt text, the commit
//     it is being graded against, the file list, the AI-edited hunks that
//     make up the evidence, and the R4 link status) into ONE deterministic,
//     bounded prompt string. Determinism matters because the same Input
//     must always compile to the same prompt (a golden-string test pins
//     this), and boundedness matters because the hunks and file list come
//     from live commits that could otherwise blow past a judge's context
//     window or (for a remote judge) its payload cap.
//
//   - ParseResult tolerantly extracts the {"delivered","missed","extra",
//     "confidence","notes"} verdict JSON object from a model's raw reply,
//     which may be fenced in a ```json code block, bare, or followed by
//     trailing prose — models do not reliably return ONLY the JSON despite
//     being asked to. Confidence is clamped to [0,1] on the way out.
//
//   - Grade composes the two over a caller-supplied Judge: build the
//     prompt, call the judge, parse the reply.
//
// The three tiers described in the plan (L local heuristic, J this
// package's judge tier, C Cloud Intelligence) are not modeled here — L
// lives in internal/projectroi and C in internal/cloudevidence /
// internal/cloudcontract (W5b). This package is the J tier's pure core
// only; persistence (internal/store/promptgrades.go) and judge selection
// (cmd/observer/alignment_wire.go) live at the seams that surround it.
package alignment
