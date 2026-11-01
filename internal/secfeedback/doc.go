// Package secfeedback is the security pillar's feedback to the agent after
// a write (security pillar plan docs/plans/security-pillar-plan-2026-10-19.md
// sections 4.7 (the context_inject post row), 5.11 (c), 6.1 and 6.2 step 2,
// and section 9 T8; spike JSP-6; lane SEC-H).
//
// Two pure halves:
//
//   - Line and Lines build the templated feedback line from rule data only:
//     the finding's rule id, a fixed phrase for what was found (the detector
//     type's words, or the category's), the location quoted, cut to 80
//     characters and filtered to a safe character set, the confidence, a fix
//     hint from this package's own table and one sentence addressed to the
//     HUMAN about exceptions. A line is at most MaxLineBytes; Lines keeps at
//     most MaxLines, the most severe first. No engine message, rule
//     description, evidence or snippet ever reaches a line (T8): the input
//     type has no field that could carry one.
//   - Write merges the lines into a host's own post-tool reply. The reply
//     writers are a data table keyed on the hook binding's dialect id
//     (internal/integration's feedback-* dialects), never on a tool name;
//     each row carries the host's reply shape and its size cap. An unknown
//     dialect, no lines, or a reply that is not a JSON object leaves the
//     reply byte-identical.
//
// The package imports no database, network, process or watcher package
// (imports_test.go pins it): the caller (cmd/observer's post-tool seam)
// asks the daemon for the findings and writes the result.
package secfeedback
