// Package sarifimport is the `security.scan.sarif-import` driver (security
// pillar plan docs/plans/security-pillar-plan-2026-10-19.md sections 4.4,
// 4.5.3 "In" and 5.11 (d), Phase G, lane SEC-G5): it reads ONE SARIF file
// the developer names, produced by a tool they run themselves (CodeQL,
// gosec, Bandit, Semgrep with their own subscription, the Claude Security
// or Codex Security plugins). Observer never runs that tool and never
// watches a folder for files.
//
// The file goes through the strictest adapter (the custom default of
// section 4.5.3): the strict decoder's size, depth and count caps; a
// location only project-relative or a file: URI under the project root; a
// foreign uriBaseId, a backslash, a query or fragment, a ".." segment, a
// remote scheme or a control character refuses the result; severities
// mapped never above medium; every finding low confidence with an unknown
// baseline, so none can block. The engine's message never reaches the
// finding. An import can never prove a project clean: an empty file is
// "unknown", and an import closes no finding.
//
// Lineage is attached as an inference, never claimed as authorship: the
// caller injects a lookup that matches a result's path to the latest AI
// edit of that path in the project's sessions.
//
// Pure: no SQL, HTTP, process or filesystem; the bytes and the lineage
// lookup are passed in.
package sarifimport
