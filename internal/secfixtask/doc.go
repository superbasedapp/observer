// Package secfixtask builds the task an agent is handed when a developer
// clicks "Fix with an agent" on the Code security page
// (docs/plans/fix-findings-with-agent-plan-2026-11-13.md section 3): the open
// findings of a selection, split by project (Group), and one project's task
// prompt (Build).
//
// It is pure: no database, network, subprocess or filesystem, and no other
// observer package (imports_test.go). The dashboard loads the findings from
// its own store rows and passes plain values in; nothing here is trusted from
// a client. The prompt treats every finding field as untrusted scanner data:
// fields are cleaned to one capped line and fenced below the instructions,
// the list is capped at MaxListed findings and the whole prompt at
// MaxPromptBytes, because the prompt is passed to the agent on argv.
package secfixtask
