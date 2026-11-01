// Package secmcp is the security pillar's MCP tools (security pillar plan
// section 6.1, "MCP tool the agent can call"; lane sec-c3):
//
//   - get_security_findings: the open findings of the agent's project,
//     each with its rule, severity, place, the rule's templated message and
//     fix hint, and the baseline label. Messages are rule text, never
//     repository or engine text, and evidence never leaves the store.
//   - check_change: the native detectors over a path and proposed content
//     before the agent writes it (the secret rows, and the CI workflow
//     rules for a workflow file). The answer names detector types and
//     lines, never a matched value.
//
// The tools satisfy internal/mcp's Tool interface structurally; the cmd
// layer composes them into `observer serve` only while the `security`
// module is active and [security.mcp].tools is on, so they are absent when
// the module or MCP is off. Every I/O is injected (the findings read, the
// project resolution); the package opens no database or file itself.
// Descriptions are kept short: MCP's schema costs every turn.
package secmcp
