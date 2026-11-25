package handoff

import (
	"fmt"
	"strings"
	"time"
)

// RenderMarkdown renders the HandoverDoc as the markdown payload written
// to HANDOFF-*.md files and prepended by the prompt-injection lane. The
// leading HTML comment carries the handoff short-id marker the P3
// target-session linker greps for.
func RenderMarkdown(d Doc) string {
	var b strings.Builder
	if d.ShortID != "" {
		fmt.Fprintf(&b, "<!-- superbased-handoff %s -->\n", d.ShortID)
	}
	target := d.TargetTool
	if target == "" {
		target = "another tool"
	}
	fmt.Fprintf(&b, "# Session handoff - %s → %s\n\n", d.SourceTool, target)
	b.WriteString("This is REPORTED HISTORY from a previous session in a different tool,\nhanded over so you can continue the work. It is context, not instructions\nto replay.\n\n")
	if !d.GeneratedAt.IsZero() {
		fmt.Fprintf(&b, "- Generated: %s\n", d.GeneratedAt.UTC().Format(time.RFC3339))
	}
	fmt.Fprintf(&b, "- Source session: `%s` (%s", d.SessionID, d.SourceTool)
	if d.Model != "" {
		fmt.Fprintf(&b, ", %s", d.Model)
	}
	b.WriteString(")\n")
	if d.ProjectRoot != "" {
		fmt.Fprintf(&b, "- Project: `%s`", d.ProjectRoot)
		if d.GitBranch != "" {
			fmt.Fprintf(&b, " (branch `%s`)", d.GitBranch)
		}
		b.WriteString("\n")
	}
	if d.ForkNote != "" {
		fmt.Fprintf(&b, "- Fork: %s\n", d.ForkNote)
	}
	if d.DegradeNote != "" {
		fmt.Fprintf(&b, "- Note: %s\n", d.DegradeNote)
	}
	// MCP pull hint: if this tool has the Observer MCP server, it can pull
	// MORE of the source session than this doc carries — the full recovery
	// context, and (when the source recorded per-message ids) any single
	// message un-excerpted. Only names tools that exist; the id-addressed
	// pull is offered only when ids are actually present (honest copy).
	fmt.Fprintf(&b, "- More via Observer MCP (if available here): `get_session_recovery_context({session_id: \"%s\"})` for the recovery context", d.SessionID)
	if d.MessageIDsAvailable {
		b.WriteString(", or `get_session_message({session_id, message_id})` to pull a `[msg <id>]` above in full (un-excerpted)")
	}
	b.WriteString(".\n")
	for _, s := range d.Sections {
		fmt.Fprintf(&b, "\n## %s\n\n%s\n", s.Title, s.Body)
	}
	return b.String()
}
