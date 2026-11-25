package handoff

import (
	"strings"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// MarkerPrefix is the literal that leads the marker embedded in a
// HandoverDoc's first line (RenderMarkdown emits
// "<!-- superbased-handoff <shortid> -->"). The marker rides into the
// TARGET session along every delivery lane — the injected first prompt
// (inject_prompt), the SessionStart additionalContext (inject_hook), or
// the model reading HANDOFF-<shortid>.md (inject_file / inject_mcp, where
// the file content enters the transcript as a tool_result). The
// best-effort P3 linker (internal/handoffsvc) checks a candidate target
// session's transcript for this marker with ContainsMarker to stamp
// handoffs.target_session_id.
const MarkerPrefix = "superbased-handoff "

// ContainsMarker reports whether the transcript carries the marker for a
// specific handoff short-id anywhere in its text or tool-call excerpts.
// An empty shortID never matches.
func ContainsMarker(msgs []models.TranscriptMessage, shortID string) bool {
	if shortID == "" {
		return false
	}
	needle := MarkerPrefix + shortID
	for _, m := range msgs {
		if strings.Contains(m.Text, needle) {
			return true
		}
		for _, tc := range m.ToolCalls {
			if strings.Contains(tc.InputExcerpt, needle) || strings.Contains(tc.ResultExcerpt, needle) {
				return true
			}
		}
	}
	return false
}
