package hook

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// TestJunieToolGateReadsProjectPath pins FU-155: Junie CLI 26.10.27 and the
// IntelliJ IDEA Junie plugin (Mac round 4, rows 19 and 30) send a PreToolUse
// payload whose cwd is the hook's registration directory (~/.junie) and whose
// project is in project_path. The junie-pretool dialect reads project_path
// first, then cwd. cwd and project_path are the round 4 field names; the
// session_id, tool_name and tool_input spellings are the doc-grounded ones the
// existing junie fixture uses (toolPayload). No other dialect reads
// project_path.
func TestJunieToolGateReadsProjectPath(t *testing.T) {
	const (
		junieHome = "/Users/lume/.junie"
		project   = "/Users/lume/superbasedtest"
	)
	for _, tc := range []struct {
		name, tool, dialect, body, wantCwd string
	}{
		{
			name: "round 4 shape: project_path wins over cwd", tool: models.ToolJunie, dialect: ToolGateDialectJunie,
			body:    `{"session_id":"s1","cwd":"` + junieHome + `","project_path":"` + project + `","tool_name":"Bash","tool_input":{"command":"echo mac-tool-deny"}}`,
			wantCwd: project,
		},
		{
			name: "project_path before cwd in the document", tool: models.ToolJunie, dialect: ToolGateDialectJunie,
			body:    `{"project_path":"` + project + `","session_id":"s1","cwd":"` + junieHome + `","tool_name":"Bash","tool_input":{"command":"echo mac-tool-deny"}}`,
			wantCwd: project,
		},
		{
			name: "no project_path: cwd", tool: models.ToolJunie, dialect: ToolGateDialectJunie,
			body:    `{"session_id":"s1","cwd":"` + project + `","tool_name":"Bash","tool_input":{"command":"echo hi"}}`,
			wantCwd: project,
		},
		{
			name: "empty project_path: cwd", tool: models.ToolJunie, dialect: ToolGateDialectJunie,
			body:    `{"session_id":"s1","cwd":"` + project + `","project_path":"","tool_name":"Bash","tool_input":{"command":"echo hi"}}`,
			wantCwd: project,
		},
		{
			// Every other Claude-shaped dialect keeps reading cwd alone.
			name: "claude-json dialect ignores project_path", tool: models.ToolCodex, dialect: ToolGateDialectClaudeJSON,
			body:    `{"session_id":"s1","cwd":"` + junieHome + `","project_path":"` + project + `","tool_name":"Bash","tool_input":{"command":"echo hi"}}`,
			wantCwd: junieHome,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			evs, ok := ToolGateEvents(tc.tool, tc.dialect, "PreToolUse", []byte(tc.body))
			if !ok || len(evs) != 1 {
				t.Fatalf("ToolGateEvents = %d events ok=%v, want one judged shell event", len(evs), ok)
			}
			if e := evs[0]; e.Cwd != tc.wantCwd || e.SessionID != "s1" {
				t.Errorf("event cwd %q session %q, want cwd %q session s1", e.Cwd, e.SessionID, tc.wantCwd)
			}
			// The project root stays what the host names as a root (none):
			// the cmd layer derives the project lookup root from the cwd.
			if evs[0].ProjectRoot != "" {
				t.Errorf("ProjectRoot = %q, want empty", evs[0].ProjectRoot)
			}
		})
	}
}
