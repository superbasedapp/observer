package junie

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// cliFixtureSession is the anonymised 2026-09-07 standalone `junie` CLI
// capture under testdata/junie/cli/ — run with the SAME prompt and
// project shape as the 2026-09-03 jetbrains-mcp fixture and the
// 2026-09-07 IDE-hosted comparison session, specifically to ground the
// CLI-vs-IDE capture-surface discriminator (see surface.go).
const cliFixtureSession = "session-260907-002452-cli1"

// cliFixtureRoot lays the CLI fixture out under a temp watch root in the
// shape the watcher expects, plus its sibling index.jsonl.
func cliFixtureRoot(t *testing.T) (root, logPath string) {
	t.Helper()
	src := filepath.Join("..", "..", "..", "testdata", "junie", "cli")
	root = filepath.Join(t.TempDir(), ".junie", "sessions")
	sessDir := filepath.Join(root, cliFixtureSession)
	if err := os.MkdirAll(sessDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	body, err := os.ReadFile(filepath.Join(src, cliFixtureSession, "events.jsonl"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	logPath = filepath.Join(sessDir, sessionLogName)
	if err := os.WriteFile(logPath, body, 0o600); err != nil {
		t.Fatalf("write log: %v", err)
	}
	idx, err := os.ReadFile(filepath.Join(src, indexFileName))
	if err != nil {
		t.Fatalf("read index fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, indexFileName), idx, 0o600); err != nil {
		t.Fatalf("write index: %v", err)
	}
	return root, logPath
}

func parseCLIFixture(t *testing.T) adapter.ParseResult {
	t.Helper()
	root, logPath := cliFixtureRoot(t)
	a := NewWithOptions(nil, root)
	res, err := a.ParseSessionFile(context.Background(), logPath, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	return res
}

// TestCLIFixtureSelfStampsCLI pins the 2026-09-07 finding: the CLI
// fixture emits a SessionCostTrajectorySnapshotEvent right before its
// TaskState, which the adapter uses as the positive CLI discriminator
// (see surface.go).
func TestCLIFixtureSelfStampsCLI(t *testing.T) {
	res := parseCLIFixture(t)
	want := models.SessionSurface{SessionID: cliFixtureSession, Surface: models.SurfaceCLI, SurfaceHost: hostJunieCLI}
	if len(res.SessionSurfaces) != 1 || res.SessionSurfaces[0] != want {
		t.Errorf("SessionSurfaces = %+v, want [%+v]", res.SessionSurfaces, want)
	}
}

// TestCLIFixtureNoIDEAttachment pins the mirror image of
// TestMCPFixtureSelfStampsIDE: the CLI fixture's first UserPromptEvent
// carries no extraAttachments at all, so the header scan never sets
// ideAttachmentSeen and no ide stamp is ever considered.
func TestCLIFixtureNoIDEAttachment(t *testing.T) {
	res := parseCLIFixture(t)
	for _, s := range res.SessionSurfaces {
		if s.Surface == models.SurfaceIDE {
			t.Errorf("unexpected ide surface stamp from the CLI fixture: %+v", s)
		}
	}
}

// TestCLIFixtureOnlyOneSurfaceStampPerParse pins that emitCLISurface is
// idempotent within a single parse call even though
// SessionCostTrajectorySnapshotEvent could in principle recur (it does
// not in this fixture, but the guard exists for robustness — see
// surfaceStamped).
func TestCLIFixtureOnlyOneSurfaceStampPerParse(t *testing.T) {
	res := parseCLIFixture(t)
	if len(res.SessionSurfaces) != 1 {
		t.Fatalf("SessionSurfaces = %+v, want exactly 1", res.SessionSurfaces)
	}
}

// TestHasIDEMCPAttachment table-drives the extraAttachments recognizer.
// The predicate requires BOTH the attachment kind AND an
// mcpServers[].env[] entry keyed IJ_MCP_AUTH_TOKEN (see surface.go) —
// the kind alone is a generic attachment label the CLI lane can also
// carry once the operator configures its own MCP server.
func TestHasIDEMCPAttachment(t *testing.T) {
	cases := []struct {
		name string
		atts []extraAttachmentRaw
		want bool
	}{
		{"nil", nil, false},
		{"empty", []extraAttachmentRaw{}, false},
		{"unrelated only", []extraAttachmentRaw{{Kind: "TaskRequestParametersAttachment"}}, false},
		{"ide kind but no mcpServers at all", []extraAttachmentRaw{
			{Kind: ideAttachmentKind},
		}, false},
		{"ide kind, mcpServers present but no auth-token key (a user-configured CLI MCP server)", []extraAttachmentRaw{
			{Kind: ideAttachmentKind, MCPServers: []mcpServerRaw{
				{Env: []mcpEnvVarRaw{{Key: "SOME_OTHER_ENV_VAR"}}},
			}},
		}, false},
		{"ide kind with the IJ_MCP_AUTH_TOKEN key", []extraAttachmentRaw{
			{Kind: "TaskRequestParametersAttachment"},
			{Kind: ideAttachmentKind, MCPServers: []mcpServerRaw{
				{Env: []mcpEnvVarRaw{{Key: "IJ_MCP_SERVER_PROJECT_PATH"}, {Key: mcpAuthTokenKey}}},
			}},
		}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := hasIDEMCPAttachment(tc.atts); got != tc.want {
				t.Errorf("hasIDEMCPAttachment(%+v) = %v, want %v", tc.atts, got, tc.want)
			}
		})
	}
}

// syntheticSessionRoot lays out a minimal, hand-written events.jsonl
// (not a real capture) under a temp watch root, for scenarios no real
// fixture demonstrates in isolation — here, an IDE-kind attachment
// missing the auth-token key, and a session carrying BOTH the IDE and
// CLI markers together.
func syntheticSessionRoot(t *testing.T, sessionID string, lines []string) (root, logPath string) {
	t.Helper()
	root = filepath.Join(t.TempDir(), ".junie", "sessions")
	sessDir := filepath.Join(root, sessionID)
	if err := os.MkdirAll(sessDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	logPath = filepath.Join(sessDir, sessionLogName)
	body := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(logPath, []byte(body), 0o600); err != nil {
		t.Fatalf("write log: %v", err)
	}
	return root, logPath
}

func parseSynthetic(t *testing.T, sessionID string, lines []string) adapter.ParseResult {
	t.Helper()
	root, logPath := syntheticSessionRoot(t, sessionID, lines)
	a := NewWithOptions(nil, root)
	res, err := a.ParseSessionFile(context.Background(), logPath, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	return res
}

const userPromptNoAuthTokenKey = `{"kind":"UserPromptEvent","requestId":"prompt-1","prompt":"hi",` +
	`"extraAttachments":[{"kind":"TaskRequestMcpServersAttachment","mcpServers":[` +
	`{"name":"user-mcp","env":[{"key":"SOME_OTHER_ENV_VAR","value":"x"}]}]}],"timestampMs":1}`

const userPromptWithAuthTokenKey = `{"kind":"UserPromptEvent","requestId":"prompt-1","prompt":"hi",` +
	`"extraAttachments":[{"kind":"TaskRequestMcpServersAttachment","mcpServers":[` +
	`{"name":"idea","args":["stdioMcpServer"],"env":[{"key":"IJ_MCP_AUTH_TOKEN","value":"x"}]}]}],"timestampMs":1}`

const costTrajectorySnapshotLine = `{"kind":"SessionCostTrajectorySnapshotEvent","taskId":"task-1","snapshot":{},"timestampMs":2}`

// TestSyntheticIDEAttachmentWithoutAuthTokenNoStamp pins the table-driven
// finding's second row: an IDE-kind attachment (the same
// "TaskRequestMcpServersAttachment" a real IDE run emits) whose
// mcpServers carry a DIFFERENT env key — the shape a CLI run with a
// user-configured MCP server would produce — gets NO surface stamp at
// all, not a false "ide".
func TestSyntheticIDEAttachmentWithoutAuthTokenNoStamp(t *testing.T) {
	res := parseSynthetic(t, "session-synth-noauth", []string{userPromptNoAuthTokenKey})
	if len(res.SessionSurfaces) != 0 {
		t.Errorf("SessionSurfaces = %+v, want none (no IJ_MCP_AUTH_TOKEN key present)", res.SessionSurfaces)
	}
}

// TestSyntheticIDEAttachmentWithAuthTokenStampsIDE pins the table-driven
// finding's first row directly against the full parse path (not just
// the hasIDEMCPAttachment unit).
func TestSyntheticIDEAttachmentWithAuthTokenStampsIDE(t *testing.T) {
	res := parseSynthetic(t, "session-synth-ide", []string{userPromptWithAuthTokenKey})
	want := models.SessionSurface{SessionID: "session-synth-ide", Surface: models.SurfaceIDE, SurfaceHost: hostJunieIDEUnknown}
	if len(res.SessionSurfaces) != 1 || res.SessionSurfaces[0] != want {
		t.Errorf("SessionSurfaces = %+v, want [%+v]", res.SessionSurfaces, want)
	}
}

// TestSyntheticBothMarkersIDEWins pins the table-driven finding's third
// row: a session carrying BOTH the IDE marker (auth-token key present)
// AND the CLI marker (a SessionCostTrajectorySnapshotEvent) still
// stamps ide, never cli — emitIDESurface runs from the header scan
// before the per-line loop ever reaches the trajectory-snapshot record,
// so surfaceStamped is already true by the time emitCLISurface would
// fire (see adapter.go's emitIDESurface/emitCLISurface).
func TestSyntheticBothMarkersIDEWins(t *testing.T) {
	res := parseSynthetic(t, "session-synth-both", []string{userPromptWithAuthTokenKey, costTrajectorySnapshotLine})
	want := models.SessionSurface{SessionID: "session-synth-both", Surface: models.SurfaceIDE, SurfaceHost: hostJunieIDEUnknown}
	if len(res.SessionSurfaces) != 1 || res.SessionSurfaces[0] != want {
		t.Errorf("SessionSurfaces = %+v, want [%+v] (ide must win over cli)", res.SessionSurfaces, want)
	}
}
