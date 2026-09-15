package junie

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// mcpFixtureSession is the anonymised 2026-09-03 IntelliJ IDEA 2026.2
// capture under testdata/junie/jetbrains-mcp/ — a Junie run whose tools
// were served over MCP by the IDE. See that directory's paragraph in
// testdata/junie/README.md.
const mcpFixtureSession = "session-260903-163227-mcp1"

// mcpFixtureRoot lays the MCP fixture out under a temp watch root in the
// shape the watcher expects, plus its sibling index.jsonl.
func mcpFixtureRoot(t *testing.T) (root, logPath string) {
	t.Helper()
	src := filepath.Join("..", "..", "..", "testdata", "junie", "jetbrains-mcp")
	root = filepath.Join(t.TempDir(), ".junie", "sessions")
	sessDir := filepath.Join(root, mcpFixtureSession)
	if err := os.MkdirAll(sessDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	body, err := os.ReadFile(filepath.Join(src, mcpFixtureSession, "events.jsonl"))
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

func parseMCPFixture(t *testing.T) adapter.ParseResult {
	t.Helper()
	root, logPath := mcpFixtureRoot(t)
	a := NewWithOptions(nil, root)
	res, err := a.ParseSessionFile(context.Background(), logPath, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	return res
}

// TestNormalizeMCPCall pins the mcpToolRules table — one case per
// observed vendor tool name, plus the fallback rows.
func TestNormalizeMCPCall(t *testing.T) {
	tests := []struct {
		name       string
		toolName   string
		input      string
		wantAction string
		wantTarget string
	}{
		{
			name:       "list directory tree with a path",
			toolName:   "idea/list_directory_tree",
			input:      "\n{\n    \"directoryPath\": \"src\",\n    \"maxDepth\": 4\n}",
			wantAction: models.ActionSearchFiles,
			wantTarget: "src",
		},
		{
			// 2 of the 3 observed list calls state directoryPath:"" —
			// the vendor's spelling for "the project root". There is
			// no path to name, so the target falls back to the tool
			// name rather than being blank or invented.
			name:       "list directory tree at the project root",
			toolName:   "idea/list_directory_tree",
			input:      "\n{\n    \"directoryPath\": \"\",\n    \"maxDepth\": 3\n}",
			wantAction: models.ActionSearchFiles,
			wantTarget: "idea/list_directory_tree",
		},
		{
			name:       "create new file",
			toolName:   "idea/create_new_file",
			input:      "\n{\n    \"pathInProject\": \"hello_world.py\",\n    \"text\": \"print(\\\"Hello World\\\")\\n\",\n    \"overwrite\": false\n}",
			wantAction: models.ActionWriteFile,
			wantTarget: "hello_world.py",
		},
		{
			name:       "execute terminal command",
			toolName:   "idea/execute_terminal_command",
			input:      "\n{\n    \"command\": \"python hello_world.py\",\n    \"executeInShell\": true\n}",
			wantAction: models.ActionRunCommand,
			wantTarget: "python hello_world.py",
		},
		{
			// The capture's file DELETION: no idea/delete_file exists
			// in the observed vocabulary, so a delete is honestly a
			// shell command.
			name:       "delete via terminal command",
			toolName:   "idea/execute_terminal_command",
			input:      "\n{\n    \"command\": \"Remove-Item -LiteralPath .\\\\hello_world.py -Force\"\n}",
			wantAction: models.ActionRunCommand,
			wantTarget: `Remove-Item -LiteralPath .\hello_world.py -Force`,
		},
		{
			name:       "apply patch updating a file",
			toolName:   "idea/apply_patch",
			input:      "\n{\n    \"patch\": \"*** Begin Patch\\n*** Update File: hello_world.py\\n@@\\n-print(1)\\n+print(2)\\n*** End Patch\"\n}",
			wantAction: models.ActionEditFile,
			wantTarget: "hello_world.py",
		},
		{
			// The patch grammar's verb is self-describing: a patch
			// that ADDS a file is a write, not an edit.
			name:       "apply patch adding a file",
			toolName:   "idea/apply_patch",
			input:      "\n{\n    \"patch\": \"*** Begin Patch\\n*** Add File: new.py\\n+print(1)\\n*** End Patch\"\n}",
			wantAction: models.ActionWriteFile,
			wantTarget: "new.py",
		},
		{
			name:       "apply patch with no recognised header keeps the default",
			toolName:   "idea/apply_patch",
			input:      "\n{\n    \"patch\": \"garbage\"\n}",
			wantAction: models.ActionEditFile,
			wantTarget: "idea/apply_patch",
		},
		{
			name:       "case insensitive name match",
			toolName:   "IDEA/Create_New_File",
			input:      "{\"pathInProject\": \"a.txt\"}",
			wantAction: models.ActionWriteFile,
			wantTarget: "a.txt",
		},
		// Fallbacks — never blank, never a guessed action.
		{
			name:       "unknown idea tool",
			toolName:   "idea/get_file_problems",
			input:      "{\"filePath\": \"a.py\"}",
			wantAction: models.ActionMCPCall,
			wantTarget: "idea/get_file_problems",
		},
		{
			name:       "third-party mcp server",
			toolName:   "acme/do_thing",
			input:      "{}",
			wantAction: models.ActionMCPCall,
			wantTarget: "acme/do_thing",
		},
		{
			name:       "malformed arguments still yield a target",
			toolName:   "idea/create_new_file",
			input:      "not json at all",
			wantAction: models.ActionWriteFile,
			wantTarget: "idea/create_new_file",
		},
		{
			name:       "missing tool name",
			toolName:   "",
			input:      "{}",
			wantAction: models.ActionMCPCall,
			wantTarget: "junie.mcp",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := normalizeMCPCall(tc.toolName, tc.input)
			if got.ActionType != tc.wantAction {
				t.Errorf("ActionType = %q, want %q", got.ActionType, tc.wantAction)
			}
			if got.Target != tc.wantTarget {
				t.Errorf("Target = %q, want %q", got.Target, tc.wantTarget)
			}
			if got.Target == "" {
				t.Error("Target must never be blank")
			}
		})
	}
}

// TestMCPFixtureActionCoverage is the before/after of the capture gap:
// the JetBrains-hosted run creates, runs, edits, runs, deletes and
// re-lists a file, and every one of those steps now lands as an action.
func TestMCPFixtureActionCoverage(t *testing.T) {
	res := parseMCPFixture(t)

	byType := map[string]int{}
	for _, ev := range res.ToolEvents {
		byType[ev.ActionType]++
	}
	want := map[string]int{
		models.ActionSessionStart:      1,
		models.ActionUserPrompt:        1,
		models.ActionSearchFiles:       3, // 3 list_directory_tree steps
		models.ActionWriteFile:         1, // create_new_file
		models.ActionRunCommand:        3, // run, run again, delete
		models.ActionEditFile:          1, // apply_patch
		models.ActionReadFile:          2, // 2 ViewFiles steps
		models.ActionPermissionRequest: 1, // the one approvalRequest
		models.ActionTaskComplete:      1, // the Result block
	}
	for action, n := range want {
		if byType[action] != n {
			t.Errorf("%s rows = %d, want %d", action, byType[action], n)
		}
	}
	for action, n := range byType {
		if _, ok := want[action]; !ok {
			t.Errorf("unexpected action type %s (%d rows)", action, n)
		}
	}
	// Before this lane existed the same file produced exactly 3 rows
	// (session start, user prompt, result) — the 42 McpBlockUpdatedEvent
	// and 6 ViewFilesBlockUpdatedEvent records were skipped silently.
	if len(res.ToolEvents) != 14 {
		t.Errorf("total ToolEvents = %d, want 14", len(res.ToolEvents))
	}

	// The 8 MCP steps + 2 ViewFiles steps + 1 Result collapse onto ONE
	// row each, despite recurring 2-6 times in the stream.
	seen := map[string]bool{}
	for _, ev := range res.ToolEvents {
		if seen[ev.SourceEventID] {
			t.Errorf("duplicate SourceEventID %q", ev.SourceEventID)
		}
		seen[ev.SourceEventID] = true
		if ev.SessionID != mcpFixtureSession {
			t.Errorf("SessionID = %q", ev.SessionID)
		}
		if ev.Tool != models.ToolJunie {
			t.Errorf("Tool = %q", ev.Tool)
		}
		if ev.Target == "" {
			t.Errorf("blank Target on %s / %s", ev.ActionType, ev.SourceEventID)
		}
	}
}

// TestMCPFixtureRowDetail pins the fields of the individual MCP rows the
// five-turn kit produced.
func TestMCPFixtureRowDetail(t *testing.T) {
	res := parseMCPFixture(t)
	byTarget := map[string]models.ToolEvent{}
	for _, ev := range res.ToolEvents {
		byTarget[ev.ActionType+"|"+ev.Target] = ev
	}

	create, ok := byTarget[models.ActionWriteFile+"|hello_world.py"]
	if !ok {
		t.Fatalf("no write_file row for hello_world.py; rows: %v", targetsOf(res.ToolEvents))
	}
	if create.RawToolName != "idea/create_new_file" {
		t.Errorf("RawToolName = %q, want the verbatim vendor name", create.RawToolName)
	}
	if !create.Success {
		t.Error("create_new_file COMPLETED, want Success")
	}
	// `details` at the terminal transition is the outcome summary, not a
	// copy of the arguments.
	if create.ToolOutput == "" || create.ToolOutput == create.RawToolInput {
		t.Errorf("ToolOutput = %q (RawToolInput %q)", create.ToolOutput, create.RawToolInput)
	}
	if create.RawToolInput == "" {
		t.Error("RawToolInput should carry the MCP arguments")
	}

	edit, ok := byTarget[models.ActionEditFile+"|hello_world.py"]
	if !ok {
		t.Fatal("no edit_file row for hello_world.py")
	}
	if edit.RawToolName != "idea/apply_patch" {
		t.Errorf("edit RawToolName = %q", edit.RawToolName)
	}

	// The permission prompt is its own row, keyed on the prompt id, and
	// carries the offered allow-list patterns as its reasoning.
	var perm *models.ToolEvent
	for i := range res.ToolEvents {
		if res.ToolEvents[i].ActionType == models.ActionPermissionRequest {
			perm = &res.ToolEvents[i]
			break
		}
	}
	if perm == nil {
		t.Fatal("no permission_request row")
	}
	if perm.Target != "idea/list_directory_tree" {
		t.Errorf("permission Target = %q, want the tool being asked about", perm.Target)
	}
	if perm.PrecedingReasoning != "idea:list_directory_tree, idea:*" {
		t.Errorf("permission PrecedingReasoning = %q", perm.PrecedingReasoning)
	}
	if !strings.HasPrefix(perm.SourceEventID, "approval:") {
		t.Errorf("permission SourceEventID = %q", perm.SourceEventID)
	}
}

// TestMCPFixtureTokens confirms the token lane is unchanged by the MCP
// work: 32 LlmResponseMetadataEvent records → 32 token rows, input
// already NET of the cache fields.
func TestMCPFixtureTokens(t *testing.T) {
	res := parseMCPFixture(t)
	if len(res.TokenEvents) != 32 {
		t.Fatalf("TokenEvents = %d, want 32", len(res.TokenEvents))
	}
	var totalIn, totalOut, totalCreate, totalRead int64
	models32 := map[string]int{}
	for _, te := range res.TokenEvents {
		if te.Tool != models.ToolJunie {
			t.Errorf("Tool = %q", te.Tool)
		}
		if te.SessionID != mcpFixtureSession {
			t.Errorf("SessionID = %q", te.SessionID)
		}
		if te.Model == "" {
			t.Error("token row with no model")
		}
		if te.Source != models.TokenSourceJSONL || te.Reliability != models.ReliabilityAccurate {
			t.Errorf("source/reliability = %q/%q", te.Source, te.Reliability)
		}
		if te.EstimatedCostUSD <= 0 {
			t.Errorf("EstimatedCostUSD = %v, want the provider-stated cost", te.EstimatedCostUSD)
		}
		models32[te.Model]++
		totalIn += te.InputTokens
		totalOut += te.OutputTokens
		totalCreate += te.CacheCreationTokens
		totalRead += te.CacheReadTokens
	}
	// The live daemon recorded 16,406 tokens for this session — its
	// `input + output` sum. The four columns land verbatim from the
	// vendor's own four fields.
	if got := totalIn + totalOut; got != 16406 {
		t.Errorf("input+output = %d, want 16406", got)
	}
	if totalIn != 14788 || totalOut != 1618 {
		t.Errorf("input/output = %d/%d, want 14788/1618", totalIn, totalOut)
	}
	if totalCreate != 18206 || totalRead != 136555 {
		t.Errorf("cache create/read = %d/%d, want 18206/136555", totalCreate, totalRead)
	}
	// Junie routes a single task across several models (a cheap
	// classifier plus the working model), so no single model owns the
	// session — the row carries the per-call model, never a session one.
	if len(models32) < 2 {
		t.Errorf("expected several models, got %v", models32)
	}
	// GROSS-vs-NET (§8.3): the one call that wrote a large cache states
	// inputTokens:3 alongside cacheCreateTokens:15847 — the input is
	// already NET, so no subtraction happens anywhere on this path.
	var sawNetInput bool
	for _, te := range res.TokenEvents {
		if te.CacheCreationTokens > 1000 {
			sawNetInput = true
			if te.InputTokens > 100 {
				t.Errorf("input %d alongside cache-create %d looks GROSS", te.InputTokens, te.CacheCreationTokens)
			}
		}
	}
	if !sawNetInput {
		t.Error("fixture should contain the large cache-create call")
	}
}

// TestMCPFixtureSelfStampsIDE pins the 2026-09-07 finding: the fixture's
// first UserPromptEvent carries the IDE-injected MCP-server wiring
// attachment ("TaskRequestMcpServersAttachment"), so the adapter now
// self-stamps a non-hosted ide/jetbrains surface for this demonstrably
// IDE-hosted run. See surface.go for the grounding and why the host
// token stays the generic "jetbrains" rather than a guessed product.
func TestMCPFixtureSelfStampsIDE(t *testing.T) {
	res := parseMCPFixture(t)
	want := models.SessionSurface{SessionID: mcpFixtureSession, Surface: models.SurfaceIDE, SurfaceHost: hostJunieIDEUnknown}
	if len(res.SessionSurfaces) != 1 || res.SessionSurfaces[0] != want {
		t.Errorf("SessionSurfaces = %+v, want [%+v]", res.SessionSurfaces, want)
	}
}

// TestMCPFixtureNeverEmitsEnvironment pins the hard rule: an
// EnvironmentVariablesUpdatedEvent's payload must never reach any
// emitted row. The fixture carries one such record with a placeholder
// value precisely so this assertion has something to fail on.
func TestMCPFixtureNeverEmitsEnvironment(t *testing.T) {
	res := parseMCPFixture(t)
	for _, ev := range res.ToolEvents {
		for _, field := range []string{ev.Target, ev.RawToolInput, ev.ToolOutput, ev.PrecedingReasoning, ev.ErrorMessage, ev.RawToolName} {
			if field != "" && strings.Contains(field, "FIXTURE_PLACEHOLDER") {
				t.Fatalf("environment payload leaked into %s: %q", ev.ActionType, field)
			}
		}
	}
}

// TestMCPFixtureIdempotent re-parses the same file from offset 0 and
// expects byte-identical output — the block collapse is a pure function
// of the file, not of accumulated state.
func TestMCPFixtureIdempotent(t *testing.T) {
	root, logPath := mcpFixtureRoot(t)
	a := NewWithOptions(nil, root)
	first, err := a.ParseSessionFile(context.Background(), logPath, 0)
	if err != nil {
		t.Fatal(err)
	}
	second, err := a.ParseSessionFile(context.Background(), logPath, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.ToolEvents) != len(second.ToolEvents) || len(first.TokenEvents) != len(second.TokenEvents) {
		t.Fatalf("re-parse differs: %d/%d vs %d/%d",
			len(first.ToolEvents), len(first.TokenEvents), len(second.ToolEvents), len(second.TokenEvents))
	}
	for i := range first.ToolEvents {
		if first.ToolEvents[i].SourceEventID != second.ToolEvents[i].SourceEventID ||
			first.ToolEvents[i].ActionType != second.ToolEvents[i].ActionType ||
			first.ToolEvents[i].Target != second.ToolEvents[i].Target {
			t.Errorf("row %d differs on re-parse", i)
		}
	}
	if first.NewOffset != second.NewOffset {
		t.Errorf("NewOffset %d vs %d", first.NewOffset, second.NewOffset)
	}
}

// TestMCPFixtureProjectRoot pins that the MCP capture still resolves a
// project root — its first CurrentDirectoryUpdatedEvent is empty, so
// this exercises the header pre-scan finding the later non-empty one.
//
// The fixture states a Windows cwd (`C:\Users\dev\projects\demo\text`),
// which the adapter routes through crossmount.TranslateForeignPath before
// git.Resolve — UNCONDITIONALLY, like the cursor/codex/copilot siblings. On a
// non-Windows host (incl. a WSL daemon) that maps the drive-letter path to its
// reachable `/mnt/<drive>/...` form; on a Windows host it stays verbatim. So the
// expectation is host-dependent, expressed the way cline's roots_test.go does.
func TestMCPFixtureProjectRoot(t *testing.T) {
	res := parseMCPFixture(t)
	want := `C:\Users\dev\projects\demo\text`
	if runtime.GOOS != "windows" {
		want = "/mnt/c/Users/dev/projects/demo/text"
	}
	for _, ev := range res.ToolEvents {
		if ev.ProjectRoot != want {
			t.Fatalf("ProjectRoot = %q, want %q", ev.ProjectRoot, want)
		}
	}
}

func targetsOf(evs []models.ToolEvent) []string {
	out := make([]string, 0, len(evs))
	for _, e := range evs {
		out = append(out, e.ActionType+"|"+e.Target)
	}
	return out
}
