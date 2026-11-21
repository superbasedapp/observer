package cloudagents

import (
	"sort"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/tooltax"
	"github.com/marmutapp/superbased-observer/internal/vendorapi"
	"github.com/marmutapp/superbased-observer/internal/vendorapi/cline"
)

// clineCloudToolCall maps one Cline Cloud tool call through MapActivity and
// returns the action it lands as.
func clineCloudToolCall(t *testing.T, c Connector, name string) models.ToolEvent {
	t.Helper()
	at := time.Date(2026, 11, 2, 9, 0, 0, 0, time.UTC)
	evs := MapActivity(c, "ses-synth0001", "/r", []Activity{{Kind: ActivityToolCall, ID: "m1/t1", At: at, Tool: name}})
	if len(evs) != 1 {
		t.Fatalf("%s: %d actions", name, len(evs))
	}
	return evs[0]
}

// TestClineCloudToolNamesClassifyLikeClineCLI is one row per tool name the
// cline-cli classifier knows (internal/adapter/clinecli normalize.go, whose
// rows tooltax owns): a Cline Cloud tool call carries the Cline SDK's names
// (live check 2026-11-02 observed run_commands and editor), so it lands
// under tool cline but classified through cline-cli's vocabulary. A name
// neither vocabulary knows stays unknown with its raw name kept.
func TestClineCloudToolNamesClassifyLikeClineCLI(t *testing.T) {
	c := mustConn(t, ConnectorClineCloud)
	cases := []struct{ name, want string }{
		{"read_files", models.ActionReadFile},
		{"run_commands", models.ActionRunCommand},
		{"apply_patch", models.ActionEditFile},
		{"editor", models.ActionEditFile},
		{"search_codebase", models.ActionSearchFiles},
		{"fetch_web_content", models.ActionWebFetch},
		{"ask_question", models.ActionAskUser},
		{"skills", models.ActionMCPCall},
		{"spawn_agent", models.ActionSpawnSubagent},
		{"submit_and_exit", models.ActionTaskComplete},
		{"team_spawn_teammate", models.ActionSpawnSubagent},
		{"team_attach_outcome_fragment", models.ActionMCPCall},
		{"team_await_runs", models.ActionMCPCall},
		{"team_broadcast", models.ActionMCPCall},
		{"team_cancel_run", models.ActionMCPCall},
		{"team_cleanup", models.ActionMCPCall},
		{"team_create_outcome", models.ActionMCPCall},
		{"team_finalize_outcome", models.ActionMCPCall},
		{"team_list_outcomes", models.ActionMCPCall},
		{"team_list_runs", models.ActionMCPCall},
		{"team_mission_log", models.ActionMCPCall},
		{"team_read_mailbox", models.ActionMCPCall},
		{"team_review_outcome_fragment", models.ActionMCPCall},
		{"team_run_task", models.ActionMCPCall},
		{"team_send_message", models.ActionMCPCall},
		{"team_shutdown_teammate", models.ActionMCPCall},
		{"team_status", models.ActionMCPCall},
		{"team_task", models.ActionMCPCall},
		// The cline-cli MCP prefix rule (tooltax's cline-cli `mcp_*` glob).
		{"mcp_github_create_issue", models.ActionMCPCall},
		// Not a Cline SDK name: no guess.
		{"definitely_not_a_tool", models.ActionUnknown},
	}
	for _, tc := range cases {
		ev := clineCloudToolCall(t, c, tc.name)
		if ev.ActionType != tc.want || ev.RawToolName != tc.name || ev.Tool != models.ToolCline {
			t.Errorf("%s: action %q raw %q tool %q, want action %q under tool cline",
				tc.name, ev.ActionType, ev.RawToolName, ev.Tool, tc.want)
		}
	}
	// Every literal name the taxonomy holds for cline-cli is covered above,
	// so a name added to cline-cli's rows fails here until it has a row.
	listed := map[string]bool{}
	for _, tc := range cases {
		listed[tc.name] = true
	}
	var missing []string
	for _, e := range tooltax.Table() {
		if e.Tool == models.ToolClineCLI && !e.IsGlob() && !listed[e.Native] {
			missing = append(missing, e.Native)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("cline-cli taxonomy names with no case here: %v", missing)
	}
}

// TestToolVocabularyLeavesOtherRowsAlone: a row with no ToolVocabulary
// classifies under its own tool, so the VS Code cline vocabulary is
// unchanged (the same names under the landing tool alone: execute_command is
// the extension's, run_commands is not).
func TestToolVocabularyLeavesOtherRowsAlone(t *testing.T) {
	c := mustConn(t, ConnectorClineCloud)
	if c.Vocabulary() != models.ToolClineCLI {
		t.Fatalf("cline-cloud vocabulary %q", c.Vocabulary())
	}
	plain := c
	plain.ToolVocabulary = ""
	if plain.Vocabulary() != models.ToolCline {
		t.Fatalf("a row with no vocabulary classifies under %q", plain.Vocabulary())
	}
	if ev := clineCloudToolCall(t, plain, "execute_command"); ev.ActionType != models.ActionRunCommand {
		t.Fatalf("VS Code vocabulary changed: execute_command -> %q", ev.ActionType)
	}
	if ev := clineCloudToolCall(t, plain, "run_commands"); ev.ActionType != models.ActionUnknown {
		t.Fatalf("VS Code vocabulary picked up a cline-cli name: run_commands -> %q", ev.ActionType)
	}
}

// TestToolVocabularyIsATaxonomyTool: every row that declares a tool
// vocabulary names a tool the canonical taxonomy has rows for, so its calls
// never silently classify as unknown because of a misspelled id.
func TestToolVocabularyIsATaxonomyTool(t *testing.T) {
	tools := map[string]bool{}
	for _, tl := range tooltax.Tools() {
		tools[tl] = true
	}
	for _, c := range Connectors {
		if c.ToolVocabulary != "" && !tools[c.ToolVocabulary] {
			t.Errorf("%s: ToolVocabulary %q has no taxonomy rows", c.ID, c.ToolVocabulary)
		}
	}
}

// TestClineHistoryFiguresNetInput is one row per input shape: Cline's
// metrics.inputTokens is gross of cache reads (live check 2026-11-02), so
// the token figure carries it net, never below zero; cache writes are
// carried as reported.
func TestClineHistoryFiguresNetInput(t *testing.T) {
	cases := []struct {
		name                         string
		in, cRead, cWrite, wantNetIn int64
	}{
		{"live shape: input includes the cache reads", 9309, 8448, 0, 861},
		{"no cache reads", 1200, 0, 0, 1200},
		{"all input from cache", 5000, 5000, 0, 0},
		{"cache reads over input never goes negative", 100, 300, 0, 0},
		{"cache writes are carried, not subtracted", 2000, 1500, 400, 500},
	}
	for _, tc := range cases {
		u := vendorapi.UsageRow{
			InputTokens: tc.in, OutputTokens: 7, CacheReadTokens: tc.cRead, CacheWriteTokens: tc.cWrite,
			At: time.Date(2026, 11, 2, 9, 0, 0, 0, time.UTC), Flags: map[string]string{cline.TokensFlag: "true"},
		}
		tok, _ := clineHistoryFigures(u)
		if tok == nil || tok.Input != tc.wantNetIn || tok.CacheRead != tc.cRead || tok.CacheCreation != tc.cWrite || tok.Output != 7 {
			t.Errorf("%s: %+v, want input %d", tc.name, tok, tc.wantNetIn)
		}
	}
}

// TestVocabularyForSource pins the read-side vocabulary lookup a reader of
// stored actions uses (the dashboard's surface breakdown): a row a
// connector with ToolVocabulary wrote reads under that vocabulary, every
// other row (another connector's, a local adapter's, a source_file that only
// looks similar) under its own tool.
func TestVocabularyForSource(t *testing.T) {
	cases := []struct {
		name, tool, sourceFile, want string
	}{
		{"cline cloud row", models.ToolCline, SourceFile(ConnectorClineCloud), models.ToolClineCLI},
		{"local cline row", models.ToolCline, "/home/u/.vscode/tasks/1/api_conversation_history.json", models.ToolCline},
		{"cursor cloud row", models.ToolCursor, SourceFile(ConnectorCursorCloud), models.ToolCursor},
		{"devin row", models.ToolDevin, SourceFile(ConnectorDevin), models.ToolDevin},
		{"openhands row", ToolOpenHands, SourceFile(ConnectorOpenHandsCloud), ToolOpenHands},
		{"qoder cloud row", models.ToolQoder, SourceFile(ConnectorQoderCloud), models.ToolQoder},
		{"warp claude harness row", models.ToolClaudeCode, SourceFile(ConnectorWarpCloud), models.ToolClaudeCode},
		{"warp codex harness row", models.ToolCodex, SourceFile(ConnectorWarpCloud), models.ToolCodex},
		{"unknown connector id", models.ToolCline, SourceFile("no-such-connector"), models.ToolCline},
		{"prefix only", models.ToolCline, SourceFilePrefix, models.ToolCline},
		{"empty source", models.ToolCline, "", models.ToolCline},
	}
	for _, tc := range cases {
		if got := VocabularyForSource(tc.tool, tc.sourceFile); got != tc.want {
			t.Errorf("%s: VocabularyForSource(%q, %q) = %q, want %q", tc.name, tc.tool, tc.sourceFile, got, tc.want)
		}
	}
}

// TestStoredToolCallsReclassifyAsCaptured is the round trip for every
// connector and every tool it can land under: each native name the
// connector's vocabulary knows is mapped by MapActivity, and a reader
// holding only the stored row (tool, source_file, raw_tool_name) must
// resolve it through VocabularyForSource to the same action type. A
// connector whose calls carry another tool's names and that the reader
// cannot see (the Cline Cloud surface gap of 2026-11-02) fails here.
func TestStoredToolCallsReclassifyAsCaptured(t *testing.T) {
	at := time.Date(2026, 11, 2, 9, 0, 0, 0, time.UTC)
	for _, base := range Connectors {
		landings := []Connector{base}
		if base.HarnessTools != nil {
			landings = landings[:0]
			for harness := range base.HarnessTools {
				if c, ok := ForTask(base, Task{Harness: harness}); ok {
					landings = append(landings, c)
				}
			}
		}
		for _, c := range landings {
			if c.Tool == "" {
				continue
			}
			names := tooltax.For(c.Vocabulary())
			if len(names) == 0 {
				continue
			}
			for name, want := range names {
				evs := MapActivity(c, "ses-synth0001", "/r", []Activity{{Kind: ActivityToolCall, ID: "t1", At: at, Tool: name}})
				if len(evs) != 1 {
					t.Fatalf("%s/%s %q: %d actions", c.ID, c.Tool, name, len(evs))
				}
				ev := evs[0]
				if ev.ActionType != want {
					t.Fatalf("%s/%s %q: captured as %q, want %q", c.ID, c.Tool, name, ev.ActionType, want)
				}
				got, _ := tooltax.ResolveActionType(VocabularyForSource(ev.Tool, ev.SourceFile), ev.RawToolName)
				if got != ev.ActionType {
					t.Errorf("%s/%s %q: stored row reads as %q, captured as %q", c.ID, c.Tool, name, got, ev.ActionType)
				}
			}
		}
	}
}
