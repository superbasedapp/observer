package tooltax_test

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/tooltax"
)

// This file holds the models-drift pins for the tooltax table.
//
// THE ADAPTER CONFORMANCE SEEDS THAT USED TO LIVE HERE ARE GONE (WP-T3).
// WP-T1 transcribed claude-code's, codex's and cowork's package-private
// `actionMap` literals into this file because tooltax could not reach
// them and WP-T1's scope did not touch internal/adapter/*. WP-T3 removed
// the need: those three adapters now READ tooltax.For(tool), and the
// old-vs-new equality pins live in the adapter packages themselves, with
// direct access to the real map instead of a transcription:
//
//   - internal/adapter/claudecode/tooltax_conversion_test.go
//   - internal/adapter/codex/tooltax_conversion_test.go
//   - internal/adapter/cowork/tooltax_conversion_test.go
//
// Every adapter still carrying a private map or switch has its own
// SUBSET conformance pin at
// internal/adapter/<tool>/tooltax_conformance_test.go, and
// internal/integration/registry_coverage_test.go's
// TestVocabularyDeclaredForEveryAdapter forces a new adapter to declare
// its native vocabulary here. Do NOT re-add transcribed literals to this
// file — a transcription is a second source of truth by construction.

// TestActionTypeValuesMatchModels pins the string constants tooltax
// re-declares (because it may not import internal/models) against the
// real models.Action* values. A rename on either side fails here.
func TestActionTypeValuesMatchModels(t *testing.T) {
	pairs := map[string]string{
		tooltax.ActionReadFile:            models.ActionReadFile,
		tooltax.ActionWriteFile:           models.ActionWriteFile,
		tooltax.ActionEditFile:            models.ActionEditFile,
		tooltax.ActionRunCommand:          models.ActionRunCommand,
		tooltax.ActionSearchText:          models.ActionSearchText,
		tooltax.ActionSearchFiles:         models.ActionSearchFiles,
		tooltax.ActionWebSearch:           models.ActionWebSearch,
		tooltax.ActionWebFetch:            models.ActionWebFetch,
		tooltax.ActionBrowserAction:       models.ActionBrowserAction,
		tooltax.ActionMCPCall:             models.ActionMCPCall,
		tooltax.ActionSpawnSubagent:       models.ActionSpawnSubagent,
		tooltax.ActionTodoUpdate:          models.ActionTodoUpdate,
		tooltax.ActionTaskComplete:        models.ActionTaskComplete,
		tooltax.ActionAskUser:             models.ActionAskUser,
		tooltax.ActionUserPrompt:          models.ActionUserPrompt,
		tooltax.ActionAssistantMessage:    models.ActionAssistantMessage,
		tooltax.ActionTurnAborted:         models.ActionTurnAborted,
		tooltax.ActionContextCompacted:    models.ActionContextCompacted,
		tooltax.ActionSystemPrompt:        models.ActionSystemPrompt,
		tooltax.ActionPromptContext:       models.ActionPromptContext,
		tooltax.ActionAPIError:            models.ActionAPIError,
		tooltax.ActionToolFailure:         models.ActionToolFailure,
		tooltax.ActionSubagentStart:       models.ActionSubagentStart,
		tooltax.ActionSubagentStop:        models.ActionSubagentStop,
		tooltax.ActionSessionStart:        models.ActionSessionStart,
		tooltax.ActionSessionEnd:          models.ActionSessionEnd,
		tooltax.ActionNotification:        models.ActionNotification,
		tooltax.ActionCwdChange:           models.ActionCwdChange,
		tooltax.ActionUserPromptExpansion: models.ActionUserPromptExpansion,
		tooltax.ActionPostToolBatch:       models.ActionPostToolBatch,
		tooltax.ActionPermissionRequest:   models.ActionPermissionRequest,
		tooltax.ActionPermissionDenied:    models.ActionPermissionDenied,
		tooltax.ActionPermissionMode:      models.ActionPermissionMode,
		tooltax.ActionSetup:               models.ActionSetup,
		tooltax.ActionInstructionsLoaded:  models.ActionInstructionsLoaded,
		tooltax.ActionConfigChange:        models.ActionConfigChange,
		tooltax.ActionWorktreeCreate:      models.ActionWorktreeCreate,
		tooltax.ActionWorktreeRemove:      models.ActionWorktreeRemove,
		tooltax.ActionRateLimit:           models.ActionRateLimit,
		tooltax.ActionUnknown:             models.ActionUnknown,
		// The eight types WP-T1 introduced to close the measured
		// unknown-bucket gap. They lived only in tooltax until WP-T4
		// promoted them into internal/models; mirroring them here is what
		// makes that promotion checkable in both directions.
		tooltax.ActionSubagentWait: models.ActionSubagentWait,
		tooltax.ActionAgentMessage: models.ActionAgentMessage,
		tooltax.ActionAgentControl: models.ActionAgentControl,
		tooltax.ActionSkillInvoke:  models.ActionSkillInvoke,
		tooltax.ActionSchedule:     models.ActionSchedule,
		tooltax.ActionToolSearch:   models.ActionToolSearch,
		tooltax.ActionStdinWrite:   models.ActionStdinWrite,
		tooltax.ActionHarnessCall:  models.ActionHarnessCall,
	}
	for tt, mm := range pairs {
		if tt != mm {
			t.Errorf("tooltax action type %q != models %q", tt, mm)
		}
	}
	if len(pairs) != 48 {
		t.Errorf("expected 48 mirrored action types, got %d — a constant was added or "+
			"two collapsed onto one key", len(pairs))
	}
	// The mirror must be TOTAL: every canonical action type tooltax
	// registers has to appear above. Without this the count check is
	// satisfiable by adding any 48 pairs, and a newly registered type
	// could ship with no models counterpart at all.
	for _, at := range tooltax.ActionTypes() {
		if _, ok := pairs[at]; !ok {
			t.Errorf("tooltax registers action type %q but it is not mirrored against "+
				"internal/models here — add the pair (and the models.Action* constant "+
				"if it does not exist yet)", at)
		}
	}
	if len(tooltax.ActionTypes()) != len(pairs) {
		t.Errorf("tooltax registers %d action types but %d are mirrored — the mirror "+
			"has drifted", len(tooltax.ActionTypes()), len(pairs))
	}
}

// TestToolIDValuesMatchModels pins the tool ids tooltax re-declares.
// Every tool that has rows in the table must be a real models.Tool*
// value; a typo would silently produce a table nobody can reach.
func TestToolIDValuesMatchModels(t *testing.T) {
	known := map[string]bool{
		models.ToolAider: true, models.ToolAntigravity: true,
		models.ToolAntigravityCLI: true, models.ToolClaudeCode: true,
		models.ToolCline: true, models.ToolClineCLI: true,
		models.ToolCodex: true, models.ToolCommandCode: true,
		models.ToolCopilot: true, models.ToolCopilotCLI: true,
		models.ToolCowork: true, models.ToolCrush: true,
		models.ToolCursor: true, models.ToolDeepSeek: true,
		models.ToolDevin: true,
		models.ToolDroid: true, models.ToolGeminiCLI: true,
		models.ToolGoose: true, models.ToolGrok: true,
		models.ToolHermes: true, models.ToolJunie: true, models.ToolKiloCode: true,
		models.ToolKiloCodeCLI: true, models.ToolKimiCode: true,
		models.ToolKiroCLI: true, models.ToolKiroCrew: true, models.ToolMuse: true,
		models.ToolOpenClaw: true,
		models.ToolOpenCode: true, models.ToolOpenInterpreter: true,
		models.ToolPi: true, models.ToolPoolside: true, models.ToolPrimeAgent: true,
		models.ToolQoder:    true,
		models.ToolQwenCode: true, models.ToolRooCode: true,
		models.ToolZcode: true, models.ToolMistralCode: true,
		models.ToolFreebuff: true, models.ToolZooCode: true,
		models.ToolZed: true,
	}
	for _, tool := range tooltax.Tools() {
		if !known[tool] {
			t.Errorf("tooltax has rows for %q which is not a known models.Tool* value", tool)
		}
	}
}

// TestCategoriesCoverTheDashboardVocabulary pins the Go categories
// against the nine in web/src/lib/actions.ts CATEGORY_COLOR, plus the
// one new category this work package adds.
func TestCategoriesCoverTheDashboardVocabulary(t *testing.T) {
	// Verbatim from web/src/lib/actions.ts:23-33.
	tsCategories := []string{"file", "cmd", "search", "web", "meta", "fail", "agent", "mcp", "user"}
	have := map[string]bool{}
	for _, c := range tooltax.Categories() {
		have[c] = true
	}
	for _, c := range tsCategories {
		if !have[c] {
			t.Errorf("dashboard category %q missing from tooltax.Categories()", c)
		}
	}
	if !have[tooltax.CategorySkill] {
		t.Error("the new `skill` category is missing")
	}
	if len(have) != len(tsCategories)+1 {
		t.Errorf("tooltax has %d categories; want the 9 dashboard ones + skill", len(have))
	}
}
