package guard

import "github.com/marmutapp/superbased-observer/internal/models"

// ReplayDetailActionTypes are the action types whose row detail (Target,
// TurnIndex, PromptText) EvaluateActions reads: the bookkeeping row it acts
// on (context compaction clears taint), the captured prompt (the post-hoc
// prompt lane) and every type classifyKind evaluates. Every other action is
// skipped before any of its fields is read, so a replay loader may present
// such a row with its identity alone (store.LoadGuardReplayInputs, demo bug
// #14 / R3-5: the skipped half of a week's history then never leaves the
// timestamp index). TestReplayDetailActionTypesCoverEvaluation pins the list
// against classifyKind over every models action type.
func ReplayDetailActionTypes() []string {
	return []string{
		models.ActionContextCompacted,
		models.ActionUserPrompt,
		models.ActionRunCommand,
		models.ActionReadFile,
		models.ActionWriteFile,
		models.ActionEditFile,
		models.ActionMCPCall,
		models.ActionConfigChange,
		models.ActionWebFetch,
		models.ActionWebSearch,
		models.ActionBrowserAction,
	}
}
