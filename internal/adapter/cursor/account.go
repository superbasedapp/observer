package cursor

import (
	"encoding/json"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// BuildAccountObservations captures Cursor's native user_email login snapshot.
// No machine-wide cache is consulted and no current login labels old transcripts.
func BuildAccountObservations(event string, body []byte, at time.Time) []models.ToolAccountObservation {
	var p struct {
		Email        string `json:"user_email"`
		SessionID    string `json:"conversation_id"`
		GenerationID string `json:"generation_id"`
	}
	if json.Unmarshal(body, &p) != nil || p.Email == "" || p.SessionID == "" || p.GenerationID == "" {
		return nil
	}
	stages := map[string]string{
		EventBeforeSubmitPrompt: "submission", EventPreToolUse: "activity", EventPostToolUse: "activity",
		EventBeforeShellCommand: "activity", EventAfterShellExecution: "activity",
		EventBeforeMCPExecution: "activity", EventAfterMCPExecution: "activity",
		EventBeforeReadFile: "activity", EventAfterFileEdit: "activity",
		EventPostToolUseFailure: "activity", EventAfterAgentResponse: "activity", EventStop: "stop",
	}
	stage, ok := stages[event]
	if !ok {
		return nil
	}
	id, role := p.GenerationID, "assistant"
	if stage == "submission" {
		id = "user:" + id
		role = "user"
	}
	return []models.ToolAccountObservation{{SessionID: p.SessionID, Tool: models.ToolCursor, BindingKind: "message", BindingID: id, Role: role, Email: p.Email, Source: "cursor_hook_user_email", Scope: "native_hook", Stage: stage, ObservedAt: at}}
}
