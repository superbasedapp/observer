package hook

import (
	"bytes"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/tooltax"
)

// TestAntigravityManageTaskIsClassified (WINNODE2 item 9): the Antigravity
// IDE 2.6.0 agent's manage_task call went through the agy PreToolUse gate
// unjudged and was recorded as a coverage gap ("could not classify the
// call"). It is the agent's own task bookkeeping: classified, nothing to
// judge, no unclassified record, on both the CLI and the IDE rows.
func TestAntigravityManageTaskIsClassified(t *testing.T) {
	for _, tool := range []string{models.ToolAntigravityCLI, models.ToolAntigravity} {
		if got, ok := tooltax.ResolveActionType(tool, "manage_task"); !ok || got != models.ActionHarnessCall {
			t.Fatalf("%s manage_task = %q, %v; want %q", tool, got, ok, models.ActionHarnessCall)
		}
		var unclassified []string
		body := []byte(`{"conversationId":"c1","workspacePaths":["C:\\Users\\developer\\projects\\payments-api"],"toolCall":{"name":"manage_task","args":{"task":"x"}}}`)
		res := HandleToolGate(ToolGateRequest{
			Tool: tool, Dialect: ToolGateDialectAntigravity, NativeEvent: "PreToolUse", Label: tool + ":PreToolUse",
			Body: body, Unclassified: func(native string) { unclassified = append(unclassified, native) },
		}, &targetEvaluator{}, nil, &bytes.Buffer{}, &bytes.Buffer{})
		if res.RecordAfterReply != nil {
			res.RecordAfterReply()
		}
		if res.Replied || len(unclassified) != 0 {
			t.Fatalf("%s: manage_task replied=%v unclassified=%v; want an allow with no coverage-gap record", tool, res.Replied, unclassified)
		}
	}
}
