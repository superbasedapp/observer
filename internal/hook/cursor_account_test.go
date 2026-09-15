package hook

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/scrub"
	"github.com/marmutapp/superbased-observer/internal/store"
)

type accountCursorSink struct {
	fakeSink
	observations []models.ToolAccountObservation
	reply        *bytes.Buffer
	t            *testing.T
}

func (s *accountCursorSink) Ingest(ctx context.Context, events []models.ToolEvent, tokens []models.TokenEvent, opts store.IngestOptions) (store.IngestResult, error) {
	if s.reply.Len() == 0 {
		s.t.Fatal("capture preceded guard reply")
	}
	s.observations = append(s.observations, opts.ToolAccounts...)
	return s.fakeSink.Ingest(ctx, events, tokens, opts)
}

func TestCursorAccountBranches(t *testing.T) {
	profile := t.TempDir()
	t.Setenv("HOME", profile)
	t.Setenv("USERPROFILE", profile)
	for _, tc := range []struct{ event, stage, role string }{{"beforeSubmitPrompt", "submission", "user"}, {"preToolUse", "activity", "assistant"}, {"postToolUse", "activity", "assistant"}, {"afterShellExecution", "activity", "assistant"}, {"afterAgentResponse", "activity", "assistant"}, {"stop", "stop", "assistant"}} {
		t.Run(tc.event, func(t *testing.T) {
			var reply, stderr bytes.Buffer
			s := &accountCursorSink{reply: &reply, t: t}
			body := fmt.Sprintf(`{"conversation_id":"s","generation_id":"g","user_email":"first@example.invalid","workspace_roots":["/tmp/accounts"],"tool_name":"Read","text":"done","prompt":"hello","hook_event_name":%q}`, tc.event)
			HandleCursorEvent(tc.event, s, scrub.New(), bytes.NewBufferString(body), &reply, &stderr, time.Second)
			if len(s.observations) != 1 || s.observations[0].Stage != tc.stage || s.observations[0].Role != tc.role {
				t.Fatalf("observations %+v; %s", s.observations, stderr.String())
			}
		})
	}
}
