package store

import (
	"context"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

func TestCursorUsageReplayAndHookOverlap(t *testing.T) {
	for _, hookFirst := range []bool{true, false} {
		t.Run(map[bool]string{true: "hook_first", false: "log_first"}[hookFirst], func(t *testing.T) {
			st, _ := newTestStore(t)
			ctx := context.Background()
			req := "6904f178-1ee4-4ed0-a4aa-9ca8882d1c07"
			base := models.TokenEvent{SessionID: "cursor-usage", ProjectRoot: t.TempDir(), Timestamp: time.Now().UTC(), Tool: models.ToolCursor, Model: "composer-2.5", InputTokens: 6263, OutputTokens: 39, CacheReadTokens: 8014, Reliability: models.ReliabilityAccurate}
			log := base
			log.Source = models.TokenSourceJSONL
			log.SourceFile = "native.log"
			log.SourceEventID = "cursor-cli-outcome:" + req
			log.MessageID = req
			hook := base
			hook.Source = models.TokenSourceHook
			hook.SourceFile = "cursor:hook"
			hook.MessageID = req + "-0-de6k"
			hook.SourceEventID = hook.MessageID + ":stop"
			unrelated := hook
			unrelated.MessageID = "different-request"
			unrelated.SourceEventID = "different-request:stop"
			unrelated.InputTokens = 17
			copied := log
			copied.SourceFile = "recovered/native.log"
			sequence := []models.TokenEvent{log, hook, unrelated, log, hook, copied}
			if hookFirst {
				sequence[0], sequence[1] = hook, log
			}
			for _, ev := range sequence {
				if _, err := st.Ingest(ctx, nil, []models.TokenEvent{ev}, IngestOptions{}); err != nil {
					t.Fatal(err)
				}
			}
			var n, input int64
			if err := st.db.QueryRowContext(ctx, "SELECT COUNT(*), SUM(input_tokens) FROM token_usage WHERE session_id = 'cursor-usage'").Scan(&n, &input); err != nil {
				t.Fatal(err)
			}
			if n != 2 || input != 6280 {
				t.Fatalf("overlap/replay: rows=%d input=%d", n, input)
			}
			if note, err := st.CursorUsageNote(ctx, "cursor-usage"); err != nil || note != "" {
				t.Fatalf("unexpected partial note %q %v", note, err)
			}
			partial := log
			partial.SourceEventID = "cursor-cli-outcome:final-retry"
			partial.MessageID = "final-retry"
			partial.Reliability = models.ReliabilityUnreliable
			if _, err := st.Ingest(ctx, nil, []models.TokenEvent{partial}, IngestOptions{}); err != nil {
				t.Fatal(err)
			}
			if note, err := st.CursorUsageNote(ctx, "cursor-usage"); err != nil || note == "" {
				t.Fatalf("missing partial note %q %v", note, err)
			}
		})
	}
}
