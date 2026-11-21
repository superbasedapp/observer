package store

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

func TestLoadTokenSources(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	at := time.Date(2026, 10, 31, 10, 0, 0, 0, time.UTC)
	tok := func(sess, eventID, source string) models.TokenEvent {
		return models.TokenEvent{
			SourceFile: "/tmp/" + sess, SourceEventID: eventID, SessionID: sess, ProjectRoot: "/tmp/fold",
			Timestamp: at, Tool: models.ToolClaudeCode, Model: "claude-opus-4", InputTokens: 10, OutputTokens: 5,
			Source: source, Reliability: models.ReliabilityAccurate,
		}
	}
	if _, err := s.Ingest(ctx, nil, []models.TokenEvent{
		tok("c1", "c1-t1", models.TokenSourceJSONL),
		tok("c1", "c1-run", models.TokenSourceSessionSummary),
		tok("c2", "c2-otel", models.TokenSourceOTel),
		tok("other", "o-run", models.TokenSourceSessionSummary),
	}, IngestOptions{}); err != nil {
		t.Fatal(err)
	}
	got, err := s.LoadTokenSources(ctx, []string{"c1", "c2", "missing"})
	if err != nil {
		t.Fatal(err)
	}
	want := map[TokenSourceKey]string{
		{SessionID: "c1", SourceEventID: "c1-run"}:  models.TokenSourceSessionSummary,
		{SessionID: "c2", SourceEventID: "c2-otel"}: models.TokenSourceOTel,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	empty, err := s.LoadTokenSources(ctx, nil)
	if err != nil || len(empty) != 0 {
		t.Errorf("no sessions: got %v, %v", empty, err)
	}
}
