package store

import (
	"context"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

func TestCapturedSessionForTool(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	project, err := s.UpsertProject(ctx, "/project", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertSession(ctx, models.Session{ID: "old-session", ProjectID: project, Tool: "codex", StartedAt: time.Now().Add(-24 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, id, tool string
		want           bool
	}{
		{"resumed captured session", "old-session", "codex", true},
		{"canonical tool case", "old-session", "CoDeX", true},
		{"wrong tool", "old-session", "claude-code", false},
		{"capture pending", "not-captured", "codex", false},
		{"empty identity", "", "codex", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := s.CapturedSessionForTool(ctx, tc.id, tc.tool)
			if err != nil || got != tc.want {
				t.Fatalf("captured = %v, err = %v; want %v", got, err, tc.want)
			}
		})
	}
}
