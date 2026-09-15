package store

import (
	"context"
	"fmt"
	"testing"
)

// TestLoadCloudEnrichedTitles pins the batched sessions-list lookup: it must
// return the newest non-superseded result's title for an enriched session,
// omit sessions with no cloud_results row, and never error on an empty input.
func TestLoadCloudEnrichedTitles(t *testing.T) {
	s, _ := cloudTestStore(t)
	ctx := context.Background()

	seedEligibleSession(t, s, "sess-enriched")
	seedEligibleSession(t, s, "sess-plain")
	seedEligibleSession(t, s, "sess-no-title")

	if _, err := s.UpsertCloudResult(ctx, CloudResult{
		SessionID:     "sess-enriched",
		SchemaVersion: "session_enrichment.v2-candidate",
		ResultJSON:    `{"title":"Fix the flaky proxy test"}`,
	}); err != nil {
		t.Fatalf("UpsertCloudResult: %v", err)
	}
	// A result with no title field at all — COALESCE(json_extract(...), '')
	// must yield "" rather than an error or a missing map entry.
	if _, err := s.UpsertCloudResult(ctx, CloudResult{
		SessionID:     "sess-no-title",
		SchemaVersion: "session_enrichment.v2-candidate",
		ResultJSON:    `{"summary":"no title here"}`,
	}); err != nil {
		t.Fatalf("UpsertCloudResult (no title): %v", err)
	}

	t.Run("empty input", func(t *testing.T) {
		got, err := s.LoadCloudEnrichedTitles(ctx, nil)
		if err != nil {
			t.Fatalf("LoadCloudEnrichedTitles(nil): %v", err)
		}
		if len(got) != 0 {
			t.Fatalf("LoadCloudEnrichedTitles(nil) = %v, want empty map", got)
		}
	})

	t.Run("mixed enriched and plain", func(t *testing.T) {
		got, err := s.LoadCloudEnrichedTitles(ctx, []string{"sess-enriched", "sess-plain", "sess-no-title"})
		if err != nil {
			t.Fatalf("LoadCloudEnrichedTitles: %v", err)
		}
		if title, ok := got["sess-enriched"]; !ok || title != "Fix the flaky proxy test" {
			t.Fatalf("sess-enriched title = (%q, %v), want (%q, true)", title, ok, "Fix the flaky proxy test")
		}
		if title, ok := got["sess-no-title"]; !ok || title != "" {
			t.Fatalf("sess-no-title = (%q, %v), want (\"\", true)", title, ok)
		}
		if _, ok := got["sess-plain"]; ok {
			t.Fatalf("sess-plain unexpectedly present in %v — unenriched sessions must be absent", got)
		}
	})

	t.Run("regeneration supersedes the old title", func(t *testing.T) {
		if _, err := s.UpsertCloudResult(ctx, CloudResult{
			SessionID:     "sess-enriched",
			SchemaVersion: "session_enrichment.v2-candidate",
			ResultJSON:    `{"title":"Second pass: fix the flaky proxy test"}`,
		}); err != nil {
			t.Fatalf("UpsertCloudResult (regeneration): %v", err)
		}
		got, err := s.LoadCloudEnrichedTitles(ctx, []string{"sess-enriched"})
		if err != nil {
			t.Fatalf("LoadCloudEnrichedTitles: %v", err)
		}
		if title := got["sess-enriched"]; title != "Second pass: fix the flaky proxy test" {
			t.Fatalf("sess-enriched title after regeneration = %q, want the newest title", title)
		}
	})

	t.Run("unknown session id is a routine miss", func(t *testing.T) {
		got, err := s.LoadCloudEnrichedTitles(ctx, []string{"sess-never-existed"})
		if err != nil {
			t.Fatalf("LoadCloudEnrichedTitles: %v", err)
		}
		if _, ok := got["sess-never-existed"]; ok {
			t.Fatalf("unknown session id unexpectedly present in %v", got)
		}
	})

	t.Run("chunking across the batch-size boundary", func(t *testing.T) {
		// Seed enough sessions to force LoadCloudEnrichedTitles to split the
		// IN (...) list across more than one chunk, and confirm every one of
		// them still round-trips its title.
		const n = cloudEnrichedTitlesChunkSize + 5
		ids := make([]string, 0, n)
		for i := 0; i < n; i++ {
			id := fmt.Sprintf("sess-chunk-%d", i)
			ids = append(ids, id)
			seedEligibleSession(t, s, id)
			if _, err := s.UpsertCloudResult(ctx, CloudResult{
				SessionID:     id,
				SchemaVersion: "session_enrichment.v2-candidate",
				ResultJSON:    fmt.Sprintf(`{"title":"title-%d"}`, i),
			}); err != nil {
				t.Fatalf("UpsertCloudResult(%s): %v", id, err)
			}
		}
		got, err := s.LoadCloudEnrichedTitles(ctx, ids)
		if err != nil {
			t.Fatalf("LoadCloudEnrichedTitles (chunked): %v", err)
		}
		if len(got) != n {
			t.Fatalf("LoadCloudEnrichedTitles (chunked) returned %d entries, want %d", len(got), n)
		}
		for i, id := range ids {
			want := fmt.Sprintf("title-%d", i)
			if got[id] != want {
				t.Fatalf("chunked title for %s = %q, want %q", id, got[id], want)
			}
		}
	})
}
