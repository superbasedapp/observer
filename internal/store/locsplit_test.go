package store

import (
	"context"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/loc"
)

// TestAISplitsFollowTheHeadlineBuckets pins the code-vs-comment split on
// the node LOC reads (operator ask 2026-09-28): SessionLOC.AISplit /
// AISidechainSplit and LOCSummary.AISplit are derived by
// internal/loc.SplitAuthored from the SAME deduplicated buckets the
// headlines sum. Docs and config lines, blank / whitespace / unknown
// lines, deleted lines, non-AI actors and editor-echo rows are in neither
// number; a sub-agent child session folds into the parent's sidechain
// split exactly as it folds into the card's sidechain headline.
func TestAISplitsFollowTheHeadlineBuckets(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	pid, err := s.UpsertProject(ctx, "/repo", "")
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC().Add(-time.Hour)

	type seed struct {
		name      string
		session   string
		category  loc.Category
		actor     string
		source    string
		sidechain bool
		stats     loc.Stats
	}
	seeds := []seed{
		// Counted: AI main-line code. Only added+modified code and added
		// comments are authored; every other bucket must stay out.
		{"main code", "p1", loc.CategoryCode, LOCActorAI, LOCSourceEdit, false, loc.Stats{
			AddedCode: 10, ModifiedCode: 2, AddedComment: 4,
			DeletedCode: 9, DeletedComment: 6, Blank: 7, Whitespace: 3, Unknown: 5,
		}},
		// Counted, but almost all blank / whitespace: only the 1 code line.
		{"blank heavy", "p1", loc.CategoryCode, LOCActorAI, LOCSourceWrite, false, loc.Stats{
			AddedCode: 1, Blank: 40, Whitespace: 20,
		}},
		// Excluded: docs and config lines are counted but never code.
		{"docs", "p1", loc.CategoryDocs, LOCActorAI, LOCSourceEdit, false, loc.Stats{AddedCode: 100, AddedComment: 1}},
		{"config", "p1", loc.CategoryConfig, LOCActorAI, LOCSourceEdit, false, loc.Stats{AddedCode: 50, AddedComment: 2}},
		// Counted as sidechain: an inline sub-agent edit on the parent.
		{"inline sidechain", "p1", loc.CategoryCode, LOCActorAI, LOCSourceEdit, true, loc.Stats{AddedCode: 3, AddedComment: 3}},
		// Counted as sidechain on the parent card via the <parent>:agent:
		// fold, although its stored sidechain flag is main-line.
		{"child session", "p1:agent:x", loc.CategoryCode, LOCActorAI, LOCSourceEdit, false, loc.Stats{AddedCode: 5, AddedComment: 1}},
		// Excluded: other actors and echo rows.
		{"human", "p1", loc.CategoryCode, LOCActorHuman, LOCSourceEditor, false, loc.Stats{AddedCode: 70, AddedComment: 30}},
		{"unattributed", "p1", loc.CategoryCode, LOCActorUnknown, LOCSourceEdit, false, loc.Stats{AddedComment: 99}},
		{"echo", "p1", loc.CategoryCode, LOCActorAI, LOCSourceEditorEcho, false, loc.Stats{AddedComment: 500}},
	}
	rows := make([]FileChangeRow, 0, len(seeds))
	for _, sd := range seeds {
		rows = append(rows, FileChangeRow{
			SessionID:    sd.session,
			ProjectID:    pid,
			FilePathHash: sha256Hex(sd.name),
			Language:     string(loc.LangGo),
			Category:     string(sd.category),
			Actor:        sd.actor,
			Confidence:   string(loc.ConfidenceHigh),
			Source:       sd.source,
			Sidechain:    sd.sidechain,
			Stats:        sd.stats,
			Version:      loc.Version,
			SavedAt:      at,
		})
	}
	if _, err := s.InsertFileChanges(ctx, rows); err != nil {
		t.Fatalf("InsertFileChanges: %v", err)
	}

	card, err := s.LoadSessionLOC(ctx, "p1")
	if err != nil {
		t.Fatalf("LoadSessionLOC: %v", err)
	}
	child, err := s.LoadSessionLOC(ctx, "p1:agent:x")
	if err != nil {
		t.Fatalf("LoadSessionLOC child: %v", err)
	}
	sum, err := s.LoadLOCSummary(ctx, 30, 0)
	if err != nil {
		t.Fatalf("LoadLOCSummary: %v", err)
	}

	// The headline each split must reconcile with, recomputed from the
	// buckets the way every surface sums them.
	headline := func(buckets []LOCBucket, side *bool) int64 {
		var st loc.Stats
		for _, b := range buckets {
			if b.Actor != LOCActorAI || b.Category != string(loc.CategoryCode) {
				continue
			}
			if side != nil && b.Sidechain != *side {
				continue
			}
			st.Add(b.Stats)
		}
		return int64(st.AddedCode + st.ModifiedCode)
	}
	mainSide, sideSide := false, true

	cases := []struct {
		name          string
		got           loc.AuthoredSplit
		wantCode      int64
		wantComment   int64
		headlineLines int64
	}{
		{"card main", card.AISplit, 13, 4, headline(card.Buckets, &mainSide)},
		{"card sidechain (inline + folded child)", card.AISidechainSplit, 8, 4, headline(card.Buckets, &sideSide)},
		{"child own card main", child.AISplit, 5, 1, headline(child.Buckets, &mainSide)},
		{"child own card sidechain", child.AISidechainSplit, 0, 0, headline(child.Buckets, &sideSide)},
		{"window summary", sum.AISplit, 21, 8, headline(sum.Buckets, nil)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.got.CodeLines != tc.wantCode || tc.got.CommentLines != tc.wantComment {
				t.Errorf("split = %d code / %d comment, want %d / %d",
					tc.got.CodeLines, tc.got.CommentLines, tc.wantCode, tc.wantComment)
			}
			if tc.got.CodeLines != tc.headlineLines {
				t.Errorf("split code %d != headline %d - the split read different buckets",
					tc.got.CodeLines, tc.headlineLines)
			}
			want := loc.SplitAuthored(tc.wantCode, tc.wantComment)
			switch {
			case want.CommentShare == nil:
				if tc.got.CommentShare != nil {
					t.Errorf("comment_share = %v for an empty scope, want absent", *tc.got.CommentShare)
				}
			case tc.got.CommentShare == nil:
				t.Errorf("comment_share absent, want %v", *want.CommentShare)
			case *tc.got.CommentShare != *want.CommentShare:
				t.Errorf("comment_share = %v, want %v", *tc.got.CommentShare, *want.CommentShare)
			}
		})
	}

	// The Sessions-list read carries the comment half beside its code
	// number, under the same scope (every AI row stored under the id, main
	// and inline sidechain, no child fold).
	lines, err := s.LoadSessionLOCLines(ctx, []string{"p1", "p1:agent:x"})
	if err != nil {
		t.Fatalf("LoadSessionLOCLines: %v", err)
	}
	if got := lines["p1"]; got.AICodeLines != 16 || got.AICommentLines != 7 {
		t.Errorf("list p1 = %d code / %d comment, want 16 / 7", got.AICodeLines, got.AICommentLines)
	}
	if got := lines["p1:agent:x"]; got.AICodeLines != 5 || got.AICommentLines != 1 {
		t.Errorf("list child = %d code / %d comment, want 5 / 1", got.AICodeLines, got.AICommentLines)
	}
}
