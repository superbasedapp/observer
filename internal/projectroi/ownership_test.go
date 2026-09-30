package projectroi

import (
	"math"
	"testing"
	"time"
)

// TestOwnership covers one case per row of the ownership table in
// ownership.go (O1-O7) plus the share-basis rule.
func TestOwnership(t *testing.T) {
	commitAt := t0.Add(24 * time.Hour)
	reachable := func(id int64, paths ...string) Commit {
		c := Commit{ID: id, SHA: "sha", CommittedAt: commitAt, Reachable: true}
		for _, p := range paths {
			c.Files = append(c.Files, CommitFile{PathHash: p})
		}
		return c
	}
	p := func(action int64, sess string, at time.Time) Prompt {
		return Prompt{ActionID: action, SessionID: sess, At: at}
	}
	e := func(sess, path string, at time.Time, code, comment int, cat string) Edit {
		return Edit{ActionID: 100, SessionID: sess, At: at, PathHash: path, AddedCode: code, AddedComment: comment, Category: cat}
	}

	cases := []struct {
		name       string
		prompts    []Prompt
		edits      []Edit
		commit     Commit
		wantOwner  string
		wantReason string
		wantBasis  string
		wantShares map[string]float64
	}{
		{
			name:       "O1 merge commit has no owner",
			prompts:    []Prompt{p(1, "s1", t0)},
			edits:      []Edit{e("s1", "a", t0.Add(time.Minute), 5, 0, "code")},
			commit:     Commit{ID: 1, CommittedAt: commitAt, Reachable: true, IsMerge: true, Files: []CommitFile{{PathHash: "a"}}},
			wantReason: OwnerNoneMerge,
		},
		{
			name:       "O2 unreachable commit has no owner",
			prompts:    []Prompt{p(1, "s1", t0)},
			edits:      []Edit{e("s1", "a", t0.Add(time.Minute), 5, 0, "code")},
			commit:     Commit{ID: 1, CommittedAt: commitAt, Reachable: false, Files: []CommitFile{{PathHash: "a"}}},
			wantReason: OwnerNoneUnreachable,
		},
		{
			// Review 2026-09-29 finding 8: a teammate's commit pulled into
			// the checkout touched the same file the local session edited.
			// Before the author check the local session "owned" it.
			name:       "O2b foreign-author commit has no owner",
			prompts:    []Prompt{p(1, "s1", t0)},
			edits:      []Edit{e("s1", "a", t0.Add(time.Minute), 5, 0, "code")},
			commit:     Commit{ID: 1, CommittedAt: commitAt, Reachable: true, ForeignAuthor: true, Files: []CommitFile{{PathHash: "a"}}},
			wantReason: OwnerNoneForeignAuthor,
		},
		{
			// An UNKNOWN local identity leaves ForeignAuthor false: the rule
			// keeps its pre-author-check behaviour (the loader's contract).
			name:       "O2b unknown local identity keeps the pre-check owner",
			prompts:    []Prompt{p(1, "s1", t0)},
			edits:      []Edit{e("s1", "a", t0.Add(time.Minute), 5, 0, "code")},
			commit:     reachable(1, "a"),
			wantOwner:  "s1",
			wantReason: OwnerSoleContributor,
			wantBasis:  ShareBasisCodeLines,
			wantShares: map[string]float64{"s1": 1},
		},
		{
			name:       "O3 commit no AI edit reached is human, never guessed",
			prompts:    []Prompt{p(1, "s1", t0)},
			edits:      []Edit{e("s1", "a", t0.Add(time.Minute), 5, 0, "code")},
			commit:     reachable(1, "zzz"),
			wantReason: OwnerNoneNoAIEdits,
		},
		{
			name:       "sole contributor owns",
			prompts:    []Prompt{p(1, "s1", t0)},
			edits:      []Edit{e("s1", "a", t0.Add(time.Minute), 5, 2, "code")},
			commit:     reachable(1, "a", "human-only"),
			wantOwner:  "s1",
			wantReason: OwnerSoleContributor,
			wantBasis:  ShareBasisCodeLines,
			wantShares: map[string]float64{"s1": 1},
		},
		{
			name:       "O4 most code lines wins even with fewer files",
			prompts:    []Prompt{p(1, "s1", t0), p(2, "s2", t0.Add(time.Hour))},
			edits:      []Edit{e("s1", "a", t0.Add(time.Minute), 10, 0, "code"), e("s1", "b", t0.Add(time.Minute), 10, 0, "code"), e("s2", "c", t0.Add(2*time.Hour), 60, 0, "code")},
			commit:     reachable(1, "a", "b", "c"),
			wantOwner:  "s2",
			wantReason: OwnerMostCodeLines,
			wantBasis:  ShareBasisCodeLines,
			wantShares: map[string]float64{"s1": 0.25, "s2": 0.75},
		},
		{
			name:    "O4 comment lines do not count toward ownership",
			prompts: []Prompt{p(1, "s1", t0), p(2, "s2", t0.Add(time.Hour))},
			// s1 wrote 200 comment lines and 3 code lines; s2 wrote 4 code lines.
			edits:      []Edit{e("s1", "a", t0.Add(time.Minute), 3, 200, "code"), e("s2", "b", t0.Add(2*time.Hour), 4, 0, "code")},
			commit:     reachable(1, "a", "b"),
			wantOwner:  "s2",
			wantReason: OwnerMostCodeLines,
			wantBasis:  ShareBasisCodeLines,
		},
		{
			name:       "O5 tie on lines, most files wins",
			prompts:    []Prompt{p(1, "s1", t0), p(2, "s2", t0.Add(time.Hour))},
			edits:      []Edit{e("s1", "a", t0.Add(time.Minute), 5, 0, "code"), e("s2", "b", t0.Add(2*time.Hour), 3, 0, "code"), e("s2", "c", t0.Add(2*time.Hour), 2, 0, "code")},
			commit:     reachable(1, "a", "b", "c"),
			wantOwner:  "s2",
			wantReason: OwnerMostFiles,
			wantBasis:  ShareBasisCodeLines,
			wantShares: map[string]float64{"s1": 0.5, "s2": 0.5},
		},
		{
			name:       "O6 tie on lines and files, earliest prompt wins",
			prompts:    []Prompt{p(1, "s-late", t0.Add(time.Hour)), p(2, "s-early", t0)},
			edits:      []Edit{e("s-late", "a", t0.Add(2*time.Hour), 5, 0, "code"), e("s-early", "b", t0.Add(time.Minute), 5, 0, "code")},
			commit:     reachable(1, "a", "b"),
			wantOwner:  "s-early",
			wantReason: OwnerEarliestPrompt,
			wantBasis:  ShareBasisCodeLines,
		},
		{
			name:       "O7 full tie, smallest session id wins",
			prompts:    []Prompt{p(1, "s-b", t0), p(2, "s-a", t0)},
			edits:      []Edit{e("s-b", "a", t0.Add(time.Minute), 5, 0, "code"), e("s-a", "b", t0.Add(time.Minute), 5, 0, "code")},
			commit:     reachable(1, "a", "b"),
			wantOwner:  "s-a",
			wantReason: OwnerSessionID,
			wantBasis:  ShareBasisCodeLines,
		},
		{
			name:       "docs-only contributions share on the files basis",
			prompts:    []Prompt{p(1, "s1", t0), p(2, "s2", t0.Add(time.Hour))},
			edits:      []Edit{e("s1", "readme", t0.Add(time.Minute), 400, 0, "docs"), e("s2", "cfg", t0.Add(2*time.Hour), 30, 0, "config"), e("s2", "notes", t0.Add(2*time.Hour), 9, 0, "docs")},
			commit:     reachable(1, "readme", "cfg", "notes"),
			wantOwner:  "s2",
			wantReason: OwnerMostFiles,
			wantBasis:  ShareBasisFiles,
			wantShares: map[string]float64{"s1": 1.0 / 3, "s2": 2.0 / 3},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			commits := []Commit{tc.commit}
			link := Link(tc.prompts, tc.edits, commits, Options{})
			got := Ownership(link, commits)[tc.commit.ID]
			if got.OwnerSessionID != tc.wantOwner || got.Reason != tc.wantReason {
				t.Fatalf("owner=%q reason=%q, want owner=%q reason=%q (%+v)", got.OwnerSessionID, got.Reason, tc.wantOwner, tc.wantReason, got)
			}
			if got.ShareBasis != tc.wantBasis {
				t.Fatalf("basis=%q, want %q", got.ShareBasis, tc.wantBasis)
			}
			if tc.wantOwner == "" {
				if len(got.Contributors) != 0 {
					t.Fatalf("no-owner commit carries contributors: %+v", got.Contributors)
				}
				return
			}
			if got.Contributors[0].SessionID != tc.wantOwner {
				t.Fatalf("Contributors[0] = %q, want the owner %q", got.Contributors[0].SessionID, tc.wantOwner)
			}
			sum := 0.0
			for _, c := range got.Contributors {
				sum += c.Share
				if want, ok := tc.wantShares[c.SessionID]; ok && math.Abs(c.Share-want) > 1e-9 {
					t.Fatalf("share[%s] = %v, want %v", c.SessionID, c.Share, want)
				}
			}
			if math.Abs(sum-1) > 1e-9 {
				t.Fatalf("shares sum to %v, want 1", sum)
			}
		})
	}
}

// TestOwnershipDeterministic re-runs a tied scenario with shuffled inputs
// and requires the same owner every time.
func TestOwnershipDeterministic(t *testing.T) {
	commitAt := t0.Add(24 * time.Hour)
	commits := []Commit{{ID: 7, CommittedAt: commitAt, Reachable: true, Files: []CommitFile{{PathHash: "a"}, {PathHash: "b"}, {PathHash: "c"}}}}
	prompts := []Prompt{{ActionID: 1, SessionID: "s3", At: t0}, {ActionID: 2, SessionID: "s1", At: t0}, {ActionID: 3, SessionID: "s2", At: t0}}
	edits := []Edit{
		{SessionID: "s3", At: t0.Add(time.Minute), PathHash: "a", AddedCode: 5},
		{SessionID: "s1", At: t0.Add(time.Minute), PathHash: "b", AddedCode: 5},
		{SessionID: "s2", At: t0.Add(time.Minute), PathHash: "c", AddedCode: 5},
	}
	for i := 0; i < 20; i++ {
		// rotate both slices
		prompts = append(prompts[1:], prompts[0])
		edits = append(edits[1:], edits[0])
		got := Ownership(Link(prompts, edits, commits, Options{}), commits)[7]
		if got.OwnerSessionID != "s1" || got.Reason != OwnerSessionID {
			t.Fatalf("iteration %d: owner=%q reason=%q, want s1/session_id", i, got.OwnerSessionID, got.Reason)
		}
	}
}

// TestOwnershipSidechainFoldsToParent pins R4.1: the loader stamps a
// sub-agent edit with its PARENT session id, so the parent owns.
func TestOwnershipSidechainFoldsToParent(t *testing.T) {
	commits := []Commit{{ID: 1, CommittedAt: t0.Add(24 * time.Hour), Reachable: true, Files: []CommitFile{{PathHash: "a"}}}}
	prompts := []Prompt{{ActionID: 1, SessionID: "parent", At: t0}}
	edits := []Edit{{SessionID: "parent", At: t0.Add(time.Minute), PathHash: "a", AddedCode: 9, Sidechain: true}}
	got := Ownership(Link(prompts, edits, commits, Options{}), commits)[1]
	if got.OwnerSessionID != "parent" {
		t.Fatalf("owner = %q, want parent", got.OwnerSessionID)
	}
}

func TestCommitsBySession(t *testing.T) {
	commitAt := t0.Add(24 * time.Hour)
	commits := []Commit{
		{ID: 1, SHA: "c1", CommittedAt: commitAt, Reachable: true, Files: []CommitFile{{PathHash: "a"}, {PathHash: "b"}}},
		{ID: 2, SHA: "c2", CommittedAt: commitAt.Add(time.Hour), Reachable: true, Files: []CommitFile{{PathHash: "x"}}},
	}
	prompts := []Prompt{{ActionID: 1, SessionID: "s1", At: t0}, {ActionID: 2, SessionID: "s2", At: t0.Add(time.Hour)}}
	edits := []Edit{
		{SessionID: "s1", At: t0.Add(time.Minute), PathHash: "a", AddedCode: 50, AddedComment: 5},
		{SessionID: "s2", At: t0.Add(2 * time.Hour), PathHash: "b", AddedCode: 5},
	}
	by := CommitsBySession(Ownership(Link(prompts, edits, commits, Options{}), commits))
	if len(by["s1"]) != 1 || !by["s1"][0].Owner || by["s1"][0].Contribution.CommentLines != 5 {
		t.Fatalf("s1 = %+v, want one owned commit with 5 comment lines", by["s1"])
	}
	if len(by["s2"]) != 1 || by["s2"][0].Owner || by["s2"][0].OwnerSessionID != "s1" {
		t.Fatalf("s2 = %+v, want one co-contributed commit owned by s1", by["s2"])
	}
}

// TestEditCodeLinesByCategory pins the one code-line definition: docs and
// config files reach commits but contribute no code or comment lines.
func TestEditCodeLinesByCategory(t *testing.T) {
	cases := []struct {
		cat                   string
		wantCode, wantComment int
	}{
		{"", 7, 2}, {"code", 7, 2}, {"docs", 0, 0}, {"config", 0, 0}, {"generated", 0, 0},
	}
	for _, tc := range cases {
		e := Edit{AddedCode: 5, ModifiedCode: 2, AddedComment: 2, Category: tc.cat}
		if e.CodeLines() != tc.wantCode || e.CommentLines() != tc.wantComment {
			t.Fatalf("category %q: code=%d comment=%d, want %d/%d", tc.cat, e.CodeLines(), e.CommentLines(), tc.wantCode, tc.wantComment)
		}
	}
}
