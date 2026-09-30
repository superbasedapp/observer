package projectroi

import (
	"testing"
	"time"
)

func tm(s string) time.Time {
	ts, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return ts
}

var t0 = tm("2026-01-01T00:00:00Z")

// commitFileMap turns a chain's Files into pathHash -> CommitID for
// terse assertions.
func commitFileMap(files []ChainFile) map[string]int64 {
	m := make(map[string]int64, len(files))
	for _, f := range files {
		m[f.PathHash] = f.CommitID
	}
	return m
}

func supersededMap(files []ChainFile) map[string]bool {
	m := make(map[string]bool, len(files))
	for _, f := range files {
		m[f.PathHash] = f.Superseded
	}
	return m
}

// TestLink covers one scenario per §2 R4 line of
// docs/plans/projects-page-roi-and-commit-alignment-plan-2026-09-21.md.
func TestLink(t *testing.T) {
	cases := []struct {
		name        string
		prompts     []Prompt
		edits       []Edit
		commits     []Commit
		opts        Options
		wantOrphans int
		wantStatus  map[int64]Status
		wantFiles   map[int64]map[string]int64 // action id -> pathHash -> want CommitID
		wantSuper   map[int64]map[string]bool  // action id -> pathHash -> want Superseded
	}{
		{
			// R4.4/R4.5: a single file, one qualifying commit -> committed.
			name: "R4.4/R4.5 single file reaches its commit -> committed",
			prompts: []Prompt{
				{ActionID: 1, SessionID: "s1", At: t0},
			},
			edits: []Edit{
				{ActionID: 11, SessionID: "s1", At: t0.Add(time.Hour), PathHash: "a", AddedCode: 5},
			},
			commits: []Commit{
				{
					ID: 100, SHA: "c100", CommittedAt: t0.Add(2 * time.Hour), Reachable: true,
					Files: []CommitFile{{PathHash: "a"}},
				},
			},
			wantStatus: map[int64]Status{1: StatusCommitted},
			wantFiles:  map[int64]map[string]int64{1: {"a": 100}},
		},
		{
			// R4.5: two files, only one reaches a commit -> partial.
			name: "R4.5 one of two files reaches -> partial",
			prompts: []Prompt{
				{ActionID: 2, SessionID: "s2", At: t0},
			},
			edits: []Edit{
				{ActionID: 21, SessionID: "s2", At: t0.Add(time.Hour), PathHash: "x"},
				{ActionID: 22, SessionID: "s2", At: t0.Add(90 * time.Minute), PathHash: "y"},
			},
			commits: []Commit{
				{
					ID: 200, SHA: "c200", CommittedAt: t0.Add(2 * time.Hour), Reachable: true,
					Files: []CommitFile{{PathHash: "x"}},
				},
			},
			wantStatus: map[int64]Status{2: StatusPartial},
			wantFiles:  map[int64]map[string]int64{2: {"x": 200, "y": 0}},
		},
		{
			// R4.5: a file with no commit at all -> uncommitted.
			name: "R4.5 no commit anywhere -> uncommitted",
			prompts: []Prompt{
				{ActionID: 3, SessionID: "s3", At: t0},
			},
			edits: []Edit{
				{ActionID: 31, SessionID: "s3", At: t0.Add(time.Hour), PathHash: "z"},
			},
			wantStatus: map[int64]Status{3: StatusUncommitted},
			wantFiles:  map[int64]map[string]int64{3: {"z": 0}},
		},
		{
			// R4.5: a prompt with zero AI edits -> no_edits.
			name: "R4.5 prompt with no edits -> no_edits",
			prompts: []Prompt{
				{ActionID: 4, SessionID: "s4", At: t0},
			},
			wantStatus: map[int64]Status{4: StatusNoEdits},
		},
		{
			// R4.2: an edit with no prompt before it in its session is an
			// orphan, never linked.
			name: "R4.2 edit with no prior prompt is an orphan",
			edits: []Edit{
				{ActionID: 51, SessionID: "s5", At: t0, PathHash: "o"},
			},
			wantOrphans: 1,
		},
		{
			// R4.1/F20: a sidechain edit belongs to the parent session's
			// prompt and links exactly like a normal edit.
			name: "F20 sidechain edit belongs to the parent session's prompt",
			prompts: []Prompt{
				{ActionID: 6, SessionID: "s6", At: t0},
			},
			edits: []Edit{
				{ActionID: 61, SessionID: "s6", At: t0.Add(time.Hour), PathHash: "sc", Sidechain: true},
			},
			commits: []Commit{
				{
					ID: 600, SHA: "c600", CommittedAt: t0.Add(2 * time.Hour), Reachable: true,
					Files: []CommitFile{{PathHash: "sc"}},
				},
			},
			wantStatus: map[int64]Status{6: StatusCommitted},
			wantFiles:  map[int64]map[string]int64{6: {"sc": 600}},
		},
		{
			// R4.3/F6: two prompts in two sessions edit the same file
			// before one commit — only the later prompt's file reaches,
			// the earlier is superseded.
			name: "R4.3 two prompts two sessions same file — later survives, earlier superseded",
			prompts: []Prompt{
				{ActionID: 7, SessionID: "sA", At: t0},
				{ActionID: 8, SessionID: "sB", At: t0.Add(20 * time.Minute)},
			},
			edits: []Edit{
				{ActionID: 71, SessionID: "sA", At: t0.Add(10 * time.Minute), PathHash: "shared"},
				{ActionID: 81, SessionID: "sB", At: t0.Add(30 * time.Minute), PathHash: "shared"},
			},
			commits: []Commit{
				{
					ID: 700, SHA: "c700", CommittedAt: t0.Add(time.Hour), Reachable: true,
					Files: []CommitFile{{PathHash: "shared"}},
				},
			},
			wantStatus: map[int64]Status{7: StatusSuperseded, 8: StatusCommitted},
			wantFiles:  map[int64]map[string]int64{7: {"shared": 0}, 8: {"shared": 700}},
			wantSuper:  map[int64]map[string]bool{7: {"shared": true}, 8: {"shared": false}},
		},
		{
			// P1/F#2: C0 -> P1 edits f -> P2 edits f -> C1. C0 predates
			// BOTH prompts and must never be used as "the earliest commit
			// that carries" P1's edit (the old bug used refs[0], the
			// path's globally-earliest carrying commit, so P1 could never
			// be superseded here). P1's own qualifying commit is C1 (the
			// earliest commit after P1's own edit); P2 edited the same
			// file before C1, so P1 is superseded and P2 reaches C1.
			name: "P1/F2 earlier unrelated commit must not stand in for the prompt's own qualifying commit",
			prompts: []Prompt{
				{ActionID: 13, SessionID: "sC", At: t0.Add(time.Minute)},
				{ActionID: 14, SessionID: "sD", At: t0.Add(3 * time.Minute)},
			},
			edits: []Edit{
				{ActionID: 131, SessionID: "sC", At: t0.Add(2 * time.Minute), PathHash: "f"},
				{ActionID: 141, SessionID: "sD", At: t0.Add(4 * time.Minute), PathHash: "f"},
			},
			commits: []Commit{
				{
					ID: 1200, SHA: "c0", CommittedAt: t0, Reachable: true,
					Files: []CommitFile{{PathHash: "f"}},
				},
				{
					ID: 1201, SHA: "c1", CommittedAt: t0.Add(5 * time.Minute), Reachable: true,
					Files: []CommitFile{{PathHash: "f"}},
				},
			},
			wantStatus: map[int64]Status{13: StatusSuperseded, 14: StatusCommitted},
			wantFiles:  map[int64]map[string]int64{13: {"f": 0}, 14: {"f": 1201}},
			wantSuper:  map[int64]map[string]bool{13: {"f": true}, 14: {"f": false}},
		},
		{
			// P1/F#2: two prompts at the EXACT same timestamp editing the
			// same file must never supersede each other — R4.3 requires a
			// STRICTLY later prompt. Both reach the same commit.
			name: "P1/F2 equal-timestamp prompts never supersede one another",
			prompts: []Prompt{
				{ActionID: 15, SessionID: "sE", At: t0},
				{ActionID: 16, SessionID: "sF", At: t0},
			},
			edits: []Edit{
				{ActionID: 151, SessionID: "sE", At: t0.Add(time.Minute), PathHash: "g"},
				{ActionID: 161, SessionID: "sF", At: t0.Add(2 * time.Minute), PathHash: "g"},
			},
			commits: []Commit{
				{
					ID: 1300, SHA: "cg", CommittedAt: t0.Add(10 * time.Minute), Reachable: true,
					Files: []CommitFile{{PathHash: "g"}},
				},
			},
			wantStatus: map[int64]Status{15: StatusCommitted, 16: StatusCommitted},
			wantFiles:  map[int64]map[string]int64{15: {"g": 1300}, 16: {"g": 1300}},
			wantSuper:  map[int64]map[string]bool{15: {"g": false}, 16: {"g": false}},
		},
		{
			// P1/F#2: a prompt whose edit lands after the only commit that
			// ever touched the file has no qualifying commit of its own —
			// it stays uncommitted, never superseded, even though a
			// strictly later prompt also edited the file.
			name: "P1/F2 edit after the last commit -> uncommitted, not superseded",
			prompts: []Prompt{
				{ActionID: 17, SessionID: "sG", At: t0.Add(time.Minute)},
				{ActionID: 18, SessionID: "sH", At: t0.Add(3 * time.Minute)},
			},
			edits: []Edit{
				{ActionID: 171, SessionID: "sG", At: t0.Add(2 * time.Minute), PathHash: "h"},
				{ActionID: 181, SessionID: "sH", At: t0.Add(4 * time.Minute), PathHash: "h"},
			},
			commits: []Commit{
				{
					ID: 1400, SHA: "ch", CommittedAt: t0, Reachable: true,
					Files: []CommitFile{{PathHash: "h"}},
				},
			},
			wantStatus: map[int64]Status{17: StatusUncommitted, 18: StatusUncommitted},
			wantFiles:  map[int64]map[string]int64{17: {"h": 0}, 18: {"h": 0}},
			wantSuper:  map[int64]map[string]bool{17: {"h": false}, 18: {"h": false}},
		},
		{
			// R4.4: a merge commit never carries anything.
			name: "R4.4 merge commit carries nothing",
			prompts: []Prompt{
				{ActionID: 9, SessionID: "s9", At: t0},
			},
			edits: []Edit{
				{ActionID: 91, SessionID: "s9", At: t0.Add(time.Hour), PathHash: "m"},
			},
			commits: []Commit{
				{
					ID: 800, SHA: "c800", CommittedAt: t0.Add(2 * time.Hour), Reachable: true, IsMerge: true,
					Files: []CommitFile{{PathHash: "m"}},
				},
			},
			wantStatus: map[int64]Status{9: StatusUncommitted},
			wantFiles:  map[int64]map[string]int64{9: {"m": 0}},
		},
		{
			// R2/R4.4: an unreachable commit (fell out of history since
			// capture) never carries anything either.
			name: "R4.4 unreachable commit carries nothing",
			prompts: []Prompt{
				{ActionID: 10, SessionID: "s10", At: t0},
			},
			edits: []Edit{
				{ActionID: 101, SessionID: "s10", At: t0.Add(time.Hour), PathHash: "u"},
			},
			commits: []Commit{
				{
					ID: 900, SHA: "c900", CommittedAt: t0.Add(2 * time.Hour), Reachable: false,
					Files: []CommitFile{{PathHash: "u"}},
				},
			},
			wantStatus: map[int64]Status{10: StatusUncommitted},
			wantFiles:  map[int64]map[string]int64{10: {"u": 0}},
		},
		{
			// Review 2026-09-29 finding 8: a teammate's commit (pulled into
			// the checkout, author != the local identity) that touched the
			// same file carries nothing - the LOCAL commit that follows it
			// is the one that carries the prompt's file.
			name: "foreign-author commit carries nothing; the local commit after it does",
			prompts: []Prompt{
				{ActionID: 19, SessionID: "s19", At: t0},
			},
			edits: []Edit{
				{ActionID: 191, SessionID: "s19", At: t0.Add(time.Hour), PathHash: "f"},
			},
			commits: []Commit{
				{
					ID: 1900, SHA: "c1900", CommittedAt: t0.Add(2 * time.Hour), Reachable: true, ForeignAuthor: true,
					Files: []CommitFile{{PathHash: "f"}},
				},
				{
					ID: 1901, SHA: "c1901", CommittedAt: t0.Add(3 * time.Hour), Reachable: true,
					Files: []CommitFile{{PathHash: "f"}},
				},
			},
			wantStatus: map[int64]Status{19: StatusCommitted},
			wantFiles:  map[int64]map[string]int64{19: {"f": 1901}},
		},
		{
			// R4.4: a commit that only lands outside the link window
			// leaves the prompt uncommitted.
			name: "R4.4 commit outside the link window -> uncommitted",
			prompts: []Prompt{
				{ActionID: 11, SessionID: "s11", At: t0},
			},
			edits: []Edit{
				{ActionID: 111, SessionID: "s11", At: t0.Add(time.Hour), PathHash: "w"},
			},
			commits: []Commit{
				{
					ID: 1000, SHA: "c1000", CommittedAt: t0.Add(20 * 24 * time.Hour), Reachable: true,
					Files: []CommitFile{{PathHash: "w"}},
				},
			},
			opts:       Options{LinkWindow: 14 * 24 * time.Hour},
			wantStatus: map[int64]Status{11: StatusUncommitted},
			wantFiles:  map[int64]map[string]int64{11: {"w": 0}},
		},
		{
			// R4.7/F19: a revert commit still "carries" the file — a
			// documented v1 limitation, not a bug. The prompt's file
			// matches the EARLIEST qualifying commit; a later commit that
			// reverts the change is invisible to Link.
			name: "R4.7 revert commit still carries (documented limitation)",
			prompts: []Prompt{
				{ActionID: 12, SessionID: "s12", At: t0},
			},
			edits: []Edit{
				{ActionID: 121, SessionID: "s12", At: t0.Add(time.Hour), PathHash: "r"},
			},
			commits: []Commit{
				{
					ID: 1100, SHA: "cfeature", CommittedAt: t0.Add(2 * time.Hour), Reachable: true,
					Files: []CommitFile{{PathHash: "r"}},
				},
				{
					ID: 1101, SHA: "crevert", CommittedAt: t0.Add(3 * time.Hour), Reachable: true,
					Files: []CommitFile{{PathHash: "r"}},
				},
			},
			wantStatus: map[int64]Status{12: StatusCommitted},
			wantFiles:  map[int64]map[string]int64{12: {"r": 1100}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := Link(tc.prompts, tc.edits, tc.commits, tc.opts)

			if len(l.Orphans) != tc.wantOrphans {
				t.Errorf("orphans = %d, want %d", len(l.Orphans), tc.wantOrphans)
			}

			byAction := make(map[int64]PromptChain, len(l.Chains))
			for _, c := range l.Chains {
				byAction[c.Prompt.ActionID] = c
			}

			for id, want := range tc.wantStatus {
				chain, ok := byAction[id]
				if !ok {
					t.Fatalf("no chain for prompt action %d", id)
				}
				if chain.Status != want {
					t.Errorf("prompt %d status = %s, want %s", id, chain.Status, want)
				}
			}

			for id, wantFiles := range tc.wantFiles {
				got := commitFileMap(byAction[id].Files)
				for path, want := range wantFiles {
					if got[path] != want {
						t.Errorf("prompt %d file %q commit = %d, want %d", id, path, got[path], want)
					}
				}
			}

			for id, wantSup := range tc.wantSuper {
				got := supersededMap(byAction[id].Files)
				for path, want := range wantSup {
					if got[path] != want {
						t.Errorf("prompt %d file %q superseded = %v, want %v", id, path, got[path], want)
					}
				}
			}
		})
	}
}

// TestLink_ByCommitIndex checks that Linkage.ByCommit only names the
// prompt that actually reached the commit, and that a superseded
// prompt is left out even though its edit touched the same path.
func TestLink_ByCommitIndex(t *testing.T) {
	prompts := []Prompt{
		{ActionID: 1, SessionID: "sA", At: t0},
		{ActionID: 2, SessionID: "sB", At: t0.Add(20 * time.Minute)},
	}
	edits := []Edit{
		{ActionID: 11, SessionID: "sA", At: t0.Add(10 * time.Minute), PathHash: "shared"},
		{ActionID: 12, SessionID: "sB", At: t0.Add(30 * time.Minute), PathHash: "shared"},
	}
	commits := []Commit{
		{
			ID: 700, SHA: "c700", CommittedAt: t0.Add(time.Hour), Reachable: true,
			Files: []CommitFile{{PathHash: "shared"}},
		},
	}
	l := Link(prompts, edits, commits, Options{})

	ids := l.ByCommit[700]
	if len(ids) != 1 || ids[0] != 2 {
		t.Fatalf("ByCommit[700] = %v, want [2]", ids)
	}
}

// TestLink_ChainCommitShare covers ChainCommit.Share in both shapes: a
// prompt that alone reached a commit (share 1.0), and two prompts that
// each contributed one of a commit's two carried files (share 0.5
// each).
func TestLink_ChainCommitShare(t *testing.T) {
	t.Run("sole contributor gets share 1.0", func(t *testing.T) {
		prompts := []Prompt{{ActionID: 1, SessionID: "s1", At: t0}}
		edits := []Edit{
			{ActionID: 11, SessionID: "s1", At: t0.Add(time.Hour), PathHash: "f1"},
			{ActionID: 12, SessionID: "s1", At: t0.Add(time.Hour), PathHash: "f2"},
		}
		commits := []Commit{
			{ID: 1, SHA: "cA", CommittedAt: t0.Add(2 * time.Hour), Reachable: true, Files: []CommitFile{{PathHash: "f1"}}},
			{ID: 2, SHA: "cB", CommittedAt: t0.Add(3 * time.Hour), Reachable: true, Files: []CommitFile{{PathHash: "f2"}}},
		}
		l := Link(prompts, edits, commits, Options{})
		chain := l.Chains[0]
		if chain.Status != StatusCommitted {
			t.Fatalf("status = %s, want committed", chain.Status)
		}
		if len(chain.Commits) != 2 {
			t.Fatalf("commits = %d, want 2", len(chain.Commits))
		}
		for _, cc := range chain.Commits {
			if cc.Share != 1.0 {
				t.Errorf("commit %d share = %v, want 1.0", cc.ID, cc.Share)
			}
		}
	})

	t.Run("two prompts split a commit's linked set 0.5/0.5", func(t *testing.T) {
		prompts := []Prompt{
			{ActionID: 1, SessionID: "sX", At: t0},
			{ActionID: 2, SessionID: "sY", At: t0},
		}
		edits := []Edit{
			{ActionID: 11, SessionID: "sX", At: t0.Add(time.Hour), PathHash: "p1"},
			{ActionID: 21, SessionID: "sY", At: t0.Add(time.Hour), PathHash: "p2"},
		}
		commits := []Commit{
			{
				ID: 5, SHA: "c5", CommittedAt: t0.Add(2 * time.Hour), Reachable: true,
				Files: []CommitFile{{PathHash: "p1"}, {PathHash: "p2"}},
			},
		}
		l := Link(prompts, edits, commits, Options{})
		for _, chain := range l.Chains {
			if len(chain.Commits) != 1 {
				t.Fatalf("prompt %d commits = %d, want 1", chain.Prompt.ActionID, len(chain.Commits))
			}
			if chain.Commits[0].Share != 0.5 {
				t.Errorf("prompt %d share = %v, want 0.5", chain.Prompt.ActionID, chain.Commits[0].Share)
			}
		}
	})
}

// TestStatusFor pins the R4.5 status table in isolation, independent of
// the rest of Link's stages.
func TestStatusFor(t *testing.T) {
	cases := []struct {
		name             string
		reach, committed int
		want             Status
	}{
		{"nothing survived supersede -> superseded", 0, 0, StatusSuperseded},
		{"reached files, none committed -> uncommitted", 2, 0, StatusUncommitted},
		{"all reached files committed -> committed", 2, 2, StatusCommitted},
		{"some but not all reached files committed -> partial", 3, 1, StatusPartial},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := statusFor(tc.reach, tc.committed); got != tc.want {
				t.Errorf("statusFor(%d, %d) = %s, want %s", tc.reach, tc.committed, got, tc.want)
			}
		})
	}
}

// TestAssignEditsToPrompts_Stage pins the R4.1/R4.2 assignment stage in
// isolation: an edit with no prompt at or before it in the same session
// is an orphan, and an edit that does have one is folded into that
// prompt's aggregate with first-seen path order preserved.
func TestAssignEditsToPrompts_Stage(t *testing.T) {
	prompts := []Prompt{
		{ActionID: 1, SessionID: "s1", At: t0},
	}
	edits := []Edit{
		{ActionID: 90, SessionID: "orphanSession", At: t0, PathHash: "orphaned"},
		{ActionID: 91, SessionID: "s1", At: t0.Add(time.Minute), PathHash: "b", AddedCode: 2},
		{ActionID: 92, SessionID: "s1", At: t0.Add(2 * time.Minute), PathHash: "a", AddedCode: 3},
		{ActionID: 93, SessionID: "s1", At: t0.Add(3 * time.Minute), PathHash: "a", ModifiedCode: 1},
	}

	promptEdits, pathOrder, agg, orphans := assignEditsToPrompts(prompts, edits)

	if len(orphans) != 1 || orphans[0].ActionID != 90 {
		t.Fatalf("orphans = %v, want [90]", orphans)
	}
	if len(promptEdits[0]) != 3 {
		t.Fatalf("promptEdits[0] = %d edits, want 3", len(promptEdits[0]))
	}
	if got := pathOrder[0]; len(got) != 2 || got[0] != "b" || got[1] != "a" {
		t.Fatalf("pathOrder[0] = %v, want [b a] (first-seen order)", got)
	}
	a := agg[fileKey{0, "a"}]
	if a.added != 3 || a.modified != 1 {
		t.Fatalf("agg[a] = %+v, want added=3 modified=1 (folded across both edits)", a)
	}
	if !a.firstAt.Equal(t0.Add(2 * time.Minute)) {
		t.Errorf("agg[a].firstAt = %v, want %v (earliest edit)", a.firstAt, t0.Add(2*time.Minute))
	}
}
