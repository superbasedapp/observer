package projectroi

import (
	"math"
	"testing"
	"time"
)

func almostEqual(a, b float64) bool {
	return math.Abs(a-b) < 1e-9
}

// TestAttributeSpend_PromptWindow checks R4.6's window: a prompt's
// spend is the cost of turns in [prompt.At, nextPrompt.At) in the same
// session, and the last prompt's window is open-ended.
func TestAttributeSpend_PromptWindow(t *testing.T) {
	prompts := []Prompt{
		{ActionID: 1, SessionID: "s1", At: t0},
		{ActionID: 2, SessionID: "s1", At: t0.Add(time.Hour)},
	}
	turns := []Turn{
		{SessionID: "s1", At: t0.Add(10 * time.Minute), CostUSD: 1.0},
		{SessionID: "s1", At: t0.Add(59 * time.Minute), CostUSD: 2.0},
		{SessionID: "s1", At: t0.Add(90 * time.Minute), CostUSD: 3.0},
		{SessionID: "s1", At: t0.Add(24 * time.Hour), CostUSD: 4.0},
	}
	l := Link(prompts, nil, nil, Options{})
	spend := AttributeSpend(l, turns, prompts)

	if !almostEqual(spend.ByPrompt[1], 3.0) {
		t.Errorf("prompt 1 spend = %v, want 3.0", spend.ByPrompt[1])
	}
	if !almostEqual(spend.ByPrompt[2], 7.0) {
		t.Errorf("prompt 2 (open-ended, last prompt) spend = %v, want 7.0", spend.ByPrompt[2])
	}
	if spend.Orphan != 0 {
		t.Errorf("orphan = %v, want 0", spend.Orphan)
	}
}

// TestAttributeSpend_OrphanTurns checks R4.2/R4.6: a turn before the
// first prompt in its session has nothing to attribute to, so it lands
// in Spend.Orphan rather than ByPrompt or ByCommit.
func TestAttributeSpend_OrphanTurns(t *testing.T) {
	prompts := []Prompt{
		{ActionID: 1, SessionID: "s1", At: t0.Add(time.Hour)},
	}
	turns := []Turn{
		{SessionID: "s1", At: t0, CostUSD: 5.0},                    // before the only prompt
		{SessionID: "s2", At: t0, CostUSD: 2.5},                    // session with no prompt at all
		{SessionID: "s1", At: t0.Add(2 * time.Hour), CostUSD: 1.0}, // after the prompt
	}
	l := Link(prompts, nil, nil, Options{})
	spend := AttributeSpend(l, turns, prompts)

	if !almostEqual(spend.Orphan, 7.5) {
		t.Errorf("orphan = %v, want 7.5", spend.Orphan)
	}
	if !almostEqual(spend.ByPrompt[1], 1.0) {
		t.Errorf("prompt 1 spend = %v, want 1.0", spend.ByPrompt[1])
	}
	if len(spend.ByCommit) != 0 {
		t.Errorf("ByCommit = %v, want empty", spend.ByCommit)
	}
}

// TestAttributeSpend_UnattributedWhenNoCommitReached checks that a
// prompt's spend stays in Unattributed, not silently dropped, when its
// reach set carried nothing to a commit (uncommitted/superseded/
// no_edits).
func TestAttributeSpend_UnattributedWhenNoCommitReached(t *testing.T) {
	prompts := []Prompt{
		{ActionID: 1, SessionID: "s1", At: t0}, // uncommitted: edits a file, no commit ever carries it
		{ActionID: 2, SessionID: "s2", At: t0}, // no_edits
	}
	edits := []Edit{
		{ActionID: 11, SessionID: "s1", At: t0.Add(time.Minute), PathHash: "never-committed"},
	}
	turns := []Turn{
		{SessionID: "s1", At: t0.Add(2 * time.Minute), CostUSD: 4.0},
		{SessionID: "s2", At: t0.Add(2 * time.Minute), CostUSD: 6.0},
	}
	l := Link(prompts, edits, nil, Options{})
	spend := AttributeSpend(l, turns, prompts)

	if !almostEqual(spend.Unattributed, 10.0) {
		t.Errorf("unattributed = %v, want 10.0", spend.Unattributed)
	}
	if len(spend.ByCommit) != 0 {
		t.Errorf("ByCommit = %v, want empty", spend.ByCommit)
	}
}

// TestAttributeSpend_ShareSplitAcrossTwoCommits checks that one
// prompt's spend divides across the several commits it reached in
// proportion to its OWN file count per commit (self-normalized — see
// AttributeSpend's doc comment on how this differs from Linkage's
// ChainCommit.Share).
func TestAttributeSpend_ShareSplitAcrossTwoCommits(t *testing.T) {
	prompts := []Prompt{
		{ActionID: 1, SessionID: "s1", At: t0},
	}
	edits := []Edit{
		{ActionID: 11, SessionID: "s1", At: t0.Add(time.Minute), PathHash: "f1"},
		{ActionID: 12, SessionID: "s1", At: t0.Add(time.Minute), PathHash: "f2"},
		{ActionID: 13, SessionID: "s1", At: t0.Add(time.Minute), PathHash: "f3"},
		{ActionID: 14, SessionID: "s1", At: t0.Add(time.Minute), PathHash: "f4"},
	}
	commits := []Commit{
		// commit A carries 3 of the prompt's 4 files.
		{
			ID: 100, SHA: "cA", CommittedAt: t0.Add(time.Hour), Reachable: true,
			Files: []CommitFile{{PathHash: "f1"}, {PathHash: "f2"}, {PathHash: "f3"}},
		},
		// commit B carries the remaining 1.
		{
			ID: 200, SHA: "cB", CommittedAt: t0.Add(2 * time.Hour), Reachable: true,
			Files: []CommitFile{{PathHash: "f4"}},
		},
	}
	turns := []Turn{
		{SessionID: "s1", At: t0.Add(2 * time.Minute), CostUSD: 100.0},
	}
	l := Link(prompts, edits, commits, Options{})
	if l.Chains[0].Status != StatusCommitted {
		t.Fatalf("status = %s, want committed", l.Chains[0].Status)
	}
	spend := AttributeSpend(l, turns, prompts)

	if !almostEqual(spend.ByCommit[100], 75.0) {
		t.Errorf("ByCommit[100] = %v, want 75.0", spend.ByCommit[100])
	}
	if !almostEqual(spend.ByCommit[200], 25.0) {
		t.Errorf("ByCommit[200] = %v, want 25.0", spend.ByCommit[200])
	}
	if !almostEqual(spend.Unattributed, 0) {
		t.Errorf("unattributed = %v, want 0", spend.Unattributed)
	}
}

// TestAttributeSpend_UnpricedTurnsByCommit pins 2026-09-22 review round
// 4 finding #9: a commit bucket must carry the SAME unpriced-turn
// coverage signal the day/session/task buckets already do, so the
// Projects page's ?by=commit rows can honestly flag a commit whose
// underlying spend is a known undercount — before this fix,
// AttributeSpend had no such field at all and the commit rows always
// silently omitted the caveat.
func TestAttributeSpend_UnpricedTurnsByCommit(t *testing.T) {
	prompts := []Prompt{
		{ActionID: 1, SessionID: "s1", At: t0},
	}
	edits := []Edit{
		{ActionID: 11, SessionID: "s1", At: t0.Add(time.Minute), PathHash: "f1"},
	}
	commits := []Commit{
		{
			ID: 100, SHA: "cA", CommittedAt: t0.Add(time.Hour), Reachable: true,
			Files: []CommitFile{{PathHash: "f1"}},
		},
	}
	turns := []Turn{
		// One priced turn, TWO unpriced ones, all inside prompt 1's window
		// and therefore all reaching commit 100.
		{SessionID: "s1", At: t0.Add(2 * time.Minute), CostUSD: 10.0, Priced: true},
		{SessionID: "s1", At: t0.Add(3 * time.Minute), CostUSD: 0, Priced: false},
		{SessionID: "s1", At: t0.Add(4 * time.Minute), CostUSD: 0, Priced: false},
	}
	l := Link(prompts, edits, commits, Options{})
	spend := AttributeSpend(l, turns, prompts)

	if !almostEqual(spend.ByCommit[100], 10.0) {
		t.Errorf("ByCommit[100] = %v, want 10.0 (only the priced turn's cost — never a fabricated price)", spend.ByCommit[100])
	}
	if spend.UnpricedTurnsByCommit[100] != 2 {
		t.Errorf("UnpricedTurnsByCommit[100] = %d, want 2 (the two unpriced turns, not collapsed or dropped)", spend.UnpricedTurnsByCommit[100])
	}

	// A commit with no unpriced turns at all must read exactly 0 (the
	// zero value), never a stray positive count leaking across commits.
	commits2 := []Commit{
		{
			ID: 200, SHA: "cB", CommittedAt: t0.Add(time.Hour), Reachable: true,
			Files: []CommitFile{{PathHash: "f1"}},
		},
	}
	fullyPriced := []Turn{{SessionID: "s1", At: t0.Add(2 * time.Minute), CostUSD: 5.0, Priced: true}}
	l2 := Link(prompts, edits, commits2, Options{})
	spend2 := AttributeSpend(l2, fullyPriced, prompts)
	if spend2.UnpricedTurnsByCommit[200] != 0 {
		t.Errorf("UnpricedTurnsByCommit[200] = %d, want 0 (every turn priced)", spend2.UnpricedTurnsByCommit[200])
	}
}
