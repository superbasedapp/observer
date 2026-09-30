package projectroi

import "sort"

// Spend is the result of AttributeSpend: a project's turn cost split
// across prompts, then across the commits those prompts' files reached.
type Spend struct {
	// ByPrompt is each prompt's own spend: the cost of every turn in
	// its session between it and the next prompt in that session
	// (R4.6). Keyed by Prompt.ActionID.
	ByPrompt map[int64]float64
	// ByCommit is each commit's attributed spend: the sum, over every
	// prompt that reached it, of that prompt's spend times its own
	// file-count share of the commits IT reached (see AttributeSpend's
	// doc comment for how this differs from ChainCommit.Share). Keyed
	// by Commit.ID.
	ByCommit map[int64]float64
	// UnpricedTurnsByCommit is the count of Turns whose cost was
	// attributed (via ByPrompt) to a prompt that reached a commit, and
	// which carried no recorded cost and no pricing-table entry
	// (Turn.Priced == false) — so ByCommit[id] is a known UNDER-count
	// by at least this many turns' worth of tokens for that commit
	// (2026-09-22 review round 4 finding #9: commit buckets used to
	// carry no unpriced signal at all, unlike every other project cost
	// bucket). Counted once per commit a contributing prompt's reach set
	// included — the same reach set ByCommit's dollar split uses — not
	// fractionally divided the way the dollar amount is: an unpriced
	// turn either did or did not help produce a commit's bucket. Keyed
	// by Commit.ID, same as ByCommit.
	UnpricedTurnsByCommit map[int64]int
	// Unattributed is spend from a linked prompt (one AttributeSpend
	// found in ByPrompt) whose reach set carried no file to any commit
	// — a prompt with StatusUncommitted, StatusSuperseded or
	// StatusNoEdits, or one Link never saw at all.
	Unattributed float64
	// Orphan is spend from turns that occurred before the first prompt
	// in their session (R4.2/R4.6) — there is no prompt to attribute
	// them to at all.
	Orphan float64
}

// AttributeSpend attributes each Turn's cost to the prompt whose window
// it falls in — [prompt.At, nextPrompt.At) within the same session, or
// [prompt.At, +inf) for a session's last prompt (R4.6) — and then
// splits each prompt's total spend across the commits its Linkage reach
// set landed in.
//
// The per-commit split weight is SELF-normalized: for one prompt, its
// weight on a commit is (this prompt's own files that reached that
// commit) / (this prompt's own total reached files, across every commit
// it reached), so one prompt's spend always sums to itself across
// ByCommit + Unattributed. This is deliberately a different
// normalization from Linkage's ChainCommit.Share, which is normalized
// over the COMMIT's total linked set (every prompt that reached it) —
// that shape answers "how much of this commit came from this prompt",
// this one answers "where did this prompt's own money go".
//
// AttributeSpend does no I/O and does not re-derive Link's reach set;
// it reads it back off the given Linkage.
func AttributeSpend(l Linkage, turns []Turn, prompts []Prompt) Spend {
	spend := Spend{
		ByPrompt:              make(map[int64]float64),
		ByCommit:              make(map[int64]float64),
		UnpricedTurnsByCommit: make(map[int64]int),
	}

	bySessionPrompts := make(map[string][]Prompt)
	for _, p := range prompts {
		bySessionPrompts[p.SessionID] = append(bySessionPrompts[p.SessionID], p)
	}
	for sid, ps := range bySessionPrompts {
		sort.Slice(ps, func(i, j int) bool { return ps[i].At.Before(ps[j].At) })
		bySessionPrompts[sid] = ps
	}

	bySessionTurns := make(map[string][]Turn)
	for _, t := range turns {
		bySessionTurns[t.SessionID] = append(bySessionTurns[t.SessionID], t)
	}

	// unpricedTurnsByPrompt mirrors ByPrompt but counts TURNS (not
	// dollars) that had no recorded cost and no pricing-table entry —
	// the per-prompt input the commit loop below folds into
	// UnpricedTurnsByCommit, the same way ByPrompt feeds ByCommit.
	unpricedTurnsByPrompt := make(map[int64]int)
	for sid, sessTurns := range bySessionTurns {
		sessPrompts := bySessionPrompts[sid]
		for _, t := range sessTurns {
			pos := sort.Search(len(sessPrompts), func(i int) bool { return sessPrompts[i].At.After(t.At) })
			if pos == 0 {
				spend.Orphan += t.CostUSD
				continue
			}
			actionID := sessPrompts[pos-1].ActionID
			spend.ByPrompt[actionID] += t.CostUSD
			if !t.Priced {
				unpricedTurnsByPrompt[actionID]++
			}
		}
	}

	chainByAction := make(map[int64]PromptChain, len(l.Chains))
	for _, c := range l.Chains {
		chainByAction[c.Prompt.ActionID] = c
	}

	for actionID, amt := range spend.ByPrompt {
		chain, ok := chainByAction[actionID]
		if !ok {
			spend.Unattributed += amt
			continue
		}
		counts := make(map[int64]int)
		total := 0
		for _, f := range chain.Files {
			if f.CommitID == 0 {
				continue
			}
			counts[f.CommitID]++
			total++
		}
		if total == 0 {
			spend.Unattributed += amt
			continue
		}
		u := unpricedTurnsByPrompt[actionID]
		for commitID, cnt := range counts {
			spend.ByCommit[commitID] += amt * float64(cnt) / float64(total)
			if u > 0 {
				spend.UnpricedTurnsByCommit[commitID] += u
			}
		}
	}

	return spend
}
