package guardrecipesvc

import (
	"sync"

	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/guardrecipe"
)

// ReplaySummary counts what one policy decided over a replayed window.
type ReplaySummary struct {
	// Mode is the guard mode the replay evaluated under.
	Mode string `json:"mode"`
	// Verdicts is the number of non-allow verdicts.
	Verdicts int `json:"verdicts"`
	// ByDecision counts verdicts per decision (flag, ask, deny).
	ByDecision map[string]int `json:"by_decision"`
	// ByRuleBlocking counts ask and deny verdicts per rule.
	ByRuleBlocking map[string]int `json:"by_rule_blocking"`
}

// Replay is the before/after comparison over the same captured actions.
type Replay struct {
	Scanned int           `json:"scanned"`
	Before  ReplaySummary `json:"before"`
	After   ReplaySummary `json:"after"`
}

// ReplayApply evaluates captured actions under the policy as it is and as
// an apply would leave it. Nothing is written or recorded: the guards are
// fresh and the dashboard simulate route, the one caller, persists nothing.
// For a project scope only that project's actions differ (the recipe joins
// that project's trusted layer); the counts cover every input.
func ReplayApply(env Env, set *guardrecipe.Set, req Request, inputs []guard.ActionInput) (*Replay, *Preview, error) {
	p, err := planApply(env, set, req)
	if err != nil {
		return nil, nil, err
	}
	return replay(env, p, inputs), p.preview, nil
}

// ReplayRemove is ReplayApply for a remove. ok is false when the scope has
// no applied recipe.
func ReplayRemove(env Env, set *guardrecipe.Set, scope guardrecipe.Scope, projectRoot string, inputs []guard.ActionInput) (*Replay, *Preview, bool, error) {
	p, ok, err := planRemove(env, set, scope, projectRoot)
	if err != nil || !ok {
		return nil, nil, ok, err
	}
	return replay(env, p, inputs), p.preview, true, nil
}

func replay(env Env, p *plan, inputs []guard.ActionInput) *Replay {
	// EvaluateActions mutates per-session taint state inside each guard;
	// each guard gets its own copy of the inputs so the two runs see the
	// same sequence.
	before := append([]guard.ActionInput(nil), inputs...)
	after := append([]guard.ActionInput(nil), inputs...)
	eval := env.Evaluate
	if eval == nil {
		eval = func(g *guard.Guard, in []guard.ActionInput) []guard.ActionVerdict { return g.EvaluateActions(in) }
	}
	// The two guards share no state (each has its own taint, repeats and
	// budget records, and its own copy of the inputs), so they run side by
	// side: a week's replay is two full evaluations, and running them one
	// after the other doubled the wait (demo bug #14).
	var beforeV, afterV []guard.ActionVerdict
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); beforeV = eval(p.cur, before) }()
	go func() { defer wg.Done(); afterV = eval(p.next, after) }()
	wg.Wait()
	return &Replay{
		Scanned: len(inputs),
		Before:  summarize(string(p.cur.Mode()), beforeV),
		After:   summarize(string(p.next.Mode()), afterV),
	}
}

func summarize(mode string, verdicts []guard.ActionVerdict) ReplaySummary {
	s := ReplaySummary{Mode: mode, ByDecision: map[string]int{}, ByRuleBlocking: map[string]int{}}
	for _, v := range verdicts {
		d := v.Verdict.Decision.String()
		if d == "allow" {
			continue
		}
		s.Verdicts++
		s.ByDecision[d]++
		if d == "ask" || d == "deny" {
			s.ByRuleBlocking[v.Verdict.RuleID]++
		}
	}
	return s
}
