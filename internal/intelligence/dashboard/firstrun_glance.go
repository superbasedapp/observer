package dashboard

import (
	"net/http"
	"sort"
	"time"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/intelligence/discover"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// The first-run "at a glance" card (local dashboard first-run design,
// docs/plans/local-dashboard-first-run-options-2026-11-18.md section 8, step 1:
// the door B history reveal). Once the watcher has read a machine's
// existing AI-tool history, the Overview welcome band settles into a short
// card of facts about it. This route adds only what /api/firstrun does not
// already carry: the last-30-days spend over the deduped spend substrate
// (dashapi.LoadSpendTurns, the one every cost surface reads), the most used
// model, the busiest project, the re-read count from Discovery's stale-read
// pass, and whether an agent is working right now. Every figure is read
// from the real database (never the demo one: like /api/firstrun it
// describes this machine). Nothing is extrapolated, and a model with no
// price is never summed as $0: those turns are counted apart.
//
// Owner-local (L): it names project roots, like /api/firstrun.

// firstRunGlanceDays is the glance window.
const firstRunGlanceDays = 30

// firstRunGlanceLiveMinutes is the "working right now" cutoff, the Live
// page's default window.
const firstRunGlanceLiveMinutes = 15

// firstRunGlanceRereadLimit bounds Discovery's stale-read pass, the limit
// the Overview tile's read uses.
const firstRunGlanceRereadLimit = 500

// firstRunGlanceTool is one tool's captured session count.
type firstRunGlanceTool struct {
	Tool     string `json:"tool"`
	Name     string `json:"name"`
	Sessions int64  `json:"sessions"`
}

// firstRunGlanceModel is the most used model in the window, by turns.
type firstRunGlanceModel struct {
	Model string `json:"model"`
	Turns int    `json:"turns"`
	// Share is Turns over every turn with a model, 0..1.
	Share float64 `json:"share"`
	// Models counts the distinct models in the window.
	Models int `json:"models"`
}

// firstRunGlanceSpend is the window's spend over the deduped substrate.
type firstRunGlanceSpend struct {
	// State: none (no turns in the window) | priced (at least one turn has
	// a price) | unpriced (turns exist, none has a price: "price unknown",
	// never $0).
	State string `json:"state"`
	// USD sums the priced turns only.
	USD float64 `json:"usd"`
	// Tokens sums every turn's tokens (input, output, cache read and
	// write, reasoning), priced or not.
	Tokens        int64 `json:"tokens"`
	PricedTokens  int64 `json:"priced_tokens"`
	PricedTurns   int   `json:"priced_turns"`
	UnpricedTurns int   `json:"unpriced_turns"`
	// Estimated: at least one priced turn was priced from the price table
	// rather than a cost the capture path recorded.
	Estimated bool `json:"estimated"`
}

// firstRunGlanceProject is the project with the most captured sessions.
type firstRunGlanceProject struct {
	Name     string `json:"name"`
	Root     string `json:"root"`
	Sessions int64  `json:"sessions"`
}

// firstRunGlanceActive is the agent working right now: tool and project
// name only, never what it is doing.
type firstRunGlanceActive struct {
	Tool    string `json:"tool"`
	Name    string `json:"name"`
	Project string `json:"project,omitempty"`
}

// firstRunGlanceResponse is GET /api/firstrun/glance.
type firstRunGlanceResponse struct {
	WindowDays     int                    `json:"window_days"`
	Sessions       int64                  `json:"sessions"`
	ProjectCount   int64                  `json:"project_count"`
	RecentSessions int64                  `json:"recent_sessions"`
	Tools          []firstRunGlanceTool   `json:"tools"`
	TopModel       *firstRunGlanceModel   `json:"top_model,omitempty"`
	Spend          firstRunGlanceSpend    `json:"spend"`
	BusiestProject *firstRunGlanceProject `json:"busiest_project,omitempty"`
	// Rereads is Discovery's stale-read count over the window (an
	// unchanged file read again); absent when the pass could not run.
	Rereads     *int                  `json:"rereads,omitempty"`
	ActiveNow   *firstRunGlanceActive `json:"active_now,omitempty"`
	GeneratedAt string                `json:"generated_at"`
}

func (s *Server) handleFirstRunGlance(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	ctx := r.Context()
	now := s.now().UTC()
	since := now.AddDate(0, 0, -firstRunGlanceDays)
	counts, totals, err := s.firstRunCounts(ctx)
	if err != nil {
		writeErr(w, err)
		return
	}
	out := firstRunGlanceResponse{
		WindowDays:   firstRunGlanceDays,
		Sessions:     totals.sessions,
		ProjectCount: totals.projects,
		Tools:        firstRunGlanceTools(counts),
		Spend:        firstRunGlanceSpend{State: "none"},
		GeneratedAt:  now.Format(time.RFC3339),
	}
	if s.opts.DB == nil {
		writeJSON(w, out)
		return
	}
	facts, err := store.New(s.opts.DB).LoadFirstRunGlance(ctx, since, now.Add(-firstRunGlanceLiveMinutes*time.Minute))
	if err != nil {
		writeErr(w, err)
		return
	}
	out.RecentSessions = facts.RecentSessions
	if p := facts.BusiestProject; p != nil {
		name := p.Name
		if name == "" {
			name = projectBaseName(p.Root)
		}
		out.BusiestProject = &firstRunGlanceProject{Name: name, Root: p.Root, Sessions: p.Sessions}
	}
	if a := facts.ActiveNow; a != nil {
		out.ActiveNow = &firstRunGlanceActive{Tool: a.Tool, Name: integration.DisplayName(a.Tool)}
		if a.ProjectRoot != "" {
			out.ActiveNow.Project = projectBaseName(a.ProjectRoot)
		}
	}
	if s.opts.CostEngine != nil {
		turns, err := dashapi.LoadSpendTurns(ctx, s.opts.DB, s.opts.CostEngine, since, time.Time{}, dashapi.SpendScope{}, nil)
		if err != nil {
			writeErr(w, err)
			return
		}
		out.Spend = firstRunGlanceSpendOf(turns)
		out.TopModel = firstRunGlanceTopModel(turns)
	}
	// Discovery's stale-read pass is the slowest read here; a failure only
	// leaves the fact out.
	if rep, err := discover.New(s.opts.DB).Run(ctx, discover.Options{
		Days: firstRunGlanceDays, Limit: firstRunGlanceRereadLimit, StaleOnly: true,
	}); err == nil {
		n := rep.Summary.StaleReadCount
		out.Rereads = &n
	}
	writeJSON(w, out)
}

// firstRunGlanceTools lists the tools with captured sessions, most first.
func firstRunGlanceTools(counts map[string]firstRunToolCount) []firstRunGlanceTool {
	out := []firstRunGlanceTool{}
	for tool, c := range counts {
		if c.sessions <= 0 || tool == "" {
			continue
		}
		out = append(out, firstRunGlanceTool{Tool: tool, Name: integration.DisplayName(tool), Sessions: c.sessions})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Sessions != out[j].Sessions {
			return out[i].Sessions > out[j].Sessions
		}
		return out[i].Tool < out[j].Tool
	})
	return out
}

// glanceSpendStates is the ordered rule table for the spend state (CLAUDE.md
// #5): the first row whose when holds decides.
var glanceSpendStates = []struct {
	state string
	when  func(sp firstRunGlanceSpend) bool
}{
	{"none", func(sp firstRunGlanceSpend) bool { return sp.PricedTurns+sp.UnpricedTurns == 0 }},
	{"unpriced", func(sp firstRunGlanceSpend) bool { return sp.PricedTurns == 0 }},
	{"priced", func(firstRunGlanceSpend) bool { return true }},
}

// glanceTurnTokens is one turn's billed token total.
func glanceTurnTokens(t dashapi.SpendTurn) int64 {
	b := t.Bundle
	return b.Input + b.Output + b.CacheRead + b.CacheCreation + b.CacheCreation1h + b.Reasoning
}

// firstRunGlanceSpendOf sums the window's spend turns. An unpriced turn adds
// tokens but never dollars.
func firstRunGlanceSpendOf(turns []dashapi.SpendTurn) firstRunGlanceSpend {
	var sp firstRunGlanceSpend
	for _, t := range turns {
		tok := glanceTurnTokens(t)
		sp.Tokens += tok
		if !t.Priced {
			sp.UnpricedTurns++
			continue
		}
		sp.PricedTurns++
		sp.PricedTokens += tok
		sp.USD += t.CostUSD
		if t.Recorded <= 0 {
			sp.Estimated = true
		}
	}
	for _, rule := range glanceSpendStates {
		if rule.when(sp) {
			sp.State = rule.state
			break
		}
	}
	return sp
}

// firstRunGlanceTopModel is the model with the most turns in the window
// (ties: the name first in order), nil when no turn names a model.
func firstRunGlanceTopModel(turns []dashapi.SpendTurn) *firstRunGlanceModel {
	byModel := map[string]int{}
	total := 0
	for _, t := range turns {
		if t.Model == "" {
			continue
		}
		byModel[t.Model]++
		total++
	}
	if total == 0 {
		return nil
	}
	best := ""
	for m, n := range byModel {
		if best == "" || n > byModel[best] || (n == byModel[best] && m < best) {
			best = m
		}
	}
	return &firstRunGlanceModel{
		Model:  best,
		Turns:  byModel[best],
		Share:  float64(byModel[best]) / float64(total),
		Models: len(byModel),
	}
}
