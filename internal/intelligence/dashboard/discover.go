package dashboard

import (
	"net/http"

	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"
	"github.com/marmutapp/superbased-observer/internal/intelligence/discover"
)

func (s *Server) handleDiscover(w http.ResponseWriter, r *http.Request) {
	days := intArg(r, "days", 30, 1, 36500)
	// The global window, including a closed range's until (REVIEW-3 P3-19).
	since, until := windowRange(r, 30, 1, 36500)
	stalePage := intArg(r, "stale_page", 1, 1, 1_000_000)
	staleLimit := intArg(r, "stale_limit", 20, 1, 500)
	repeatedPage := intArg(r, "repeated_page", 1, 1, 1_000_000)
	repeatedLimit := intArg(r, "repeated_limit", 20, 1, 500)
	proj := r.URL.Query().Get("project")
	tool := r.URL.Query().Get("tool")

	// sections=stale computes only the stale-read pass (discover.Options
	// StaleOnly): the Overview KPI tile reads nothing else, and the full
	// report's repeated-command / rerun passes dominate the cost.
	staleOnly := r.URL.Query().Get("sections") == "stale"

	// Cap the per-panel SQL limit at 500 — generous enough for realistic
	// dashboards while keeping a single discover.Run cheap.
	report, err := discover.New(s.db()).Run(r.Context(), discover.Options{
		ProjectRoot: proj, Tool: tool, Model: modelParam(r), Days: days, Since: since, Until: until, Limit: 500, StaleOnly: staleOnly,
	})
	if err != nil {
		writeErr(w, err)
		return
	}

	staleTotal := len(report.StaleReads)
	staleStart := (stalePage - 1) * staleLimit
	staleEnd := staleStart + staleLimit
	if staleStart > staleTotal {
		staleStart = staleTotal
	}
	if staleEnd > staleTotal {
		staleEnd = staleTotal
	}
	staleSlice := report.StaleReads[staleStart:staleEnd]

	repTotal := len(report.RepeatedCommands)
	repStart := (repeatedPage - 1) * repeatedLimit
	repEnd := repStart + repeatedLimit
	if repStart > repTotal {
		repStart = repTotal
	}
	if repEnd > repTotal {
		repEnd = repTotal
	}
	repSlice := report.RepeatedCommands[repStart:repEnd]

	// Blended input rate — derived from the user's actual last-30d
	// api_turns (per-model prompt-token volume × per-model rate) so
	// the ~$ wasted KPI tile reflects real model mix rather than a
	// hardcoded representative rate. Falls back to the default
	// (claude-sonnet-4 input rate) when no proxy data is available.
	blendedRate, err := s.opts.CostEngine.BlendedInputRate(r.Context(), s.db(), 30)
	if err != nil {
		s.opts.Logger.Warn("discover: blended input rate", "err", err)
		blendedRate = cost.DefaultBlendedInputRate
	}

	writeJSON(w, map[string]any{
		"stale_reads":                    staleSlice,
		"stale_total":                    staleTotal,
		"stale_page":                     stalePage,
		"stale_limit":                    staleLimit,
		"repeated_commands":              repSlice,
		"repeated_total":                 repTotal,
		"repeated_page":                  repeatedPage,
		"repeated_limit":                 repeatedLimit,
		"cross_tool_files":               report.CrossToolFiles,
		"native_vs_bash":                 report.NativeVsBash,
		"summary":                        report.Summary,
		"blended_input_rate_per_million": blendedRate,
	})
}
