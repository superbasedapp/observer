package dimcode

import (
	"encoding/json"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// usageJSON is the `usage` column of usage_ledger (and the shape of the
// mirrored run row). Keys are DimCode's normalized mapUsage() output. The
// nested `lastCall` object (final call of a run) is deliberately not decoded:
// the run total already contains it.
type usageJSON struct {
	PromptTokens     *int64 `json:"promptTokens"`
	CompletionTokens *int64 `json:"completionTokens"`
	TotalTokens      *int64 `json:"totalTokens"`
	CacheReadTokens  *int64 `json:"cacheReadTokens"`
	CacheWriteTokens *int64 `json:"cacheWriteTokens"`
}

// costJSON is the `cost` column of usage_run_stats. quality is DimCode's own
// enum: exact | base_tokens | missing_price.
type costJSON struct {
	TotalCostUsd float64 `json:"totalCostUsd"`
	Quality      string  `json:"quality"`
}

// netInput converts DimCode's GROSS prompt count into Observer's NET
// non-cached input. DimCode's mapUsage() defines promptTokens as the reported
// prompt PLUS any cache read/write the provider reports outside it, and
// totalTokens as prompt + completion, so cache read and cache write are both
// subsets of the prompt. Clamped at zero.
func netInput(prompt, cacheRead, cacheWrite int64) int64 {
	n := prompt - cacheRead - cacheWrite
	if n < 0 {
		return 0
	}
	return n
}

// exactCost returns DimCode's own total cost only when it vouches for it
// (quality "exact"); every other quality leaves pricing to the cost engine.
func exactCost(raw string) float64 {
	if strings.TrimSpace(raw) == "" {
		return 0
	}
	var c costJSON
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		return 0
	}
	if c.Quality != "exact" || c.TotalCostUsd < 0 {
		return 0
	}
	return c.TotalCostUsd
}

// tokenEvents emits one TokenEvent per run (from usage_run_stats) and one per
// standalone ledger call (e.g. the session-title generation call, which the
// run row does not include). A ledger row that merely mirrors a run
// (ledgerId == "usage_"+runId) is skipped when the run row exists; when it
// does not, the mirror stands in for it under the same `run:<runId>` key so a
// later run row upgrades rather than duplicates.
func (a *Adapter) tokenEvents(c *sessionCtx, runs []runRow, ledger []ledgerRow, finalAssistant map[string]string) []models.TokenEvent {
	var out []models.TokenEvent
	haveRun := map[string]bool{}
	for _, r := range runs {
		haveRun[r.RunID] = true
		ev := models.TokenEvent{
			SourceFile:          c.sourceFile,
			SourceEventID:       "run:" + r.RunID,
			SessionID:           c.sessionID,
			ProjectRoot:         c.projectRoot,
			GitRemote:           c.gitRemote,
			Timestamp:           parseTime(r.EndedAt),
			Tool:                models.ToolDimCode,
			Model:               firstNonEmpty(r.Model, c.defaultModel),
			InputTokens:         netInput(r.Input, r.CacheRead.Int64, r.CacheWrite.Int64),
			OutputTokens:        r.Output,
			CacheReadTokens:     r.CacheRead.Int64,
			CacheCreationTokens: r.CacheWrite.Int64,
			EstimatedCostUSD:    exactCost(r.Cost),
			Source:              models.TokenSourceJSONL,
			Reliability:         models.ReliabilityApproximate,
			MessageID:           firstNonEmpty(finalAssistant[r.RunID], r.RunID),
			TurnID:              r.RunID,
		}
		if tokenEventEmpty(ev) {
			continue
		}
		out = append(out, ev)
	}
	for _, l := range ledger {
		isMirror := l.RunID != "" && l.LedgerID == "usage_"+l.RunID
		if isMirror && haveRun[l.RunID] {
			continue
		}
		var u usageJSON
		if err := json.Unmarshal([]byte(l.Usage), &u); err != nil {
			continue
		}
		cr, cw := deref(u.CacheReadTokens), deref(u.CacheWriteTokens)
		ev := models.TokenEvent{
			SourceFile:          c.sourceFile,
			SourceEventID:       "ledger:" + l.LedgerID,
			SessionID:           c.sessionID,
			ProjectRoot:         c.projectRoot,
			GitRemote:           c.gitRemote,
			Timestamp:           parseTime(l.CreatedAt),
			Tool:                models.ToolDimCode,
			Model:               firstNonEmpty(l.Model, c.defaultModel),
			InputTokens:         netInput(deref(u.PromptTokens), cr, cw),
			OutputTokens:        deref(u.CompletionTokens),
			CacheReadTokens:     cr,
			CacheCreationTokens: cw,
			Source:              models.TokenSourceJSONL,
			Reliability:         models.ReliabilityApproximate,
		}
		if isMirror {
			ev.SourceEventID = "run:" + l.RunID
			ev.MessageID = firstNonEmpty(finalAssistant[l.RunID], l.RunID)
			ev.TurnID = l.RunID
		}
		if tokenEventEmpty(ev) {
			continue
		}
		out = append(out, ev)
	}
	return out
}

// tokenEventEmpty reports a row that carries no tokens at all (a run that
// failed before any model call returned usage).
func tokenEventEmpty(ev models.TokenEvent) bool {
	return ev.InputTokens == 0 && ev.OutputTokens == 0 &&
		ev.CacheReadTokens == 0 && ev.CacheCreationTokens == 0
}

func deref(p *int64) int64 {
	if p == nil {
		return 0
	}
	return *p
}
