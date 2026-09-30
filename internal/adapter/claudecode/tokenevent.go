package claudecode

import (
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// tokenEventFromLine builds the TokenEvent for one usage-bearing assistant
// JSONL record. Extracted verbatim from ParseSessionFile's main loop
// (S10-SPEED) so the generation-timing pass can re-emit the previous parse
// window's tail message from look-back lines with byte-identical token
// figures - the store's UNIQUE(source_file, source_event_id) upsert then
// only fills gen_ms. msg.Usage must be non-nil.
func tokenEventFromLine(path string, line rawLine, msg rawMessage, ts time.Time, projectRoot, projectRemote string) models.TokenEvent {
	// Prefer message.id as the dedup key — one API call shares it
	// across N content-block records — and fall back to the
	// per-record UUID when the JSONL line predates the id field
	// or is a non-API-call assistant entry.
	eventID := msg.ID
	if eventID == "" {
		eventID = line.UUID
	}
	cacheCreation := msg.Usage.CacheCreationInputTokens
	if cacheCreation == 0 {
		cacheCreation = msg.Usage.CacheCreation.Ephemeral5mInputTokens +
			msg.Usage.CacheCreation.Ephemeral1hInputTokens
	}
	ev := models.TokenEvent{
		SourceFile:            path,
		SourceEventID:         eventID,
		SessionID:             line.SessionID,
		ProjectRoot:           projectRoot,
		GitBranch:             line.GitBranch,
		GitRemote:             projectRemote,
		Timestamp:             ts,
		Tool:                  models.ToolClaudeCode,
		Model:                 msg.Model,
		InputTokens:           msg.Usage.InputTokens,
		OutputTokens:          msg.Usage.OutputTokens,
		CacheReadTokens:       msg.Usage.CacheReadInputTokens,
		CacheCreationTokens:   cacheCreation,
		CacheCreation1hTokens: msg.Usage.CacheCreation.Ephemeral1hInputTokens,
		// Server-side tool fees (audit B3, v1.6.10): per-message
		// count of Anthropic web_search invocations billed at
		// $0.01/call. web_fetch_requests is captured too but
		// currently not column-mapped (no column on token_usage
		// and unclear pricing — see audit doc §B3 / X-followup).
		WebSearchRequests: msg.Usage.ServerToolUse.WebSearchRequests,
		// Fast-tier capture (Opus 4.8 `/fast`): the usage block
		// echoes back the request's speed selector. Stamping it
		// here lets the cost engine apply Pricing.FastMultiplier
		// on the JSONL path, matching the proxy's api_turns path.
		Fast:        msg.Usage.Speed == "fast",
		Source:      models.TokenSourceJSONL,
		Reliability: models.ReliabilityUnreliable,
		MessageID:   msg.ID,
		// Sub-agent usage attribution (migration 087): the
		// same line-level isSidechain bit the tool events
		// carry. Without it a sub-agent's turns are counted
		// in the session totals but can't be bucketed into
		// its window by the dashboard's sub-agents view.
		IsSidechain: line.IsSidechain,
	}
	return ev
}
