package ccotel

import (
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/otelident"
	"github.com/marmutapp/superbased-observer/internal/otlpvendor"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
)

// SourceTag is the provenance value stamped on turns parsed here. It MUST equal
// store.SourceCCOTel — the store's source<->fidelity boundary maps it to
// FidelityNativeExact. Kept as a literal to avoid an adapter->store import; a
// guard test pins the equality.
const SourceTag = "cc_otel"

// toolClaudeCode is the mapping-table row this package reads.
const toolClaudeCode = models.ToolClaudeCode

// resourceEmittedByObserver is the resource attribute Observer stamps on spans
// it emits itself (internal/exporter/otel). The receiver drops these on the way
// in (§3.2 echo guard); ParseLogs honors the same guard for logs (the guard
// itself lives in internal/otlpvendor).
// The marker's one owner is internal/otelident.
const (
	attrEmittedBy = otelident.EchoAttr
	emittedBySelf = otelident.EchoValue
)

// ParseLogs maps an OTLP logs export to Claude Code API-turn observations. It
// returns the recognized api_request turns and skipped, the count of
// api_request events dropped because they carried no request_id (which would
// risk duplication against a proxied row, so they are not emitted). Resources
// tagged as Observer-emitted are ignored (echo guard).
//
// Since T-475 the mapping itself is the claude-code row of the vendor-agnostic
// table in internal/otlpvendor; this function is the Claude-Code-shaped view
// of it, kept so every existing caller and test reads exactly what it read
// before.
func ParseLogs(req *collogspb.ExportLogsServiceRequest) (turns []models.APITurn, skipped int) {
	if req == nil {
		return nil, 0
	}
	res := otlpvendor.ParseLogs(req)
	for _, t := range res.Turns {
		if t.Tool != toolClaudeCode {
			continue
		}
		turns = append(turns, APITurnFrom(t))
	}
	return turns, res.Skipped
}

// APITurnFrom converts a mapped turn to the store's API-turn observation.
func APITurnFrom(t otlpvendor.Turn) models.APITurn {
	return models.APITurn{
		Provider:            t.Provider,
		Model:               t.Model,
		RequestID:           t.RequestID,
		SessionID:           t.SessionID,
		Timestamp:           t.Timestamp,
		InputTokens:         t.InputTokens,
		OutputTokens:        t.OutputTokens,
		CacheReadTokens:     t.CacheReadTokens,
		CacheCreationTokens: t.CacheWriteTokens,
		CostUSD:             t.CostUSD,
		TotalResponseMS:     t.DurationMS,
		Source:              t.SourceTag,
	}
}
