package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter/ccotel"
	otlpingest "github.com/marmutapp/superbased-observer/internal/ingest/otlp"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/scrub"
	"github.com/marmutapp/superbased-observer/internal/store"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
)

// otlpLogsHandler composes the native-console ingest glue: parse an OTLP logs
// export into API-turn observations (ccotel) and dedup-merge each into the
// store by request_id (store.UpsertTurnByRequestID). It is the single seam
// between the network receiver (internal/ingest/otlp, schema-blind) and the
// store. Per-turn upsert errors are logged and skipped so one bad turn never
// fails the whole export (telemetry is at-least-once). It never returns an
// error today — the receiver maps a nil return to an OTLP success.
//
// contentMaxBytes bounds a single otel_content row's stored Content (see
// ingestOTelContent) — callers pass config.IngestOTelConfig.MaxContentBytes().
func otlpLogsHandler(st *store.Store, logger *slog.Logger, captureContent bool, contentMaxBytes int) otlpingest.Handler {
	scrubber := scrub.New()
	return func(ctx context.Context, req *collogspb.ExportLogsServiceRequest) error {
		turns, skipped := ccotel.ParseLogs(req)
		if skipped > 0 {
			logger.Warn("otlp ingest: skipped api_request events missing request_id", "count", skipped)
		}
		for i := range turns {
			if _, _, err := st.UpsertTurnByRequestID(ctx, turns[i]); err != nil {
				logger.Warn("otlp ingest: upsert failed", "request_id", turns[i].RequestID, "err", err)
			}
		}
		if captureContent {
			ingestOTelContent(ctx, st, scrubber, logger, req, contentMaxBytes)
		}
		return nil
	}
}

// ingestOTelContent extracts content bodies, scrubs them for secrets at the
// boundary (ccotel stays pure), bounds each to contentMaxBytes, and stores
// them. Best-effort: a content-store failure logs and never fails the turn
// ingest above.
//
// Scrubber choice: [scrub.Scrubber.String], not [scrub.Scrubber.ScrubForward].
// ScrubForward exists to protect a body being FORWARDED upstream as a request
// (the proxy path) — its whole purpose is guaranteeing the output stays valid
// JSON so a mangled secret-redaction never truncates a live API request.
// otel_content bodies are never forwarded anywhere; they are stored, once,
// same as raw_tool_input. And per ccotel.ContentRecord's doc comment + a read
// of contentFromRecord, Content is always a single OTel attribute/body
// string (prompt text, tool I/O text) — never a JSON envelope — so there is
// no JSON structure for ScrubForward's fallback path to protect; on non-JSON
// input ScrubForward's own doc comment says it "falls through to String's
// output" anyway, i.e. it degrades to exactly this call. String is the
// correct, already-idiomatic choice here (same as scrub.RawJSON's non-JSON
// fallback for raw_tool_input).
//
// Cap: bounding happens AFTER scrubbing (redaction can only shrink or
// same-size the text — patterns replace with the fixed-length "[REDACTED]" —
// so scrub-then-cut never re-exposes truncated secret bytes) and BEFORE the
// hash is computed by the caller (InsertOTelContent hashes whatever Content
// it's handed) — see the ContentHash comment in internal/store/otelcontent.go
// for why the hash must cover the FULL scrubbed body, not the capped one.
func ingestOTelContent(ctx context.Context, st *store.Store, scrubber *scrub.Scrubber, logger *slog.Logger, req *collogspb.ExportLogsServiceRequest, contentMaxBytes int) {
	recs := ccotel.ParseContent(req)
	if len(recs) == 0 {
		return
	}
	rows := make([]models.OTelContent, 0, len(recs))
	for _, r := range recs {
		var ts time.Time
		if r.TimeUnixNano != 0 {
			ts = time.Unix(0, int64(r.TimeUnixNano)).UTC()
		}
		scrubbed := scrubber.String(r.Content)
		rows = append(rows, models.OTelContent{
			RequestID:   r.RequestID,
			SessionID:   r.SessionID,
			ToolUseID:   r.ToolUseID,
			Kind:        r.Kind,
			Content:     scrub.TruncateN(scrubbed, contentMaxBytes),
			ContentHash: store.HashOTelContent(scrubbed),
			Timestamp:   ts,
			Source:      ccotel.SourceTag,
		})
	}
	if _, err := st.InsertOTelContent(ctx, rows); err != nil {
		logger.Warn("otlp ingest: content store failed", "count", len(rows), "err", err)
	}
}
