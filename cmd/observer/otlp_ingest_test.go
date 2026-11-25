//go:build !sbo_omit_ingest_otlp

package main

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/otlpvendor"
	"github.com/marmutapp/superbased-observer/internal/store"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
)

// TestSourceTagPinnedToStore guards the cross-package contract: the
// claude-code row of internal/otlpvendor stamps a literal source tag (the
// package must not import store), so this asserts the two stay equal. If
// they drift, native turns would map to the wrong fidelity.
func TestSourceTagPinnedToStore(t *testing.T) {
	v, ok := otlpvendor.ForTool(models.ToolClaudeCode)
	if !ok {
		t.Fatal("otlpvendor has no claude-code row")
	}
	if v.SourceTag != store.SourceCCOTel {
		t.Fatalf("otlpvendor claude-code row source tag (%q) != store.SourceCCOTel (%q)", v.SourceTag, store.SourceCCOTel)
	}
}

func TestOTLPLogsHandler_UpsertsTurn(t *testing.T) {
	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: t.TempDir() + "/o.db"})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer func() { _ = database.Close() }()
	st := store.New(database)
	h := otlpLogsHandler(st, slog.New(slog.NewTextHandler(io.Discard, nil)), true, config.DefaultIngestOTelContentMaxBytes)

	req := &collogspb.ExportLogsServiceRequest{
		ResourceLogs: []*logspb.ResourceLogs{{
			ScopeLogs: []*logspb.ScopeLogs{{
				LogRecords: []*logspb.LogRecord{{
					EventName: "claude_code.api_request",
					Attributes: []*commonpb.KeyValue{
						{Key: "request_id", Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: "req_h"}}},
						{Key: "model", Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: "claude-opus-4-8"}}},
						{Key: "input_tokens", Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_IntValue{IntValue: 321}}},
					},
				}},
			}},
		}},
	}
	if err := h(ctx, req); err != nil {
		t.Fatalf("handler: %v", err)
	}

	var (
		count       int
		inputTokens int64
		source      string
	)
	row := database.QueryRowContext(ctx,
		`SELECT COUNT(*), COALESCE(MAX(input_tokens),0), COALESCE(MAX(source),'') FROM api_turns WHERE request_id = 'req_h'`)
	if err := row.Scan(&count, &inputTokens, &source); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if count != 1 || inputTokens != 321 || source != store.SourceCCOTel {
		t.Fatalf("turn not stored as cc_otel: count=%d input=%d source=%q", count, inputTokens, source)
	}
}
