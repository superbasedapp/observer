//go:build sbo_omit_ingest_otlp

package main

import (
	"context"
	"database/sql"
	"log/slog"

	"github.com/marmutapp/superbased-observer/internal/config"
	otlpingest "github.com/marmutapp/superbased-observer/internal/ingest/otlp"
)

// otlp_ingest_omit.go is the off side of otlp_ingest.go: in a
// `-tags sbo_omit_ingest_otlp` build (component ingest.otlp compiled out)
// internal/otlpvendor and the vendor logs handler are not in the binary.
// [ingest.otel] is reported, never obeyed: the receiver serves no logs, and
// traces still reach Plane A when [observability] is on.
func wireVendorOTLPIngest(_ context.Context, _ config.Config, _ *sql.DB, logger *slog.Logger, planeA otlpingest.TraceHandler) (otlpingest.Handler, otlpingest.TraceHandler) {
	if logger != nil {
		logger.Warn("otlp receiver: [ingest.otel] enabled is ignored: OTLP ingest (ingest.otlp) is not in this build")
	}
	return nil, planeA
}
