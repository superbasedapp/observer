//go:build sbo_omit_isolation || sbo_omit_isolation_seal

package main

import (
	"context"
	"database/sql"
	"log/slog"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// installEvidenceSealer is a no-op in an image without isolation.seal:
// terminal runs stay unsealed (evidence_seal.go).
func installEvidenceSealer(context.Context, config.Config, *sql.DB, *slog.Logger) {}

// sealEvidenceOnHandle is a no-op in an image without isolation.seal.
func sealEvidenceOnHandle(config.Config, *sql.DB, *slog.Logger) func() { return func() {} }
