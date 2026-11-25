package main

import (
	"io"
	"log/slog"
)

// discardLogger is a logger that writes nothing. It lives in an untagged file
// because tests under different omit tags use it (the org-update tests and
// the security tests): defined only beside the security tests, it broke
// `go vet -tags sbo_omit_security ./cmd/observer/` (maint defects lane B
// note, 2026-11-24).
func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }
