//go:build sbo_omit_ingest_otlp

package main

import (
	"context"
	"fmt"

	"github.com/marmutapp/superbased-observer/internal/components"
)

// cloudsession_otelloop_omit.go is the off side of
// cloudsession_otelloop_serve.go: a build without ingest.otlp has no
// receiver to serve. ensure still runs (it only probes and spawns), and the
// spawned serve exits with this error, which lands nowhere a session sees:
// the hook itself always succeeds.
func runOTelLoopbackServe(_ context.Context, _ otelLoopServeOptions) error {
	return fmt.Errorf("otel-receiver: OTLP ingest (ingest.otlp) is not in this build; %s", components.DistrosHaving("ingest.otlp"))
}
