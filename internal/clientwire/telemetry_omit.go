//go:build sbo_omit_ingest_otlp

package clientwire

import "fmt"

// telemetry_omit.go is the off side of telemetry_wire.go: in a
// `-tags sbo_omit_ingest_otlp` build (component ingest.otlp compiled out)
// there is no OTLP receiver to point an exporter at and no exporter-config
// writer, so no tool is offered the telemetry part. An earlier full build's
// exporter entries are not removed by this build: the Components page and
// docs/components.md say so, and a build with ingest.otlp removes them.

// TelemetrySupported is false: OTLP ingest is not in this build.
func TelemetrySupported(string) bool { return false }

// removeTelemetry refuses: the exporter-config writer is not in this build.
func removeTelemetry(tool string, opts TelemetryOptions) TelemetryResult {
	return TelemetryResult{Tool: tool, DryRun: opts.DryRun, Error: fmt.Errorf("clientwire: OTLP ingest (ingest.otlp) is not in this build, so %s's exporter wiring cannot be removed here", tool)}
}
