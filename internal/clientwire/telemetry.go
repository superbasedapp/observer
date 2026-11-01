package clientwire

import "errors"

// telemetry.go holds the exporter-wiring types every build carries. The
// writer itself (TelemetrySupported, WireTelemetry and the ownership record)
// belongs to the ingest.otlp component and lives in telemetry_wire.go; a
// `-tags sbo_omit_ingest_otlp` build links telemetry_omit.go instead, so
// internal/telemetrywire leaves the binary (modular packaging plan 5.1,
// lane MP-L1C).

// PartTelemetry is the tool's own OpenTelemetry exporter pointed at this
// node's OTLP receiver (T-537, opt-in, never written by default).
const PartTelemetry Part = "telemetry"

// TelemetryOptions parameterize one exporter-config write.
type TelemetryOptions struct {
	// HomeDir pins the user home ("" = os.UserHomeDir).
	HomeDir string
	// Getenv resolves the file's directory override (CODEX_HOME). nil is
	// the one pinned-home rule (crossmount.HomeEnv, R-188 F1): os.Getenv
	// only when the process home is not isolated; a pinned HomeDir ignores
	// the environment.
	Getenv func(string) string
	// Addr is the node receiver's OTLP/HTTP BIND address ([ingest.otel]
	// http_addr, host:port). Required for a write; ignored by a removal.
	// The endpoint written is always its loopback form
	// (telemetrywire.ReceiverAddr), never the bind address itself.
	Addr string
	// ReceiverRequiresToken reports that the node receiver demands its edge
	// token on every export ([ingest.otel] allow_non_loopback). An apply is
	// then refused (ErrReceiverRequiresToken): Observer never writes that
	// token into a vendor config file, and an exporter without it would only
	// be answered 401 (operator ruling D-359 on P3-12). A removal is
	// unaffected.
	ReceiverRequiresToken bool
	// DryRun computes the edit and writes nothing.
	DryRun bool
}

// TelemetryResult is one exporter-config write or removal.
type TelemetryResult struct {
	Tool       string
	ConfigPath string
	// Changed reports the file was (or, in a dry run, would be) rewritten.
	Changed bool
	DryRun  bool
	// Wired reports Observer's exporter wiring is present after the call.
	Wired bool
	// Conflict says why nothing was written (a setting the user made).
	Conflict string
	Summary  []string
	Error    error
}

// ErrReceiverRequiresToken refuses exporter wiring while the node receiver
// requires its edge token (see TelemetryOptions.ReceiverRequiresToken).
var ErrReceiverRequiresToken = errors.New("this node's OTLP receiver accepts non-loopback connections ([ingest.otel] allow_non_loopback = true), so every export must carry its receiver token; Observer does not write that token into an AI tool's config file, so the exporter is not wired. Set allow_non_loopback = false to wire exporters to the loopback receiver")
