package config

// This file holds the config types of [exporter] and [ingest].

// ExporterConfig groups second-rail telemetry exporters (Teams & Org
// Visibility, spec §2.4.3). Currently only the OTel exporter. Like the org
// client it is OFF by default: a solo-local install has no [exporter] section
// (or Enabled=false on each sub-exporter), so the daemon makes zero exporter
// network calls and the behaviour is byte-identical to a non-org build.
type ExporterConfig struct {
	OTel OTelExporterConfig `toml:"otel"`
}

// IngestConfig groups the agent-side native-telemetry receivers
// (native-console integration). Today only the OTLP logs receiver exists.
type IngestConfig struct {
	OTel IngestOTelConfig `toml:"otel"`
}

// IngestOTelConfig configures the embedded OTLP logs receiver that ingests a
// coding assistant's native telemetry (e.g. Claude Code with
// CLAUDE_CODE_ENABLE_TELEMETRY=1) directly — no OpenTelemetry Collector needed.
// Disabled by default: a solo-local install opens no listener and the
// solo-local UX stays byte-identical.
type IngestOTelConfig struct {
	// Enabled gates the receiver. When false (default), start.go opens no
	// listener and the process accepts no OTLP traffic.
	Enabled bool `toml:"enabled"`
	// GRPCAddr / HTTPAddr are the loopback binds for OTLP/gRPC and OTLP/HTTP.
	// Empty disables that transport. Defaults 127.0.0.1:4317 / 127.0.0.1:4318.
	GRPCAddr string `toml:"grpc_addr"`
	HTTPAddr string `toml:"http_addr"`
	// AllowNonLoopback permits binding a non-loopback address. Default false —
	// opening the receiver to a network is an explicit operator decision with
	// a documented threat model (native-console template §2.2 / L3).
	AllowNonLoopback bool `toml:"allow_non_loopback"`
	// ContentCapture sets how much of the OTel stream's CONTENT the receiver
	// stores: "full" (prompts + tool I/O bodies, when the admin enabled the
	// OTEL_LOG_* flags at Claude Code), "metadata" (turns/tokens only — content
	// events skipped), or "none" (alias of metadata). Default "full" — in an
	// admin-driven deployment the admin already chose to emit this content at
	// the source. Stored content is scrubbed for secrets and obeys the same
	// node-side push gate as locally-captured content.
	ContentCapture string `toml:"content_capture"`
	// ContentMaxBytes caps a single otel_content row's stored Content, after
	// scrubbing. Mirrors the org gateway's classify.Policy.BodyMaxBytes bound
	// (32 KiB) — an OTel content event is one prompt/tool-I/O body, the same
	// shape that bound already governs on the server-side capture ladder, and
	// unlike raw_tool_input/RawJSON's 1 MiB ceiling this stream has no
	// dashboard full-text-fetch use case pushing for a larger cap. 0 or
	// negative falls back to the default (partial TOML merge leaves it unset).
	ContentMaxBytes int `toml:"content_max_bytes"`
}

// OTelExporterConfig configures the agent-side OpenTelemetry exporter that
// emits one gen_ai.client span per api_turns row to any OTLP/HTTP endpoint
// (spec §2.4.3). It requires only M0 (it works identically on a solo-local
// install and never couples to the org server). All fields default to the
// safe, privacy-preserving option; OTEL_* environment variables override the
// file values at construction time per the OTel configuration spec.
type OTelExporterConfig struct {
	// Enabled gates the exporter. When false (the default), start.go starts
	// no exporter goroutine and the process makes zero OTLP network calls.
	Enabled bool `toml:"enabled"`
	// Endpoint is the OTLP/HTTP collector endpoint as host:port (no scheme,
	// no path — the SDK appends /v1/traces). Default "localhost:4318".
	// Overridden by OTEL_EXPORTER_OTLP_ENDPOINT / _TRACES_ENDPOINT.
	Endpoint string `toml:"endpoint"`
	// Insecure sends over plain HTTP instead of HTTPS. Default false.
	Insecure bool `toml:"insecure"`
	// PollIntervalSeconds is the row-tail poll cadence against api_turns.id.
	// Default 1.
	PollIntervalSeconds int `toml:"poll_interval_seconds"`
	// EmitPromptContent attaches prompt/completion bodies as the
	// gen_ai.client.inference.operation.details event. Default false — the
	// data-volume and privacy implications are documented in the exporter's
	// doc.go; the operator who turns it on has read that doc.
	EmitPromptContent bool `toml:"emit_prompt_content"`
	// EmitUserEmail attaches sbo.user.email when the agent is enrolled.
	// Default false — opt-in for the customer who wants per-developer slicing
	// in their own backend.
	EmitUserEmail bool `toml:"emit_user_email"`
	// SemconvStability is the value the exporter advertises for
	// OTEL_SEMCONV_STABILITY_OPT_IN. Default "gen_ai_latest_experimental" so
	// the exporter emits the v1.41.0 gen_ai.* attribute names. Overridden by
	// the OTEL_SEMCONV_STABILITY_OPT_IN environment variable.
	SemconvStability string `toml:"semconv_stability"`
}

// OTel exporter defaults (spec §2.4.3 / §2.7).
const (
	// DefaultOTelEndpoint is the default OTLP/HTTP collector endpoint
	// (host:port). The SDK appends the /v1/traces path.
	DefaultOTelEndpoint = "localhost:4318"
	// DefaultOTelPollIntervalSeconds is the default api_turns row-tail
	// poll cadence.
	DefaultOTelPollIntervalSeconds = 1
	// DefaultOTelSemconvStability emits the v1.41.0 GenAI attribute names
	// per the OTel semconv transition plan.
	DefaultOTelSemconvStability = "gen_ai_latest_experimental"
	// DefaultIngestOTelGRPCAddr / DefaultIngestOTelHTTPAddr are the loopback
	// binds for the embedded OTLP logs receiver — the standard OTLP ports on
	// 127.0.0.1 so managed-settings can point Claude Code straight at them.
	DefaultIngestOTelGRPCAddr = "127.0.0.1:4317"
	DefaultIngestOTelHTTPAddr = "127.0.0.1:4318"

	// Content-capture levels for [ingest.otel].content_capture.
	ContentCaptureFull     = "full"     // store prompts + tool I/O content
	ContentCaptureMetadata = "metadata" // turns/tokens only; skip content events
	ContentCaptureNone     = "none"     // alias of metadata

	// DefaultIngestOTelContentMaxBytes is the default per-row cap for
	// [ingest.otel].content_max_bytes — see the field doc comment.
	DefaultIngestOTelContentMaxBytes = 32 << 10 // 32 KiB
)

// CapturesContent reports whether the configured content-capture level stores
// OTel content events. Unknown/empty values are treated as "full" (the default).
func (c IngestOTelConfig) CapturesContent() bool {
	switch c.ContentCapture {
	case ContentCaptureMetadata, ContentCaptureNone:
		return false
	default: // ContentCaptureFull and any unrecognized value
		return true
	}
}

// MaxContentBytes resolves the effective per-row content cap: the configured
// ContentMaxBytes when positive, else DefaultIngestOTelContentMaxBytes.
func (c IngestOTelConfig) MaxContentBytes() int {
	if c.ContentMaxBytes > 0 {
		return c.ContentMaxBytes
	}
	return DefaultIngestOTelContentMaxBytes
}
