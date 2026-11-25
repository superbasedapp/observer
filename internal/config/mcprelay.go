package config

// This file holds the config types of [mcp_relay].

// MCPRelayConfig is the [mcp_relay] block — the node-side MCP relay of the
// Agent Access arc (doc3 §8.2, §11.7 P4, §12). The relay fronts the AI
// clients' MCP servers on this node: it pulls the org's signed
// tools.mcp_access policy through the four-gate accept, compiles it into the
// node decision table (internal/mcprelay/localpdp), projects the approved
// remote entries into every verified client's config
// (internal/mcprelay/project, journaled before every write), and mediates
// node-local stdio servers through the stdio wrapper.
//
// LOCAL-ONLY (like [guard] / [routing]) and entirely additive: with Enabled
// false nothing below is read, no client config is rewritten, no listener
// binds and no table cache is written — byte-identical to a build without
// the relay. Enabling is per node (per-node opt-in IS the canary).
type MCPRelayConfig struct {
	// Enabled turns the relay on. Default false. Turning it on rewrites each
	// AI client's MCP entry to point at the relay (the original is journaled
	// in mcp_relay_launch_spec first, so disabling restores it byte-for-byte).
	Enabled bool `toml:"enabled"`
	// Mode selects the PRIMARY mediation path: "stdio_wrapper" (default —
	// the relay is the process the client spawns, process-attested),
	// "ipc" (owner-only unix socket / named pipe, ipc_bound) or "loopback"
	// (a loopback HTTP listener the client config points at; configured,
	// so product-scoped grants are NOT honoured on it).
	Mode string `toml:"mode"`
	// GatewayURL is the org MCP gateway base URL (https://…). On a managed
	// node it comes from the enrolment grant, not from TOML; set it here
	// only for an individual node that dials a gateway directly.
	GatewayURL string `toml:"gateway_url"`
	// AuditMode is the local audit posture (doc3 §12.4, R14.4): "async"
	// (default — durable local append, sidecar-before-forward when the DB
	// append fails, a gap record on the next append) or "strict" (block the
	// call on ANY append failure). The effective posture is strict when
	// THIS is strict OR a signed policy marks the vserver audit_strict.
	AuditMode string `toml:"audit_mode"`
	// Listen is the host:port of the relay's DEDICATED loopback HTTP
	// listener, serving the streamable-HTTP relay at /mcp/<vserver-slug>.
	// When set, the daemon binds it on start (whatever Mode is) and projects
	// each approved vserver into the AI clients' configs as a remote entry
	// http://<listen>/mcp/<slug> (when remote forwarding is wired). Empty
	// (the default) binds nothing: no /mcp/ route is served on this node -
	// the daemon's proxy listener does not host one - and no remote entry is
	// projected; the stdio wrap still applies. It MUST be a loopback
	// host:port (127.0.0.1 / localhost / ::1) — the relay is never exposed
	// beyond this machine.
	Listen string `toml:"listen"`
	// IPCPath is the owner-only IPC endpoint for Mode "ipc": a unix socket
	// path (0700 directory, 0600 socket) on unix; on Windows the value names
	// the pipe (`\.\pipe\…`). Empty resolves beside the observer database
	// (~/.observer/mcp-relay.sock). `~` is expanded at load.
	IPCPath string `toml:"ipc_path"`
	// PollIntervalSeconds is the relay's local reconcile cadence: how often
	// it recompiles the node table from the latest ACCEPTED tools.mcp_access
	// resource and re-projects approved entries into client configs. It is
	// NOT the signed-policy pull cadence — that is
	// [org_client].policy_poll_interval_seconds. Default 300; bounds 10–3600.
	PollIntervalSeconds int `toml:"poll_interval_seconds"`
}

// MCPRelay vocabularies (closed; validated at load).
const (
	MCPRelayModeStdioWrapper = "stdio_wrapper"
	MCPRelayModeIPC          = "ipc"
	MCPRelayModeLoopback     = "loopback"
	MCPRelayAuditAsync       = "async"
	MCPRelayAuditStrict      = "strict"
	// DefaultMCPRelayPollIntervalSeconds is the default reconcile cadence.
	DefaultMCPRelayPollIntervalSeconds = 300
)
