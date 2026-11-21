package telemetrywire

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/cloudsession"
)

// cloudenv.go renders the Settings text for pointing Claude Code CLOUD
// sessions' own OpenTelemetry exporter at this node's OTLP receiver
// (cloud-agents lane CA-B4, Rail T, plan section 6; reworked by lane CA-C7).
// Nothing is written: the destination lives in the organization's
// SERVER-MANAGED settings and the network level in each cloud environment's
// settings (claude.ai), not in any file Observer can reach, so the user pastes
// the result there. The text is the one source every surface renders
// (`observer init --otlp-cloud-endpoint`, a Settings card).
//
// What it encodes, grounded on 2026-10-31 (docs/plans/cloud-agents/
// grounding/claude-code-cloud-2026-10-31.md sections 4 and 7) and on
// 2026-11-01 (code.claude.com/docs/en/monitoring-usage, "Telemetry from cloud
// sessions and Claude Tag" and "How managed settings lock the OTLP
// destination"; terms review grounding/terms-review-claude-code-proxy-
// 2026-11-01.md section 7):
//   - the receiver a cloud VM can reach is necessarily non-loopback, so it
//     is token-gated (start.go, SR27-B5) and the export must carry the
//     HeaderEdgeToken header: a CREDENTIAL;
//   - a credential never goes in a cloud environment's variables ("Anyone
//     who uses an environment can read its variables"), and a network
//     secret does not reach Claude Code's own telemetry export, so the WHOLE
//     export goes in the env block of server-managed settings (CA-C7, the
//     operator's rule). Splitting it (endpoint on the environment, header in
//     managed settings) does not work: a managed credential makes Claude
//     Code remove every endpoint variable set outside managed settings;
//   - no server-managed setting adds a domain to an environment's network
//     allowlist, so each cloud environment still needs the receiver's host
//     under its Limited level's Allowed domains (or Full);
//   - the header value is a cloud-session ship token minted on this node
//     (`observer cloud-session token mint <label>`, CA-D18): labelled,
//     expiring, revocable alone, accepted by the receiver beside its shared
//     token. Observer never writes or prints a token here (operator ruling
//     D-359): the header carries a placeholder naming the mint command.
// A route that needs no credential at all is the in-sandbox loopback
// receiver (internal/cloudsession otelloop.go), for repositories set up with
// `observer cloud-session init --otel-loopback`.

// edgeTokenHeader mirrors internal/ingest/otlp.HeaderEdgeToken (that package
// is not imported here: this one stays pure). Pinned by a cmd/observer test.
const edgeTokenHeader = "X-Observer-Edge-Token" //nolint:gosec // G101: HTTP header NAME, not a credential value

// CloudEnvironmentInput is what the caller resolved about this node.
type CloudEnvironmentInput struct {
	// Endpoint is the receiver's OTLP/HTTP base URL as the cloud VM must
	// reach it ("https://node.tailnet.example:4318"): scheme http or https,
	// a host that is not loopback, an optional port, no path, query or
	// credentials.
	Endpoint string
	// TokenFile is the path of this node's SHARED receiver token, named
	// (never read) in the note that says not to use it in a cloud
	// environment.
	TokenFile string
	// Environment is the ship token's label, used in the mint command the
	// text shows ("" shows DefaultCloudTokenLabel).
	Environment string
}

// DefaultCloudTokenLabel labels the ship token the managed settings carry
// when the caller names none: one token serves every cloud session the
// organization's server-managed settings reach.
const DefaultCloudTokenLabel = "claude-code-server-managed"

// CloudEnvironmentText is the rendered Settings text.
type CloudEnvironmentText struct {
	// Env is the server-managed settings env block, in order. The header
	// value carries a placeholder, never the token.
	Env [][2]string
	// NetworkHost is the host to add under the environment's Allowed domains
	// (cloudsession.ClaudeCodeNetwork).
	NetworkHost string
	// Steps are the instructions, in order, ready to show as a list.
	Steps []string
	// Notes are the caveats a reader needs before relying on it.
	Notes []string
}

// Errors CloudEnvironment refuses with.
var (
	ErrCloudEndpointInvalid  = errors.New("the receiver endpoint must be an http(s) URL with a host and no path, query or credentials")
	ErrCloudEndpointLoopback = errors.New("a loopback receiver address is unreachable from a cloud environment: give the address the cloud VM can reach (a tailnet name or a public TLS endpoint)")
)

// CloudEnvironment renders the Settings text for in.
func CloudEnvironment(in CloudEnvironmentInput) (CloudEnvironmentText, error) {
	u, err := url.Parse(strings.TrimSpace(in.Endpoint))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" ||
		u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return CloudEnvironmentText{}, ErrCloudEndpointInvalid
	}
	host := u.Hostname()
	if isLoopbackHost(host) {
		return CloudEnvironmentText{}, ErrCloudEndpointLoopback
	}
	endpoint := u.Scheme + "://" + u.Host
	tokenFile := in.TokenFile
	if tokenFile == "" {
		tokenFile = "the node's OTLP receiver token file" //nolint:gosec // G101: prose naming a file, not a credential value
	}
	label := strings.TrimSpace(in.Environment)
	if label == "" {
		label = DefaultCloudTokenLabel
	}
	mint := fmt.Sprintf("observer cloud-session token mint %q --ttl 168h", label)
	placeholder := "<paste the ship token from `" + mint + "`>"
	out := CloudEnvironmentText{
		Env: [][2]string{
			{"CLAUDE_CODE_ENABLE_TELEMETRY", "1"},
			{"OTEL_LOGS_EXPORTER", "otlp"},
			{"OTEL_EXPORTER_OTLP_PROTOCOL", "http/protobuf"},
			{envEndpointKey, endpoint},
			{"OTEL_EXPORTER_OTLP_HEADERS", edgeTokenHeader + "=" + placeholder},
		},
		NetworkHost: host,
	}
	out.Steps = []string{
		"On this node, enable the OTLP receiver for the network: [ingest.otel] enabled = true, http_addr on an address the cloud VM can reach, allow_non_loopback = true (Settings > OTel export > More settings), then restart the daemon so the receiver starts token-gated.",
		"On this node, mint the ship token the managed settings will carry: `" + mint + "`. It is shown once, labelled, expires on its own (a week here; 8 hours without --ttl) and can be revoked alone. Mint a new one and update the managed settings before it expires.",
		"In your organization's server-managed settings for Claude Code (Team or Enterprise; claude.ai admin settings), add the env block below, replacing the placeholder with that token. Put it nowhere else: not in a cloud environment's variables, which anyone using the environment can read, and not as a network secret, which Claude Code's own telemetry export never receives.",
		"In every cloud environment whose sessions should report, in network access, " + fmt.Sprintf(cloudsession.ClaudeCodeNetwork.AddHost, host) + fmt.Sprintf(". No server-managed setting adds an allowed domain, and the egress gateway refuses a host that is not allowed (%s) at CONNECT, so nothing arrives.", host),
		"Start a new cloud session (Claude Code reads the settings at startup). Its exported turns land on this node as a Claude Code session marked as run in the vendor cloud, joined by ccr.session.id.",
	}
	out.Notes = []string{
		"Server-managed settings reach every member's own machine too, not only cloud sessions. Because they carry a credential, Claude Code removes every OTLP endpoint variable set anywhere else: each member's local Claude Code then exports to this receiver, a developer's own OTLP export setting stops applying, and the in-sandbox loopback route (cloud-session init --otel-loopback) is overridden. Use this route only when this receiver should get the whole organization's Claude Code telemetry; otherwise use the loopback route, which needs no credential.",
		"Claude Tag (Claude in Slack) channel sessions and Cowork sessions do not receive server-managed settings, so this route does not cover them.",
		"The token is still visible to the agent inside each session's VM (settings env becomes the process environment). It is ingest-only: it can send telemetry and cloud-session capture to this node and read nothing; revoke it alone with `observer cloud-session token revoke <id>`.",
		"Do not use the node's shared receiver token (" + tokenFile + "): it has no expiry and rotating it cuts off every exporter at once. The receiver still accepts it, for collectors on your own network.",
		"Exported telemetry carries tokens, cost and timing per model call. Prompts and tool output are sent only if you also add OTEL_LOG_USER_PROMPTS / OTEL_LOG_TOOL_DETAILS, which this text does not.",
		"Rate-limit usage (the 5-hour and weekly gauges) has no sanctioned source in a cloud session: the export carries none and Observer's proxy does not run there, so those gauges stay empty for cloud sessions, never zero.",
		"Checked live: Claude Code in a cloud VM puts ccr.session.id (the cse_ id) on every exported record. Not yet checked: server-managed settings reaching a cloud session, and delivery through the environment's egress gateway to an allowed domain. Prefer an https endpoint.",
	}
	if u.Scheme == "https" {
		out.Notes = append(out.Notes, "The node's receiver itself serves plain HTTP: an https endpoint needs a TLS terminator in front of http_addr (for example tailscale serve, or a reverse proxy).")
	}
	if u.Scheme == "http" {
		out.Notes = append(out.Notes, "This endpoint is plain http: the token and telemetry cross the network unencrypted unless the path is a private tailnet.")
	}
	return out, nil
}

// ManagedSettingsJSON renders t.Env as the server-managed settings document
// to paste: {"env": {...}} in two-space layout, keys in order, with a
// trailing newline. Merge its env keys into existing managed settings rather
// than replacing them.
func (t CloudEnvironmentText) ManagedSettingsJSON() string {
	var b strings.Builder
	b.WriteString("{\n  \"env\": {\n")
	for i, kv := range t.Env {
		b.WriteString("    " + jsonText(kv[0]) + ": " + jsonText(kv[1]))
		if i < len(t.Env)-1 {
			b.WriteString(",")
		}
		b.WriteString("\n")
	}
	b.WriteString("  }\n}\n")
	return b.String()
}

// jsonText encodes s as a JSON string without HTML escaping, so the
// placeholder's angle brackets stay readable.
func jsonText(s string) string {
	var b strings.Builder
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s) // a string always encodes
	return strings.TrimSuffix(b.String(), "\n")
}

// EnvLines renders t.Env as KEY=value lines (for display; the form to paste
// is ManagedSettingsJSON).
func (t CloudEnvironmentText) EnvLines() []string {
	lines := make([]string, 0, len(t.Env))
	for _, kv := range t.Env {
		lines = append(lines, kv[0]+"="+kv[1])
	}
	return lines
}

// isLoopbackHost reports a loopback name or address.
func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") || strings.HasSuffix(strings.ToLower(host), ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && (ip.IsLoopback() || ip.IsUnspecified())
}
