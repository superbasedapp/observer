package telemetrywire

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// TestCloudEnvironment pins the Claude Code cloud-session Settings text
// (cloud-agents lane CA-B4, reworked by CA-C7 to server-managed settings): the exporter variables, the endpoint normalized
// to scheme://host:port, the token header carrying a placeholder that names
// the token file (never a value), the Allowed domains host, and the refusals
// for an endpoint the cloud VM cannot use.
func TestCloudEnvironment(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		endpoint string
		wantErr  error
		wantEP   string
		wantHost string
	}{
		{"https tailnet", "https://node.tailnet.example:4318", nil, "https://node.tailnet.example:4318", "node.tailnet.example"},
		{"trailing slash", "https://node.tailnet.example:4318/", nil, "https://node.tailnet.example:4318", "node.tailnet.example"},
		{"plain http on a private address", "http://100.64.1.2:4318", nil, "http://100.64.1.2:4318", "100.64.1.2"},
		{"loopback name", "http://localhost:4318", ErrCloudEndpointLoopback, "", ""},
		{"loopback ip", "http://127.0.0.1:4318", ErrCloudEndpointLoopback, "", ""},
		{"ipv6 loopback", "http://[::1]:4318", ErrCloudEndpointLoopback, "", ""},
		{"unspecified", "http://0.0.0.0:4318", ErrCloudEndpointLoopback, "", ""},
		{"path", "https://node.example/v1/logs", ErrCloudEndpointInvalid, "", ""},
		{"credentials", "https://u:p@node.example", ErrCloudEndpointInvalid, "", ""},
		{"query", "https://node.example?x=1", ErrCloudEndpointInvalid, "", ""},
		{"scheme", "grpc://node.example:4317", ErrCloudEndpointInvalid, "", ""},
		{"no host", "https://", ErrCloudEndpointInvalid, "", ""},
		{"empty", "", ErrCloudEndpointInvalid, "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := CloudEnvironment(CloudEnvironmentInput{Endpoint: tc.endpoint, TokenFile: "/home/dev/.observer/otlp-ingest-token", Environment: "web env"})
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v; want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			want := []string{
				"CLAUDE_CODE_ENABLE_TELEMETRY=1",
				"OTEL_LOGS_EXPORTER=otlp",
				"OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf",
				"OTEL_EXPORTER_OTLP_ENDPOINT=" + tc.wantEP,
				"OTEL_EXPORTER_OTLP_HEADERS=X-Observer-Edge-Token=<paste the ship token from `observer cloud-session token mint \"web env\" --ttl 168h`>",
			}
			lines := got.EnvLines()
			if strings.Join(lines, "\n") != strings.Join(want, "\n") {
				t.Errorf("env =\n%s\nwant\n%s", strings.Join(lines, "\n"), strings.Join(want, "\n"))
			}
			if got.NetworkHost != tc.wantHost {
				t.Errorf("network host = %q; want %q", got.NetworkHost, tc.wantHost)
			}
			// The paste form is a server-managed settings document whose env
			// block holds exactly those keys, values verbatim.
			var doc struct {
				Env map[string]string `json:"env"`
			}
			if err := json.Unmarshal([]byte(got.ManagedSettingsJSON()), &doc); err != nil {
				t.Fatalf("managed settings JSON: %v\n%s", err, got.ManagedSettingsJSON())
			}
			if len(doc.Env) != len(got.Env) {
				t.Errorf("managed env has %d keys; want %d", len(doc.Env), len(got.Env))
			}
			for _, kv := range got.Env {
				if doc.Env[kv[0]] != kv[1] {
					t.Errorf("managed env %s = %q; want %q", kv[0], doc.Env[kv[0]], kv[1])
				}
			}
			if strings.Contains(got.ManagedSettingsJSON(), `\u003c`) {
				t.Error("managed settings JSON HTML-escaped the placeholder")
			}
			all := strings.Join(append(append([]string{}, got.Steps...), got.Notes...), "\n")
			// CA-C7: the credential lives in server-managed settings only;
			// the steps say where not to put it, the allowlist still applies
			// per environment, the lock-out and coverage limits are stated,
			// and rate limits are named as having no sanctioned source.
			for _, must := range []string{
				"Allowed domains", "Limited", tc.wantHost, "allow_non_loopback", "ccr.session.id",
				"server-managed settings", "not in a cloud environment's variables", "network secret",
				"No server-managed setting adds an allowed domain",
				"removes every OTLP endpoint variable set anywhere else", "loopback route",
				"Claude Tag", "Cowork", "Rate-limit usage", "no sanctioned source",
				`observer cloud-session token mint "web env" --ttl 168h`, "revoke it alone",
				"Do not use the node's shared receiver token (/home/dev/.observer/otlp-ingest-token)",
			} {
				if !strings.Contains(all, must) {
					t.Errorf("text does not mention %q", must)
				}
			}
		})
	}
}
