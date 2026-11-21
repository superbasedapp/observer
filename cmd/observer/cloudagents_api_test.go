package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cloudagents"
	"github.com/marmutapp/superbased-observer/internal/cloudagentsnet"
	"github.com/marmutapp/superbased-observer/internal/cloudagentssvc"
	"github.com/marmutapp/superbased-observer/internal/keystore"
)

func runCloudAgentsIn(t *testing.T, stdin string, args ...string) (string, error) {
	t.Helper()
	cmd := newCloudAgentsCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetIn(strings.NewReader(stdin))
	cmd.SetArgs(args)
	err := cmd.ExecuteContext(context.Background())
	return out.String(), err
}

func readTestdata(t *testing.T, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestCloudAgentsCLI_APIConnectorKeyFromStdin drives `connect cursor-cloud`
// through the real egress package against an httptest TLS server standing
// in for api.cursor.com: the key is read from stdin (not a TTY), presented
// as Basic auth, stored in the keychain only and never printed.
func TestCloudAgentsCLI_APIConnectorKeyFromStdin(t *testing.T) {
	const key = "key_cli_SECRET_00ff11ee"
	var sawKey []string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, _, _ := r.BasicAuth()
		sawKey = append(sawKey, u)
		switch {
		case r.URL.Path == "/v1/me":
			_, _ = w.Write(readTestdata(t, "vendorapi/cursor/cursor.cloudagent.meta/normal_page.json"))
		case r.URL.Path == "/v1/agents" && r.URL.Query().Get("cursor") == "":
			_, _ = w.Write(readTestdata(t, "vendorapi/cursor/cursor.cloudagent.agents/normal_page.json"))
		case r.URL.Path == "/v1/agents":
			_, _ = w.Write([]byte(`{"items":[]}`))
		case strings.HasSuffix(r.URL.Path, "/runs"):
			_, _ = w.Write(readTestdata(t, "vendorapi/cursor/cursor.cloudagent.runs/normal_page.json"))
		case strings.HasSuffix(r.URL.Path, "/usage"):
			_, _ = w.Write(readTestdata(t, "vendorapi/cursor/cursor.cloudagent.usage/normal_page.json"))
		case strings.HasSuffix(r.URL.Path, "/stream"):
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = w.Write(readTestdata(t, "cloudagents/cursor-cloud/stream-live.sse"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	addr := srv.Listener.Addr().String()
	keys := &keystore.MemStore{}
	cloudAgentsTestKeys = keys
	cloudAgentsTestNet = func(o *cloudagentsnet.Options) {
		o.HTTP = &http.Client{Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, addr)
			},
			TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "example.com", MinVersion: tls.VersionTLS12},
		}}
	}
	t.Cleanup(func() { cloudAgentsTestKeys, cloudAgentsTestNet = nil, nil })
	cfg := plansTestConfig(t)

	// A key is never a flag.
	if _, err := runCloudAgentsIn(t, "", "connect", "cursor-cloud", "--key", key, "--config", cfg); err == nil {
		t.Fatal("--key must not exist")
	}
	// Devin needs its organization before the key is read; a CLI connector
	// takes no organization.
	if out, err := runCloudAgentsIn(t, key+"\n", "connect", "devin", "--config", cfg); err == nil || !strings.Contains(out+err.Error(), "--org-id") {
		t.Fatalf("devin without org: %v %s", err, out)
	}
	if _, err := runCloudAgentsIn(t, "", "connect", "codex-cloud", "--org-id", "x", "--config", cfg); err == nil {
		t.Fatal("codex-cloud took an org id")
	}
	if len(sawKey) != 0 {
		t.Fatalf("a refused command called out: %v", sawKey)
	}
	// An empty stdin is no key.
	if _, err := runCloudAgentsIn(t, "\n", "test", "cursor-cloud", "--config", cfg); err == nil {
		t.Fatal("an empty key was accepted")
	}

	out, err := runCloudAgentsIn(t, key+"\n", "connect", "cursor-cloud", "--config", cfg)
	if err != nil {
		t.Fatalf("connect: %v %s", err, out)
	}
	if strings.Contains(out, key) {
		t.Fatalf("the key was printed: %s", out)
	}
	m := regexp.MustCompile(`linked as account (\d+)`).FindStringSubmatch(out)
	if m == nil || !strings.Contains(out, "reachable as developer@example.com (user:42)") || !strings.Contains(out, "1 run stream(s)") {
		t.Fatalf("connect output: %s", out)
	}
	for _, k := range sawKey {
		if k != key {
			t.Fatalf("a request carried %q", k)
		}
	}
	if got, err := keys.Get(cloudagentssvc.SecretName(cloudagents.ConnectorCursorCloud, 1)); err != nil || got != key {
		t.Fatalf("keychain = %q %v", got, err)
	}
	out, err = runCloudAgentsIn(t, "", "--config", cfg)
	if err != nil || !strings.Contains(out, "cursor-cloud") || strings.Contains(out, key) {
		t.Fatalf("status: %v %s", err, out)
	}
	out, err = runCloudAgentsIn(t, "", "disconnect", m[1], "--config", cfg)
	if err != nil || !strings.Contains(out, "unlinked") {
		t.Fatalf("disconnect: %v %s", err, out)
	}
	if _, err := keys.Get(cloudagentssvc.SecretName(cloudagents.ConnectorCursorCloud, 1)); err == nil {
		t.Fatal("disconnect left the key")
	}
}
