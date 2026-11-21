package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cloudagents"
	"github.com/marmutapp/superbased-observer/internal/cloudagentsnet"
	"github.com/marmutapp/superbased-observer/internal/cloudagentssvc"
	"github.com/marmutapp/superbased-observer/internal/keystore"
)

// TestCloudAgentsCLI_ServerErrorHint: a vendor 500 on the connect probe
// (seen live 2026-11-01) prints server_error and a "try again" hint through
// the real egress, never "unreachable".
func TestCloudAgentsCLI_ServerErrorHint(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"Internal server error"}`))
	}))
	defer srv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	addr := srv.Listener.Addr().String()
	cloudAgentsTestKeys = &keystore.MemStore{}
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
	out, err := runCloudAgentsIn(t, "key_cli_SECRET_00ff11ee\n", "test", "cursor-cloud", "--config", cfg)
	if err != nil {
		t.Fatalf("test: %v %s", err, out)
	}
	if !strings.Contains(out, "not usable (server_error)") || !strings.Contains(out, "Cursor returned a server error (HTTP 5xx)") ||
		strings.Contains(out, "unreachable") {
		t.Fatalf("output: %s", out)
	}
}

// TestCloudAgentsCLI_HintTable: every API connector has a hint for the
// server_error class, and the Cursor key hint names where the key is made.
func TestCloudAgentsCLI_HintTable(t *testing.T) {
	for _, c := range cloudagents.Connectors {
		if c.Kind != cloudagents.SourceAPI {
			continue
		}
		if classHint(cloudagents.ErrServerError, c.ID) == "" {
			t.Errorf("%s: no server_error hint", c.ID)
		}
	}
	if h := classHint(cloudagents.ErrNotSignedIn, cloudagents.ConnectorCursorCloud); !strings.Contains(h, "Dashboard > API Keys") || strings.Contains(h, "Integrations") {
		t.Errorf("cursor key hint: %q", h)
	}
}

// TestCloudAgentsCLI_SyncPrintsOwed: finished sessions still owed a read are
// reported apart from the running ones, an API connector prints no CLI
// "re-read" count, and a failed pass carries its class hint.
func TestCloudAgentsCLI_SyncPrintsOwed(t *testing.T) {
	cases := []struct {
		name    string
		r       cloudagentssvc.SyncResult
		want    []string
		mustNot []string
	}{
		{
			name:    "owed apart from running",
			r:       cloudagentssvc.SyncResult{AccountID: 1, Connector: cloudagents.ConnectorCursorCloud, Tasks: 4, Pages: 1, Details: 8, Streams: 3, Owed: 2},
			want:    []string{"0 still running", "2 finished session(s) still owed a read"},
			mustNot: []string{"re-read,"},
		},
		{
			name: "cli connector keeps re-read",
			r:    cloudagentssvc.SyncResult{AccountID: 2, Connector: cloudagents.ConnectorCopilotAgent, Tasks: 1, Pages: 1, Views: 1, OpenTasks: 1},
			want: []string{"1 re-read", "1 still running"},
		},
		{
			name:    "waiting apart from running (Devin waiting_for_user)",
			r:       cloudagentssvc.SyncResult{AccountID: 3, Connector: cloudagents.ConnectorDevin, Tasks: 2, Pages: 1, OpenTasks: 1, Waiting: 1},
			want:    []string{"1 still running, 1 waiting for the user"},
			mustNot: []string{"2 still running"},
		},
		{
			name:    "no waiting, line as before",
			r:       cloudagentssvc.SyncResult{AccountID: 3, Connector: cloudagents.ConnectorDevin, Tasks: 1, Pages: 1, OpenTasks: 1},
			want:    []string{"1 still running\n"},
			mustNot: []string{"waiting"},
		},
		{
			name:    "server error hint",
			r:       cloudagentssvc.SyncResult{AccountID: 1, Connector: cloudagents.ConnectorCursorCloud, ErrorClass: cloudagents.ErrServerError, Coverage: cloudagents.CoverageVerified},
			want:    []string{"failed (server_error)", "try again in a minute"},
			mustNot: []string{"unreachable"},
		},
	}
	for _, tc := range cases {
		var b bytes.Buffer
		printSyncResult(&b, tc.r)
		out := b.String()
		for _, w := range tc.want {
			if !strings.Contains(out, w) {
				t.Errorf("%s: missing %q in %s", tc.name, w, out)
			}
		}
		for _, w := range tc.mustNot {
			if strings.Contains(out, w) {
				t.Errorf("%s: unexpected %q in %s", tc.name, w, out)
			}
		}
	}
	var b bytes.Buffer
	printCloudAgentsView(&b, cloudagentssvc.View{Accounts: []cloudagentssvc.AccountView{{
		ID: 1, Connector: cloudagents.ConnectorCursorCloud, AccountID: "user:1", Coverage: cloudagents.CoverageVerified, OpenTasks: 0, Waiting: 1, Owed: 2,
	}}})
	if !strings.Contains(b.String(), "OWED") || !strings.Contains(b.String(), "WAITING") {
		t.Errorf("status has no WAITING and OWED columns: %s", b.String())
	}
}
