//go:build !sbo_omit_ingest_otlp

package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	otlpingest "github.com/marmutapp/superbased-observer/internal/ingest/otlp"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/store"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
)

func strAttr(k, v string) *commonpb.KeyValue {
	return &commonpb.KeyValue{Key: k, Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: v}}}
}

// TestOTLPCloudSessionStampsExecution drives the node's OTLP logs handler
// with a Claude Code cloud export (cloud-agents lane CA-B4, Rail T): the
// ccr.session.id marker creates the session row (Claude Code's export
// otherwise never does, NoSessionRows) and stamps vendor_cloud plus the
// reference; a malformed reference is dropped but the location lands; a
// local export (no marker) creates no session row, exactly as before.
func TestOTLPCloudSessionStampsExecution(t *testing.T) {
	tests := []struct {
		name        string
		ccr         string // "" = no marker attribute
		wantSession bool
		wantRef     string
	}{
		{"cloud", "cse_0123456789abcdefABCDEFGH", true, "cse_0123456789abcdefABCDEFGH"},
		{"cloud, malformed reference", "cse bad ref", true, ""},
		{"local", "", false, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			database, err := dbtemplate.Open(ctx, db.Options{Path: t.TempDir() + "/o.db"})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = database.Close() }()
			st := store.New(database)
			h := otlpLogsHandler(st, slog.New(slog.NewTextHandler(io.Discard, nil)), false, config.DefaultIngestOTelContentMaxBytes)
			attrs := []*commonpb.KeyValue{
				strAttr("session.id", "sess-cloud-otlp"), strAttr("request_id", "req_cloud"),
				strAttr("model", "claude-opus-5-5"),
				{Key: "input_tokens", Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_IntValue{IntValue: 12}}},
			}
			if tc.ccr != "" {
				attrs = append(attrs, strAttr("ccr.session.id", tc.ccr))
			}
			req := &collogspb.ExportLogsServiceRequest{ResourceLogs: []*logspb.ResourceLogs{{
				ScopeLogs: []*logspb.ScopeLogs{{LogRecords: []*logspb.LogRecord{{
					EventName: "claude_code.api_request", TimeUnixNano: 1_790_000_000_000_000_000, Attributes: attrs,
				}}}},
			}}}
			if err := h(ctx, req); err != nil {
				t.Fatalf("handler: %v", err)
			}
			got, err := st.LoadSessionExecution(ctx, "sess-cloud-otlp")
			if !tc.wantSession {
				if err == nil {
					t.Fatalf("local export created a session row: %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("session row not created: %v", err)
			}
			if got.ExecutionLocation != models.ExecutionVendorCloud || got.VendorSessionRef != tc.wantRef {
				t.Fatalf("stored = %+v; want vendor_cloud / %q", got, tc.wantRef)
			}
			var turns int
			if err := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM api_turns WHERE request_id = 'req_cloud'`).Scan(&turns); err != nil || turns != 1 {
				t.Fatalf("turn rows = %d (%v); want 1", turns, err)
			}
		})
	}
}

// TestOTLPCloudEnvironmentText pins `observer init --otlp-cloud-endpoint`:
// it prints the server-managed settings text (CA-C7) (the receiver's real token header
// name, the token FILE, never a token), writes nothing, and refuses a
// loopback endpoint.
func TestOTLPCloudEnvironmentText(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	dbPath := filepath.Join(dir, "state", "observer.db")
	if err := os.WriteFile(cfgPath, []byte("[observer]\ndb_path = \""+filepath.ToSlash(dbPath)+"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := runOTLPCloudEnvironment(&out, cfgPath, "https://node.tailnet.example:4318"); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	for _, must := range []string{
		`"OTEL_EXPORTER_OTLP_ENDPOINT": "https://node.tailnet.example:4318"`,
		`"OTEL_EXPORTER_OTLP_HEADERS": "` + otlpingest.HeaderEdgeToken + "=<paste the ship token from `observer cloud-session token mint \\\"claude-code-server-managed\\\" --ttl 168h`>\"",
		"Server-managed settings (merge into the env block; never a cloud environment's variables):",
		// CLOUDTEL-1 (CA-D18): the shared receiver token file is named only
		// to say it does not belong in the managed settings.
		"Do not use the node's shared receiver token (" + otlpIngestTokenPath(config.Config{Observer: config.ObserverConfig{DBPath: dbPath}}) + ")",
		"Network access: Limited, with node.tailnet.example under Allowed domains (or Full)",
		"not open to the network yet",
	} {
		if !strings.Contains(got, must) {
			t.Errorf("output lacks %q:\n%s", must, got)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "state")); !os.IsNotExist(err) {
		t.Errorf("the print-only command created state: %v", err)
	}
	if err := runOTLPCloudEnvironment(&out, cfgPath, "http://127.0.0.1:4318"); err == nil {
		t.Error("loopback endpoint accepted")
	}
}
