//go:build !sbo_omit_ingest_otlp

package main

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	otlpingest "github.com/marmutapp/superbased-observer/internal/ingest/otlp"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/store"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	"google.golang.org/protobuf/proto"
)

// freeLoopbackAddr returns a loopback address with a port nothing holds.
func freeLoopbackAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func otelLoopConfig(t *testing.T) (cfgPath, dbPath string) {
	t.Helper()
	dir := t.TempDir()
	cfgPath = filepath.Join(dir, "config.toml")
	dbPath = filepath.Join(dir, "state", "observer.db")
	if err := os.WriteFile(cfgPath, []byte("[observer]\ndb_path = \""+filepath.ToSlash(dbPath)+"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Seed the sandbox database from the migrated template. The receiver
	// opens it before it listens, and a fresh database runs every migration
	// first: about 20s under -race, past the wait for the port. These tests
	// are about the receiver, not the migration chain.
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		t.Fatal(err)
	}
	seeded, err := dbtemplate.Open(context.Background(), db.Options{Path: dbPath})
	if err != nil {
		t.Fatalf("seed database: %v", err)
	}
	if err := seeded.Close(); err != nil {
		t.Fatal(err)
	}
	return cfgPath, dbPath
}

// TestOTelLoopbackServe drives the in-sandbox receiver end to end (lane
// CA-C7): a Claude Code cloud export posted over OTLP/HTTP protobuf lands its
// api_request turn in the sandbox database and stamps the session
// vendor_cloud with its ccr.session.id; the receiver stops on its idle bound
// and logs to the cloud-session state directory.
func TestOTelLoopbackServe(t *testing.T) {
	cfgPath, dbPath := otelLoopConfig(t)
	addr := freeLoopbackAddr(t)
	done := make(chan error, 1)
	go func() {
		done <- runOTelLoopbackServe(context.Background(), otelLoopServeOptions{
			ConfigPath: cfgPath, Addr: addr, Idle: 1500 * time.Millisecond, MaxLifetime: time.Minute,
		})
	}()
	deadline := time.Now().Add(10 * time.Second)
	for !probeLoopback(addr) {
		select {
		case err := <-done:
			// serve ended before it ever listened: say why, instead of
			// waiting out the deadline and blaming the probe.
			t.Fatalf("receiver ended before it answered: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("receiver never answered")
		}
		time.Sleep(50 * time.Millisecond)
	}
	req := &collogspb.ExportLogsServiceRequest{ResourceLogs: []*logspb.ResourceLogs{{
		ScopeLogs: []*logspb.ScopeLogs{{LogRecords: []*logspb.LogRecord{{
			EventName: "claude_code.api_request", TimeUnixNano: uint64(time.Now().UnixNano()),
			Attributes: []*commonpb.KeyValue{
				strAttr("session.id", "sess-loop"), strAttr("ccr.session.id", "cse_0123456789abcdefABCDEFGH"),
				strAttr("request_id", "req_loop"), strAttr("model", "claude-opus-5-5"),
				{Key: "input_tokens", Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_IntValue{IntValue: 2}}},
				{Key: "output_tokens", Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_IntValue{IntValue: 4}}},
			},
		}}}},
	}}}
	body, err := proto.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	postOTLP(t, "http://"+addr+"/v1/logs", body, "application/x-protobuf")

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serve: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("receiver did not stop on its idle bound")
	}
	if probeLoopback(addr) {
		t.Error("port still answers after the idle stop")
	}

	database, err := db.Open(context.Background(), db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = database.Close() }()
	if n := countRows(t, database, `SELECT COUNT(*) FROM api_turns WHERE request_id = 'req_loop' AND session_id = 'sess-loop'`); n != 1 {
		t.Fatalf("api_turns = %d; want 1", n)
	}
	ex, err := store.New(database).LoadSessionExecution(context.Background(), "sess-loop")
	if err != nil || ex.ExecutionLocation != models.ExecutionVendorCloud || ex.VendorSessionRef != "cse_0123456789abcdefABCDEFGH" {
		t.Fatalf("execution = %+v, %v", ex, err)
	}
	logb, err := os.ReadFile(filepath.Join(filepath.Dir(dbPath), "cloud-session", "otel-receiver.log"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(logb), "otel-receiver: listening") || !strings.Contains(string(logb), "reason=idle") {
		t.Errorf("log:\n%s", logb)
	}
}

// TestOTelLoopbackServeRefusesNonLoopback: the receiver never binds beyond
// loopback, whatever address reaches it.
func TestOTelLoopbackServeRefusesNonLoopback(t *testing.T) {
	cfgPath, _ := otelLoopConfig(t)
	err := runOTelLoopbackServe(context.Background(), otelLoopServeOptions{
		ConfigPath: cfgPath, Addr: "0.0.0.0:0", Idle: time.Second, MaxLifetime: time.Second,
	})
	if !errors.Is(err, otlpingest.ErrNonLoopback) {
		t.Fatalf("err = %v; want ErrNonLoopback", err)
	}
}
