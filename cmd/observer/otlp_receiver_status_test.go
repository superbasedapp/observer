package main

import (
	"context"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/diag"
	otlpingest "github.com/marmutapp/superbased-observer/internal/ingest/otlp"

	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
)

// TestOTLPReceiverStatusCheck pins W0-4 / F25: a port clash is recorded by
// the daemon and shown by doctor as a FAIL, a bound receiver as OK.
func TestOTLPReceiverStatusCheck(t *testing.T) {
	cfg := config.Default()
	cfg.Observer.DBPath = filepath.Join(t.TempDir(), "observer.db")
	cfg.Observability.Enabled = true

	if c := otlpReceiverStatusCheck(cfg); c.Status != diag.StatusOK || !strings.Contains(c.Message, "no OTLP receiver status") {
		t.Fatalf("no record: %+v", c)
	}

	// A real clash: hold a port, then try to open the receiver on it.
	held, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	_, err = otlpingest.New(otlpingest.Options{
		HTTPAddr:     held.Addr().String(),
		TraceHandler: func(context.Context, *coltracepb.ExportTraceServiceRequest) error { return nil },
	})
	if err == nil {
		t.Fatal("expected a bind error on a held port")
	}
	if err := recordOTLPReceiverStatus(cfg, otlpReceiverStatus{State: otlpReceiverBindFailed, HTTPAddr: held.Addr().String(), Error: err.Error()}); err != nil {
		t.Fatal(err)
	}
	c := otlpReceiverStatusCheck(cfg)
	if c.Status != diag.StatusFail || !strings.Contains(strings.Join(c.Details, "\n"), held.Addr().String()) {
		t.Fatalf("bind failure: %+v", c)
	}

	if err := recordOTLPReceiverStatus(cfg, otlpReceiverStatus{State: otlpReceiverListening, HTTPAddr: "127.0.0.1:4318"}); err != nil {
		t.Fatal(err)
	}
	if c := otlpReceiverStatusCheck(cfg); c.Status != diag.StatusOK || c.Message != "OTLP receiver listening" {
		t.Fatalf("listening: %+v", c)
	}

	cfg.Observability.Enabled, cfg.Ingest.OTel.Enabled = false, false
	if c := otlpReceiverStatusCheck(cfg); c.Status != diag.StatusOK || !strings.Contains(c.Message, "not opened") {
		t.Fatalf("receiver off: %+v", c)
	}
}
