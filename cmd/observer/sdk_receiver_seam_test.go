package main

import (
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// TestSDKDashboardSeamsReportTheReceiverRecord pins review E-72's wiring: the
// dashboard's receiver seam reads the same record `observer doctor` does.
func TestSDKDashboardSeamsReportTheReceiverRecord(t *testing.T) {
	cfg := config.Default()
	cfg.Observer.DBPath = filepath.Join(t.TempDir(), "observer.db")
	seams := sdkDashboardSeams(cfg, nil)
	if seams.Receiver == nil {
		t.Fatal("the receiver seam is not wired")
	}
	if _, ok := seams.Receiver(); ok {
		t.Fatal("no record yet must read as not recorded")
	}
	if err := recordOTLPReceiverStatus(cfg, otlpReceiverStatus{State: otlpReceiverBindFailed, HTTPAddr: "127.0.0.1:4318", Error: "address already in use"}); err != nil {
		t.Fatal(err)
	}
	got, ok := seams.Receiver()
	if !ok || got.State != "bind_failed" || got.HTTPAddr != "127.0.0.1:4318" || got.Error != "address already in use" || got.At == "" {
		t.Fatalf("receiver = %+v ok=%v", got, ok)
	}
}
