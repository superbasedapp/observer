package main

import (
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/cloudmetrics"
)

// TestStartMetricsListener: off by default (no socket, nil registry), a
// malformed or public-colliding value refuses to start, and a set value
// serves the process's own families on GET /metrics.
func TestStartMetricsListener(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	env := func(v string) func(string) string {
		return func(k string) string {
			if k == "SBCI_METRICS_LISTEN" {
				return v
			}
			return ""
		}
	}
	reg, err := startMetricsListener(t.Context(), log, env(""), cloudmetrics.ProcessAPI, ":8090")
	if err != nil || reg != nil {
		t.Fatalf("unset: reg=%v err=%v, want nil nil", reg, err)
	}
	for _, bad := range []string{"9470", "host.example:9470", "0.0.0.0:8090"} {
		if _, err := startMetricsListener(t.Context(), log, env(bad), cloudmetrics.ProcessAPI, ":8090"); err == nil {
			t.Errorf("%q: want a refusal", bad)
		}
	}
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := probe.Addr().String()
	probe.Close()
	reg, err = startMetricsListener(t.Context(), log, env(addr), cloudmetrics.ProcessWorker, "")
	if err != nil || reg == nil {
		t.Fatalf("set: reg=%v err=%v", reg, err)
	}
	reg.DeletionBlocked("org", "billing_seam_unwired")
	resp, err := http.Get("http://" + addr + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), `sbci_deletion_blocked_total{kind="org",reason="billing_seam_unwired"} 1`) {
		t.Fatalf("worker /metrics:\n%s", body)
	}
	if strings.Contains(string(body), "sbci_audit_events_total") {
		t.Fatal("the worker rendered the API's families")
	}
}
