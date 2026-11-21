package cloudmetricshttp

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/cloudmetrics"
)

func TestParseListen(t *testing.T) {
	for _, tc := range []struct {
		raw, public, want string
		wantErr           bool
	}{
		{"", ":8090", "", false},
		{"   ", ":8090", "", false},
		{"0.0.0.0:9470", ":8090", "0.0.0.0:9470", false},
		{"127.0.0.1:9471", ":8090", "127.0.0.1:9471", false},
		{":9470", ":8090", ":9470", false},
		{"localhost:9470", ":8090", "localhost:9470", false},
		{"[::1]:9470", ":8090", "[::1]:9470", false},
		{"9470", ":8090", "", true},
		{"0.0.0.0:0", ":8090", "", true},
		{"0.0.0.0:70000", ":8090", "", true},
		{"0.0.0.0:http", ":8090", "", true},
		{"metrics.example.com:9470", ":8090", "", true},
		{"0.0.0.0:8090", ":8090", "", true},
		{"127.0.0.1:8090", "0.0.0.0:8090", "", true},
		{"127.0.0.1:8090", "10.0.0.1:8090", "127.0.0.1:8090", false},
	} {
		got, err := ParseListen(tc.raw, tc.public)
		if (err != nil) != tc.wantErr || got != tc.want {
			t.Errorf("ParseListen(%q,%q) = %q,%v; want %q, err=%v", tc.raw, tc.public, got, err, tc.want, tc.wantErr)
		}
	}
}

func TestNewServerOffByDefault(t *testing.T) {
	if NewServer("", cloudmetrics.New(cloudmetrics.ProcessAPI)) != nil {
		t.Fatal("an empty listen must open nothing")
	}
	if NewServer(":9470", nil) != nil {
		t.Fatal("no registry, no listener")
	}
	if err := Start(t.Context(), nil, nil); err != nil {
		t.Fatal(err)
	}
	srv := NewServer("127.0.0.1:9470", cloudmetrics.New(cloudmetrics.ProcessAPI))
	if srv == nil || srv.ReadHeaderTimeout == 0 || srv.WriteTimeout == 0 {
		t.Fatalf("server bounds missing: %+v", srv)
	}
}

func TestHandlerServesOnlyMetrics(t *testing.T) {
	reg := cloudmetrics.New(cloudmetrics.ProcessAPI)
	reg.AuditEvent("paddle_webhook_signature_invalid")
	ts := httptest.NewServer(Handler(reg))
	defer ts.Close()

	resp, err := http.Get(ts.URL + Path)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/plain; version=0.0.4") {
		t.Fatalf("GET /metrics: %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	if !strings.Contains(string(body), `sbci_audit_events_total{event="paddle_webhook_signature_invalid"} 1`) {
		t.Fatalf("body lacks the counter:\n%s", body)
	}
	for _, p := range []string{"/", "/healthz", "/portal/webhooks/paddle", "/metrics/x"} {
		r, err := http.Get(ts.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		if r.StatusCode != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", p, r.StatusCode)
		}
	}
	r, err := http.Post(ts.URL+Path, "text/plain", strings.NewReader("x"))
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if r.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST /metrics = %d, want 405", r.StatusCode)
	}
}

func TestStartBindsAndShutsDown(t *testing.T) {
	reg := cloudmetrics.New(cloudmetrics.ProcessWorker)
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := probe.Addr().String()
	probe.Close()

	ctx, cancel := context.WithCancel(t.Context())
	if err := Start(ctx, NewServer(addr, reg), func(err error) { t.Errorf("serve: %v", err) }); err != nil {
		t.Fatal(err)
	}
	resp, err := http.Get("http://" + addr + Path)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "sbci_deletion_blocked_open") {
		t.Fatalf("worker exposition missing:\n%s", body)
	}
	// A second start on the same port fails at once (not in a goroutine).
	if err := Start(t.Context(), NewServer(addr, reg), nil); err == nil {
		t.Fatal("a port in use must fail Start")
	}
	cancel()
	deadline := time.Now().Add(5 * time.Second)
	for {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err != nil {
			break
		}
		c.Close()
		if time.Now().After(deadline) {
			t.Fatal("the listener is still open after ctx ended")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
