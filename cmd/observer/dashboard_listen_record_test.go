package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestDashboardListenRecord (SBX-UPD audit finding 3): the daemon's record of
// its dashboard address is owner-only beside the database and reads back; the
// exit removal removes only a record that still names this process; a
// damaged record reads as none.
func TestDashboardListenRecord(t *testing.T) {
	db := filepath.Join(t.TempDir(), "observer.db")
	if _, ok := readDashboardListenRecord(db); ok {
		t.Fatal("a record before any was written")
	}
	remove, err := writeDashboardListenRecord(db, "0.0.0.0:18081")
	if err != nil {
		t.Fatal(err)
	}
	p := dashboardListenRecordPath(db)
	if fi, err := os.Stat(p); err != nil || (runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600) {
		t.Fatalf("record %v %v", fi, err)
	}
	rec, ok := readDashboardListenRecord(db)
	if !ok || rec.Addr != "0.0.0.0:18081" || rec.PID != os.Getpid() {
		t.Fatalf("read back %+v %v", rec, ok)
	}
	remove()
	if _, err := os.Stat(p); err == nil {
		t.Fatal("the exit removal left this process's record")
	}
	if err := os.WriteFile(p, []byte(`{"addr":"127.0.0.1:9","pid":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	remove()
	if _, err := os.Stat(p); err != nil {
		t.Fatal("the exit removal removed another process's record")
	}
	if err := os.WriteFile(p, []byte(`{"addr":"no port"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := readDashboardListenRecord(db); ok {
		t.Fatal("a damaged record read back")
	}
}

// TestDialableDashboardAddr: an every-interface bind is dialled on loopback.
func TestDialableDashboardAddr(t *testing.T) {
	for in, want := range map[string]string{
		"0.0.0.0:8081":   "127.0.0.1:8081",
		"[::]:8081":      "127.0.0.1:8081",
		":8081":          "127.0.0.1:8081",
		"127.0.0.1:9000": "127.0.0.1:9000",
		"[::1]:9000":     "[::1]:9000",
		"10.0.0.5:8081":  "10.0.0.5:8081",
		"bad":            "bad",
	} {
		if got := dialableDashboardAddr(in); got != want {
			t.Errorf("%q = %q, want %q", in, got, want)
		}
	}
}

// TestLiveRunsQueryRefusedVsOther (SBX-UPD audit finding 3): a refused
// connection is no daemon (no error, not answered); any other failure is an
// error the CLI names, and the restart is refused for it unless
// --end-sandboxed-runs.
func TestLiveRunsQueryRefusedVsOther(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := ln.Addr().String()
	_ = ln.Close()
	rep, err := httpLiveRunsClient("http://" + closed + "/api/admin/restart").query(context.Background())
	if err != nil || rep.Answered {
		t.Fatalf("refused: %+v %v, want no daemon", rep, err)
	}
	if !isConnRefused(func() error { _, e := net.Dial("tcp", closed); return e }()) {
		t.Fatal("a refused dial is not recognised")
	}
	if isConnRefused(errors.New("EOF")) {
		t.Fatal("a plain error read as refused")
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			return
		}
		c, _, _ := hj.Hijack()
		_ = c.Close()
	}))
	defer srv.Close()
	c := httpLiveRunsClient(srv.URL + "/api/admin/restart")
	if _, err := c.query(context.Background()); err == nil {
		t.Fatal("a daemon that hung up read as no daemon")
	}
	var out strings.Builder
	err = cliLiveRunCheck(context.Background(), &out, liveRunTriggerServiceRestart, c, cliLiveRunChoice{flagHint: "--end-sandboxed-runs"})
	if err == nil || !errors.Is(err, errLiveRunsUnknown) || !strings.Contains(err.Error(), "--end-sandboxed-runs") {
		t.Fatalf("an unreadable daemon: err %v", err)
	}
	out.Reset()
	if err := cliLiveRunCheck(context.Background(), &out, liveRunTriggerServiceRestart, c, cliLiveRunChoice{endRuns: true}); err != nil || !strings.Contains(out.String(), "WARN could not read") {
		t.Fatalf("--end-sandboxed-runs with an unreadable daemon: err %v, out %q", err, out.String())
	}
}
