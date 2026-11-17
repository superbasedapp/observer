//go:build !sbo_omit_security && !sbo_omit_security_dast

package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
)

// TestSecurityDASTDashRefusals: the dashboard seam refuses every run and
// accept unless security.dast is selected, refuses a run before the accept
// and a URL that is not a dev server on this machine, and the accept it
// records reads as the dashboard's.
func TestSecurityDASTDashRefusals(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.toml")
	write := func(body string) {
		if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	ctx := context.Background()

	write("")
	seam := securityDASTDash(cfg, nil)
	if st := seam.State(ctx); st.Selected || st.AcceptText == "" {
		t.Fatalf("no block: %+v", st)
	}
	if _, err := seam.Run(ctx, dir, srv.URL+"/", false); !errors.Is(err, dashapi.ErrDASTNotSelected) {
		t.Fatalf("not selected run: %v", err)
	}
	if err := seam.Accept(ctx); !errors.Is(err, dashapi.ErrDASTNotSelected) {
		t.Fatalf("not selected accept: %v", err)
	}

	write("[components]\nadd = [\"security\", \"security.dast\"]\n")
	if st := seam.State(ctx); !st.Selected || st.Accepted {
		t.Fatalf("selected, not accepted: %+v", st)
	}
	if _, err := seam.Run(ctx, dir, srv.URL+"/", false); !errors.Is(err, dashapi.ErrDASTNotAccepted) {
		t.Fatalf("not accepted run: %v", err)
	}
	if err := seam.Accept(ctx); err != nil {
		t.Fatal(err)
	}
	st := seam.State(ctx)
	if !st.Accepted || st.AcceptedOn != "dashboard" {
		t.Fatalf("accepted: %+v", st)
	}
	for _, bad := range []string{"http://example.com:80/", "http://192.168.1.2:3000/", "file:///etc/passwd"} {
		if _, err := seam.Run(ctx, dir, bad, false); !errors.Is(err, dashapi.ErrDASTBadTarget) {
			t.Errorf("%s: %v", bad, err)
		}
	}
	// A run while another holds the lock is busy.
	dastDashRun.Lock()
	_, err := seam.Run(ctx, dir, srv.URL+"/", false)
	dastDashRun.Unlock()
	if !errors.Is(err, dashapi.ErrDASTBusy) {
		t.Fatalf("busy: %v", err)
	}
}

// TestDASTOriginRuns: newest run first.
func TestDASTOriginRuns(t *testing.T) {
	t0 := time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC)
	rec := dastProjectRecord{Version: 1, Origins: map[string]dastOriginRecord{
		"http://localhost:3000": {At: t0, Outcome: "complete", Findings: 2},
		"http://localhost:5173": {At: t0.Add(time.Hour), Outcome: "partial", Findings: 1},
	}}
	got := dastOriginRuns(rec)
	if len(got) != 2 || got[0].Origin != "http://localhost:5173" || got[1].Findings != 2 || got[0].At != "2026-11-13T11:00:00Z" {
		t.Fatalf("%+v", got)
	}
}
