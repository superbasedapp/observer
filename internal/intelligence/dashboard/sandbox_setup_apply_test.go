//go:build !sbo_omit_remote

package dashboard

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"testing"
)

// sandbox_setup_apply_test.go pins the live apply of [terminal.sandbox]
// (fix round 3, item 1): POST .../setup/{backend}/apply and the Settings
// save both reach the seam's ApplyLive, the one seam a sandbox config write
// takes effect through in a running daemon.

// fakeLiveApplier is a setup seam that can apply live.
type fakeLiveApplier struct {
	fakeSandboxSetup
	applied int
}

func (f *fakeLiveApplier) ApplyLive(context.Context) { f.applied++ }

// TestSandboxSetupApplyRoute is one case per row.
func TestSandboxSetupApplyRoute(t *testing.T) {
	cases := []struct {
		name      string
		applier   bool
		token     bool
		wantCode  int
		wantApply bool
		wantCalls int
	}{
		{name: "a daemon seam applies", applier: true, token: true, wantCode: http.StatusOK, wantApply: true, wantCalls: 1},
		{name: "a seam that cannot apply says so", applier: false, token: true, wantCode: http.StatusOK, wantApply: false},
		{name: "no confirm token is refused and applies nothing", applier: true, token: false, wantCode: http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fa := &fakeLiveApplier{}
			h := setupServer(t, &fa.fakeSandboxSetup, Options{})
			if tc.applier {
				h = setupServer(t, fa, Options{})
			}
			rec := componentsPost(h, "/api/terminal/sandbox/setup/bwrap/apply", `{}`, tc.token)
			if rec.Code != tc.wantCode {
				t.Fatalf("apply = %d %s, want %d", rec.Code, rec.Body.String(), tc.wantCode)
			}
			if fa.applied != tc.wantCalls {
				t.Fatalf("ApplyLive calls = %d, want %d", fa.applied, tc.wantCalls)
			}
			if tc.wantCode != http.StatusOK {
				return
			}
			var body struct {
				Applied bool `json:"applied"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.Applied != tc.wantApply {
				t.Fatalf("body = %s (err %v), want applied %v", rec.Body.String(), err, tc.wantApply)
			}
		})
	}
}

// TestTerminalSandboxConfigPutAppliesLive: a real Settings save reaches the
// seam's ApplyLive once.
func TestTerminalSandboxConfigPutAppliesLive(t *testing.T) {
	const body = `{"enabled":true,"backend":"bwrap","home_mode":"tmpfs","prep_timeout_seconds":300}`
	s, h := newManageServer(t)
	fa := &fakeLiveApplier{}
	s.opts.SandboxSetup = fa
	if code, out := putSandboxConfig(t, h, body); code != http.StatusOK {
		t.Fatalf("PUT = %d: %v", code, out)
	}
	if fa.applied != 1 {
		t.Fatalf("ApplyLive calls after a save = %d, want 1", fa.applied)
	}
}

// TestSandboxSetupApplyRouteLogs (R4 (a)): the daemon logs one info line
// for each apply the route serves, naming the backend and the source, and a
// refused request logs none.
func TestSandboxSetupApplyRouteLogs(t *testing.T) {
	for _, tc := range []struct {
		name  string
		token bool
		want  int
	}{
		{"an apply is logged once", true, 1},
		{"a refused request logs nothing", false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			fa := &fakeLiveApplier{}
			h := setupServer(t, fa, Options{Logger: slog.New(slog.NewTextHandler(&buf, nil))})
			componentsPost(h, "/api/terminal/sandbox/setup/seatbelt/apply", `{}`, tc.token)
			got := 0
			for _, line := range strings.Split(buf.String(), "\n") {
				if strings.Contains(line, "sandbox setup: live apply") {
					got++
					if !strings.Contains(line, "level=INFO") || !strings.Contains(line, "backend=seatbelt") || !strings.Contains(line, `source="route apply"`) || !strings.Contains(line, "applied=true") {
						t.Fatalf("log line = %q", line)
					}
				}
			}
			if got != tc.want {
				t.Fatalf("apply log lines = %d, want %d (log %q)", got, tc.want, buf.String())
			}
		})
	}
}
