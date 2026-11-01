package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/db"
)

// fakeLiveRuns is a scriptable dashapi.LiveSandboxRuns.
type fakeLiveRuns struct {
	runs           []dashapi.LiveSandboxRun
	ended          int
	pending        bool
	updateDeferred bool
	updatePending  bool
	policy         string
}

func (f *fakeLiveRuns) State() dashapi.LiveSandboxRunsState {
	return dashapi.LiveSandboxRunsState{
		Runs: f.runs, RestartPending: f.pending,
		RestartPendingSince: time.Date(2026, 10, 23, 10, 0, 0, 0, time.UTC),
		UpdateDeferred:      f.updateDeferred, UpdatePending: f.updatePending, Policy: f.policy,
	}
}

func (f *fakeLiveRuns) EndRuns(context.Context) (int, error) {
	n := len(f.runs)
	f.ended += n
	f.runs = nil
	return n, nil
}
func (f *fakeLiveRuns) RestartWhenFinished() error { f.pending = true; return nil }
func (f *fakeLiveRuns) CancelPending() bool {
	was := f.pending || f.updatePending
	f.pending, f.updatePending = false, false
	return was
}
func (f *fakeLiveRuns) ApplyUpdateWhenFinished() error { f.updatePending = true; return nil }

// newLiveRunsServer builds a loopback dashboard with a restart hook and the
// live-run seam (nil seam: the route of before).
func newLiveRunsServer(t *testing.T, restart func() error, seam dashapi.LiveSandboxRuns) http.Handler {
	t.Helper()
	return newLiveRunsServerWith(t, restart, seam, nil)
}

// newLiveRunsServerWith is newLiveRunsServer with a restart preflight.
func newLiveRunsServerWith(t *testing.T, restart func() error, seam dashapi.LiveSandboxRuns, preflight func() error) http.Handler {
	t.Helper()
	dir := t.TempDir()
	database, err := openTestDB(context.Background(), db.Options{Path: filepath.Join(dir, "observer.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	opts := Options{DB: database, ConfigPath: filepath.Join(dir, "config.toml"), RestartFunc: restart, RestartPreflight: preflight}
	if seam != nil {
		opts.LiveSandboxRuns = seam
	}
	s, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s.Handler()
}

func restartReq(t *testing.T, h http.Handler, method, body string) *httptest.ResponseRecorder {
	t.Helper()
	var req *http.Request
	if body == "" {
		req = httptest.NewRequest(method, "/api/admin/restart", nil)
	} else {
		req = httptest.NewRequest(method, "/api/admin/restart", strings.NewReader(body))
	}
	req.Host = "127.0.0.1:8080"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

var oneLiveRun = []dashapi.LiveSandboxRun{{RunID: "r1", Tool: "claude-code", Backend: "bwrap", AgeSeconds: 300, NativeResume: true}}

// TestRestartGoldenWithNoLiveRun pins that with no live sandboxed run the
// route answers byte for byte as it did before the question existed: the
// seam absent, and the seam wired with zero runs (only the count header is
// new).
func TestRestartGoldenWithNoLiveRun(t *testing.T) {
	const postGolden = `{"delay_ms":300,"restart_scheduled":true}` + "\n"
	for _, tc := range []struct {
		name string
		seam dashapi.LiveSandboxRuns
	}{{"no seam", nil}, {"seam, zero runs", &fakeLiveRuns{policy: "defer"}}} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			h := newLiveRunsServer(t, func() error { calls++; return nil }, tc.seam)
			rec := restartReq(t, h, http.MethodPost, "")
			if rec.Code != http.StatusOK || rec.Body.String() != postGolden || calls != 1 {
				t.Fatalf("POST = %d %q (calls %d), want 200 %q", rec.Code, rec.Body.String(), calls, postGolden)
			}
			get := restartReq(t, h, http.MethodGet, "")
			var m map[string]any
			if err := json.Unmarshal(get.Body.Bytes(), &m); err != nil {
				t.Fatalf("GET body: %v", err)
			}
			for k := range m {
				switch k {
				case "available", "proxy_port", "window_s", "proxy_recent_requests":
				default:
					t.Fatalf("GET grew key %q with no live run: %s", k, get.Body.String())
				}
			}
			if hdr := get.Header().Get(dashapi.LiveRunsHeader); (tc.seam == nil) != (hdr == "") {
				t.Fatalf("count header = %q with seam=%v", hdr, tc.seam != nil)
			}
		})
	}
}

// TestRestartAsksWithLiveRuns: a plain restart with a live sandboxed run is
// refused 409 naming the runs, and the restart hook never runs.
func TestRestartAsksWithLiveRuns(t *testing.T) {
	calls := 0
	seam := &fakeLiveRuns{runs: oneLiveRun, policy: "defer"}
	h := newLiveRunsServer(t, func() error { calls++; return nil }, seam)
	rec := restartReq(t, h, http.MethodPost, "")
	if rec.Code != http.StatusConflict || calls != 0 {
		t.Fatalf("POST = %d (calls %d), want 409 and no restart: %s", rec.Code, calls, rec.Body.String())
	}
	var body struct {
		Error string                   `json:"error"`
		Runs  []dashapi.LiveSandboxRun `json:"runs"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.Error != "live_sandboxed_runs" || len(body.Runs) != 1 || body.Runs[0].Backend != "bwrap" {
		t.Fatalf("409 body = %s (err %v)", rec.Body.String(), err)
	}
	if rec.Header().Get(dashapi.LiveRunsHeader) != "1" {
		t.Fatalf("count header = %q, want 1", rec.Header().Get(dashapi.LiveRunsHeader))
	}
	get := restartReq(t, h, http.MethodGet, "")
	if !strings.Contains(get.Body.String(), `"live_sandboxed_runs"`) {
		t.Fatalf("GET does not list the runs: %s", get.Body.String())
	}
}

// TestRestartAnswers covers both answers and the cancel: "end" ends the
// runs then restarts; "when_finished" schedules a pending restart (202, no
// restart now) that "cancel" withdraws; "end_only" ends without restarting.
func TestRestartAnswers(t *testing.T) {
	t.Run("end", func(t *testing.T) {
		calls := 0
		seam := &fakeLiveRuns{runs: oneLiveRun}
		h := newLiveRunsServer(t, func() error { calls++; return nil }, seam)
		rec := restartReq(t, h, http.MethodPost, `{"live_runs":"end"}`)
		if rec.Code != http.StatusOK || calls != 1 || seam.ended != 1 || !strings.Contains(rec.Body.String(), `"ended_sandboxed_runs":1`) {
			t.Fatalf("end = %d %s (calls %d, ended %d)", rec.Code, rec.Body.String(), calls, seam.ended)
		}
	})
	t.Run("when_finished then cancel", func(t *testing.T) {
		calls := 0
		seam := &fakeLiveRuns{runs: oneLiveRun}
		h := newLiveRunsServer(t, func() error { calls++; return nil }, seam)
		rec := restartReq(t, h, http.MethodPost, `{"live_runs":"when_finished"}`)
		if rec.Code != http.StatusAccepted || calls != 0 || !seam.pending {
			t.Fatalf("when_finished = %d %s (calls %d, pending %v)", rec.Code, rec.Body.String(), calls, seam.pending)
		}
		if get := restartReq(t, h, http.MethodGet, ""); !strings.Contains(get.Body.String(), `"restart_pending":true`) {
			t.Fatalf("GET does not show the pending restart: %s", get.Body.String())
		}
		rec = restartReq(t, h, http.MethodPost, `{"live_runs":"cancel"}`)
		if rec.Code != http.StatusOK || seam.pending || !strings.Contains(rec.Body.String(), `"pending_cancelled":true`) {
			t.Fatalf("cancel = %d %s", rec.Code, rec.Body.String())
		}
	})
	t.Run("end_only", func(t *testing.T) {
		calls := 0
		seam := &fakeLiveRuns{runs: oneLiveRun}
		h := newLiveRunsServer(t, func() error { calls++; return nil }, seam)
		rec := restartReq(t, h, http.MethodPost, `{"live_runs":"end_only"}`)
		if rec.Code != http.StatusOK || calls != 0 || seam.ended != 1 {
			t.Fatalf("end_only = %d %s (calls %d)", rec.Code, rec.Body.String(), calls)
		}
	})
	t.Run("unknown answer", func(t *testing.T) {
		h := newLiveRunsServer(t, func() error { return nil }, &fakeLiveRuns{runs: oneLiveRun})
		if rec := restartReq(t, h, http.MethodPost, `{"live_runs":"maybe"}`); rec.Code != http.StatusBadRequest {
			t.Fatalf("unknown answer = %d", rec.Code)
		}
	})
}

// TestRestartStatusShowsTheDeferredUpdate: a deferred update apply shows in
// the GET report as the same question; ask_immediately sets update_question
// (the dialog opens at once), defer leaves it to the banner; and
// apply_when_finished is accepted 202.
func TestRestartStatusShowsTheDeferredUpdate(t *testing.T) {
	for _, tc := range []struct {
		policy   string
		question bool
	}{{"defer", false}, {"ask_immediately", true}} {
		seam := &fakeLiveRuns{runs: oneLiveRun, updateDeferred: true, policy: tc.policy}
		h := newLiveRunsServer(t, func() error { return nil }, seam)
		get := restartReq(t, h, http.MethodGet, "")
		var m map[string]any
		if err := json.Unmarshal(get.Body.Bytes(), &m); err != nil {
			t.Fatal(err)
		}
		if m["update_deferred_live_sandbox"] != true || m["update_question"] != tc.question || m["live_run_update_policy"] != tc.policy {
			t.Fatalf("%s: GET = %s", tc.policy, get.Body.String())
		}
		rec := restartReq(t, h, http.MethodPost, `{"live_runs":"apply_when_finished"}`)
		if rec.Code != http.StatusAccepted || !seam.updatePending {
			t.Fatalf("%s: apply_when_finished = %d %s", tc.policy, rec.Code, rec.Body.String())
		}
	}
}

// TestRestartEndPreflightsFirst (SBX-UPD audit finding 1): "end the runs and
// restart" runs the restart's refusal checks before it ends anything, so a
// restart that refuses leaves the runs live. No re-exec on this OS (a native
// Windows daemon) answers 501; a config preflight refusal answers 500; a
// passing preflight ends the runs and restarts as before.
func TestRestartEndPreflightsFirst(t *testing.T) {
	for _, tc := range []struct {
		name      string
		preflight error
		code      int
	}{
		{"no re-exec on this OS", fmt.Errorf("start: %w", dashapi.ErrRestartUnsupported), http.StatusNotImplemented},
		{"config would not come back", errors.New("restart refused - the current config is invalid (fix it first)"), http.StatusInternalServerError},
		{"preflight passes", nil, http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls, checks := 0, 0
			seam := &fakeLiveRuns{runs: oneLiveRun}
			restart := func() error {
				calls++
				return tc.preflight
			}
			h := newLiveRunsServerWith(t, restart, seam, func() error { checks++; return tc.preflight })
			rec := restartReq(t, h, http.MethodPost, `{"live_runs":"end"}`)
			if rec.Code != tc.code || checks != 1 {
				t.Fatalf("end = %d %s (preflight runs %d), want %d", rec.Code, rec.Body.String(), checks, tc.code)
			}
			if tc.preflight != nil {
				if seam.ended != 0 || len(seam.runs) != 1 || calls != 0 {
					t.Fatalf("a refused restart ended %d run(s) (left %d, restart calls %d)", seam.ended, len(seam.runs), calls)
				}
				return
			}
			if seam.ended != 1 || calls != 1 {
				t.Fatalf("a passing preflight: ended %d, restart calls %d", seam.ended, calls)
			}
		})
	}
}

// TestRestartBodyIgnoredWithNoSeam (SBX-UPD audit finding 6): with no live-run
// seam wired the route never reads its body, so a body that is not JSON
// restarts exactly as an empty one did; with the seam it is refused 400.
func TestRestartBodyIgnoredWithNoSeam(t *testing.T) {
	calls := 0
	h := newLiveRunsServer(t, func() error { calls++; return nil }, nil)
	if rec := restartReq(t, h, http.MethodPost, "not json"); rec.Code != http.StatusOK || calls != 1 {
		t.Fatalf("no seam, non-JSON body = %d %s (calls %d), want the plain restart", rec.Code, rec.Body.String(), calls)
	}
	h = newLiveRunsServer(t, func() error { calls++; return nil }, &fakeLiveRuns{})
	if rec := restartReq(t, h, http.MethodPost, "not json"); rec.Code != http.StatusBadRequest {
		t.Fatalf("seam, non-JSON body = %d, want 400", rec.Code)
	}
}
