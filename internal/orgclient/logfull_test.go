package orgclient

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// TestPushOnce_LogFullKeepsRowsAndResends pins the node half of T-823: when
// the org's durable log is at its byte cap the server answers 503 log_full +
// Retry-After. The node must keep every row unpushed (cursor untouched, push
// log "retry", the Retry-After hint carried to the loop) and, once the server
// accepts again, send the SAME rows. Nothing is marked pushed on a refusal.
func TestPushOnce_LogFullKeepsRowsAndResends(t *testing.T) {
	s := newAgentStore(t)
	bs := &memBearerStore{}

	var refuse atomic.Bool
	refuse.Store(true)
	var sentRows []int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wire, _ := io.ReadAll(r.Body)
		env := decodeEnvelope(t, wire)
		rows := len(env.Sessions) + len(env.Actions) + len(env.APITurns) + len(env.TokenUsage)
		sentRows = append(sentRows, rows)
		if refuse.Load() {
			w.Header().Set("Retry-After", "5")
			writeTestJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "log_full"})
			return
		}
		writeTestJSON(w, http.StatusOK, orgcontract.PushResponse{AcceptedRows: int64(rows), NextCursor: env.CursorTo})
	}))
	defer srv.Close()
	enrolFixture(t, s, bs, srv.URL)
	seedActivity(t, s, 3) // 1 session + 3 actions
	c := newTestClient(t, s, bs)
	ctx := context.Background()

	for attempt := 1; attempt <= 2; attempt++ {
		_, err := c.PushOnce(ctx)
		var hs *httpStatusError
		if !errors.As(err, &hs) || hs.status != http.StatusServiceUnavailable {
			t.Fatalf("attempt %d: PushOnce = %v, want a 503 httpStatusError", attempt, err)
		}
		if hs.retryAfter != 5*time.Second || retryAfterOf(err) != 5*time.Second {
			t.Errorf("attempt %d: retryAfter = %v, want 5s from the header", attempt, hs.retryAfter)
		}
		if cur, _ := s.LoadPushCursor(ctx); cur.Actions != 0 || cur.Sessions != 0 {
			t.Fatalf("attempt %d: cursor advanced on 503 log_full: %+v", attempt, cur)
		}
		if last, _ := s.LastPushLog(ctx); last == nil || last.Status != "retry" {
			t.Errorf("attempt %d: push log = %+v, want retry", attempt, last)
		}
	}

	refuse.Store(false)
	res, err := c.PushOnce(ctx)
	if err != nil {
		t.Fatalf("PushOnce after recovery: %v", err)
	}
	if res.RowCount != 4 {
		t.Fatalf("recovered push carried %d rows, want all 4 kept from the refused attempts", res.RowCount)
	}
	if len(sentRows) != 3 || sentRows[0] != 4 || sentRows[1] != 4 || sentRows[2] != 4 {
		t.Errorf("rows per attempt = %v, want the same 4 rows every time", sentRows)
	}
	if cur, _ := s.LoadPushCursor(ctx); cur.Actions == 0 || cur.Sessions == 0 {
		t.Errorf("cursor not advanced after the accepted push: %+v", cur)
	}
}

// TestLoopRetryHonoursRetryAfter pins that the server's Retry-After is a
// FLOOR under the jittered backoff (never shortens it, never stops the loop).
func TestLoopRetryHonoursRetryAfter(t *testing.T) {
	c := New(config.OrgClientConfig{}, nil, &memBearerStore{}, "v", http.DefaultClient, quietLogger())
	tests := []struct {
		name     string
		err      error
		minSleep time.Duration
		maxSleep time.Duration
	}{
		{"503 with Retry-After waits at least the hint", &httpStatusError{status: 503, retryAfter: 5 * time.Second}, 5 * time.Second, 5 * time.Second},
		{"503 without a hint uses the ladder floor", &httpStatusError{status: 503}, 0, time.Second},
		{"plain error uses the ladder floor", errors.New("dial tcp: refused"), 0, time.Second},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := newLoopRetry()
			sleep, stop, ok := r.after(c, tc.err, time.Minute)
			if stop || ok {
				t.Fatalf("after() stop=%v ok=%v, want a retry", stop, ok)
			}
			if sleep < tc.minSleep || sleep > tc.maxSleep {
				t.Errorf("sleep = %v, want within [%v, %v]", sleep, tc.minSleep, tc.maxSleep)
			}
		})
	}
}

// TestParseRetryAfter covers both header forms and the clamp.
func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		in   string
		want time.Duration
	}{
		{"", 0},
		{"5", 5 * time.Second},
		{" 2 ", 2 * time.Second},
		{"-3", 0},
		{"junk", 0},
		{now.Add(30 * time.Second).Format(http.TimeFormat), 30 * time.Second},
		{now.Add(-time.Minute).Format(http.TimeFormat), 0},
		{"86400", maxBackoff},
	}
	for _, tc := range tests {
		if got := parseRetryAfter(tc.in, now); got != tc.want {
			t.Errorf("parseRetryAfter(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}
