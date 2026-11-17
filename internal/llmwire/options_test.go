package llmwire

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const okBody = `{"choices":[{"message":{"content":"x"},"finish_reason":"stop"}]}`

func noWait(context.Context, time.Duration) error { return nil }

func TestRetryPolicyRules(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		p         RetryPolicy
		attempt   int
		transport bool
		status    int
		want      bool
	}{
		{"zero policy never retries", RetryPolicy{}, 0, true, 0, false},
		{"transport retried", RetryPolicy{Retries: 1, On: RetryTransport}, 0, true, 0, true},
		{"transport not selected", RetryPolicy{Retries: 1, On: RetryServerError}, 0, true, 0, false},
		{"5xx retried", RetryPolicy{Retries: 1, On: RetryServerError}, 0, false, 503, true},
		{"5xx not selected", RetryPolicy{Retries: 1, On: RetryTransport}, 0, false, 503, false},
		{"4xx never retried", RetryPolicy{Retries: 1, On: RetryTransport | RetryServerError}, 0, false, 429, false},
		{"budget exhausted", RetryPolicy{Retries: 1, On: RetryTransport | RetryServerError}, 1, false, 500, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if got := c.p.shouldRetry(c.attempt, c.transport, c.status); got != c.want {
				t.Errorf("shouldRetry = %v, want %v", got, c.want)
			}
		})
	}
}

func TestClientOptions(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		opts       []Option
		statuses   []int // answered in order, last repeats
		wantCalls  int32
		wantErrIs  error
		wantStatus int // expected *StatusError status ("" -> 0)
		check      func(t *testing.T, r *http.Request)
	}{
		{name: "defaults: no retry on 503", statuses: []int{503, 200}, wantCalls: 1, wantStatus: 0, wantErrIs: nil},
		{
			name:      "retry 5xx then ok",
			opts:      []Option{WithRetry(RetryPolicy{Retries: 1, On: RetryServerError, Wait: noWait})},
			statuses:  []int{503, 200},
			wantCalls: 2,
		},
		{
			name:       "retry exhausted returns last raw status",
			opts:       []Option{WithRetry(RetryPolicy{Retries: 1, On: RetryServerError, Wait: noWait}), WithRawErrors()},
			statuses:   []int{500, 502},
			wantCalls:  2,
			wantStatus: 502,
		},
		{
			name:       "raw errors keep 429 as a status",
			opts:       []Option{WithRawErrors()},
			statuses:   []int{429},
			wantCalls:  1,
			wantStatus: 429,
		},
		{
			name:      "api-key auth and extra header",
			opts:      []Option{WithAuth(AuthAPIKey), WithHeaders(map[string]string{"X-Title": "t"})},
			statuses:  []int{200},
			wantCalls: 1,
			check: func(t *testing.T, r *http.Request) {
				if r.Header.Get("api-key") != "k" || r.Header.Get("Authorization") != "" || r.Header.Get("X-Title") != "t" {
					t.Errorf("headers = %v", r.Header)
				}
			},
		},
		{
			name:      "bearer default",
			statuses:  []int{200},
			wantCalls: 1,
			check: func(t *testing.T, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer k" || r.Header.Get("api-key") != "" {
					t.Errorf("headers = %v", r.Header)
				}
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			var calls atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				n := int(calls.Add(1)) - 1
				if n >= len(c.statuses) {
					n = len(c.statuses) - 1
				}
				if c.check != nil {
					c.check(t, r)
				}
				w.WriteHeader(c.statuses[n])
				if c.statuses[n] == 200 {
					_, _ = w.Write([]byte(okBody))
				} else {
					_, _ = w.Write([]byte("body"))
				}
			}))
			defer srv.Close()
			cl, err := NewClient(srv.Client(), c.opts...)
			if err != nil {
				t.Fatal(err)
			}
			_, err = cl.Complete(context.Background(), srv.URL, "k", Request{Model: "m", System: "s"})
			if got := calls.Load(); got != c.wantCalls {
				t.Errorf("calls = %d, want %d", got, c.wantCalls)
			}
			if c.wantStatus != 0 {
				var se *StatusError
				if !errors.As(err, &se) || se.StatusCode != c.wantStatus || se.Body != "body" {
					t.Fatalf("err = %v, want StatusError %d", err, c.wantStatus)
				}
			}
		})
	}
}

func TestMaxResponseBytes(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(500)
		_, _ = w.Write([]byte(strings.Repeat("x", 100)))
	}))
	defer srv.Close()
	cl, _ := NewClient(srv.Client(), WithMaxResponseBytes(10), WithRawErrors())
	_, err := cl.Complete(context.Background(), srv.URL, "", Request{Model: "m", System: "s"})
	var se *StatusError
	if !errors.As(err, &se) || len(se.Body) != 10 {
		t.Fatalf("err = %v", err)
	}
}

func TestRawTransportErrorAndCancelledRetry(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close() // connection refused
	var calls atomic.Int32
	wait := func(context.Context, time.Duration) error { calls.Add(1); return nil }
	cl, _ := NewClient(&http.Client{}, WithRawErrors(),
		WithRetry(RetryPolicy{Retries: 2, On: RetryTransport, Wait: wait}))
	_, err := cl.Complete(context.Background(), url, "", Request{Model: "m", System: "s"})
	var te *TransportError
	if !errors.As(err, &te) {
		t.Fatalf("err = %v, want TransportError", err)
	}
	if calls.Load() != 2 {
		t.Errorf("waits = %d, want 2", calls.Load())
	}

	// A cancelled context ends the loop without retrying.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls.Store(0)
	if _, err := cl.Complete(ctx, url, "", Request{Model: "m", System: "s"}); !errors.As(err, &te) || calls.Load() != 0 {
		t.Errorf("cancelled: err = %v waits = %d", err, calls.Load())
	}
}

func TestNumCtx(t *testing.T) {
	t.Parallel()
	b, err := EncodeRequest(Request{Model: "m", System: "s", NumCtx: 4096})
	if err != nil || !strings.Contains(string(b), `"num_ctx":4096`) {
		t.Fatalf("body = %s err = %v", b, err)
	}
	b, _ = EncodeRequest(Request{Model: "m", System: "s"})
	if strings.Contains(string(b), "num_ctx") {
		t.Errorf("num_ctx sent when zero: %s", b)
	}
	if _, err := EncodeRequest(Request{Model: "m", System: "s", NumCtx: -1}); !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("negative num_ctx err = %v", err)
	}
}
