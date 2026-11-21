package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestTurnRecordsItsUpstreamLane pins review E-23: a turn on an /up/<id>
// lane (the gateway rail) is recorded with its lane, a default-lane turn (a
// coding agent's) with none, so the store lets an app's SDK span enrich only
// the former.
func TestTurnRecordsItsUpstreamLane(t *testing.T) {
	const responseBody = `{"id":"msg_lane","model":"claude-sonnet-4","stop_reason":"end_turn","usage":{"input_tokens":4,"output_tokens":2}}`
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(responseBody))
	}))
	defer up.Close()
	sink := &fakeSink{}
	p, err := New(Options{AnthropicUpstream: up.URL, OpenAIUpstream: up.URL, Upstreams: map[string]string{"hostedapp": up.URL}, Sink: sink})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()
	for _, path := range []string{"/up/hostedapp/v1/messages", "/v1/messages"} {
		req, _ := http.NewRequest(http.MethodPost, ts.URL+path, strings.NewReader(`{"model":"claude-sonnet-4","messages":[{"role":"user","content":"hi"}]}`))
		req.Header.Set("X-Api-Key", "sk-ant-test")
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
	}
	turns := sink.all()
	if len(turns) != 2 {
		t.Fatalf("turns = %d, want 2", len(turns))
	}
	if turns[0].UpstreamLane != "hostedapp" || turns[1].UpstreamLane != "" {
		t.Fatalf("lanes = %q, %q; want hostedapp, empty", turns[0].UpstreamLane, turns[1].UpstreamLane)
	}
}
