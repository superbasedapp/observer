package proxy

import (
	"context"
	"net/http"
	"sync"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// rfInjector is a CredentialInjector that never injects; with fold set it
// is also a RunSessionFolder answering fold for every request.
type rfInjector struct {
	fold func(RunSessionRequest) (string, bool)
	mu   sync.Mutex
	seen []RunSessionRequest
}

func (*rfInjector) Inject(context.Context, CredentialRequest) (string, string, bool) {
	return "", "", false
}

// rfFolder adds the fold extension.
type rfFolder struct{ *rfInjector }

func (f rfFolder) FoldRunSession(_ context.Context, in RunSessionRequest) (string, bool) {
	f.mu.Lock()
	f.seen = append(f.seen, in)
	f.mu.Unlock()
	return f.fold(in)
}

// TestResolveAPITurnSessionIDRunFold (F-003, OSH-R-150): a stamped request
// lands on the session it names only when the installed injector folds it
// to exactly that session; every other case keeps today's run namespace,
// and a request with no run header never asks.
func TestResolveAPITurnSessionIDRunFold(t *testing.T) {
	p, err := New(Options{
		AnthropicUpstream: "http://127.0.0.1:1",
		OpenAIUpstream:    "http://127.0.0.1:1",
		ChatGPTUpstream:   "http://127.0.0.1:1",
		Sink:              &fakeSink{},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const body = `{"metadata":{"user_id":"{\"session_id\":\"native-1\"}"}}`
	yes := func(in RunSessionRequest) (string, bool) { return in.Session, true }
	for _, tc := range []struct {
		name    string
		inj     CredentialInjector
		headers map[string]string
		body    string
		want    string
		asked   bool
	}{
		{"no injector: run namespace", nil, map[string]string{sandboxvocab.RelayRunHeader: "run-7"}, body, "rsbx-run-7-native-1", false},
		{"injector without fold: run namespace", &rfInjector{}, map[string]string{sandboxvocab.RelayRunHeader: "run-7"}, body, "rsbx-run-7-native-1", false},
		{"fold holds: native session", rfFolder{&rfInjector{fold: yes}}, map[string]string{sandboxvocab.RelayRunHeader: "run-7", SandboxCredTokenHeader: "tok"}, body, "native-1", true},
		{"fold refused: run namespace", rfFolder{&rfInjector{fold: func(RunSessionRequest) (string, bool) { return "", false }}}, map[string]string{sandboxvocab.RelayRunHeader: "run-7"}, body, "rsbx-run-7-native-1", true},
		{"fold names another session: run namespace", rfFolder{&rfInjector{fold: func(RunSessionRequest) (string, bool) { return "other", true }}}, map[string]string{sandboxvocab.RelayRunHeader: "run-7"}, body, "rsbx-run-7-native-1", true},
		{"no session named: the run's own key, fold not asked", rfFolder{&rfInjector{fold: yes}}, map[string]string{sandboxvocab.RelayRunHeader: "run-7"}, `{}`, "rsbx-run-7", false},
		{"not run-shaped: fold not asked", rfFolder{&rfInjector{fold: yes}}, map[string]string{sandboxvocab.RelayRunHeader: "run 7/../x"}, body, "native-1", false},
		{"no run header: fold not asked", rfFolder{&rfInjector{fold: yes}}, nil, body, "native-1", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			SetCredentialInjector(tc.inj)
			defer SetCredentialInjector(nil)
			req, _ := http.NewRequest(http.MethodPost, "http://test/v1/messages", nil)
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			if got := p.resolveAPITurnSessionID(req, models.ProviderAnthropic, []byte(tc.body)); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
			var seen []RunSessionRequest
			if f, ok := tc.inj.(rfFolder); ok {
				seen = f.seen
			}
			if (len(seen) > 0) != tc.asked {
				t.Fatalf("fold asked %v, want %v", seen, tc.asked)
			}
			if tc.asked {
				want := RunSessionRequest{RunID: "run-7", Token: tc.headers[SandboxCredTokenHeader], Session: "native-1"}
				if seen[0] != want {
					t.Errorf("fold asked %+v, want %+v", seen[0], want)
				}
			}
		})
	}
}

// TestRunFoldLandsTheTurn: end to end through the proxy, a folded relayed
// turn's api_turns row carries the native session, and the run header and
// token still never go upstream.
func TestRunFoldLandsTheTurn(t *testing.T) {
	inj := rfFolder{&rfInjector{fold: func(in RunSessionRequest) (string, bool) {
		return in.Session, in.RunID == "run1" && in.Token == ciToken
	}}}
	seen, sink, _ := ciRun(t, func(string) CredentialInjector { return inj }, func(r *http.Request) {
		r.Header.Set("X-Session-Id", "native-2")
	})
	if seen.Get(sandboxvocab.RelayRunHeader) != "" || seen.Get(SandboxCredTokenHeader) != "" {
		t.Fatalf("run headers went upstream: %v", seen)
	}
	turns := sink.all()
	if len(turns) != 1 || turns[0].SessionID != "native-2" {
		t.Fatalf("turns = %+v, want one on native-2", turns)
	}
}
