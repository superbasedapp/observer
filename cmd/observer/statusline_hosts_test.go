package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/hook"
)

// TestStatusline_HostPayloads drives `observer statusline` with each host's
// payload shape (anonymized, built the way the host's source builds it)
// against a live test daemon: the line carries what the payload honestly
// has, and only a host declaring Claude Code's plan rate_limits forwards
// them to Plans & limits.
func TestStatusline_HostPayloads(t *testing.T) {
	const rateLimits = `"rate_limits":{"five_hour":{"used_percentage":40,"resets_at":4102444800}}`
	cases := []struct {
		name, host, payload, want string
		forwards                  bool
		explain                   string
	}{
		{
			name:     "claude code registration (no --host)",
			payload:  `{"hook_event_name":"Status","session_id":"s-1","model":{"id":"claude-opus-4-5","display_name":"Opus"},"cost":{"total_cost_usd":1.25},"output_style":{"name":"default"},` + rateLimits + `}`,
			want:     "▞ superbased · $1.25 session · $9.00 today · Opus",
			forwards: true, explain: "payload=claude",
		},
		{
			name:    "codebuddy: a look-alike rate_limits never feeds Claude's plan",
			host:    "codebuddy",
			payload: `{"hook_event_name":"Status","session_id":"cb-1","model":{"id":"hy4-preview","display_name":"HY4"},"cost":{"total_cost_usd":0.5},"context_window":{"context_window_size":200000},` + rateLimits + `}`,
			want:    "▞ superbased · $0.50 session · $9.00 today · HY4",
			explain: "payload=claude host=\"codebuddy\"",
		},
		{
			name:    "kimchi nested session",
			host:    "kimchi",
			payload: `{"model":{"id":"kimi-k2.5","name":"Kimi K2.5"},"credits":"$4.20","budget":"$10.00","workspace":{"cwd":"/home/u/p","current_dir":"/home/u/p"},"session":{"cost_usd":0.75,"id":"019a0000-0000-7000-8000-000000000001","transcript_path":"/home/u/s.jsonl"},"cost":{"total_cost_usd":0.75}}`,
			want:    "▞ superbased · $0.75 session · $9.00 today · Kimi K2.5",
			explain: "payload=nested-session",
		},
		{
			name:    "vtcode: no session, no cost - omitted, never zeroed",
			host:    "vtcode",
			payload: `{"hook_event_name":"Status","cwd":"/home/u/p","workspace":{"current_dir":"/home/u/p","project_dir":"/home/u/p"},"model":{"id":"gpt-5.5","display_name":"GPT-5.5"},"runtime":{"reasoning_effort":"medium"},"version":"0.180.2"}`,
			want:    "▞ superbased · $9.00 today · GPT-5.5",
			explain: "payload=no-session",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			setTestHome(t, t.TempDir())
			dbDir := newStatuslineLockDir(t)
			var posts atomic.Int32
			var sessionParam atomic.Value
			sessionParam.Store("")
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/api/plans/statusline":
					posts.Add(1)
					w.WriteHeader(http.StatusNoContent)
				case "/api/statusline":
					sessionParam.Store(r.URL.Query().Get("session_id"))
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(map[string]any{"today_usd": 9.0, "generated_at": time.Now().UTC().Format(time.RFC3339)})
				}
			}))
			defer ts.Close()
			deps := baseStatuslineDeps(dbDir, ts.URL)
			deps.stdinTTY = func() bool { return false }
			cmd := newStatuslineCmdWith(deps)
			var out, errBuf bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetErr(&errBuf)
			cmd.SetIn(strings.NewReader(c.payload))
			args := []string{"--explain", "--timeout", "2s"}
			if c.host != "" {
				args = append(args, "--host", c.host)
			}
			cmd.SetArgs(args)
			if err := cmd.Execute(); err != nil {
				t.Fatalf("Execute: %v", err)
			}
			if got := strings.TrimRight(out.String(), "\n"); got != c.want {
				t.Errorf("line = %q, want %q", got, c.want)
			}
			if !strings.Contains(errBuf.String(), c.explain) {
				t.Errorf("explain = %q, want it to contain %q", errBuf.String(), c.explain)
			}
			if got := posts.Load() > 0; got != c.forwards {
				t.Errorf("plan forward = %v, want %v", got, c.forwards)
			}
			if c.host == "vtcode" && sessionParam.Load().(string) != "" {
				t.Errorf("a session-less payload sent session_id %q", sessionParam.Load())
			}
		})
	}
}

// TestRunStatuslineToolsInit drives `observer init --statusline-tools`
// through its runner over a temp home: register, idempotent re-run,
// uninstall back to the exact bytes, and the refusals for a tool the flag
// does not write.
func TestRunStatuslineToolsInit(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	kimchi := filepath.Join(home, ".config", "kimchi", "harness", "settings.json")
	vt := filepath.Join(home, ".config", "vtcode", "vtcode.toml")
	for p, body := range map[string]string{kimchi: "{\n  \"theme\": \"dark\"\n}\n", vt: "[agent]\nprovider = \"openai\"\n"} {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	sum := func(p string) [32]byte {
		b, _ := os.ReadFile(p)
		return sha256.Sum256(b)
	}
	beforeK, beforeV := sum(kimchi), sum(vt)
	opts := hook.Options{
		BinaryPath:    "/opt/observer/bin/observer",
		HomeDir:       home,
		GOOS:          "linux",
		ChecksumsPath: filepath.Join(home, ".observer", "hook_checksums.json"),
	}

	var out bytes.Buffer
	if err := runStatuslineToolsInit(&out, opts, []string{"kimchi", " vtcode", "kimchi", "codebuddy"}, false); err != nil {
		t.Fatalf("register: %v", err)
	}
	for _, want := range []string{"kimchi: registered", "vtcode: registered", "codebuddy: skipped", "estimated list price"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, out.String())
		}
	}
	if sum(kimchi) == beforeK || sum(vt) == beforeV {
		t.Fatal("register wrote nothing")
	}
	out.Reset()
	if err := runStatuslineToolsInit(&out, opts, []string{"kimchi"}, false); err != nil || !strings.Contains(out.String(), "already set") {
		t.Fatalf("re-run: %v\n%s", err, out.String())
	}
	out.Reset()
	if err := runStatuslineToolsInit(&out, opts, []string{"kimchi", "vtcode"}, true); err != nil {
		t.Fatalf("uninstall: %v", err)
	}
	if sum(kimchi) != beforeK || sum(vt) != beforeV {
		t.Fatal("uninstall did not restore the files byte for byte")
	}
	if _, err := os.Stat(filepath.Join(home, ".observer", "statusline")); !os.IsNotExist(err) {
		t.Error("wrapper directory left behind")
	}

	for _, c := range []struct{ tool, want string }{
		{"claude-code", "--statusline"},
		{"stakpak", "no status-line writer"},
		{"", "no tool named"},
	} {
		err := runStatuslineToolsInit(&out, opts, []string{c.tool}, false)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%q: err = %v, want %q", c.tool, err, c.want)
		}
	}
}
