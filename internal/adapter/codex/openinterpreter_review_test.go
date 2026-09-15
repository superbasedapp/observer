package codex

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestOpenInterpreterNeverReadsConfigTOML pins security ledger OI-1: the
// Open Interpreter variant's root config.toml (which, for the desktop
// app's codex-home, holds plaintext provider API keys) is NEVER opened —
// the service-tier probe is a codex-proper capability (readsServiceTier),
// so a `service_tier = "priority"` there produces no ServiceTier pill and
// no Fast token row on the OI instance, while codex proper still reads
// its own.
func TestOpenInterpreterNeverReadsConfigTOML(t *testing.T) {
	t.Parallel()
	rollout := strings.Join([]string{
		`{"timestamp":"2026-09-03T00:00:01Z","type":"session_meta","payload":{"id":"thread-oi","cwd":"/tmp/proj","originator":"codex_ui","cli_version":"0.0.10","source":"vscode","model_provider":"openrouter"}}`,
		`{"timestamp":"2026-09-03T00:00:02Z","type":"turn_context","payload":{"turn_id":"turn-1","model":"gpt-5.4","cwd":"/tmp/proj"}}`,
		`{"timestamp":"2026-09-03T00:00:03Z","type":"event_msg","payload":{"type":"agent_message","turn_id":"turn-1","message":"Working on it"}}`,
		`{"timestamp":"2026-09-03T00:00:04Z","type":"event_msg","payload":{"type":"token_count","info":{"last_token_usage":{"input_tokens":10,"cached_input_tokens":4,"output_tokens":2,"reasoning_output_tokens":1,"total_tokens":12}}}}`,
		``,
	}, "\n")
	cfg := "model = \"gpt-5.4\"\nservice_tier = \"priority\"\n"

	for _, tc := range []struct {
		name     string
		dirName  string
		build    func(root string) *Adapter
		wantTier string
		wantFast bool
	}{
		{"open-interpreter variant never reads it", ".openinterpreter", func(root string) *Adapter { return NewOpenInterpreterWithOptions(nil, root) }, "", false},
		{"codex proper still does", ".codex", func(root string) *Adapter { return NewWithOptions(nil, root) }, "priority", true},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tmp := t.TempDir()
			root := filepath.Join(tmp, tc.dirName)
			sessions := filepath.Join(root, "sessions", "2026", "09", "03")
			if err := os.MkdirAll(sessions, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "config.toml"), []byte(cfg), 0o600); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(sessions, "rollout-2026-09-03T00-00-00-thread.jsonl")
			if err := os.WriteFile(path, []byte(rollout), 0o600); err != nil {
				t.Fatal(err)
			}
			a := tc.build(tmp)
			res, err := a.ParseSessionFile(context.Background(), path, 0)
			if err != nil {
				t.Fatalf("ParseSessionFile: %v", err)
			}
			var found bool
			for _, e := range res.ToolEvents {
				if e.RawToolName != "codex.assistant_text" {
					continue
				}
				found = true
				got := ""
				if e.Metadata != nil {
					got = e.Metadata.ServiceTier
				}
				if got != tc.wantTier {
					t.Errorf("ServiceTier = %q, want %q", got, tc.wantTier)
				}
			}
			if !found {
				t.Fatal("no codex.assistant_text row emitted")
			}
			if len(res.TokenEvents) != 1 {
				t.Fatalf("token events: %d want 1", len(res.TokenEvents))
			}
			if res.TokenEvents[0].Fast != tc.wantFast {
				t.Errorf("token Fast = %v, want %v", res.TokenEvents[0].Fast, tc.wantFast)
			}
		})
	}
}
