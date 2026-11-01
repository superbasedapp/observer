package hook

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/hookctx"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/models"
)

func TestLocalAccountSnapshotsUseSourceProfile(t *testing.T) {
	root := t.TempDir()
	jwt := "header." + base64.RawURLEncoding.EncodeToString([]byte(`{"email":"first@example.invalid","name":"First"}`)) + ".signature"
	auth := []byte(`{"auth_mode":"chatgpt","tokens":{"account_id":"workspace1","id_token":"` + jwt + `","access_token":"secret-sentinel","refresh_token":"secret-sentinel"}}`)
	claude := []byte(`{"oauthAccount":{"emailAddress":"second@example.invalid","displayName":"Second","accountUuid":"person2"},"accessToken":"secret-sentinel"}`)
	for _, tc := range []struct {
		name, tool, event, transcript, source, mid, kind, role string
		data                                                   []byte
	}{
		{"codex activity", models.ToolCodex, "PreToolUse", filepath.Join(root, "custom-codex", "sessions", "2026", "rollout.jsonl"), filepath.Join(root, "custom-codex", "auth.json"), "turn1", "turn", "assistant", auth},
		{"codex submission", models.ToolCodex, "UserPromptSubmit", filepath.Join(root, "custom-codex", "sessions", "2026", "rollout.jsonl"), filepath.Join(root, "custom-codex", "auth.json"), "user:turn1", "message", "user", auth},
		{"claude default", models.ToolClaudeCode, "PostToolUse", filepath.Join(root, ".claude", "projects", "project", "session.jsonl"), filepath.Join(root, ".claude.json"), "call1", "tool_call", "assistant", claude},
		{"claude custom", models.ToolClaudeCode, "PreToolUse", filepath.Join(root, "custom-claude", "projects", "project", "session.jsonl"), filepath.Join(root, "custom-claude", ".claude.json"), "call1", "tool_call", "assistant", claude},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body, _ := json.Marshal(map[string]string{"session_id": "session1", "turn_id": "turn1", "tool_use_id": "call1", "transcript_path": tc.transcript})
			read := func(path string) ([]byte, error) {
				if filepath.Base(path) == "config.toml" {
					return nil, os.ErrNotExist
				}
				if path != tc.source {
					t.Fatalf("wrong source %q want %q", path, tc.source)
				}
				return tc.data, nil
			}
			emptyEnv := func(string) string { return "" }
			got := localAccountObservations(tc.tool, tc.event, body, read, emptyEnv, time.Now())
			if len(got) != 1 || got[0].BindingID != tc.mid || got[0].BindingKind != tc.kind || got[0].Role != tc.role {
				t.Fatalf("bad binding %+v", got)
			}
			wire, _ := json.Marshal(got)
			if strings.Contains(string(wire), "secret-sentinel") || strings.Contains(string(wire), "signature") {
				t.Fatal("credential escaped projection")
			}
			if got := localAccountObservations(tc.tool, tc.event, body, func(string) ([]byte, error) { return nil, errors.New("locked") }, emptyEnv, time.Now()); len(got) != 0 {
				t.Fatal("locked source fabricated identity")
			}
			if got := localAccountObservations(tc.tool, tc.event, body, read, func(string) string { return "api-override" }, time.Now()); len(got) != 0 {
				t.Fatal("API override attributed to cached OAuth")
			}
			badBody, _ := json.Marshal(map[string]string{"session_id": "session1", "turn_id": "turn1", "tool_use_id": "call1", "transcript_path": filepath.Join(root, "unrelated", "log.jsonl")})
			if got := localAccountObservations(tc.tool, tc.event, badBody, func(string) ([]byte, error) { t.Fatal("read unrelated login"); return nil, nil }, emptyEnv, time.Now()); len(got) != 0 {
				t.Fatal("unrelated source fabricated identity")
			}
		})
	}
}

func TestCodexAccountFileStorageMode(t *testing.T) {
	for _, tc := range []struct {
		mode string
		want bool
	}{{"", true}, {"file", true}, {"keyring", false}, {"auto", false}, {"ephemeral", false}} {
		t.Run(tc.mode, func(t *testing.T) {
			read := func(string) ([]byte, error) { return []byte(`cli_auth_credentials_store = "` + tc.mode + `"`), nil }
			if got := codexAccountFileEnabled(read, "auth.json"); got != tc.want {
				t.Fatalf("enabled=%v want %v", got, tc.want)
			}
		})
	}
}

// TestLocalAccountObservationsReadThroughTheProcessContext (P-032): a
// caller that passes a fresh context still reads the account snapshot
// through the process's hook context, so a relay child (daemon path, the
// run's confined Files) never falls back to a plain host read.
func TestLocalAccountObservationsReadThroughTheProcessContext(t *testing.T) {
	root := t.TempDir()
	claude := []byte(`{"oauthAccount":{"emailAddress":"a@example.invalid","displayName":"A","accountUuid":"p1"}}`)
	if err := os.WriteFile(filepath.Join(root, ".claude.json"), claude, 0o600); err != nil {
		t.Fatal(err)
	}
	transcript := filepath.Join(root, ".claude", "projects", "p", "s.jsonl")
	body, _ := json.Marshal(map[string]string{"session_id": "s1", "tool_use_id": "c1", "transcript_path": transcript})
	if got := LocalAccountObservations(context.Background(), models.ToolClaudeCode, "PostToolUse", body); len(got) != 1 {
		t.Fatalf("host path: %d observations", len(got))
	}
	var reads []string
	files := hookctx.Files{Open: func(p string) (hookctx.File, error) {
		reads = append(reads, p)
		return nil, &os.PathError{Op: "read", Path: p, Err: hookctx.ErrRefused}
	}}
	hookctx.SetProcess(hookctx.Daemon(context.Background(), hookctx.Request{Tool: models.ToolClaudeCode}, hookctx.Channel{Files: files}, hookctx.DaemonProviders{}))
	t.Cleanup(func() { hookctx.SetProcess(nil) })
	if got := LocalAccountObservations(context.Background(), models.ToolClaudeCode, "PostToolUse", body); len(got) != 0 {
		t.Fatalf("daemon path read the snapshot past the confined reader: %+v", got)
	}
	if len(reads) == 0 {
		t.Fatal("the confined reader was never asked")
	}
}

// TestClaudeAccountProviderSelectorsSuppress pins CC-10 at the hook: a
// Claude Code session on a cloud backend (Claude Platform on AWS and Mantle
// included) is not labelled with the cached claude.ai login, and the
// overrides read the integration registry's one selector table.
func TestClaudeAccountProviderSelectorsSuppress(t *testing.T) {
	root := t.TempDir()
	claude := []byte(`{"oauthAccount":{"emailAddress":"a@example.invalid","accountUuid":"p1"}}`)
	body, _ := json.Marshal(map[string]string{"session_id": "s1", "tool_use_id": "call1", "transcript_path": filepath.Join(root, ".claude", "projects", "p", "s.jsonl")})
	read := func(string) ([]byte, error) { return claude, nil }
	if got := localAccountObservations(models.ToolClaudeCode, "PreToolUse", body, read, func(string) string { return "" }, time.Now()); len(got) != 1 {
		t.Fatalf("baseline: want one observation, got %+v", got)
	}
	selectors := integration.ProviderSelectorEnvKeys(models.ToolClaudeCode)
	for _, key := range []string{"CLAUDE_CODE_USE_ANTHROPIC_AWS", "CLAUDE_CODE_USE_MANTLE"} {
		found := false
		for _, s := range selectors {
			found = found || s == key
		}
		if !found {
			t.Fatalf("selector table lacks %s", key)
		}
	}
	for _, key := range selectors {
		env := func(k string) string {
			if k == key {
				return "1"
			}
			return ""
		}
		if got := localAccountObservations(models.ToolClaudeCode, "PreToolUse", body, read, env, time.Now()); len(got) != 0 {
			t.Errorf("%s=1: the cloud backend session was labelled with the cached login: %+v", key, got)
		}
	}
}
