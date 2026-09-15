package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/store"
)

func TestNativeHookAccountCaptureWithoutActionOrEffort(t *testing.T) {
	for _, key := range []string{"OPENAI_API_KEY", "CODEX_API_KEY", "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_VERTEX", "CLAUDE_CODE_USE_FOUNDRY"} {
		t.Setenv(key, "")
	}
	for _, tool := range []string{models.ToolCodex, models.ToolClaudeCode} {
		t.Run(tool, func(t *testing.T) {
			root := t.TempDir()
			t.Setenv("HOME", root)
			t.Setenv("USERPROFILE", root)
			dbPath := filepath.Join(root, "observer.db")
			configPath := filepath.Join(root, "observer.toml")
			write := func(path, body string) {
				t.Helper()
				if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			write(configPath, "[observer]\ndb_path = "+strconv.Quote(filepath.ToSlash(dbPath))+"\n")
			transcript := filepath.Join(root, ".claude", "projects", "repo", "s.jsonl")
			write(filepath.Join(root, ".claude.json"), `{"oauthAccount":{"emailAddress":"first@example.invalid","accountUuid":"person1"}}`)
			if tool == models.ToolCodex {
				transcript = filepath.Join(root, ".codex", "sessions", "2026", "rollout.jsonl")
				jwt := "header." + base64.RawURLEncoding.EncodeToString([]byte(`{"email":"first@example.invalid","sub":"person1"}`)) + ".signature"
				write(filepath.Join(root, ".codex", "auth.json"), `{"auth_mode":"chatgpt","tokens":{"id_token":"`+jwt+`","account_id":"shared-workspace"}}`)
			}
			body, _ := json.Marshal(map[string]string{"session_id": "s", "turn_id": "turn", "tool_use_id": "call", "transcript_path": transcript, "cwd": root, "tool_name": "Read"})
			var reply, stderr bytes.Buffer
			if tool == models.ToolClaudeCode {
				handleClaudeCodePostTool(bytes.NewReader(body), &reply, &stderr, "claude-code", configPath)
			} else {
				runCodexAccountHook(t, body, configPath)
			}
			database, err := db.Open(context.Background(), db.Options{Path: dbPath})
			if err != nil {
				t.Fatal(err)
			}
			defer database.Close()
			st := store.New(database)
			_, err = st.Ingest(context.Background(), []models.ToolEvent{{SessionID: "s", ProjectRoot: root, Tool: tool, MessageID: "turn", SourceFile: "fixture", SourceEventID: "call", Timestamp: time.Now(), ActionType: models.ActionReadFile, Success: true}}, nil, store.IngestOptions{})
			if err != nil {
				t.Fatal(err)
			}
			accounts, err := st.LoadMessageAccounts(context.Background(), "s", tool)
			if err != nil || accounts["assistant:turn"].Label != "first@example.invalid" {
				t.Fatalf("capture missing: %+v %v %s", accounts, err, stderr.String())
			}
		})
	}
}

func runCodexAccountHook(t *testing.T, body []byte, configPath string) {
	t.Helper()
	inR, inW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer inR.Close()
	if _, err := inW.Write(body); err != nil {
		t.Fatal(err)
	}
	_ = inW.Close()
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer outR.Close()
	originalIn, originalOut := os.Stdin, os.Stdout
	defer func() { os.Stdin, os.Stdout = originalIn, originalOut; _ = outW.Close() }()
	os.Stdin, os.Stdout = inR, outW
	handleCodexHook(context.Background(), "PreToolUse", configPath)
	_ = outW.Close()
	out, _ := io.ReadAll(outR)
	if string(bytes.TrimSpace(out)) != "{}" {
		t.Fatalf("native reply changed: %q", out)
	}
}
