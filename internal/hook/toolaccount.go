package hook

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/pathnorm"
	"github.com/marmutapp/superbased-observer/internal/toolaccount"
)

type accountSnapshotSpec struct {
	directory string
	filename  string
	decode    func([]byte) models.ToolAccountObservation
	allowFile func(func(string) ([]byte, error), string) bool
	binding   string
	overrides []string
}

var accountSnapshotSpecs = map[string]accountSnapshotSpec{
	models.ToolCodex:      {directory: "sessions", filename: "auth.json", decode: toolaccount.CodexIdentity, allowFile: codexAccountFileEnabled, binding: "turn", overrides: []string{"OPENAI_API_KEY", "CODEX_API_KEY"}},
	models.ToolClaudeCode: {directory: "projects", filename: ".claude.json", decode: toolaccount.ClaudeIdentity, binding: "tool_call", overrides: []string{"ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_VERTEX", "CLAUDE_CODE_USE_FOUNDRY"}},
}

// LocalAccountObservations reads a login snapshot only during a live hook.
// Its source home is derived from the transcript, never the observer's home.
// Missing/locked/oversized files degrade to no evidence; no secrets leave here.
// Call after the guard reply. This function is never used during transcript scans.
func LocalAccountObservations(ctx context.Context, tool, event string, body []byte) []models.ToolAccountObservation {
	ctx, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
	defer cancel()
	read := func(path string) ([]byte, error) { return readAccountFile(ctx, path) }
	return localAccountObservations(tool, event, body, read, os.Getenv, time.Now().UTC())
}

func readAccountFile(ctx context.Context, path string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	const maxSize = 2 * 1024 * 1024
	if !info.Mode().IsRegular() || info.Size() > maxSize {
		return nil, fmt.Errorf("unsupported account file")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxSize+1))
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if len(data) > maxSize {
		return nil, fmt.Errorf("oversized account file")
	}
	return data, err
}

func localAccountObservations(tool, event string, body []byte, read func(string) ([]byte, error), getenv func(string) string, at time.Time) []models.ToolAccountObservation {
	spec, ok := accountSnapshotSpecs[tool]
	if !ok {
		return nil
	}
	// Only exact live tool calls carry grounded activity. Stop is context-only;
	// prompt-only and session-start events cannot label assistant execution.
	stages := map[string]string{"PreToolUse": "activity", "PostToolUse": "activity", "Stop": "stop", "UserPromptSubmit": "submission"}
	stage, ok := stages[event]
	if !ok {
		return nil
	}
	for _, key := range spec.overrides {
		if getenv(key) != "" {
			return nil
		}
	}
	var p struct {
		SessionID  string `json:"session_id"`
		TurnID     string `json:"turn_id"`
		ToolUseID  string `json:"tool_use_id"`
		Transcript string `json:"transcript_path"`
	}
	if json.Unmarshal(body, &p) != nil || p.SessionID == "" || p.Transcript == "" {
		return nil
	}
	id := p.ToolUseID
	if spec.binding == "turn" {
		id = p.TurnID
	}
	if id == "" {
		return nil
	}
	transcript := filepath.Clean(pathnorm.Normalize(p.Transcript))
	if !filepath.IsAbs(transcript) || strings.HasPrefix(transcript, `\\`) || strings.HasPrefix(transcript, "//") {
		return nil
	}
	// Find a known transcript-store boundary. Files in unrelated paths never
	// cause fallback to the daemon's login, even when the daemon is signed in.
	parent := filepath.Dir(transcript)
	for filepath.Base(parent) != spec.directory {
		next := filepath.Dir(parent)
		if next == parent {
			return nil
		}
		parent = next
	}
	profile := filepath.Dir(parent)
	path := filepath.Join(profile, spec.filename)
	if spec.binding == "tool_call" && filepath.Base(profile) == ".claude" {
		path = filepath.Join(filepath.Dir(profile), spec.filename)
	}
	if spec.allowFile != nil && !spec.allowFile(read, path) {
		return nil
	}
	data, err := read(path)
	if err != nil {
		return nil
	}
	o := spec.decode(data)
	if o.Email == "" && o.Name == "" && o.AccountID == "" {
		return nil
	}
	o.SessionID, o.Tool, o.BindingKind, o.BindingID, o.Role = p.SessionID, tool, spec.binding, id, "assistant"
	if stage == "submission" {
		if spec.binding != "turn" {
			return nil
		}
		o.Role = "user"
		o.BindingKind = "message"
		o.BindingID = "user:" + id
	}
	// The path itself is not a display field. Scope distinguishes installations
	// without copying the user's home/profile path into every API row.
	o.Scope = fmt.Sprintf("profile:%x", sha256.Sum256([]byte(strings.ReplaceAll(path, "\\", "/"))))
	o.Stage, o.ObservedAt = stage, at
	return []models.ToolAccountObservation{o}
}

// An old auth.json may survive a change to keyring/ephemeral storage. Do not
// label messages from that stale file when the profile explicitly uses another
// storage mode. Auto may use a keyring, so it is conservative unknown too.
func codexAccountFileEnabled(read func(string) ([]byte, error), authPath string) bool {
	body, err := read(filepath.Join(filepath.Dir(authPath), "config.toml"))
	if err != nil {
		return os.IsNotExist(err)
	}
	var cfg struct {
		Store string `toml:"cli_auth_credentials_store"`
	}
	if _, err := toml.Decode(string(body), &cfg); err != nil {
		return false
	}
	return cfg.Store == "" || cfg.Store == "file"
}
