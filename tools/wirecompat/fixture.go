package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// The fixture. Every value is invented: an example.invalid remote, a /work
// root that is no machine's real path, example identities. Changing any of
// them changes every future recording, so the older versions' recordings
// would no longer describe the same node data; leave them alone.
const (
	fixturePlaceholder = "wirecompat"
	fixtureOrgID       = "org-wirecompat"
	fixtureUserID      = "user-wirecompat"
	fixtureUserEmail   = "dev@wirecompat.example"
	fixtureRoot        = "/work/wirecompat-demo"
	fixtureRemote      = "https://git.example.invalid/acme/wirecompat-demo.git"
	fixtureSession1    = "wc-session-0001"
	fixtureSession2    = "wc-session-0002"
	fixtureLog1        = "/work/wirecompat-demo/.transcripts/wc-session-0001.jsonl"
	fixtureLog2        = "/work/wirecompat-demo/.transcripts/wc-session-0002.jsonl"
	fixtureCommand     = "go test ./internal/app/..."
)

// at is the fixture clock: a fixed base plus sec seconds.
func at(sec int) time.Time {
	return time.Date(2026, 8, 1, 9, 0, 0, 0, time.UTC).Add(time.Duration(sec) * time.Second)
}

// hashHex is the node's path-hash spelling: lowercase hex SHA-256.
func hashHex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// seed writes the fixture through the node's own store seams. The project
// row is inserted directly so its root is stored byte for byte on every
// host (UpsertProject would translate a POSIX root on Windows).
func seed(ctx context.Context, st *store.Store, sqlDB *sql.DB) error {
	if _, err := sqlDB.ExecContext(ctx,
		`INSERT INTO projects (root_path, git_remote, created_at, root_path_hash, git_remote_hash)
		 VALUES (?, ?, ?, ?, ?)`,
		fixtureRoot, fixtureRemote, "2026-08-01T09:00:00Z", hashHex(fixtureRoot), hashHex(fixtureRemote)); err != nil {
		return fmt.Errorf("seed: project: %w", err)
	}
	var pid int64
	if err := sqlDB.QueryRowContext(ctx, `SELECT id FROM projects WHERE root_path = ?`, fixtureRoot).Scan(&pid); err != nil {
		return fmt.Errorf("seed: project id: %w", err)
	}
	if err := seedSessions(ctx, st, pid); err != nil {
		return err
	}
	if _, err := st.InsertActions(ctx, fixtureActions(pid)); err != nil {
		return fmt.Errorf("seed: %w", err)
	}
	if _, err := st.InsertTokenEvents(ctx, fixtureTokens()); err != nil {
		return fmt.Errorf("seed: %w", err)
	}
	if _, err := st.InsertAPITurn(ctx, models.APITurn{
		SessionID: fixtureSession1, ProjectID: pid, Timestamp: at(12), Provider: "anthropic",
		Model: "claude-sonnet-4-5", RequestID: "req_wirecompat_0001", InputTokens: 1200, OutputTokens: 340,
		CacheReadTokens: 800, CacheCreationTokens: 200, CostUSD: 0.0123, MessageCount: 4, ToolUseCount: 1,
		TimeToFirstTokenMS: 640, TotalResponseMS: 2100, StopReason: "tool_use", HTTPStatus: 200,
	}); err != nil {
		return fmt.Errorf("seed: %w", err)
	}
	if _, err := st.InsertGuardEvents(ctx, []store.GuardEventRow{{
		TS: at(29), SessionID: fixtureSession1, Tool: "claude-code", EventKind: "shell_exec",
		RuleID: "R-001", Category: "destructive", Severity: "low", Decision: "allow", Source: "hook",
		Reason: "fixture: a test command", TargetHash: hashHex(fixtureCommand),
		TargetExcerpt: fixtureCommand,
	}}); err != nil {
		return fmt.Errorf("seed: %w", err)
	}
	return nil
}

// seedSessions writes the two fixture sessions.
func seedSessions(ctx context.Context, st *store.Store, pid int64) error {
	for _, s := range []models.Session{
		{
			ID: fixtureSession1, ProjectID: pid, Tool: "claude-code", Model: "claude-sonnet-4-5",
			GitBranch: "feature/wirecompat", StartedAt: at(0), EndedAt: at(600), TotalActions: 3,
		},
		{
			ID: fixtureSession2, ProjectID: pid, Tool: "codex", Model: "gpt-5",
			GitBranch: "main", StartedAt: at(900), EndedAt: at(1200), TotalActions: 1,
		},
	} {
		if err := st.UpsertSession(ctx, s); err != nil {
			return fmt.Errorf("seed: %w", err)
		}
	}
	return nil
}

// fixtureActions are the fixture's tool calls (one failed command).
func fixtureActions(pid int64) []models.Action {
	return []models.Action{
		{
			SessionID: fixtureSession1, ProjectID: pid, Timestamp: at(10), TurnIndex: 1, ActionType: "read_file",
			IsNativeTool: true, Target: "internal/app/server.go", Success: true, DurationMs: 12, RawToolName: "Read",
			Tool: "claude-code", SourceFile: fixtureLog1, SourceEventID: "wc-evt-0001", MessageID: "wc-msg-0001",
		},
		{
			SessionID: fixtureSession1, ProjectID: pid, Timestamp: at(20), TurnIndex: 2, ActionType: "edit_file",
			IsNativeTool: true, Target: "internal/app/server.go", Success: true, DurationMs: 30, RawToolName: "Edit",
			Tool: "claude-code", SourceFile: fixtureLog1, SourceEventID: "wc-evt-0002", MessageID: "wc-msg-0002",
		},
		{
			SessionID: fixtureSession1, ProjectID: pid, Timestamp: at(30), TurnIndex: 3, ActionType: "run_command",
			IsNativeTool: true, Target: fixtureCommand, Success: false, DurationMs: 4200, RawToolName: "Bash",
			Tool: "claude-code", SourceFile: fixtureLog1, SourceEventID: "wc-evt-0003", MessageID: "wc-msg-0003",
		},
		{
			SessionID: fixtureSession2, ProjectID: pid, Timestamp: at(910), TurnIndex: 1, ActionType: "read_file",
			IsNativeTool: true, Target: "README.md", Success: true, DurationMs: 8, RawToolName: "read_file",
			Tool: "codex", SourceFile: fixtureLog2, SourceEventID: "wc-evt-0101", MessageID: "wc-msg-0101",
		},
	}
}

// fixtureTokens are the fixture's token usage rows.
func fixtureTokens() []models.TokenEvent {
	return []models.TokenEvent{
		{
			SourceFile: fixtureLog1, SourceEventID: "wc-tok-0001", SessionID: fixtureSession1, ProjectRoot: fixtureRoot,
			Timestamp: at(11), Tool: "claude-code", Model: "claude-sonnet-4-5", InputTokens: 1200, OutputTokens: 340,
			CacheReadTokens: 800, CacheCreationTokens: 200, EstimatedCostUSD: 0.0123, Source: "jsonl",
			Reliability: "accurate", MessageID: "wc-msg-0001",
		},
		{
			SourceFile: fixtureLog1, SourceEventID: "wc-tok-0002", SessionID: fixtureSession1, ProjectRoot: fixtureRoot,
			Timestamp: at(31), Tool: "claude-code", Model: "claude-sonnet-4-5", InputTokens: 900, OutputTokens: 120,
			CacheReadTokens: 1600, EstimatedCostUSD: 0.0071, Source: "jsonl",
			Reliability: "accurate", MessageID: "wc-msg-0003",
		},
		{
			SourceFile: fixtureLog2, SourceEventID: "wc-tok-0101", SessionID: fixtureSession2, ProjectRoot: fixtureRoot,
			Timestamp: at(911), Tool: "codex", Model: "gpt-5", InputTokens: 640, OutputTokens: 90,
			EstimatedCostUSD: 0.0019, Source: "jsonl", Reliability: "approximate", MessageID: "wc-msg-0101",
		},
	}
}
