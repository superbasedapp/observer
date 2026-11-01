//go:build !sbo_omit_adapter_claude_code

package main

import (
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/testsupport/jsoncompat"
)

// TestHookEntryJSONGolden is internal/hook TestHookJSONGolden for the hook
// entry points that decode in this package: every Claude Code action-row
// builder, the PreToolUse rewrite decision, the observe-only decode and
// the fail-closed payload probes. It pins them against the v1
// encoding/json decoder over the real fixtures in testdata/ and their
// byte-level rewrites (Go 1.27 backs encoding/json with v2; plan
// docs/plans/security-pillar-plan-2026-10-19.md section 8.4, risk T17).
// See internal/testsupport/jsoncompat for the regeneration procedure.
func TestHookEntryJSONGolden(t *testing.T) {
	t.Setenv("OBSERVER_CLAUDE_WORKTREE_ROOT", "/worktrees")
	root, err := jsoncompat.RepoRoot()
	if err != nil {
		t.Fatal(err)
	}
	payloads, err := jsoncompat.Payloads(root)
	if err != nil {
		t.Fatal(err)
	}
	jsoncompat.Check(t, filepath.Join("testdata", "jsoncompat", "hook_entry.golden"), hookEntryJSONDecoders(), payloads)
}

// generatedWorktree matches the name buildClaudeWorktreeCreateReply makes
// up from the clock for a payload that names no worktree.
var generatedWorktree = regexp.MustCompile(`worktree-[0-9a-z]{8,}`)

func hookEntryJSONDecoders() []jsoncompat.Decoder {
	type pair struct {
		A, B any
	}
	builders := []struct {
		name  string
		build claudeActionBuilder
	}{
		{"SessionEnd", buildClaudeSessionEndEvent},
		{"UserPromptSubmit", buildClaudeUserPromptSubmitEvent},
		{"PostToolUseFailure", buildClaudePostToolFailureEvent},
		{"StopFailure", buildClaudeStopFailureEvent},
		{"SubagentStart", buildClaudeSubagentStartEvent},
		{"SubagentStop", buildClaudeSubagentStopEvent},
		{"Stop", buildClaudeStopEvent},
		{"Notification", buildClaudeNotificationEvent},
		{"CwdChanged", buildClaudeCwdChangedEvent},
		{"Setup", buildClaudeSetupEvent},
		{"UserPromptExpansion", buildClaudeUserPromptExpansionEvent},
		{"PostToolBatch", buildClaudePostToolBatchEvent},
		{"PermissionRequest", buildClaudePermissionRequestEvent},
		{"PermissionDenied", buildClaudePermissionDeniedEvent},
		{"InstructionsLoaded", buildClaudeInstructionsLoadedEvent},
		{"ConfigChange", buildClaudeConfigChangeEvent},
		{"WorktreeRemove", buildClaudeWorktreeRemoveEvent},
	}
	var decs []jsoncompat.Decoder
	for _, b := range builders {
		build := b.build
		decs = append(decs, jsoncompat.Decoder{Name: "claude-code/" + b.name, Decode: func(body []byte) any {
			ev, ok := build(body)
			return pair{ev, ok}
		}})
	}

	cfg := config.Default()
	cfg.Compression.Shell.Enabled = true
	decs = append(decs,
		jsoncompat.Decoder{Name: "claude-code/WorktreeCreate", Decode: func(body []byte) any {
			// A payload without a name gets a clock-derived one.
			path, ev, has := buildClaudeWorktreeCreateReply(body)
			// The path is joined with the host separator; the golden
			// holds the slash form so it is one file on every OS (Windows
			// 11 Pro rerun 2026-10-25, D5 group 10).
			path, ev.RawToolInput = filepath.ToSlash(path), filepath.ToSlash(ev.RawToolInput)
			return generatedWorktree.ReplaceAllString(jsoncompat.Dump([]any{path, ev, has}, time.Now()), "worktree-(generated)")
		}},
		jsoncompat.Decoder{Name: "decidePreToolRewrite/linux", Decode: func(body []byte) any {
			rewrite, cmd, reason := decidePreToolRewrite(body, cfg, nil, "/usr/local/bin/observer", nil, "linux")
			return []any{rewrite, cmd, reason}
		}},
		jsoncompat.Decoder{Name: "decidePreToolRewrite/windows", Decode: func(body []byte) any {
			rewrite, cmd, reason := decidePreToolRewrite(body, cfg, nil, `C:\observer\observer.exe`, nil, "windows")
			return []any{rewrite, cmd, reason}
		}},
		jsoncompat.Decoder{Name: "decodeObservePayload", Decode: func(body []byte) any {
			p, ok := decodeObservePayload(body)
			return []any{p, p.raw, ok}
		}},
		jsoncompat.Decoder{Name: "hookPayloadUnparseable", Decode: func(body []byte) any { return hookPayloadUnparseable(body) }},
		jsoncompat.Decoder{Name: "hookPayloadSessionID", Decode: func(body []byte) any { return hookPayloadSessionID(body) }},
		jsoncompat.Decoder{Name: "claudeContentHash", Decode: func(body []byte) any { return claudeContentHash(body) }},
	)
	return decs
}
