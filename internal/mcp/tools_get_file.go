package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/mcp/audit"
)

// -----------------------------------------------------------------------------
// get_file — V7-12 retrieval-surface MCP tool (v1.7.8, first of four).
//
// Lets the agent read disk bytes directly under the project root,
// optionally line-sliced, without going through codex's shell tool
// (which re-feeds LogsCompressor and re-truncates the response).
//
// V7-13 Gap 4 path-scoping defenses applied in safeResolvePath +
// matchesAny + extensionAllowed (see internal/mcp/pathsafety.go).
//
// V7-14 audit: every call (success or denial) writes one row into
// mcp_audit via the AuditWriter wired by `observer serve`.
// -----------------------------------------------------------------------------

// GetFileOptions tunes the get_file tool at registration time.
// Mirrors [config.IntelligenceMCPGetFileConfig] minus the Enabled
// gate (which lives in server.go's registration decision).
type GetFileOptions struct {
	AllowExtensions []string
	DenyPaths       []string
	MaxResponseKB   int
}

func (o GetFileOptions) withDefaults() GetFileOptions {
	if o.MaxResponseKB <= 0 {
		o.MaxResponseKB = 100
	}
	return o
}

type getFileTool struct {
	opts   GetFileOptions
	audit  audit.Writer
	maxKBN int // resolved from opts.MaxResponseKB
}

func newGetFileTool(opts GetFileOptions, w audit.Writer) Tool {
	resolved := opts.withDefaults()
	if w == nil {
		w = audit.NewNoopWriter()
	}
	return &getFileTool{
		opts:   resolved,
		audit:  w,
		maxKBN: resolved.MaxResponseKB,
	}
}

func (*getFileTool) Name() string { return "get_file" }

func (*getFileTool) Description() string {
	return "Read a file from disk under the project root, optionally line-sliced. " +
		"Use this when a LogsCompressor elision marker tells you what's in an elided " +
		"range and you need the actual bytes — get_file bypasses the shell tool so the " +
		"response isn't re-truncated by compression. Path must resolve under " +
		"project_root after symlink expansion and must pass the operator's " +
		"allow-extension / deny-path checks. Oversized responses are truncated and " +
		"flagged with truncated=true so you can retry with a tighter line range."
}

func (*getFileTool) InputSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"project_root": map[string]any{
				"type":        "string",
				"description": "Absolute path to the project root. Required.",
			},
			"path": map[string]any{
				"type":        "string",
				"description": "Absolute or project-relative path to read. Must resolve under project_root after symlink expansion.",
			},
			"start_line": map[string]any{
				"type":        "integer",
				"minimum":     1,
				"description": "Optional 1-based start line (inclusive). Omit to start at line 1.",
			},
			"end_line": map[string]any{
				"type":        "integer",
				"minimum":     1,
				"description": "Optional 1-based end line (inclusive). Omit to read to EOF.",
			},
			"session_id": map[string]any{
				"type":        "string",
				"description": "Optional. Threads the call into the V7-14 audit log so per-session forensics work. Codex sessions populate this from their session metadata when possible.",
			},
		},
		"required": []string{"project_root", "path"},
	}
}

type getFileArgs struct {
	ProjectRoot string `json:"project_root"`
	Path        string `json:"path"`
	StartLine   int    `json:"start_line"`
	EndLine     int    `json:"end_line"`
	SessionID   string `json:"session_id"`
}

type getFileResult struct {
	OK                  bool      `json:"ok"`
	Path                string    `json:"path"`
	ProjectRelativePath string    `json:"project_relative_path"`
	Lines               lineRange `json:"lines"`
	Body                string    `json:"body"`
	SizeBytes           int       `json:"size_bytes"`
	Truncated           bool      `json:"truncated"`
	// Warnings is the V7-17 closed-set tag slice. Empty (nil) →
	// omitted. get_file doesn't depend on the code index so warnings are
	// rare here, but the field exists for shape uniformity across
	// the V7-12 tools. Reserved for future signals (e.g. permission
	// downgrades, soft-truncation explanations).
	Warnings []string `json:"warnings,omitempty"`
}

func (t *getFileTool) Invoke(ctx context.Context, raw json.RawMessage) (any, error) {
	started := time.Now()
	var args getFileArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		t.recordDenial(args, "invalid arguments", "", started)
		return nil, fmt.Errorf("invalid arguments: %w", err)
	}

	if args.ProjectRoot == "" || args.Path == "" {
		t.recordDenial(args, "project_root and path are required", "", started)
		return nil, errors.New("project_root and path are required")
	}

	abs, err := safeResolvePath(args.ProjectRoot, args.Path)
	if err != nil {
		reason := err.Error()
		t.recordDenial(args, "get_file: "+reason, "", started)
		return nil, fmt.Errorf("get_file: %s", reason)
	}

	// Compute project-relative path AFTER resolution — used both in the
	// response (so the model has a stable handle for follow-up calls)
	// and as the matchee for deny-glob checks (deny patterns are
	// authored relative to the project tree, not the absolute path).
	rootResolved, _ := filepath.EvalSymlinks(args.ProjectRoot)
	if rootResolved == "" {
		rootResolved, _ = filepath.Abs(args.ProjectRoot)
	}
	rel, relErr := filepath.Rel(rootResolved, abs)
	if relErr != nil {
		// Should be unreachable — safeResolvePath already checked
		// containment. Defensive: treat as denial.
		t.recordDenial(args, "get_file: relative-path resolution failed", abs, started)
		return nil, fmt.Errorf("get_file: relative-path resolution failed: %w", relErr)
	}
	rel = filepath.ToSlash(rel)

	if !extensionAllowed(abs, t.opts.AllowExtensions) {
		ext := strings.TrimPrefix(filepath.Ext(abs), ".")
		reason := fmt.Sprintf("extension %q not in allow list", ext)
		t.recordDenial(args, "get_file: "+reason, abs, started)
		return nil, fmt.Errorf("get_file: %s", reason)
	}

	if matchesAny(rel, t.opts.DenyPaths) {
		reason := fmt.Sprintf("path %q matches deny pattern", rel)
		t.recordDenial(args, "get_file: "+reason, abs, started)
		return nil, fmt.Errorf("get_file: %s", reason)
	}

	if args.StartLine < 0 || args.EndLine < 0 {
		reason := "negative line numbers not allowed"
		t.recordDenial(args, "get_file: "+reason, abs, started)
		return nil, fmt.Errorf("get_file: %s", reason)
	}
	if args.StartLine > 0 && args.EndLine > 0 && args.StartLine > args.EndLine {
		reason := fmt.Sprintf("invalid line range: start_line=%d > end_line=%d", args.StartLine, args.EndLine)
		t.recordDenial(args, "get_file: "+reason, abs, started)
		return nil, fmt.Errorf("get_file: %s", reason)
	}

	info, err := os.Stat(abs)
	if err != nil {
		reason := fmt.Sprintf("stat: %v", err)
		t.recordDenial(args, "get_file: "+reason, abs, started)
		return nil, fmt.Errorf("get_file: %s", reason)
	}
	if !info.Mode().IsRegular() {
		t.recordDenial(args, "get_file: not a regular file", abs, started)
		return nil, errors.New("get_file: not a regular file")
	}

	body, lines, truncated, err := readSlice(abs, args.StartLine, args.EndLine, t.maxKBN*1024)
	if err != nil {
		reason := err.Error()
		t.recordDenial(args, "get_file: "+reason, abs, started)
		return nil, fmt.Errorf("get_file: %s", reason)
	}

	res := getFileResult{
		OK:                  true,
		Path:                abs,
		ProjectRelativePath: rel,
		Lines:               lines,
		Body:                string(body),
		SizeBytes:           len(body),
		Truncated:           truncated,
	}
	t.recordSuccess(args, abs, res, started)
	return res, nil
}

// readSlice lives in internal/mcp/fileread.go — shared with get_symbols.

func (t *getFileTool) recordSuccess(args getFileArgs, abs string, res getFileResult, started time.Time) {
	t.audit.Record(context.Background(), audit.Row{
		Tool:              "get_file",
		SessionID:         args.SessionID,
		RequestHash:       audit.RequestHash("get_file", args),
		PathRequested:     abs,
		ResponseBytes:     res.SizeBytes,
		ResponseTruncated: res.Truncated,
		ResponseOK:        true,
		Duration:          time.Since(started),
	})
}

func (t *getFileTool) recordDenial(args getFileArgs, reason, abs string, started time.Time) {
	t.audit.Record(context.Background(), audit.Row{
		Tool:          "get_file",
		SessionID:     args.SessionID,
		RequestHash:   audit.RequestHash("get_file", args),
		PathRequested: abs,
		ResponseOK:    false,
		Reason:        reason,
		Duration:      time.Since(started),
	})
}
