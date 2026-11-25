package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/mcp/audit"
	"github.com/marmutapp/superbased-observer/internal/stash"
)

// -----------------------------------------------------------------------------
// retrieve_stashed (CCR — v1.4.41 / Tier 1 / G31; V7-12 batch + slice — v1.7.11)
// -----------------------------------------------------------------------------

// defaultMaxShasPerCall caps the array-form sha input. Mirrors
// get_symbols's per-call batch cap; commit 3 exposes a config knob.
const defaultMaxShasPerCall = 25

type retrieveStashedTool struct {
	store          *stash.Stash
	signals        SignalRecorder
	audit          audit.Writer
	maxShasPerCall int
}

func newRetrieveStashedTool(s *stash.Stash, signals SignalRecorder, w audit.Writer, maxShasPerCall int) Tool {
	if w == nil {
		w = audit.NewNoopWriter()
	}
	if maxShasPerCall <= 0 {
		maxShasPerCall = defaultMaxShasPerCall
	}
	return &retrieveStashedTool{store: s, signals: signals, audit: w, maxShasPerCall: maxShasPerCall}
}

func (*retrieveStashedTool) Name() string { return "retrieve_stashed" }
func (*retrieveStashedTool) Description() string {
	return "Retrieve stashed tool_result body bytes. Pass `sha` as a single string for byte-identical legacy retrieval, or as an array of shas (max 25) for batched retrieval. Optional `start_line` / `end_line` slice the blob (1-indexed, inclusive) - use these when the marker points at a large blob but you only need a section to save agent context budget. Single-string + no range returns the v1.7.10 shape unchanged; single-string + range augments it with `returned: {start_line, end_line}` and `total_lines_in_blob`; array input switches to a `responses: [...]` envelope with per-sha `ok`/`reason` for mixed-success batches."
}

func (*retrieveStashedTool) InputSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"sha": map[string]any{
				"oneOf": []map[string]any{
					{"type": "string"},
					{"type": "array", "items": map[string]any{"type": "string"}, "minItems": 1, "maxItems": defaultMaxShasPerCall},
				},
				"description": "Single sha (64-char lowercase hex SHA-256) for legacy single-blob retrieval, OR an array of shas for batched retrieval. Array form switches the response shape to a `responses: [...]` envelope.",
			},
			"start_line": map[string]any{
				"type":        "integer",
				"minimum":     1,
				"description": "Optional 1-based start line (inclusive). Applies to every sha when the input is an array. Omit to start at line 1.",
			},
			"end_line": map[string]any{
				"type":        "integer",
				"minimum":     1,
				"description": "Optional 1-based end line (inclusive). Applies to every sha when the input is an array. Omit to read to EOF.",
			},
			"max_bytes": map[string]any{
				"type":        "integer",
				"description": "Optional cap on returned bytes per sha. When set and the (already-sliced) body is larger, returns only the first max_bytes bytes plus a `truncated: true` flag.",
			},
			"session_id": map[string]any{
				"type":        "string",
				"description": "Optional. Threads the call into the V7-14 audit log so per-session forensics work. Codex sessions populate this from their session metadata when possible.",
			},
		},
		"required": []string{"sha"},
	}
}

// retrieveStashedResult is the v1.7.10 single-sha-no-range response
// shape. PINNED BY TestRetrieveStashed_BackwardsCompat_SingleStringByteIdentical
// — do not add fields or rename JSON tags without a major version bump
// (V7-16 contract). The two pointer-shaped fields below were introduced
// in v1.7.11 and only marshal when populated (omitempty); legacy callers
// never see them.
type retrieveStashedResult struct {
	Sha              string     `json:"sha"`
	SizeBytes        int        `json:"size_bytes"`
	Content          string     `json:"content"`
	Truncated        bool       `json:"truncated,omitempty"`
	Returned         *lineRange `json:"returned,omitempty"`
	TotalLinesInBlob int        `json:"total_lines_in_blob,omitempty"`
}

// retrieveStashedPerResponse is one element of the array-form envelope.
// OK is always emitted (helps the agent parse mixed-success batches with
// a stable shape).
type retrieveStashedPerResponse struct {
	Sha              string     `json:"sha"`
	OK               bool       `json:"ok"`
	Reason           string     `json:"reason,omitempty"`
	SizeBytes        int        `json:"size_bytes,omitempty"`
	Content          string     `json:"content,omitempty"`
	Truncated        bool       `json:"truncated,omitempty"`
	Returned         *lineRange `json:"returned,omitempty"`
	TotalLinesInBlob int        `json:"total_lines_in_blob,omitempty"`
}

type retrieveStashedEnvelope struct {
	OK        bool                         `json:"ok"`
	Responses []retrieveStashedPerResponse `json:"responses"`
}

type retrieveStashedArgs struct {
	Sha       json.RawMessage `json:"sha"`
	StartLine int             `json:"start_line"`
	EndLine   int             `json:"end_line"`
	MaxBytes  int             `json:"max_bytes"`
	SessionID string          `json:"session_id"`
}

func (t *retrieveStashedTool) Invoke(ctx context.Context, raw json.RawMessage) (any, error) {
	started := time.Now()
	var args retrieveStashedArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, fmt.Errorf("invalid arguments: %w", err)
	}
	if len(args.Sha) == 0 {
		return nil, errors.New("sha is required")
	}

	// Peek at the JSON token type. A string starts with '"'; an array
	// with '['. Anything else is malformed.
	first := firstNonSpace(args.Sha)
	switch first {
	case '"':
		var single string
		if err := json.Unmarshal(args.Sha, &single); err != nil {
			return nil, fmt.Errorf("invalid sha string: %w", err)
		}
		return t.invokeSingle(ctx, args, single, started)
	case '[':
		var shas []string
		if err := json.Unmarshal(args.Sha, &shas); err != nil {
			return nil, fmt.Errorf("invalid sha array: %w", err)
		}
		return t.invokeArray(ctx, args, shas, started)
	default:
		return nil, errors.New("sha must be a string or array of strings")
	}
}

// firstNonSpace returns the first non-whitespace byte of a JSON value,
// or 0 if all whitespace. Used to peek at the sha field's JSON token
// type without a full Unmarshal-into-interface{} (which would normalise
// numbers to float64, hiding precision issues — overkill for a token
// type peek).
func firstNonSpace(raw json.RawMessage) byte {
	for _, b := range raw {
		switch b {
		case ' ', '\t', '\n', '\r':
			continue
		default:
			return b
		}
	}
	return 0
}

// invokeSingle handles `sha: "..."` input. With no range params, emits
// the v1.7.10 byte-identical legacy shape. With at least one range
// param, augments with `returned` and `total_lines_in_blob` — extra
// fields don't break callers reading only the legacy keys (V7-16 BC).
func (t *retrieveStashedTool) invokeSingle(ctx context.Context, args retrieveStashedArgs, sha string, started time.Time) (any, error) {
	if strings.TrimSpace(sha) == "" {
		return nil, errors.New("sha is required")
	}
	per := t.processOne(sha, args.StartLine, args.EndLine, args.MaxBytes)
	t.recordRow(args, sha, per, started)
	if !per.OK {
		// Legacy contract: single-string failures surface as a top-level
		// error (callers branch on isError), not as a soft `ok: false`.
		return nil, errors.New(per.Reason)
	}
	if t.signals != nil {
		_ = t.signals.RecordRetrieveStashed(ctx, sha, args.SessionID)
	}
	res := retrieveStashedResult{
		Sha:       sha,
		SizeBytes: per.SizeBytes,
		Content:   per.Content,
		Truncated: per.Truncated,
	}
	if args.StartLine > 0 || args.EndLine > 0 {
		res.Returned = per.Returned
		res.TotalLinesInBlob = per.TotalLinesInBlob
	}
	return res, nil
}

// invokeArray handles `sha: ["a", "b", ...]` input. Always emits the
// envelope shape — single-element arrays are explicit caller intent
// to use the new wire (see D-2 in the v1.7.11 plan doc).
func (t *retrieveStashedTool) invokeArray(ctx context.Context, args retrieveStashedArgs, shas []string, started time.Time) (any, error) {
	if len(shas) == 0 {
		return nil, errors.New("sha array must contain at least one element")
	}
	if len(shas) > t.maxShasPerCall {
		return nil, fmt.Errorf("sha array exceeds max %d shas per call (got %d); split into multiple requests", t.maxShasPerCall, len(shas))
	}
	out := retrieveStashedEnvelope{OK: true, Responses: make([]retrieveStashedPerResponse, 0, len(shas))}
	for _, sha := range shas {
		per := t.processOne(sha, args.StartLine, args.EndLine, args.MaxBytes)
		t.recordRow(args, sha, per, started)
		if per.OK && t.signals != nil {
			_ = t.signals.RecordRetrieveStashed(ctx, sha, args.SessionID)
		}
		out.Responses = append(out.Responses, per)
	}
	return out, nil
}

// processOne fetches one sha (with optional range slice + byte cap) and
// returns the per-sha result. Never returns an error directly — failures
// land in PerResponse.OK + Reason so the array-form callers can keep
// going through partial failures. The single-form caller adapts to the
// top-level-error contract by checking per.OK.
func (t *retrieveStashedTool) processOne(sha string, startLine, endLine, maxBytes int) retrieveStashedPerResponse {
	out := retrieveStashedPerResponse{Sha: sha}
	if strings.TrimSpace(sha) == "" {
		out.Reason = "sha_required"
		return out
	}
	var body []byte
	var total int
	var err error
	if startLine > 0 || endLine > 0 {
		body, total, err = t.store.ReadSlice(sha, startLine, endLine)
	} else {
		body, err = t.store.Read(sha)
	}
	switch {
	case errors.Is(err, stash.ErrNotFound):
		out.Reason = fmt.Sprintf("sha_not_found: %s (may have been GCed; re-run the producing tool to regenerate)", sha)
		return out
	case errors.Is(err, stash.ErrCorrupt):
		out.Reason = fmt.Sprintf("sha_corrupt: %s (re-run the producing tool)", sha)
		return out
	case err != nil:
		out.Reason = fmt.Sprintf("retrieve_stashed: %v", err)
		return out
	}
	fullSize := len(body)
	if maxBytes > 0 && len(body) > maxBytes {
		body = body[:maxBytes]
		out.Truncated = true
	}
	out.OK = true
	out.SizeBytes = fullSize
	out.Content = string(body)
	if startLine > 0 || endLine > 0 {
		// emittedStart / emittedEnd here are best-effort: stash.ReadSlice
		// clamps endLine to total and start>total returns empty. Surface
		// the clamped form so the agent sees what it actually got.
		emittedStart, emittedEnd := startLine, endLine
		if emittedStart <= 0 {
			emittedStart = 1
		}
		if emittedEnd <= 0 || emittedEnd > total {
			emittedEnd = total
		}
		if emittedStart > total {
			emittedStart = 0
			emittedEnd = 0
		}
		out.Returned = &lineRange{Start: emittedStart, End: emittedEnd, Total: total}
		out.TotalLinesInBlob = total
	}
	return out
}

// recordRow writes one audit row per (sha, attempt). PathRequested
// encodes the sha as `stashed://<sha>` so operator queries
// (`SELECT … WHERE path_requested LIKE 'stashed://%'`) can sweep
// retrieve_stashed activity uniformly. RequestHash is computed on the
// full args (including range params) so re-issues of the same batch
// hash identically.
func (t *retrieveStashedTool) recordRow(args retrieveStashedArgs, sha string, per retrieveStashedPerResponse, started time.Time) {
	t.audit.Record(context.Background(), audit.Row{
		Tool:              "retrieve_stashed",
		SessionID:         args.SessionID,
		RequestHash:       audit.RequestHash("retrieve_stashed", args),
		PathRequested:     "stashed://" + sha,
		ResponseBytes:     per.SizeBytes,
		ResponseTruncated: per.Truncated,
		ResponseOK:        per.OK,
		Reason:            per.Reason,
		Duration:          time.Since(started),
	})
}
