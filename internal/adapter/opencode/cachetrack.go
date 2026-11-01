package opencode

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter/cacheobs"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// MaxBlocksPerSession caps the per-session Tier-2 accumulator's
// running block count. Matches claudecode's cap (same memory
// budget, same OOM guard). When exceeded, subsequent observations
// emit with BlockHashes=nil so the engine flips to KindReanchor
// rather than running unbounded.
const MaxBlocksPerSession = cacheobs.DefaultMaxBlocksPerSession

// loadCacheObservations walks every message + its parts (in
// (session, message.time_created, part.time_created, part.id)
// order) and emits one CacheTurnObservation per assistant message
// whose `time_updated > fromOffset` AND whose token bundle is
// non-empty.
//
// Spec §14.3 — opencode Tier-2. See
// docs/audits/cachetrack-opencode-tier2-audit-2026-06-09.md for
// the volatile-element exclusion rationale (the wall-clock fields
// inside tool/reasoning/subtask part bodies are the opencode
// equivalent of Anthropic's x-anthropic-billing-header cch nonce
// — they would churn the chain hash on every emission of the
// same logical block if folded in verbatim).
//
// Per-session accumulator: a single message can land across two
// (or more) ParseSessionFile calls (poll-tick + final flush);
// observation cadence is gated on the message's own time_updated
// so a given message emits exactly once.
func (a *Adapter) loadCacheObservations(ctx context.Context, db *sql.DB, sourceFile string, fromOffset int64) ([]models.CacheTurnObservation, error) {
	msgRows, err := db.QueryContext(ctx, `
		SELECT m.id, m.session_id, m.time_created, m.time_updated, m.data
		  FROM message m
		 WHERE m.session_id IN (SELECT DISTINCT session_id FROM message WHERE time_updated > ?)
		 ORDER BY m.session_id ASC, m.time_created ASC, m.id ASC`, fromOffset)
	if err != nil {
		return nil, err
	}
	defer msgRows.Close()

	type msg struct {
		ID         string
		SessionID  string
		TimeCreate int64
		TimeUpdate int64
		Data       string
	}
	var messages []msg
	for msgRows.Next() {
		var m msg
		if err := msgRows.Scan(&m.ID, &m.SessionID, &m.TimeCreate, &m.TimeUpdate, &m.Data); err != nil {
			return nil, err
		}
		messages = append(messages, m)
	}
	if err := msgRows.Err(); err != nil {
		return nil, err
	}
	if len(messages) == 0 {
		return nil, nil
	}

	accBySession := map[string]*cacheobs.Accumulator{}
	var out []models.CacheTurnObservation

	for _, m := range messages {
		var meta messageData
		if err := json.Unmarshal([]byte(m.Data), &meta); err != nil {
			continue
		}

		parts, err := loadOrderedParts(ctx, db, m.ID)
		if err != nil {
			return nil, fmt.Errorf("opencode.loadCacheObservations: parts for %s: %w", m.ID, err)
		}
		blocks := accumulateCacheBlocksTier2(parts, meta.Role)

		acc := accBySession[m.SessionID]
		if acc == nil {
			acc = cacheobs.New(MaxBlocksPerSession)
			accBySession[m.SessionID] = acc
		}
		acc.ObserveBlocks(blocks)

		// Emit only assistant messages with non-zero tokens AND
		// whose own time_updated has crossed the cursor. This
		// matches loadTokenEvents' cadence so observation + token
		// emission stay in lockstep per message.
		if meta.Role != "assistant" {
			continue
		}
		if meta.Tokens.Input == 0 && meta.Tokens.Output == 0 &&
			meta.Tokens.Cache.Read == 0 && meta.Tokens.Cache.Write == 0 &&
			meta.Tokens.Reasoning == 0 {
			continue
		}
		if m.TimeUpdate <= fromOffset {
			// T-930: an earlier parse already emitted this step. Close
			// its delta without emitting, so the first new step carries
			// only the blocks written since it, not the session's older
			// blocks again (same contract as loadCacheObservationsV2).
			_ = acc.Emit(sourceFile, m.SessionID, m.ID, "", time.Time{}, models.CacheUsage{}, false)
			continue
		}

		model := firstNonEmpty(meta.ModelID, meta.Model.ModelID)
		ts := meta.Time.Completed
		if ts == 0 {
			ts = m.TimeUpdate
		}
		usage := models.CacheUsage{
			NetInputTokens:      meta.Tokens.Input,
			OutputTokens:        meta.Tokens.Output,
			CacheReadTokens:     meta.Tokens.Cache.Read,
			CacheCreationTokens: meta.Tokens.Cache.Write,
		}
		obs := acc.Emit(sourceFile, m.SessionID, m.ID, model, millisToTime(ts), usage, false)
		// §15.3 boundary: when the routed (providerID, modelID) pair
		// is implicit-cache shape (OpenAI / OpenRouter / deepseek /
		// etc.), overlay ImplicitCache=true so the engine
		// dispatches to the reduced attribution path. Anthropic-
		// routed sessions are unchanged. The implicit-cache path
		// ignores BlockHashes — cacheobs.ApplyImplicitCacheOverlay
		// clears it to keep the persisted-side cache_segments table
		// free of rows that the engine will never read against.
		// Same shape as the codex Tier-2 emitter in Phase 3.
		provider := firstNonEmpty(meta.ProviderID, meta.Model.ProviderID)
		obs = cacheobs.ApplyImplicitCacheOverlay(obs, provider, model)
		out = append(out, obs)
	}
	return out, nil
}

// loadOrderedParts returns every part of a message in
// (time_created, id) order. Caller filters by part type at
// canonical-bytes time.
func loadOrderedParts(ctx context.Context, db *sql.DB, messageID string) ([]rawOpenCodePart, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT id, time_created, data
		  FROM part
		 WHERE message_id = ?
		 ORDER BY time_created ASC, id ASC`, messageID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []rawOpenCodePart
	for rows.Next() {
		var p rawOpenCodePart
		if err := rows.Scan(&p.ID, &p.TimeCreate, &p.Data); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// rawOpenCodePart is the minimal per-part record the cachetrack
// path reads. Avoids a wider partRow JOIN since the chain doesn't
// need session/cwd/message-JSON enrichment.
type rawOpenCodePart struct {
	ID         string
	TimeCreate int64
	Data       string
}

// accumulateCacheBlocksTier2 converts an ordered slice of opencode
// parts into deterministic CacheBlockMeta entries. Per the audit
// (cachetrack-opencode-tier2-audit-2026-06-09.md):
//
//   - text          → include {type, text}
//   - tool          → include {type, tool, callID, state.{status, input,
//     output, metadata.{output, exit, description, filepath,
//     truncated}}}; EXCLUDE state.title, state.time.*
//   - reasoning     → include {type, text}; EXCLUDE time.*
//   - subtask       → include {type, prompt, description, agent,
//     model.*, command}; EXCLUDE time.created
//   - step-finish   → SKIPPED (usage rollup, not a content block;
//     would double-count vs the message-level token bundle)
//
// Each canonical payload is marshalled from an explicit STRUCT
// (NOT a map) so encoding/json's deterministic field order
// preserves byte-stability across re-parses — the R3 invariant
// the engine's rolling chain hash depends on.
func accumulateCacheBlocksTier2(parts []rawOpenCodePart, role string) []models.CacheBlockMeta {
	if len(parts) == 0 {
		return nil
	}
	out := make([]models.CacheBlockMeta, 0, len(parts))
	for _, p := range parts {
		// Discriminate on the part's type field cheaply (one
		// json.RawMessage decode) before committing to a fixed
		// struct.
		var head struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal([]byte(p.Data), &head); err != nil {
			continue
		}
		canon, kind, ok := marshalCanonicalPartTier2(head.Type, p.Data)
		if !ok {
			continue
		}
		out = append(out, models.CacheBlockMeta{
			LevelLabel:     "message", // R1: transcripts never expose tools/system
			Kind:           kind,
			CanonicalBytes: canon,
			Role:           role,
		})
	}
	return out
}

// marshalCanonicalPartTier2 produces the deterministic JSON
// canonical form of one opencode part. Returns the canonical
// bytes, the engine kind label, and ok=false when the part type
// is excluded (step-finish, todo, unknown) so the caller drops
// the row from the chain.
//
// CRITICAL: every payload type is an explicit STRUCT — never a
// map[string]any. Map iteration order is random in Go and would
// silently break the R3 byte-stability guard the engine's rolling
// hash chain depends on.
func marshalCanonicalPartTier2(partType, raw string) (canon []byte, kind string, ok bool) {
	switch partType {
	case "text":
		var p textPartData
		if err := json.Unmarshal([]byte(raw), &p); err != nil {
			return nil, "", false
		}
		payload := struct {
			Type string `json:"type"`
			Text string `json:"text,omitempty"`
		}{Type: "text", Text: p.Text}
		b, err := json.Marshal(payload)
		if err != nil {
			return nil, "", false
		}
		return b, "text", true

	case "tool":
		var p toolPartData
		if err := json.Unmarshal([]byte(raw), &p); err != nil {
			return nil, "", false
		}
		payload := struct {
			Type   string `json:"type"`
			Tool   string `json:"tool,omitempty"`
			CallID string `json:"call_id,omitempty"`
			State  struct {
				Status   string          `json:"status,omitempty"`
				Input    json.RawMessage `json:"input,omitempty"`
				Output   string          `json:"output,omitempty"`
				Metadata struct {
					Output      string `json:"output,omitempty"`
					Exit        int    `json:"exit,omitempty"`
					Description string `json:"description,omitempty"`
					FilePath    string `json:"filepath,omitempty"`
					Truncated   bool   `json:"truncated,omitempty"`
				} `json:"metadata,omitempty"`
			} `json:"state"`
		}{
			Type:   "tool",
			Tool:   p.Tool,
			CallID: p.CallID,
		}
		payload.State.Status = p.State.Status
		payload.State.Input = p.State.Input
		payload.State.Output = p.State.Output
		payload.State.Metadata.Output = p.State.Metadata.Output
		payload.State.Metadata.Exit = p.State.Metadata.Exit
		payload.State.Metadata.Description = p.State.Metadata.Description
		payload.State.Metadata.FilePath = p.State.Metadata.FilePath
		payload.State.Metadata.Truncated = p.State.Metadata.Truncated
		b, err := json.Marshal(payload)
		if err != nil {
			return nil, "", false
		}
		return b, "tool_use", true

	case "reasoning":
		var p reasoningPartData
		if err := json.Unmarshal([]byte(raw), &p); err != nil {
			return nil, "", false
		}
		payload := struct {
			Type string `json:"type"`
			Text string `json:"text,omitempty"`
		}{Type: "reasoning", Text: p.Text}
		b, err := json.Marshal(payload)
		if err != nil {
			return nil, "", false
		}
		return b, "thinking", true

	case "subtask":
		var p subtaskPartData
		if err := json.Unmarshal([]byte(raw), &p); err != nil {
			return nil, "", false
		}
		payload := struct {
			Type        string `json:"type"`
			Prompt      string `json:"prompt,omitempty"`
			Description string `json:"description,omitempty"`
			Agent       string `json:"agent,omitempty"`
			Model       struct {
				ProviderID string `json:"providerID,omitempty"`
				ModelID    string `json:"modelID,omitempty"`
			} `json:"model,omitempty"`
			Command string `json:"command,omitempty"`
		}{
			Type:        "subtask",
			Prompt:      p.Prompt,
			Description: p.Description,
			Agent:       p.Agent,
			Command:     p.Command,
		}
		payload.Model.ProviderID = p.Model.ProviderID
		payload.Model.ModelID = p.Model.ModelID
		b, err := json.Marshal(payload)
		if err != nil {
			return nil, "", false
		}
		return b, "tool_use", true

	default:
		// step-finish, todo, snapshot, and unknowns: not chain-fed.
		return nil, "", false
	}
}
