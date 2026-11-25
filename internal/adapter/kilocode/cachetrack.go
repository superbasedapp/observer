package kilocode

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
// running block count. Matches claudecode/opencode (same memory
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
// Spec §14.3 — kilo-cli Tier-2. See
// docs/audits/cachetrack-kilo-cli-tier2-audit-2026-06-09.md for
// the volatile-element exclusion rationale (mirrors opencode's
// audit; kilo-specific divergences documented at the top of the
// audit). The struct-based canonical-bytes marshallers below
// enforce the R3 byte-stability invariant.
func (a *CLIAdapter) loadCacheObservations(ctx context.Context, db *sql.DB, sourceFile string, fromOffset int64) ([]models.CacheTurnObservation, error) {
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
			return nil, fmt.Errorf("kilocode.loadCacheObservations: parts for %s: %w", m.ID, err)
		}
		blocks := accumulateCacheBlocksTier2(parts, meta.Role)

		acc := accBySession[m.SessionID]
		if acc == nil {
			acc = cacheobs.New(MaxBlocksPerSession)
			accBySession[m.SessionID] = acc
		}
		acc.ObserveBlocks(blocks)

		// Emit only assistant messages with non-zero tokens AND whose own
		// time_updated has crossed the cursor (loadTokenEvents' cadence).
		if meta.Role != "assistant" {
			continue
		}
		if meta.Tokens.Input == 0 && meta.Tokens.Output == 0 &&
			meta.Tokens.Cache.Read == 0 && meta.Tokens.Cache.Write == 0 &&
			meta.Tokens.Reasoning == 0 {
			continue
		}
		if m.TimeUpdate <= fromOffset {
			// T-930 (CAPTURE-01, ported from opencode): an earlier parse
			// already emitted this step. Close its delta without emitting,
			// so the first new step carries only the blocks written since
			// it, not the session's older blocks again.
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
		// §15.3 boundary: overlay ImplicitCache for routed implicit-
		// cache providers. Kilo-auto family stays Anthropic-shape
		// (the Gateway is Anthropic-backed for kilo-auto/* per the
		// v1.8.2 audit); other provider strings (openai, openrouter,
		// deepseek, etc.) route to implicit per the routing table.
		provider := firstNonEmpty(meta.ProviderID, meta.Model.ProviderID)
		obs = cacheobs.ApplyImplicitCacheOverlay(obs, provider, model)
		out = append(out, obs)
	}
	return out, nil
}

// loadOrderedParts returns every part of a message in
// (time_created, id) order.
func loadOrderedParts(ctx context.Context, db *sql.DB, messageID string) ([]rawKiloCLIPart, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT id, time_created, data
		  FROM part
		 WHERE message_id = ?
		 ORDER BY time_created ASC, id ASC`, messageID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []rawKiloCLIPart
	for rows.Next() {
		var p rawKiloCLIPart
		if err := rows.Scan(&p.ID, &p.TimeCreate, &p.Data); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

type rawKiloCLIPart struct {
	ID         string
	TimeCreate int64
	Data       string
}

// accumulateCacheBlocksTier2 converts an ordered slice of kilo-cli
// parts into deterministic CacheBlockMeta entries. Mirrors
// opencode's exclusions plus the kilo-specific tool metadata
// carve-out documented in the audit. Each canonical payload is
// marshalled from an explicit STRUCT (NOT a map) per the R3
// byte-stability guard.
func accumulateCacheBlocksTier2(parts []rawKiloCLIPart, role string) []models.CacheBlockMeta {
	if len(parts) == 0 {
		return nil
	}
	out := make([]models.CacheBlockMeta, 0, len(parts))
	for _, p := range parts {
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
			LevelLabel:     "message",
			Kind:           kind,
			CanonicalBytes: canon,
			Role:           role,
		})
	}
	return out
}

// marshalCanonicalPartTier2 produces the deterministic JSON
// canonical form of one kilo-cli part. Returns canonical bytes,
// the engine kind label, and ok=false when the part type is
// excluded (step-finish, todo, unknown).
//
// Volatile fields excluded per audit:
//   - tool: state.title, state.time.{start,end},
//     metadata.openrouter.reasoning_details (per-call provider
//     noise, NOT cache-prefix bearing)
//   - reasoning: time.{start,end}
//   - subtask: time.created
//   - step-finish: SKIPPED (usage rollup)
//
// Kilo-specific stable additions on messageData (mode, parentID,
// path.root, tokens.total) are message-level fields the chain
// never touches.
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
		return nil, "", false
	}
}
