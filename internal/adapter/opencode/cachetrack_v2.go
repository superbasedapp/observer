package opencode

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter/cacheobs"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// loadCacheObservationsV2 is loadCacheObservations over the OpenCode 2.x
// store (T-925). The data the 1.x path reads is all there: a user row's
// text, an assistant step's ordered content items (text, reasoning, tool
// with its settled result) and the step's own token bundle, cache read
// and write included. Every session touched since the cursor is replayed
// from its first message (session_message.seq order) so the per-session
// block chain is complete, and one observation is emitted per assistant
// step whose row crossed the cursor and carries usage, the same cadence
// as v2TokenEvent.
//
// Canonical blocks reuse the 1.x shapes and exclusions (no wall-clock
// time.* fields, R3 byte stability through explicit structs). Each
// observation carries the blocks since the previous step (the
// accumulator's delta contract). When the 1.x tables are present too (an
// upgraded database), a step whose id is still in `message` belongs to
// the 1.x emitter: the 2.x path closes its delta without emitting, so
// the next 2.x step carries only its own blocks. A completed compaction
// resets the chain (cacheobs ObserveCompaction): the steps after it send
// the summary, not the earlier prefix.
func (a *Adapter) loadCacheObservationsV2(ctx context.Context, db *sql.DB, sourceFile string, fromOffset int64, besideV1 bool) ([]models.CacheTurnObservation, error) {
	owned := `0`
	if besideV1 {
		owned = `EXISTS (SELECT 1 FROM message m WHERE m.id = sm.id)`
	}
	//nolint:gosec // owned is one of two literal expressions above
	rows, err := db.QueryContext(ctx, `
		SELECT sm.id, sm.session_id, sm.type, sm.time_updated, sm.data, `+owned+`
		  FROM session_message sm
		 WHERE sm.type IN ('user', 'assistant', 'compaction')
		   AND sm.session_id IN (SELECT DISTINCT session_id FROM session_message WHERE time_updated > ?)
		 ORDER BY sm.session_id ASC, sm.seq ASC`, fromOffset)
	if err != nil {
		return nil, fmt.Errorf("opencode.loadCacheObservationsV2: %w", err)
	}
	type row struct {
		id, session, typ, data string
		updated                int64
		ownedByV1              bool
	}
	var all []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.session, &r.typ, &r.updated, &r.data, &r.ownedByV1); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("opencode.loadCacheObservationsV2: %w", err)
		}
		all = append(all, r)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, fmt.Errorf("opencode.loadCacheObservationsV2: %w", err)
	}
	_ = rows.Close()

	accBySession := map[string]*cacheobs.Accumulator{}
	var out []models.CacheTurnObservation
	for _, r := range all {
		var msg v2Message
		if err := json.Unmarshal([]byte(r.data), &msg); err != nil {
			continue
		}
		acc := accBySession[r.session]
		if acc == nil {
			acc = cacheobs.New(MaxBlocksPerSession)
			accBySession[r.session] = acc
		}
		if r.typ == "compaction" {
			if msg.Status == "completed" {
				acc.ObserveCompaction()
			}
			continue
		}
		acc.ObserveBlocks(v2CacheBlocks(r.typ, msg))

		if r.typ != "assistant" || msg.Tokens.empty() {
			continue
		}
		if r.ownedByV1 || r.updated <= fromOffset {
			// Close this step's delta: it was (or will be) emitted by
			// the 1.x path or by an earlier parse.
			_ = acc.Emit(sourceFile, r.session, r.id, msg.Model.ID, time.Time{}, models.CacheUsage{}, false)
			continue
		}
		ts := int64(msg.Time.Completed)
		if ts == 0 {
			ts = r.updated
		}
		usage := models.CacheUsage{
			NetInputTokens:      int64(msg.Tokens.Input),
			OutputTokens:        int64(msg.Tokens.Output),
			CacheReadTokens:     int64(msg.Tokens.Cache.Read),
			CacheCreationTokens: int64(msg.Tokens.Cache.Write),
		}
		obs := acc.Emit(sourceFile, r.session, r.id, msg.Model.ID, millisToTime(ts), usage, false)
		out = append(out, cacheobs.ApplyImplicitCacheOverlay(obs, msg.Model.ProviderID, msg.Model.ID))
	}
	return out, nil
}

// v2CacheBlocks converts one 2.x message into its canonical cache blocks:
// a user row is its text; an assistant step is its content items in
// order. Item shapes match marshalCanonicalPartTier2's 1.x payloads.
func v2CacheBlocks(typ string, msg v2Message) []models.CacheBlockMeta {
	block := func(kind, role string, payload any) (models.CacheBlockMeta, bool) {
		b, err := json.Marshal(payload)
		if err != nil {
			return models.CacheBlockMeta{}, false
		}
		return models.CacheBlockMeta{LevelLabel: "message", Kind: kind, CanonicalBytes: b, Role: role}, true
	}
	type textPayload struct {
		Type string `json:"type"`
		Text string `json:"text,omitempty"`
	}
	var out []models.CacheBlockMeta
	if typ == "user" {
		if msg.Text != "" {
			if b, ok := block("text", "user", textPayload{Type: "text", Text: msg.Text}); ok {
				out = append(out, b)
			}
		}
		return out
	}
	for _, item := range msg.Content {
		var (
			b  models.CacheBlockMeta
			ok bool
		)
		switch item.Type {
		case "text":
			b, ok = block("text", "assistant", textPayload{Type: "text", Text: item.Text})
		case "reasoning":
			b, ok = block("thinking", "assistant", textPayload{Type: "reasoning", Text: item.Text})
		case "tool":
			var outParts []string
			for _, c := range item.State.Content {
				if c.Type == "text" && c.Text != "" {
					outParts = append(outParts, c.Text)
				}
			}
			payload := struct {
				Type   string `json:"type"`
				Tool   string `json:"tool,omitempty"`
				CallID string `json:"call_id,omitempty"`
				State  struct {
					Status string          `json:"status,omitempty"`
					Input  json.RawMessage `json:"input,omitempty"`
					Output string          `json:"output,omitempty"`
					Error  string          `json:"error,omitempty"`
				} `json:"state"`
			}{Type: "tool", Tool: item.Name, CallID: item.ID}
			payload.State.Status = item.State.Status
			payload.State.Input = item.State.Input
			payload.State.Output = strings.Join(outParts, "\n")
			payload.State.Error = item.State.Error.Message
			b, ok = block("tool_use", "assistant", payload)
		}
		if ok {
			out = append(out, b)
		}
	}
	return out
}
