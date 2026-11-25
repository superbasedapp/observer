package cacheobs

import (
	"encoding/json"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// This file owns the canonical forms of ANTHROPIC-SHAPE content blocks
// (text / thinking / tool_use / tool_result / image entries of a message
// content array) that cline, cline-cli and cowork each used to marshal
// with byte-identical code. Which source block maps to which builder, and
// any adapter-only field, stays in the adapter's own switch.
//
// The same R3 rule as message.go applies: these bytes feed the chain hash,
// so a payload change here changes every persisted chain for every user.

// ContentBlocks converts a content array into ordered CacheBlockMeta rows,
// one per block marshal accepts, tagged with role. INPUT ORDER maps to
// OUTPUT ORDER (no map iteration on the path), the R3 determinism guard.
// It returns nil for an empty array.
func ContentBlocks[B any](blocks []B, role string, marshal func(B) (canon []byte, kind string, ok bool)) []models.CacheBlockMeta {
	if len(blocks) == 0 {
		return nil
	}
	out := make([]models.CacheBlockMeta, 0, len(blocks))
	for _, b := range blocks {
		canon, kind, ok := marshal(b)
		if !ok {
			continue
		}
		out = append(out, models.CacheBlockMeta{
			LevelLabel:     messageLevel,
			Kind:           kind,
			CanonicalBytes: canon,
			Role:           role,
		})
	}
	return out
}

// ContentText returns the canonical form of a text-like block,
// {"type":<kind>,"text":<text>}, with kind as the engine kind label. Used
// for "text" and "thinking" blocks; unlike MarshalTextBlock an empty text
// still yields a block (its presence keeps the chain position-accurate).
func ContentText(kind, text string) (canon []byte, kindOut string, ok bool) {
	payload := struct {
		Type string `json:"type"`
		Text string `json:"text,omitempty"`
	}{Type: kind, Text: text}
	buf, err := json.Marshal(payload)
	if err != nil {
		return nil, "", false
	}
	return buf, kind, true
}

// ContentToolUse returns the canonical form of a tool_use block,
// {"type":"tool_use","id":..,"name":..,"input":<raw>}. The input's source
// bytes are kept verbatim.
func ContentToolUse(id, name string, input json.RawMessage) (canon []byte, kind string, ok bool) {
	payload := struct {
		Type  string          `json:"type"`
		ID    string          `json:"id,omitempty"`
		Name  string          `json:"name,omitempty"`
		Input json.RawMessage `json:"input,omitempty"`
	}{
		Type:  "tool_use",
		ID:    id,
		Name:  name,
		Input: input,
	}
	buf, err := json.Marshal(payload)
	if err != nil {
		return nil, "", false
	}
	return buf, "tool_use", true
}

// ContentToolResult returns the canonical form of a tool_result block,
// {"type":"tool_result","tool_use_id":..,"is_error":..,"content":<raw>}.
func ContentToolResult(toolUseID string, isError bool, content json.RawMessage) (canon []byte, kind string, ok bool) {
	payload := struct {
		Type      string          `json:"type"`
		ToolUseID string          `json:"tool_use_id,omitempty"`
		IsError   bool            `json:"is_error,omitempty"`
		Content   json.RawMessage `json:"content,omitempty"`
	}{
		Type:      "tool_result",
		ToolUseID: toolUseID,
		IsError:   isError,
		Content:   content,
	}
	buf, err := json.Marshal(payload)
	if err != nil {
		return nil, "", false
	}
	return buf, "tool_result", true
}

// ContentImage returns the canonical form of an image block,
// {"type":"image"}, under the "text" kind. No image bytes are folded in
// (they are never stored); the block's presence and position are what the
// chain needs.
func ContentImage() (canon []byte, kind string, ok bool) {
	payload := struct {
		Type string `json:"type"`
	}{Type: "image"}
	buf, err := json.Marshal(payload)
	if err != nil {
		return nil, "", false
	}
	return buf, "text", true
}
