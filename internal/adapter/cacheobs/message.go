package cacheobs

import (
	"encoding/json"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// This file owns the canonical forms of FLATTENED message-level blocks:
// the shape used by adapters whose source record has already been reduced
// to plain strings (a prompt or reply text, a tool name plus its scrubbed
// input or args string, a tool result's flattened text). Every such
// adapter used to carry its own byte-identical copy of these builders.
//
// The canonical bytes feed the cachetrack engine's rolling chain hash
// (spec R3), so changing any payload here changes every persisted chain
// hash for every adapter that uses it. Each payload is an explicit STRUCT
// (never a map) so encoding/json's declaration-order field output is
// byte-stable across runs.

// messageLevel is the CacheBlockMeta.LevelLabel every transcript-derived
// block carries (R1: transcripts never expose the tools/system levels).
const messageLevel = "message"

// MarshalTextBlock returns the canonical form of a plain text block,
// {"type":"text","text":<text>}. It returns false for an empty text,
// which contributes no block.
func MarshalTextBlock(text string) ([]byte, bool) {
	return marshalTypedText("text", text)
}

// MarshalToolResultBlock returns the canonical form of a tool result's
// flattened text, {"type":"tool_result","text":<text>}. It returns false
// for an empty text.
func MarshalToolResultBlock(text string) ([]byte, bool) {
	return marshalTypedText("tool_result", text)
}

// marshalTypedText encodes the {type, text} payload both builders above
// share, skipping an empty text.
func marshalTypedText(typ, text string) ([]byte, bool) {
	if text == "" {
		return nil, false
	}
	payload := struct {
		Type string `json:"type"`
		Text string `json:"text,omitempty"`
	}{Type: typ, Text: text}
	buf, err := json.Marshal(payload)
	if err != nil {
		return nil, false
	}
	return buf, true
}

// MarshalToolUseBlock returns the canonical form of one tool call whose
// input is a (scrubbed) string, {"type":"tool_use","name":..,"input":..}.
// It returns false when both name and input are empty.
func MarshalToolUseBlock(name, input string) ([]byte, bool) {
	if name == "" && input == "" {
		return nil, false
	}
	payload := struct {
		Type  string `json:"type"`
		Name  string `json:"name,omitempty"`
		Input string `json:"input,omitempty"`
	}{Type: "tool_use", Name: name, Input: input}
	buf, err := json.Marshal(payload)
	if err != nil {
		return nil, false
	}
	return buf, true
}

// MarshalToolUseArgsBlock is MarshalToolUseBlock with the call's string
// under an "args" key, {"type":"tool_use","name":..,"args":..}: the form
// the muse and openclaw chains were recorded with. It stays distinct
// because renaming the key would change those adapters' chain hashes.
func MarshalToolUseArgsBlock(name, args string) ([]byte, bool) {
	if name == "" && args == "" {
		return nil, false
	}
	payload := struct {
		Type string `json:"type"`
		Name string `json:"name,omitempty"`
		Args string `json:"args,omitempty"`
	}{Type: "tool_use", Name: name, Args: args}
	buf, err := json.Marshal(payload)
	if err != nil {
		return nil, false
	}
	return buf, true
}

// observeOne appends one canonical message-level block when ok.
func (a *Accumulator) observeOne(canon []byte, ok bool, kind, role string) {
	if !ok {
		return
	}
	a.ObserveBlocks([]models.CacheBlockMeta{{
		LevelLabel:     messageLevel,
		Kind:           kind,
		CanonicalBytes: canon,
		Role:           role,
	}})
}

// ObserveText feeds one (already scrubbed) text block under role, as a
// "text" kind block. An empty text adds nothing.
func (a *Accumulator) ObserveText(text, role string) {
	canon, ok := MarshalTextBlock(text)
	a.observeOne(canon, ok, "text", role)
}

// ObserveToolUse feeds one assistant tool call (name plus the scrubbed
// input string) in the MarshalToolUseBlock form.
func (a *Accumulator) ObserveToolUse(name, input string) {
	canon, ok := MarshalToolUseBlock(name, input)
	a.observeOne(canon, ok, "tool_use", "assistant")
}

// ObserveToolUseArgs feeds one assistant tool call in the
// MarshalToolUseArgsBlock form.
func (a *Accumulator) ObserveToolUseArgs(name, args string) {
	canon, ok := MarshalToolUseArgsBlock(name, args)
	a.observeOne(canon, ok, "tool_use", "assistant")
}

// ObserveToolResult feeds one tool result's (scrubbed, flattened) text
// under the "tool" role.
func (a *Accumulator) ObserveToolResult(text string) {
	canon, ok := MarshalToolResultBlock(text)
	a.observeOne(canon, ok, "tool_result", "tool")
}

// EmitTurn is the emit step most Tier-2 producers share: it returns nil
// for an all-zero usage (the in-progress-turn carve-out, which leaves the
// pending delta for the next turn), otherwise drains the delta through
// Emit (never a fast-mode turn) and applies the §15.3 implicit-cache
// overlay for (provider, model). Adapters build usage from their own
// token record; that mapping stays local.
func (a *Accumulator) EmitTurn(
	path, sessionID, messageID, model, provider string,
	ts time.Time,
	usage models.CacheUsage,
) *models.CacheTurnObservation {
	if IsZeroUsage(usage) {
		return nil
	}
	obs := a.Emit(path, sessionID, messageID, model, ts, usage, false)
	obs = ApplyImplicitCacheOverlay(obs, provider, model)
	return &obs
}
