package deepagents

import (
	"encoding/json"
	"fmt"
	"strings"
)

// messages.go turns one decoded `messages` channel write into normalized
// rawMessage values. dcode stores a conversation as LangGraph channel writes:
// every write on the `messages` channel is a msgpack list whose items are
// pydantic-v2 extensions (ext 5) of langchain_core message classes. The
// message is the ext's kwargs dict — the same field set LangChain's
// `message.model_dump()` produces.

// rawToolCall is one entry of an AIMessage.tool_calls list.
type rawToolCall struct {
	ID   string
	Name string
	Args map[string]any
}

// rawMessage is a LangChain message reduced to the fields the adapter reads.
type rawMessage struct {
	// ID is the message id the add_messages reducer keys on: an AI message
	// is `lc_run--<uuid>`, human / tool messages carry a plain uuid.
	ID string
	// Role is one of "human", "ai", "tool", "system" ("" when unknown).
	Role string
	// Name is the message `name`: the agent name on an AI message, the tool
	// name on a tool message.
	Name       string
	Content    any
	ToolCalls  []rawToolCall
	ToolCallID string
	// Status is a ToolMessage status ("success" / "error").
	Status           string
	Artifact         any
	AdditionalKwargs map[string]any
	ResponseMetadata map[string]any
	UsageMetadata    map[string]any

	// CheckpointID is the checkpoint the write that FIRST carried this
	// message hung off (a UUIDv6 whose embedded clock is the message's
	// fallback timestamp); TaskID is the LangGraph task that wrote it (the
	// model call's task also writes its `_last_model_request_at`).
	CheckpointID string
	TaskID       string
}

// messageClasses maps a langchain_core message class name to its role. The
// `type` kwarg is authoritative when present; this is the fallback.
var messageClasses = map[string]string{
	"HumanMessage":       "human",
	"HumanMessageChunk":  "human",
	"AIMessage":          "ai",
	"AIMessageChunk":     "ai",
	"ToolMessage":        "tool",
	"ToolMessageChunk":   "tool",
	"SystemMessage":      "system",
	"SystemMessageChunk": "system",
}

// collectMessages walks a decoded channel-write value and calls emit for
// every message found. The channel value is normally a list of message
// extensions; LangGraph also wraps a wholesale replacement in an `Overwrite`
// object, and an input dict (`{"role": "user", "content": ...}`) can appear
// where a message was not yet coerced. RemoveMessage items are ignored on
// purpose: a removal drops a message from the live state, but its tokens
// were already spent, so the log of every message ever written is what the
// adapter counts.
func collectMessages(v any, emit func(rawMessage)) {
	switch t := v.(type) {
	case []any:
		for _, item := range t {
			collectMessages(item, emit)
		}
	case extValue:
		_, class, payload, ok := t.object()
		if !ok {
			return
		}
		if class == "Overwrite" {
			// kwargs {"value": [...]} or a single positional argument.
			if m, isMap := payload.(map[string]any); isMap {
				collectMessages(m["value"], emit)
			} else {
				collectMessages(payload, emit)
			}
			return
		}
		role, isMsg := messageClasses[class]
		if !isMsg {
			return
		}
		kw, isMap := payload.(map[string]any)
		if !isMap {
			return
		}
		emit(messageFromFields(role, kw))
	case map[string]any:
		// A bare dict message ({"role"|"type": ..., "content": ...}).
		if _, hasContent := t["content"]; !hasContent {
			return
		}
		role := roleOf(firstString(t, "type", "role"))
		if role == "" {
			return
		}
		emit(messageFromFields(role, t))
	}
}

// roleOf normalizes a LangChain message `type` / OpenAI `role` to the
// adapter's four roles; "" when it is none of them.
func roleOf(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "human", "user", "humanmessagechunk":
		return "human"
	case "ai", "assistant", "aimessagechunk":
		return "ai"
	case "tool", "function", "toolmessagechunk":
		return "tool"
	case "system", "developer", "systemmessagechunk":
		return "system"
	}
	return ""
}

// messageFromFields builds a rawMessage from a message's field dict. The
// class-derived role is overridden by an explicit `type` field.
func messageFromFields(classRole string, kw map[string]any) rawMessage {
	role := classRole
	if r := roleOf(firstString(kw, "type")); r != "" {
		role = r
	}
	m := rawMessage{
		ID:               firstString(kw, "id"),
		Role:             role,
		Name:             firstString(kw, "name"),
		Content:          kw["content"],
		ToolCallID:       firstString(kw, "tool_call_id"),
		Status:           firstString(kw, "status"),
		Artifact:         kw["artifact"],
		AdditionalKwargs: asMap(kw["additional_kwargs"]),
		ResponseMetadata: asMap(kw["response_metadata"]),
		UsageMetadata:    asMap(kw["usage_metadata"]),
	}
	if calls, ok := kw["tool_calls"].([]any); ok {
		for _, c := range calls {
			cm := asMap(c)
			if cm == nil {
				continue
			}
			m.ToolCalls = append(m.ToolCalls, rawToolCall{
				ID:   firstString(cm, "id"),
				Name: firstString(cm, "name"),
				Args: asMap(cm["args"]),
			})
		}
	}
	return m
}

// asMap returns v as a map or nil.
func asMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

// firstString returns the first non-empty string value among keys.
func firstString(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if s, ok := m[k].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

// asInt64 coerces a decoded msgpack number to int64 (0 when absent or not a
// number). Floats truncate.
func asInt64(v any) int64 {
	switch t := v.(type) {
	case int64:
		return t
	case float64:
		return int64(t)
	}
	return 0
}

// asFloat coerces a decoded msgpack number to float64.
func asFloat(v any) float64 {
	switch t := v.(type) {
	case float64:
		return t
	case int64:
		return float64(t)
	}
	return 0
}

// contentText flattens a message `content` to its visible text. Content is a
// bare string (human / tool / plain AI) or a list of blocks whose text lives
// in `text`; reasoning / thinking blocks are NOT part of the visible text
// (reasoningText reads those).
func contentText(content any) string {
	switch t := content.(type) {
	case string:
		return t
	case []any:
		var parts []string
		for _, b := range t {
			switch bt := b.(type) {
			case string:
				parts = append(parts, bt)
			case map[string]any:
				switch strings.ToLower(firstString(bt, "type")) {
				case "reasoning", "thinking", "redacted_thinking":
					continue
				}
				if s := firstString(bt, "text"); s != "" {
					parts = append(parts, s)
				}
			}
		}
		return strings.Join(parts, "\n")
	}
	return ""
}

// reasoningText extracts the model's reasoning text carried on a message:
// `thinking` / `reasoning` content blocks (Anthropic thinking, OpenAI
// Responses reasoning summaries) and the `reasoning_content` additional
// kwarg OpenAI-compatible providers use. Empty when there is none.
func reasoningText(m rawMessage) string {
	var parts []string
	if blocks, ok := m.Content.([]any); ok {
		for _, b := range blocks {
			bt := asMap(b)
			if bt == nil {
				continue
			}
			switch strings.ToLower(firstString(bt, "type")) {
			case "thinking":
				if s := firstString(bt, "thinking", "text"); s != "" {
					parts = append(parts, s)
				}
			case "reasoning":
				if s := firstString(bt, "reasoning", "text"); s != "" {
					parts = append(parts, s)
					continue
				}
				if sum, ok := bt["summary"].([]any); ok {
					for _, it := range sum {
						if s := firstString(asMap(it), "text"); s != "" {
							parts = append(parts, s)
						}
					}
				}
			}
		}
	}
	if s := firstString(m.AdditionalKwargs, "reasoning_content"); s != "" {
		parts = append(parts, s)
	}
	return strings.Join(parts, "\n")
}

// promptMeta reads the harness-stamped per-prompt metadata dcode attaches to
// every human message it composes (additional_kwargs.
// deepagents_code_user_prompt). literal is the text exactly as the user typed
// it (the message content may carry expanded @file context); turnID groups
// every model call of one user turn.
func promptMeta(m rawMessage) (literal, turnID string) {
	pm := asMap(m.AdditionalKwargs["deepagents_code_user_prompt"])
	if pm == nil {
		return "", ""
	}
	return firstString(pm, "literal_user_text"), firstString(pm, "turn_id")
}

// jsonArgs renders tool-call arguments as deterministic JSON (Go sorts map
// keys), or "" when there are none.
func jsonArgs(args map[string]any) string {
	if len(args) == 0 {
		return ""
	}
	b, err := json.Marshal(args)
	if err != nil {
		return ""
	}
	return string(b)
}

// synthID builds a deterministic id for a message that carries none.
func synthID(checkpointID, taskID string, idx, pos int) string {
	return fmt.Sprintf("k:%s:%s:%d:%d", checkpointID, taskID, idx, pos)
}
