package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
)

// PostCompactInjector is the optional pre-compression hook that
// prepends a synthetic system block carrying recovery context to
// Anthropic request bodies whose session_id has a recent compaction
// event in the observer DB. Production impl is
// (*compaction.Injector).Get; the interface stays here so the proxy
// contract is import-cycle-free and proxy_test.go can stub it.
//
// Get returns "" when no injection should fire (no compaction event /
// no recovery data / sessionID empty); otherwise returns the stable
// per-compaction content the body should be prefixed with.
type PostCompactInjector interface {
	Get(ctx context.Context, sessionID string) (string, error)
}

// injectAnthropicSystemBlock prepends a `{type:"text", text:content}`
// block to the request body's `system` field. Handles all three shapes
// Anthropic's Messages API accepts:
//   - missing field: sets `system` to a one-element array.
//   - top-level string: lifts to a two-element array (new block first).
//   - top-level array: prepends the new block.
//
// Returns the body unchanged when:
//   - content is empty.
//   - the body is empty or not a JSON object.
//   - the existing `system` field is neither string nor array.
//
// On every successful path the output is deterministic for the same
// (body, content) pair — same input bytes → same output bytes. This
// is the cross-turn invariance predicate the compression pipeline's
// fast-path early-return relies on.
func injectAnthropicSystemBlock(body []byte, content string) ([]byte, error) {
	if content == "" || len(bytes.TrimSpace(body)) == 0 {
		return body, nil
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(body, &envelope); err != nil {
		return body, fmt.Errorf("injectAnthropicSystemBlock: parse: %w", err)
	}

	newBlock := map[string]any{"type": "text", "text": content}

	var systemArr []any
	if existing, ok := envelope["system"]; ok && len(bytes.TrimSpace(existing)) > 0 && string(existing) != "null" {
		var s string
		if err := json.Unmarshal(existing, &s); err == nil {
			systemArr = []any{newBlock, map[string]any{"type": "text", "text": s}}
		} else {
			var arr []any
			if err := json.Unmarshal(existing, &arr); err != nil {
				return body, fmt.Errorf("injectAnthropicSystemBlock: system field is neither string nor array: %w", err)
			}
			systemArr = append([]any{newBlock}, arr...)
		}
	} else {
		systemArr = []any{newBlock}
	}

	encoded, err := json.Marshal(systemArr)
	if err != nil {
		return body, fmt.Errorf("injectAnthropicSystemBlock: marshal system: %w", err)
	}
	envelope["system"] = encoded

	out, err := marshalEnvelope(envelope)
	if err != nil {
		return body, fmt.Errorf("injectAnthropicSystemBlock: marshal envelope: %w", err)
	}
	return out, nil
}

// marshalEnvelope is the proxy-side cousin of
// conversation.marshalEnvelope: deterministic key-ordered serialisation
// of a map[string]json.RawMessage. The proxy is linked into builds that
// omit the proxy.compression component, whose packages
// (internal/compression/conversation and its types subpackage) must then
// stay out of the binary, so the proxy cannot import that helper; the
// (small) function is duplicated here instead. Keep the two
// implementations in sync — the cross-turn invariance predicate depends
// on byte-identical envelope ordering.
func marshalEnvelope(obj map[string]json.RawMessage) ([]byte, error) {
	tmp := make(map[string]json.RawMessage, len(obj))
	for k, v := range obj {
		tmp[k] = v
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(tmp); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}
