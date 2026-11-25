package transcriptutil

import "encoding/json"

// DecodeContent decodes an Anthropic-shape message "content" field, which
// a transcript stores either as an array of content blocks or as a bare
// string (a typed prompt). An array decodes into []B; a string becomes the
// single block text(s). Anything else (empty input, only whitespace, an
// object, a number, malformed JSON) yields nil.
//
// claudecode, cline and cowork each decode their own block type through
// it; text builds that type's text block.
func DecodeContent[B any](raw json.RawMessage, text func(string) B) []B {
	if len(raw) == 0 {
		return nil
	}
	trimmed := TrimJSONSpace(raw)
	if len(trimmed) == 0 {
		return nil
	}
	switch trimmed[0] {
	case '[':
		var blocks []B
		if err := json.Unmarshal(raw, &blocks); err != nil {
			return nil
		}
		return blocks
	case '"':
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil
		}
		return []B{text(s)}
	}
	return nil
}

// TrimJSONSpace trims the four JSON whitespace bytes (space, tab, LF, CR)
// from both ends of b. Unlike bytes.TrimSpace it leaves every other space
// character in place: those are not JSON whitespace, so a decoder rejects
// them anyway.
func TrimJSONSpace(b []byte) []byte {
	start, end := 0, len(b)
	for start < end && isJSONSpace(b[start]) {
		start++
	}
	for end > start && isJSONSpace(b[end-1]) {
		end--
	}
	return b[start:end]
}

func isJSONSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r'
}
