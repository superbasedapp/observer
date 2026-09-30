package alignment

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ParseResult tolerantly extracts the {"delivered","missed","extra",
// "confidence","notes"} verdict object from a model's raw reply. Models
// asked to "return ONLY JSON" routinely wrap it in a ```json fenced code
// block, or append a sentence of trailing prose after the closing brace;
// ParseResult finds the first balanced JSON object in the reply (preferring
// one found inside a fenced block when present) and decodes that,
// tolerating everything around it. Confidence is clamped to [0,1].
//
// An error is returned only when no balanced JSON object can be found, or
// the object found does not decode — e.g. a reply that is pure prose with
// no JSON at all.
func ParseResult(raw string) (Result, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return Result{}, fmt.Errorf("alignment.ParseResult: empty reply")
	}

	candidate := extractJSONObject(raw)
	if candidate == "" {
		return Result{}, fmt.Errorf("alignment.ParseResult: no JSON object found in reply")
	}

	var wire struct {
		Delivered  []string `json:"delivered"`
		Missed     []string `json:"missed"`
		Extra      []string `json:"extra"`
		Confidence float64  `json:"confidence"`
		Notes      string   `json:"notes"`
	}
	if err := json.Unmarshal([]byte(candidate), &wire); err != nil {
		return Result{}, fmt.Errorf("alignment.ParseResult: decode: %w", err)
	}

	confidence := wire.Confidence
	switch {
	case confidence < 0:
		confidence = 0
	case confidence > 1:
		confidence = 1
	}

	return Result{
		Delivered:  wire.Delivered,
		Missed:     wire.Missed,
		Extra:      wire.Extra,
		Confidence: confidence,
		Notes:      wire.Notes,
	}, nil
}

// extractJSONObject returns the first balanced {...} object in raw,
// preferring one found inside a ```-fenced code block (with an optional
// "json" language tag) when a fence is present, and falling back to
// searching the whole reply otherwise. Returns "" when no balanced object
// is found anywhere.
func extractJSONObject(raw string) string {
	if idx := strings.Index(raw, "```"); idx != -1 {
		rest := raw[idx+3:]
		if end := strings.Index(rest, "```"); end != -1 {
			fenced := rest[:end]
			fenced = strings.TrimPrefix(fenced, "json")
			fenced = strings.TrimPrefix(fenced, "JSON")
			if obj := firstBalancedJSONObject(fenced); obj != "" {
				return obj
			}
		}
	}
	return firstBalancedJSONObject(raw)
}

// firstBalancedJSONObject scans s for the first '{' and returns the
// substring up to its matching '}', respecting JSON string literals (so a
// brace inside a quoted string is not mistaken for structure) and their
// backslash escapes. Returns "" when the braces never balance (e.g. a
// truncated or non-JSON reply).
func firstBalancedJSONObject(s string) string {
	start := strings.IndexByte(s, '{')
	if start == -1 {
		return ""
	}
	depth := 0
	inString := false
	escaped := false
	for i := start; i < len(s); i++ {
		c := s[i]
		if inString {
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
			}
			continue
		}
		switch c {
		case '"':
			inString = true
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return s[start : i+1]
			}
		}
	}
	return ""
}
