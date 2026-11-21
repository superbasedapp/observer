package otelident

import (
	"encoding/json"
	"sort"
	"strings"
	"unicode/utf8"
)

// Clamp trims s and cuts it to at most max bytes on a rune boundary. Every
// identity value passes through it before it is stored or shipped.
func Clamp(s string, max int) string {
	s = strings.TrimSpace(s)
	if max <= 0 || len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// ClampValue is Clamp at MaxValueLen: the bound for tenant, end user,
// session, service, environment and release.
func ClampValue(s string) string { return Clamp(s, MaxValueLen) }

// NormalizeTags returns the bounded, canonical tag set: each tag trimmed and
// clamped to MaxTagLen, empties dropped, de-duplicated, sorted, and capped at
// MaxTags (the first MaxTags in sorted order survive, so the result is
// deterministic whatever order the inputs arrived in). nil when empty.
func NormalizeTags(in ...[]string) []string {
	seen := map[string]bool{}
	var out []string
	for _, list := range in {
		for _, t := range list {
			t = Clamp(t, MaxTagLen)
			if t == "" || seen[t] {
				continue
			}
			seen[t] = true
			out = append(out, t)
		}
	}
	if len(out) == 0 {
		return nil
	}
	sort.Strings(out)
	if len(out) > MaxTags {
		out = out[:MaxTags]
	}
	return out
}

// ParseTags reads one tag attribute's STRING form: a JSON array string
// (`["a","b"]`) or a comma-separated list (`a, b`). A single bare word is one
// tag. The result is not yet normalized.
func ParseTags(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	if strings.HasPrefix(s, "[") {
		var arr []any
		if json.Unmarshal([]byte(s), &arr) == nil {
			out := make([]string, 0, len(arr))
			for _, v := range arr {
				if str, ok := scalarString(v); ok {
					out = append(out, str)
				}
			}
			return out
		}
	}
	return strings.Split(s, ",")
}

// NormalizeMetadata returns the bounded metadata map. Maps are applied in
// order and an EARLIER map's key wins over a later one (so a caller passes the
// higher-precedence source first: span before resource, stored before
// incoming). Keys and values are clamped (MaxMetadataKeyLen,
// MaxMetadataValueLen), empty keys dropped, and the map is capped at
// MaxMetadataKeys keeping the lexically smallest keys, so the result is
// deterministic. nil when empty.
func NormalizeMetadata(in ...map[string]string) map[string]string {
	out := map[string]string{}
	for _, m := range in {
		for k, v := range m {
			k = Clamp(k, MaxMetadataKeyLen)
			if k == "" {
				continue
			}
			if _, ok := out[k]; ok {
				continue
			}
			out[k] = Clamp(v, MaxMetadataValueLen)
		}
	}
	if len(out) == 0 {
		return nil
	}
	if len(out) > MaxMetadataKeys {
		keys := make([]string, 0, len(out))
		for k := range out {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys[MaxMetadataKeys:] {
			delete(out, k)
		}
	}
	return out
}

// ParseMetadataJSON reads one metadata attribute's STRING form: a JSON object
// whose scalar values become strings and whose nested values are kept as
// their compact JSON. A non-object string yields nil (the caller may then
// keep it under a single key of its choosing).
func ParseMetadataJSON(s string) map[string]string {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "{") {
		return nil
	}
	var obj map[string]any
	if json.Unmarshal([]byte(s), &obj) != nil {
		return nil
	}
	out := make(map[string]string, len(obj))
	for k, v := range obj {
		if str, ok := scalarString(v); ok {
			out[k] = str
			continue
		}
		if b, err := json.Marshal(v); err == nil {
			out[k] = string(b)
		}
	}
	return out
}

// MetadataKeyFor returns the metadata entry name for a flattened attribute
// key (the remainder after a MetadataPrefixes prefix) and true, or "", false
// when key carries no metadata prefix or is itself an identity key.
func MetadataKeyFor(key string) (string, bool) {
	if isIdentityKey(key) {
		return "", false
	}
	for _, p := range MetadataPrefixes {
		if strings.HasPrefix(key, p) && len(key) > len(p) {
			return key[len(p):], true
		}
	}
	return "", false
}

// isIdentityKey reports whether key is in any identity list (so it is never
// also metadata).
func isIdentityKey(key string) bool {
	for _, list := range [][]string{TenantKeys, UserKeys, SessionKeys, ServiceKeys, EnvironmentKeys, ReleaseKeys, TagKeys, MetadataKeys} {
		for _, k := range list {
			if k == key {
				return true
			}
		}
	}
	return false
}

// EncodeTags returns the canonical JSON array of NormalizeTags(tags), or ""
// when there are none (stored as NULL / omitted).
func EncodeTags(tags []string) string {
	n := NormalizeTags(tags)
	if len(n) == 0 {
		return ""
	}
	b, err := json.Marshal(n)
	if err != nil {
		return ""
	}
	return string(b)
}

// DecodeTags is EncodeTags' inverse; malformed input yields nil.
func DecodeTags(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	if json.Unmarshal([]byte(s), &out) != nil {
		return nil
	}
	return out
}

// EncodeMetadata returns the canonical JSON object of NormalizeMetadata(m)
// (keys sorted by encoding/json), or "" when empty.
func EncodeMetadata(m map[string]string) string {
	n := NormalizeMetadata(m)
	if len(n) == 0 {
		return ""
	}
	b, err := json.Marshal(n)
	if err != nil {
		return ""
	}
	return string(b)
}

// DecodeMetadata is EncodeMetadata's inverse; malformed input yields nil.
func DecodeMetadata(s string) map[string]string {
	if s == "" {
		return nil
	}
	var out map[string]string
	if json.Unmarshal([]byte(s), &out) != nil {
		return nil
	}
	return out
}

func scalarString(v any) (string, bool) {
	switch x := v.(type) {
	case string:
		return x, true
	case bool, float64, json.Number:
		b, err := json.Marshal(x)
		if err != nil {
			return "", false
		}
		return string(b), true
	default:
		return "", false
	}
}
