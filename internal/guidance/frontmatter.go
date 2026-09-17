package guidance

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// knownFrontmatterKeys is the closed set of front-matter keys the
// scanner retains. Everything else in a block is dropped: this table is
// what keeps a guidance row metadata and stops it turning into a copy of
// the file (CLAUDE.md "Don'ts").
var knownFrontmatterKeys = []string{
	"name",
	"description",
	"globs",
	"alwaysApply",
	"applyTo",
	"model",
	"tools",
	"allowed-tools",
	"argument-hint",
}

// KnownFrontmatterKeys returns the retained key vocabulary, sorted. Used
// by consumers that render a front-matter table and by the tests.
func KnownFrontmatterKeys() []string {
	out := make([]string, len(knownFrontmatterKeys))
	copy(out, knownFrontmatterKeys)
	sort.Strings(out)
	return out
}

// splitFrontmatter separates a leading "---" fenced block from the body.
// ok is false when the file simply has no front matter, which is not an
// error — most instruction files are pure prose. The body is returned so
// the caller can mine a fallback description from it; it is never
// retained past that.
func splitFrontmatter(b []byte) (block, body string, ok bool) {
	s := strings.ReplaceAll(string(b), "\r\n", "\n")
	if !strings.HasPrefix(s, "---\n") && s != "---" && !strings.HasPrefix(s, "---\r") {
		return "", s, false
	}
	rest := strings.TrimPrefix(s, "---\n")
	// The closing fence is a line that is exactly "---" (or "..." — YAML's
	// document terminator, which a few generators emit).
	lines := strings.Split(rest, "\n")
	for i, ln := range lines {
		t := strings.TrimRight(ln, " \t")
		if t == "---" || t == "..." {
			return strings.Join(lines[:i], "\n"), strings.Join(lines[i+1:], "\n"), true
		}
	}
	// An opening fence with no closing fence is malformed, not absent.
	return rest, "", true
}

// parseYAMLFrontmatter decodes a "---" fenced block into the flat,
// allow-listed string map the File carries. A malformed block yields a
// non-empty parseErr and an empty map — the file still counts as
// discovered, it just has no usable metadata.
func parseYAMLFrontmatter(b []byte) (fm map[string]string, body string, parseErr string) {
	block, body, ok := splitFrontmatter(b)
	if !ok {
		return nil, body, ""
	}
	if strings.TrimSpace(block) == "" {
		return nil, body, ""
	}
	var raw map[string]any
	if err := yaml.Unmarshal([]byte(block), &raw); err != nil {
		return nil, body, fmt.Sprintf("front matter: %v", err)
	}
	if raw == nil {
		// A block that parses to a scalar or a list, not a mapping.
		return nil, body, "front matter: expected a mapping"
	}
	return pickKnown(raw), body, ""
}

// parseJSONConfig handles the two JSON dialects in the table. Only
// opencode.json contributes metadata (its instructions[] array names
// further guidance files); every other config file is validated as JSON
// and otherwise carries nothing.
func parseJSONConfig(b []byte, wantInstructions bool) (fm map[string]string, parseErr string) {
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, fmt.Sprintf("json: %v", err)
	}
	if !wantInstructions {
		return nil, ""
	}
	v, present := raw["instructions"]
	if !present {
		return nil, ""
	}
	s := flatten(v)
	if s == "" {
		return nil, ""
	}
	return map[string]string{"instructions": s}, ""
}

// pickKnown reduces a decoded mapping to the allow-listed keys, flattening
// each value to a single display string.
func pickKnown(raw map[string]any) map[string]string {
	out := make(map[string]string, len(knownFrontmatterKeys))
	for _, k := range knownFrontmatterKeys {
		v, present := raw[k]
		if !present {
			continue
		}
		if s := flatten(v); s != "" {
			out[k] = s
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// flatten renders a decoded YAML/JSON value as one display string. Lists
// join with ", "; anything structural collapses to its element strings.
// Values are capped so a pathological front matter cannot smuggle a file
// body into the metadata.
const maxFrontmatterValueBytes = 2000

func flatten(v any) string {
	var s string
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		s = t
	case bool:
		s = strconv.FormatBool(t)
	case int:
		s = strconv.Itoa(t)
	case int64:
		s = strconv.FormatInt(t, 10)
	case float64:
		s = strconv.FormatFloat(t, 'f', -1, 64)
	case []any:
		parts := make([]string, 0, len(t))
		for _, e := range t {
			if p := flatten(e); p != "" {
				parts = append(parts, p)
			}
		}
		s = strings.Join(parts, ", ")
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			if p := flatten(t[k]); p != "" {
				parts = append(parts, k+"="+p)
			}
		}
		s = strings.Join(parts, ", ")
	default:
		s = fmt.Sprintf("%v", t)
	}
	s = strings.TrimSpace(s)
	if len(s) > maxFrontmatterValueBytes {
		s = s[:maxFrontmatterValueBytes]
	}
	return s
}

// maxDescriptionBytes caps a body-derived description. A description is
// a one-line summary, never an excerpt of the guidance itself.
const maxDescriptionBytes = 300

// describeBody derives a short description from a markdown body when the
// front matter had none: the first non-blank, non-heading, non-fence
// line. This is deliberately the ONLY body text the scanner keeps.
func describeBody(body string) string {
	inFence := false
	for _, ln := range strings.Split(body, "\n") {
		t := strings.TrimSpace(ln)
		if strings.HasPrefix(t, "```") || strings.HasPrefix(t, "~~~") {
			inFence = !inFence
			continue
		}
		if inFence || t == "" || strings.HasPrefix(t, "#") || t == "---" {
			continue
		}
		if len(t) > maxDescriptionBytes {
			t = t[:maxDescriptionBytes]
		}
		return t
	}
	return ""
}
