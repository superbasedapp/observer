package mcpschema

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// HashVersion is the domain separator SchemaHash and CfgHash prepend, so a
// future canonical form can coexist with v1 rows.
const HashVersion = "sbo-mcpschema-v1"

// Tool is one tools/list entry in the MCP 2025-06-18 shape. The schema and
// annotation members are kept raw: canonicalization owns their shape.
type Tool struct {
	Name         string          `json:"name"`
	Title        string          `json:"title,omitempty"`
	Description  string          `json:"description,omitempty"`
	InputSchema  json.RawMessage `json:"inputSchema,omitempty"`
	OutputSchema json.RawMessage `json:"outputSchema,omitempty"`
	Annotations  json.RawMessage `json:"annotations,omitempty"`
}

// ErrDuplicateTool reports two tools sharing one name in one set.
var ErrDuplicateTool = errors.New("mcpschema: duplicate tool name")

// ErrToolName reports a tool name outside the accepted vocabulary.
var ErrToolName = errors.New("mcpschema: invalid tool name")

// toolNameRE is the accepted tool-name vocabulary (letters, digits, "_", "-",
// "." - the characters every MCP client and the CEL compiler round-trip
// verbatim), 1..128 bytes.
var toolNameRE = regexp.MustCompile(`^[A-Za-z0-9_.\-]{1,128}$`)

// ValidToolName reports whether name is in the accepted vocabulary.
func ValidToolName(name string) bool { return toolNameRE.MatchString(name) }

// ParseToolsListResult decodes a tools/list RESULT object ({"tools": [...],
// "nextCursor": "..."}) and returns the tools plus the pagination cursor.
func ParseToolsListResult(result []byte) ([]Tool, string, error) {
	var body struct {
		Tools      []Tool `json:"tools"`
		NextCursor string `json:"nextCursor"`
	}
	if err := json.Unmarshal(result, &body); err != nil {
		return nil, "", fmt.Errorf("%w: tools/list result: %w", ErrInvalidJSON, err)
	}
	return body.Tools, body.NextCursor, nil
}

// ParseTools decodes a canonical tools_json array.
func ParseTools(raw []byte) ([]Tool, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, nil
	}
	var tools []Tool
	if err := json.Unmarshal(raw, &tools); err != nil {
		return nil, fmt.Errorf("%w: tools array: %w", ErrInvalidJSON, err)
	}
	return tools, nil
}

// sortedTools returns a copy of tools ordered by name, or ErrDuplicateTool /
// ErrToolName.
func sortedTools(tools []Tool) ([]Tool, error) {
	out := make([]Tool, len(tools))
	copy(out, tools)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	for i := range out {
		if !ValidToolName(out[i].Name) {
			return nil, fmt.Errorf("%w: %q", ErrToolName, out[i].Name)
		}
		if i > 0 && out[i].Name == out[i-1].Name {
			return nil, fmt.Errorf("%w: %q", ErrDuplicateTool, out[i].Name)
		}
	}
	return out, nil
}

// CanonicalTool returns the canonical bytes of one descriptor: an object with
// the members annotations / description / inputSchema / name / outputSchema /
// title (absent members omitted), each schema member itself canonicalized
// with bounded $ref resolution.
func CanonicalTool(t Tool, opts Options) ([]byte, error) {
	obj := map[string]any{"name": t.Name}
	if t.Title != "" {
		obj["title"] = t.Title
	}
	if t.Description != "" {
		obj["description"] = t.Description
	}
	for _, m := range []struct {
		key string
		raw json.RawMessage
	}{{"inputSchema", t.InputSchema}, {"outputSchema", t.OutputSchema}, {"annotations", t.Annotations}} {
		if len(bytes.TrimSpace(m.raw)) == 0 {
			continue
		}
		c, err := Canonicalize(m.raw, opts)
		if err != nil {
			return nil, fmt.Errorf("tool %q %s: %w", t.Name, m.key, err)
		}
		obj[m.key] = json.RawMessage(c)
	}
	// obj holds canonical raw members already; a second pass sorts the top
	// level and leaves the members' bytes untouched.
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		writeString(&buf, k)
		buf.WriteByte(':')
		switch v := obj[k].(type) {
		case string:
			writeString(&buf, v)
		case json.RawMessage:
			buf.Write(v)
		}
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

// MarshalTools renders a tool set in its canonical tools_json form: an array
// of canonical descriptors ordered by name.
func MarshalTools(tools []Tool, opts Options) ([]byte, error) {
	sorted, err := sortedTools(tools)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	buf.WriteByte('[')
	for i, t := range sorted {
		if i > 0 {
			buf.WriteByte(',')
		}
		c, err := CanonicalTool(t, opts)
		if err != nil {
			return nil, err
		}
		buf.Write(c)
	}
	buf.WriteByte(']')
	return buf.Bytes(), nil
}

// SchemaHash is the FULL-schema hash of a tool set (mcp_server_snapshot.
// schema_hash, R8.10): SHA-256 hex over HashVersion and the canonical
// descriptors ordered by name, NUL-delimited. An empty set has a hash too
// (a server that advertises no tools is a valid, pinnable state).
func SchemaHash(tools []Tool, opts Options) (string, error) {
	sorted, err := sortedTools(tools)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write([]byte(HashVersion + ":schema"))
	h.Write([]byte{0})
	for _, t := range sorted {
		c, err := CanonicalTool(t, opts)
		if err != nil {
			return "", err
		}
		h.Write(c)
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// LaunchShape is the config SHAPE of one registered server - what CfgHash
// covers. Only key/header NAMES are included, never a value.
type LaunchShape struct {
	Transport   string
	URL         string
	OpenAPIRef  string
	Command     string
	Args        []string
	EnvKeys     []string
	HeaderNames []string
}

// CfgHash hashes the launch/config shape (mcp_server_snapshot.cfg_hash):
// fixed field order, NUL-delimited fields, section separators between the
// lists, list members sorted so a reordering is not a change.
func CfgHash(s LaunchShape) string {
	h := sha256.New()
	h.Write([]byte(HashVersion + ":cfg"))
	h.Write([]byte{0})
	for _, part := range []string{strings.TrimSpace(s.Transport), strings.TrimSpace(s.URL), strings.TrimSpace(s.OpenAPIRef), strings.TrimSpace(s.Command)} {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	for _, list := range [][]string{s.Args, sortedCopy(s.EnvKeys), sortedCopy(s.HeaderNames)} {
		h.Write([]byte{1})
		for _, v := range list {
			h.Write([]byte(v))
			h.Write([]byte{0})
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

func sortedCopy(in []string) []string {
	out := make([]string, len(in))
	copy(out, in)
	sort.Strings(out)
	return out
}

// Annotations is the decoded MCP ToolAnnotations object with the spec's
// defaults applied by the accessor methods (destructiveHint and openWorldHint
// default TRUE when absent; readOnlyHint and idempotentHint default FALSE).
type Annotations struct {
	Title           string `json:"title,omitempty"`
	ReadOnlyHint    *bool  `json:"readOnlyHint,omitempty"`
	DestructiveHint *bool  `json:"destructiveHint,omitempty"`
	IdempotentHint  *bool  `json:"idempotentHint,omitempty"`
	OpenWorldHint   *bool  `json:"openWorldHint,omitempty"`
}

// ParseAnnotations decodes a raw annotations member; empty input is the
// all-defaults value.
func ParseAnnotations(raw json.RawMessage) (Annotations, error) {
	var a Annotations
	if len(bytes.TrimSpace(raw)) == 0 {
		return a, nil
	}
	if err := json.Unmarshal(raw, &a); err != nil {
		return Annotations{}, fmt.Errorf("%w: annotations: %w", ErrInvalidJSON, err)
	}
	return a, nil
}

func boolOr(v *bool, def bool) bool {
	if v == nil {
		return def
	}
	return *v
}

// Destructive reports the effective destructiveHint: an absent hint means
// the tool MAY be destructive (spec default true) unless readOnlyHint is set,
// in which case the tool cannot modify anything.
func (a Annotations) Destructive() bool {
	if boolOr(a.ReadOnlyHint, false) {
		return false
	}
	return boolOr(a.DestructiveHint, true)
}

// ReadOnly reports the effective readOnlyHint (default false).
func (a Annotations) ReadOnly() bool { return boolOr(a.ReadOnlyHint, false) }

// Idempotent reports the effective idempotentHint (default false).
func (a Annotations) Idempotent() bool { return boolOr(a.IdempotentHint, false) }

// OpenWorld reports the effective openWorldHint (default true).
func (a Annotations) OpenWorld() bool { return boolOr(a.OpenWorldHint, true) }
