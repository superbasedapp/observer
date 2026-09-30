package mcpschema

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
)

// NameMap is the explicit native -> exposed tool-name mapping of one
// snapshot (mcp_server_snapshot.native_to_exposed_map, R8.10). A native
// name absent from the map is exposed under its own name.
type NameMap map[string]string

// ErrNameMap reports a mapping ValidateNameMap refused.
var ErrNameMap = errors.New("mcpschema: invalid name map")

// ParseNameMap decodes the stored JSON object; empty input is an empty map.
func ParseNameMap(raw []byte) (NameMap, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return NameMap{}, nil
	}
	var m NameMap
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidJSON, err)
	}
	if m == nil {
		m = NameMap{}
	}
	return m, nil
}

// MarshalJSON renders the map with sorted keys (canonical, diff-stable).
func (m NameMap) MarshalJSON() ([]byte, error) {
	keys := make([]string, 0, len(m))
	for k := range m {
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
		writeString(&buf, m[k])
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

// ValidateNameMap checks m against the tool set it maps: every native key
// must name a tool in the set, every exposed value must be a valid tool
// name, and the EXPOSED namespace (mapped values plus the unmapped natives
// exposed under their own name) must be collision-free.
func ValidateNameMap(m NameMap, tools []Tool) error {
	native := map[string]bool{}
	for _, t := range tools {
		native[t.Name] = true
	}
	exposed := map[string]string{} // exposed -> native
	for k, v := range m {
		if !native[k] {
			return fmt.Errorf("%w: native tool %q is not in the snapshot", ErrNameMap, k)
		}
		if !ValidToolName(v) {
			return fmt.Errorf("%w: exposed name %q for %q is not a valid tool name", ErrNameMap, v, k)
		}
		if prev, dup := exposed[v]; dup {
			return fmt.Errorf("%w: exposed name %q is mapped from both %q and %q", ErrNameMap, v, prev, k)
		}
		exposed[v] = k
	}
	for _, t := range tools {
		if _, mapped := m[t.Name]; mapped {
			continue
		}
		if prev, dup := exposed[t.Name]; dup {
			return fmt.Errorf("%w: exposed name %q (mapped from %q) collides with the unmapped native tool %q", ErrNameMap, t.Name, prev, t.Name)
		}
		exposed[t.Name] = t.Name
	}
	return nil
}

// Exposed returns the name a native tool is exposed under.
func (m NameMap) Exposed(native string) string {
	if v, ok := m[native]; ok {
		return v
	}
	return native
}

// Native returns the native tool behind an exposed name and whether the
// exposed name is known to the (validated) map + tool set. A name that is
// neither mapped nor a plain native tool of tools is unknown.
func (m NameMap) Native(exposed string, tools []Tool) (string, bool) {
	for k, v := range m {
		if v == exposed {
			return k, true
		}
	}
	if _, remapped := m[exposed]; remapped {
		// The native name has been renamed away; its old name is not exposed.
		return "", false
	}
	for _, t := range tools {
		if t.Name == exposed {
			return exposed, true
		}
	}
	return "", false
}
