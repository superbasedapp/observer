package sandboxrelayd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path"
	"path/filepath"
	"strings"
)

// pathmap.go is a run's box-to-host path map (lane G4 fix round 2,
// G4-R2). A hosted box that works in a fixed path of its own (the
// org-hosted row's /sandbox/workspace) reports that path in its hook
// payloads; the host's copy of the workspace is the run's directory. The
// relay rewrites the box prefix to the host directory in the payload's
// working-directory and file keys before any binding check or confined
// read, so a hook read of a box path is served from the run's directory
// and the box path itself is never a host root. A path under no mapped
// prefix is left as written, so the binding refuses it as it refuses any
// other path outside the run (fail closed).

// PathPrefix maps one box path prefix (a slash path in the box) onto a
// host directory.
type PathPrefix struct {
	Box  string `json:"box"`
	Host string `json:"host"`
}

// validPathMap checks every row: an absolute, clean box path that is not
// the box root, and an absolute, clean host directory.
func validPathMap(m []PathPrefix) error {
	for _, p := range m {
		if p.Box == "" || p.Box == "/" || !path.IsAbs(p.Box) || path.Clean(p.Box) != p.Box {
			return fmt.Errorf("%w: path map box prefix %q", ErrBadRecord, p.Box)
		}
		if p.Host == "" || !filepath.IsAbs(p.Host) || filepath.Clean(p.Host) != p.Host {
			return fmt.Errorf("%w: path map host directory %q", ErrBadRecord, p.Host)
		}
	}
	return nil
}

// MapBoxPath returns p with its box prefix replaced by the host directory
// the map names, matched by whole path components after cleaning ("..",
// a double slash and a trailing slash cannot step out of or around a
// prefix). A path under no prefix comes back unchanged with false.
func MapBoxPath(m []PathPrefix, p string) (string, bool) {
	if !path.IsAbs(p) || strings.ContainsRune(p, 0) {
		return p, false
	}
	c := path.Clean(p)
	for _, row := range m {
		if c == row.Box {
			return row.Host, true
		}
		if rest, ok := strings.CutPrefix(c, row.Box+"/"); ok {
			return filepath.Join(row.Host, filepath.FromSlash(rest)), true
		}
	}
	return p, false
}

// mapPayloadPaths rewrites the mapped box paths in a hook payload's
// working-directory and file keys (the keys the binding and the confined
// reader act on); a tool call's own operands are left as the agent wrote
// them. A payload that is not a JSON object, or that names no mapped path,
// comes back byte for byte.
func mapPayloadPaths(stdin []byte, m []PathPrefix) []byte {
	if len(m) == 0 {
		return stdin
	}
	body := bytes.TrimPrefix(stdin, []byte{0xEF, 0xBB, 0xBF})
	var raw json.RawMessage
	if err := json.NewDecoder(bytes.NewReader(body)).Decode(&raw); err != nil || firstByte(raw) != '{' {
		return stdin
	}
	nodes := 0
	out, changed := mapPayloadValue(raw, m, 0, &nodes)
	if !changed {
		return stdin
	}
	return out
}

// mapPayloadValue rewrites one JSON value and everything nested in it,
// within the payload walk's own depth and node bounds (past them the value
// is left as written; the binding refuses such a payload anyway).
func mapPayloadValue(raw json.RawMessage, m []PathPrefix, depth int, nodes *int) (json.RawMessage, bool) {
	*nodes++
	if depth > maxPayloadDepth || *nodes > maxPayloadNodes {
		return raw, false
	}
	switch firstByte(raw) {
	case '{':
		var obj map[string]json.RawMessage
		if json.Unmarshal(raw, &obj) != nil {
			return raw, false
		}
		changed := false
		for k, v := range obj {
			var nv json.RawMessage
			var c bool
			switch {
			case keyMatches(k, payloadOperandKeys):
				continue
			case keyMatches(k, payloadDirKeys), keyMatches(k, payloadFileKeys):
				nv, c = mapPathValue(v, m)
			default:
				nv, c = mapPayloadValue(v, m, depth+1, nodes)
			}
			if c {
				obj[k], changed = nv, true
			}
		}
		if !changed {
			return raw, false
		}
		return encodeRaw(obj, raw)
	case '[':
		var arr []json.RawMessage
		if json.Unmarshal(raw, &arr) != nil {
			return raw, false
		}
		changed := false
		for i, v := range arr {
			if nv, c := mapPayloadValue(v, m, depth+1, nodes); c {
				arr[i], changed = nv, true
			}
		}
		if !changed {
			return raw, false
		}
		return encodeRaw(arr, raw)
	}
	return raw, false
}

// mapPathValue rewrites a string, or the strings of an array, under a
// path key.
func mapPathValue(raw json.RawMessage, m []PathPrefix) (json.RawMessage, bool) {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		mapped, ok := MapBoxPath(m, s)
		if !ok {
			return raw, false
		}
		return encodeRaw(mapped, raw)
	}
	var arr []string
	if json.Unmarshal(raw, &arr) != nil {
		return raw, false
	}
	changed := false
	for i, s := range arr {
		if mapped, ok := MapBoxPath(m, s); ok {
			arr[i], changed = mapped, true
		}
	}
	if !changed {
		return raw, false
	}
	return encodeRaw(arr, raw)
}

// encodeRaw encodes v without HTML escaping; on an error it keeps old.
func encodeRaw(v any, old json.RawMessage) (json.RawMessage, bool) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return old, false
	}
	return json.RawMessage(bytes.TrimRight(b.Bytes(), "\n")), true
}
