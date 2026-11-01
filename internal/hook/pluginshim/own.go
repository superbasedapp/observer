package pluginshim

import (
	"bytes"
	"encoding/json"
)

// RenderedBinaries reports whether data is the embedded shim template
// with only its profile filled in (what Render writes, byte for byte
// outside the profile), and returns the binaries that profile names: the
// observer binary and the WSL-side binary ("" when unset). The repository
// trust check (docs/security.md SECP-5) counts a shim as Observer's own
// only when this holds and each named binary is Observer's;
// LooksLikeObserverShim, a marker test, stays the registrar's refresh test.
//
// Render writes the template with the post-tool feedback block either kept
// or dropped (withPostToolBlock, lane sec-h), so both renderings count.
func RenderedBinaries(data []byte) (bin, wslBin string, ok bool) {
	for _, keep := range []bool{false, true} {
		tmpl, err := withPostToolBlock(shimTemplate, keep)
		if err != nil {
			return "", "", false
		}
		if bin, wslBin, ok := renderedBinariesOf(tmpl, data); ok {
			return bin, wslBin, true
		}
	}
	return "", "", false
}

// renderedBinariesOf is RenderedBinaries against one template rendering.
func renderedBinariesOf(tmpl, data []byte) (bin, wslBin string, ok bool) {
	i := bytes.Index(tmpl, []byte(profilePlaceholder))
	if i < 0 {
		return "", "", false
	}
	pre, post := tmpl[:i], tmpl[i+len(profilePlaceholder):]
	if len(data) < len(pre)+len(post) || !bytes.HasPrefix(data, pre) || !bytes.HasSuffix(data, post) {
		return "", "", false
	}
	dec := json.NewDecoder(bytes.NewReader(data[len(pre) : len(data)-len(post)]))
	dec.DisallowUnknownFields()
	var p profile
	if err := dec.Decode(&p); err != nil || dec.More() {
		return "", "", false
	}
	return p.Bin, p.WSLBin, true
}
