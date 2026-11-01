package credfile

import (
	"bytes"
	"errors"

	"github.com/marmutapp/superbased-observer/internal/cfgfmt"
)

// The member editor (surface-gap lane w6-routes, decisions D9 / D16): one
// key at a time in a credential-bearing YAML, JSON or TOML file, for the
// route writers whose file is YAML (Poolside settings.yaml, goose
// config.yaml, Hermes config.yaml) and for any writer that edits a single
// member. It is the YAML twin of SetObjectPath and SetTOMLTable, built on
// the comment- and order-preserving cfgfmt engine:
//
//   - only the member at path changes; every other byte stays, and an edit
//     cfgfmt could make only by re-serializing the file (a flow mapping on
//     the path, an anchor) is refused;
//   - the result is decoded and compared, value for value, with the
//     original plus exactly that one change, before anything is returned;
//   - no value read from the file and no decoder message reaches an error.

// SetYAMLMember sets (present) or removes (!present) the value at path in a
// YAML document, under the member-editor rules. An empty orig is an empty
// mapping.
func SetYAMLMember(orig []byte, path []string, value any, present bool) ([]byte, error) {
	return SetMember(cfgfmt.FormatYAML, orig, path, value, present)
}

// SetMember is SetYAMLMember for any cfgfmt format. Removing an absent key
// returns orig unchanged.
func SetMember(f cfgfmt.Format, orig []byte, path []string, value any, present bool) ([]byte, error) {
	if len(path) == 0 {
		return nil, ErrPatch
	}
	doc, err := cfgfmt.ParseWith(f, orig, cfgfmt.Options{ForbidReserialize: true})
	if err != nil {
		return nil, ErrPatch
	}
	before, err := doc.Value()
	if err != nil {
		return nil, ErrPatch
	}
	key := cfgfmt.Path(path)
	if present {
		err = doc.Set(key, value)
	} else {
		var found bool
		found, err = doc.Delete(key)
		if err == nil && !found {
			return orig, nil
		}
	}
	if err != nil {
		if errors.Is(err, cfgfmt.ErrNeedsReserialize) || errors.Is(err, cfgfmt.ErrUnsupported) || errors.Is(err, cfgfmt.ErrTypeMismatch) {
			return nil, SafeErrorf("the member %s is held in a form Observer cannot edit in place (a flow or inline table, an anchor, or a value of another type on the path)", key)
		}
		return nil, ErrPatch
	}
	out := doc.Bytes()
	re, err := cfgfmt.Parse(f, out)
	if err != nil {
		return nil, ErrPatch
	}
	after, err := re.Value()
	if err != nil {
		return nil, ErrPatch
	}
	if !cfgfmt.Equal(after, expectMember(before, path, value, present)) {
		return nil, ErrPatch
	}
	if bytes.Equal(out, orig) {
		return orig, nil
	}
	return out, nil
}

// MemberValue reads the one value at path (found=false when it is absent or
// the path crosses a non-mapping). The rest of the document is decoded by
// the parser but never returned.
func MemberValue(f cfgfmt.Format, orig []byte, path []string) (value any, found bool, err error) {
	doc, err := cfgfmt.Parse(f, orig)
	if err != nil {
		return nil, false, ErrPatch
	}
	v, ok, gerr := doc.Get(cfgfmt.Path(path))
	if gerr != nil {
		return nil, false, nil //nolint:nilerr // a path through a non-mapping value is "absent"
	}
	return v, ok, nil
}

// expectMember is before with the one change applied: the tree the edited
// document must decode to.
func expectMember(before map[string]any, path []string, value any, present bool) map[string]any {
	out := cloneTree(before)
	m := out
	for i, k := range path {
		last := i == len(path)-1
		if last {
			if present {
				nv, err := cfgfmt.Normalize(value)
				if err != nil {
					nv = value
				}
				m[k] = nv
			} else {
				delete(m, k)
			}
			break
		}
		next, ok := m[k].(map[string]any)
		if !ok {
			if !present {
				return out
			}
			next = map[string]any{}
			m[k] = next
		}
		m = next
	}
	return out
}

// cloneTree deep-copies the mappings of a decoded tree (leaves are shared;
// they are never mutated).
func cloneTree(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		if sub, ok := v.(map[string]any); ok {
			out[k] = cloneTree(sub)
			continue
		}
		out[k] = v
	}
	return out
}
