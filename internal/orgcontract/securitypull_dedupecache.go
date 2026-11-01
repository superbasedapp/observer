package orgcontract

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// securitypull_dedupecache.go keeps the org's finding dedupe key out of the
// node's managed pull cache (lane LEFT-SHARED merge audit finding 4). The
// cache stores the whole signed document and re-verifies it on every load,
// so the key cannot simply be dropped: StripSecurityOrgDedupeKey blanks the
// key's string value in place, byte for byte everywhere else, before the
// document is cached, and RestoreSecurityOrgDedupeKey puts the key the node
// holds in its owner-only key file back at the same place on load, before
// the signature is checked. A key that is not held (no file, another
// version) leaves the cached document unverifiable, so the node simply asks
// the server again (no conditional request without a verified document).

// ErrSecurityOrgDedupeNotHeld is a cached body whose org_dedupe key the node
// does not hold at the body's version.
var ErrSecurityOrgDedupeNotHeld = errors.New("orgcontract: the org dedupe key of a cached security pull is not held")

// securityOrgDedupeSpan locates the served org_dedupe object in a security
// pull body: its version and the byte span [start, end) of its key's JSON
// string value, quotes included. found is false for a body with no
// org_dedupe (or one that is not an object); a body that is not JSON, or an
// org_dedupe that is not {version, key}, or one named twice, is an error.
func securityOrgDedupeSpan(body []byte) (version int64, start, end int, found bool, err error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		if len(bytes.TrimSpace(body)) == 0 {
			return 0, 0, 0, false, nil
		}
		return 0, 0, 0, false, err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return 0, 0, 0, false, nil
	}
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return 0, 0, 0, false, err
		}
		if k, _ := kt.(string); k != "org_dedupe" {
			var skip json.RawMessage
			if err := dec.Decode(&skip); err != nil {
				return 0, 0, 0, false, err
			}
			continue
		}
		if found {
			return 0, 0, 0, false, errors.New("org_dedupe named twice")
		}
		if t, err := dec.Token(); err != nil || t != json.Delim('{') {
			return 0, 0, 0, false, errors.New("org_dedupe is not an object")
		}
		haveKey, haveVersion := false, false
		for dec.More() {
			ft, err := dec.Token()
			if err != nil {
				return 0, 0, 0, false, err
			}
			switch f, _ := ft.(string); f {
			case "key":
				after := int(dec.InputOffset())
				vt, err := dec.Token()
				if _, ok := vt.(string); err != nil || !ok || haveKey {
					return 0, 0, 0, false, errors.New("org_dedupe.key is not one string")
				}
				end = int(dec.InputOffset())
				q := bytes.IndexByte(body[after:end], '"')
				if q < 0 {
					return 0, 0, 0, false, errors.New("org_dedupe.key has no opening quote")
				}
				start, haveKey = after+q, true
			case "version":
				vt, err := dec.Token()
				n, ok := vt.(json.Number)
				if err != nil || !ok || haveVersion {
					return 0, 0, 0, false, errors.New("org_dedupe.version is not one number")
				}
				if version, err = n.Int64(); err != nil {
					return 0, 0, 0, false, err
				}
				haveVersion = true
			default:
				var skip json.RawMessage
				if err := dec.Decode(&skip); err != nil {
					return 0, 0, 0, false, err
				}
			}
		}
		if _, err := dec.Token(); err != nil {
			return 0, 0, 0, false, err
		}
		if !haveKey || !haveVersion {
			return 0, 0, 0, false, errors.New("org_dedupe needs a version and a key")
		}
		found = true
	}
	return version, start, end, found, nil
}

// splice returns body with [start, end) replaced by with.
func splice(body []byte, start, end int, with []byte) []byte {
	out := make([]byte, 0, len(body)-(end-start)+len(with))
	out = append(out, body[:start]...)
	out = append(out, with...)
	return append(out, body[end:]...)
}

// StripSecurityOrgDedupeKey returns a security pull body with its served
// org_dedupe key value replaced by the empty string, every other byte
// unchanged; a body with no org_dedupe comes back as it is.
func StripSecurityOrgDedupeKey(body []byte) ([]byte, error) {
	_, start, end, found, err := securityOrgDedupeSpan(body)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSecurityManagedPolicy, err)
	}
	if !found {
		return body, nil
	}
	return splice(body, start, end, []byte(`""`)), nil
}

// RestoreSecurityOrgDedupeKey puts back the key a stripped body lost, from
// held (the node's key file): the held key's version must equal the body's
// org_dedupe version, else ErrSecurityOrgDedupeNotHeld. A body with no
// org_dedupe, or whose key was never stripped, comes back as it is.
func RestoreSecurityOrgDedupeKey(body []byte, held func() (SecurityOrgDedupe, bool)) ([]byte, error) {
	version, start, end, found, err := securityOrgDedupeSpan(body)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSecurityManagedPolicy, err)
	}
	if !found || string(body[start:end]) != `""` {
		return body, nil
	}
	var d SecurityOrgDedupe
	ok := false
	if held != nil {
		d, ok = held()
	}
	if !ok || d.Version != version {
		return nil, ErrSecurityOrgDedupeNotHeld
	}
	if _, err := d.KeyBytes(); err != nil {
		return nil, err
	}
	q, err := json.Marshal(d.Key)
	if err != nil {
		return nil, err
	}
	return splice(body, start, end, q), nil
}
