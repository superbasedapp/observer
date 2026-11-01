package orgcontract

import (
	"reflect"
	"strings"
	"unicode"
	"unicode/utf8"
)

// securitysecrets.go is ruling P-055 (lane SEC-E2 audit finding 4) as one
// pure gate over every security wire row: a secret value, and any 8 or more
// character piece of one, never reaches a wire row in any share mode. A node
// shipping raw content may carry a secret finding's rel_path and its
// evidence_redacted excerpt, but the excerpt is the scrubbed, masked form; a
// node without raw content ships neither (StripSecurityRaw), so a secret
// finding there is its fingerprint (finding_ref, evidence_hash) and its
// classes only.
//
// The detection is injected (CLAUDE.md rule 1): this package imports no
// scrubber. The node (internal/store/secorgrows.go) and the server
// (internal/orgserver/secorg) both pass internal/scrub's detector, so the
// one rule runs on both sides of the wire.

// SecuritySecretScan is the injected secret detector the gate runs.
type SecuritySecretScan struct {
	// Certain reports whether s holds a pattern-certain secret (a typed
	// detector, never the entropy heuristic).
	Certain func(s string) bool
	// Any reports whether s holds anything secret-shaped, the entropy
	// heuristic included.
	Any func(s string) bool
	// Mask returns s with every secret-shaped span replaced by a marker
	// that carries no part of the value.
	Mask func(s string) string
}

// GateSecuritySecrets applies P-055 to row, a pointer to a security wire
// row, after normalization and the raw strip. The redacted evidence is
// masked, its edge tokens dropped when it sits at the window cap (a clipped
// window can end in a piece of a secret no detector recognises), and
// cleared when anything secret-shaped survives; every other raw-class text
// (a path, a path alias, a reference) holding a certain secret is cleared,
// and an always-class text holding one drops the whole row (ok=false), since
// an always field ships in every mode. With a zero scan the gate refuses the
// row, so an unwired caller fails closed.
func GateSecuritySecrets(row any, scan SecuritySecretScan) bool {
	if scan.Certain == nil || scan.Any == nil || scan.Mask == nil {
		return false
	}
	v := reflect.ValueOf(row)
	if v.Kind() != reflect.Pointer || v.IsNil() || v.Elem().Kind() != reflect.Struct {
		return false
	}
	return gateSecretsValue(v.Elem(), SecurityWireAlways, "", scan)
}

func gateSecretsValue(v reflect.Value, class, name string, scan SecuritySecretScan) bool {
	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() {
			return true
		}
		return gateSecretsValue(v.Elem(), class, name, scan)
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			f := v.Type().Field(i)
			if !gateSecretsValue(v.Field(i), f.Tag.Get("wire"), f.Name, scan) {
				return false
			}
		}
		return true
	case reflect.String:
		s := v.String()
		if s == "" {
			return true
		}
		if class == SecurityWireRaw {
			v.SetString(gateRawText(name, s, scan))
			return true
		}
		return !scan.Certain(s)
	case reflect.Slice:
		if v.Type().Elem().Kind() != reflect.String {
			for i := 0; i < v.Len(); i++ {
				if !gateSecretsValue(v.Index(i), class, name, scan) {
					return false
				}
			}
			return true
		}
		return gateStringList(v, class, scan)
	}
	return true
}

// gateStringList keeps the elements of a string list that hold no certain
// secret; an always-class list holding one drops the row.
func gateStringList(v reflect.Value, class string, scan SecuritySecretScan) bool {
	kept := reflect.MakeSlice(v.Type(), 0, v.Len())
	for i := 0; i < v.Len(); i++ {
		if !scan.Certain(v.Index(i).String()) {
			kept = reflect.Append(kept, v.Index(i))
			continue
		}
		if class != SecurityWireRaw {
			return false
		}
	}
	switch {
	case kept.Len() == 0 && v.Len() > 0:
		v.Set(reflect.Zero(v.Type()))
	case kept.Len() != v.Len():
		v.Set(kept)
	}
	return true
}

// gateRawText is the raw-class text rule: the evidence excerpt is masked,
// everything else is kept or cleared.
func gateRawText(name, s string, scan SecuritySecretScan) string {
	if name != "EvidenceRedacted" {
		if scan.Certain(s) {
			return ""
		}
		return s
	}
	atCap := utf8.RuneCountInString(s) >= maxSecEvidence
	m := scan.Mask(s)
	if atCap {
		m = trimEdgeTokens(m)
	}
	m = secEvidence(m)
	if scan.Any(m) {
		return ""
	}
	return m
}

// trimEdgeTokens drops the first and the last whitespace-separated token of
// s (a clipped window's edges may be pieces of a longer value); a single
// token leaves nothing.
func trimEdgeTokens(s string) string {
	first := strings.IndexFunc(s, unicode.IsSpace)
	last := strings.LastIndexFunc(s, unicode.IsSpace)
	if first < 0 || first >= last {
		return ""
	}
	return strings.TrimSpace(s[first:last])
}
