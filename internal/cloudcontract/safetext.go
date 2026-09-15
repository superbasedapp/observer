package cloudcontract

import (
	"encoding/json"
	"fmt"
	"html"
	"net/url"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// SafeText is an OPAQUE result-derived text value (plan §6 CI-P4 / Sol SC7,
// FE1). Model output is untrusted data: enrichment titles/descriptions/tags are
// shown in terminals, embedded in JSON, written to logs, exported to CSV, and
// rendered in HTML. A single value type normalizes ONCE at construction and
// offers per-sink escaping contracts, so a hostile completion cannot smuggle a
// control sequence, a bidi override, a stored-XSS payload, a spreadsheet
// formula, or a forged log line downstream.
//
// The value is unexported, so a SafeText cannot be constructed with arbitrary
// bytes: the ONLY ways to obtain a non-zero SafeText are NormalizeText (which
// validates + NFC-normalizes) and UnmarshalJSON (which does the same on the way
// in). A restored/migrated row, an alternate constructor, a local test caller,
// or a future sink therefore cannot hold un-normalized text after a successful
// decode — the earlier "SafeText(string)" alias could.
//
// The purity pin is preserved: this file imports only stdlib plus
// golang.org/x/text/unicode/norm — a pure, non-I/O library already a direct
// module dependency. Go's stdlib has no Unicode normalization, and NFC is a
// hard requirement of the spec.
type SafeText struct {
	// v is the NFC-normalized, control/bidi-free value. Unexported: the zero
	// value is the empty string, and every other value has passed normalization.
	v string
}

// Disallowed bidirectional-formatting code points. The explicit isolates and
// embeddings/overrides (U+2066–2069, U+202A–202E) are the classic
// bidi-spoofing set (CVE-2021-42574 "Trojan Source"); the marks (LRM/RLM/ALM)
// are included for completeness. Rejecting them outright — rather than
// stripping — keeps the failure loud: a result carrying one is invalid.
func isBidiControl(r rune) bool {
	switch {
	case r >= 0x202A && r <= 0x202E: // LRE RLE PDF LRO RLO
		return true
	case r >= 0x2066 && r <= 0x2069: // LRI RLI FSI PDI
		return true
	case r == 0x200E || r == 0x200F: // LRM RLM
		return true
	case r == 0x061C: // ALM
		return true
	}
	return false
}

// isDisallowedControl reports C0 controls (U+0000–U+001F, including NUL, TAB,
// LF, CR, and ESC — the ANSI/OSC escape introducer), DEL (U+007F), and C1
// controls (U+0080–U+009F, including the single-byte CSI U+009B). ANSI and OSC
// terminal-escape sequences are introduced by ESC (0x1B) or the C1 CSI/OSC
// code points, so rejecting the whole control range neutralizes them at the
// source. Result text is single-value structured data — it needs no control
// characters at all.
func isDisallowedControl(r rune) bool {
	return r < 0x20 || r == 0x7F || (r >= 0x80 && r <= 0x9F)
}

// normalizeString is the field-independent half of the SafeText contract: it
// rejects invalid UTF-8, C0/C1/DEL controls (covers ANSI/OSC terminal escapes),
// and bidi controls, then NFC-normalizes (a documented canonical form so equal
// text has equal bytes and combining-character tricks collapse). It enforces NO
// byte/rune bound — the per-field cap lives in NormalizeText, which knows each
// field's max. `field` names the value in error messages.
func normalizeString(field, s string) (string, error) {
	if !utf8.ValidString(s) {
		return "", fmt.Errorf("cloudcontract: %s is not valid UTF-8", field)
	}
	// Reject disallowed code points on the RAW input first, so a payload that
	// NFC would fold away cannot slip through.
	for i, r := range s {
		if r == utf8.RuneError {
			return "", fmt.Errorf("cloudcontract: %s has an invalid rune at byte %d", field, i)
		}
		if isDisallowedControl(r) {
			return "", fmt.Errorf("cloudcontract: %s contains a control character U+%04X at byte %d", field, r, i)
		}
		if isBidiControl(r) {
			return "", fmt.Errorf("cloudcontract: %s contains a bidirectional-control character U+%04X at byte %d", field, r, i)
		}
	}
	normalized := norm.NFC.String(s)
	// NFC could in principle re-introduce a disallowed point via composition;
	// re-check the normalized form (defense in depth).
	for _, r := range normalized {
		if isDisallowedControl(r) || isBidiControl(r) {
			return "", fmt.Errorf("cloudcontract: %s normalizes to a disallowed control character", field)
		}
	}
	return normalized, nil
}

// NormalizeText is the ONE central validator/normalizer every result text field
// is run through (plan §6 CI-P4). It runs normalizeString (UTF-8/control/bidi/
// NFC) AND enforces a byte bound AND a rune bound (a grapheme-count proxy:
// every grapheme is at least one rune, so a rune cap bounds the visible length)
// on the NORMALIZED form, since NFC can change length. It returns the opaque
// SafeText, or an error naming the field and the specific violation.
// required=false permits an empty value (an optional field); required=true
// rejects it.
func NormalizeText(field, s string, maxBytes int, required bool) (SafeText, error) {
	if s == "" {
		if required {
			return SafeText{}, fmt.Errorf("cloudcontract.NormalizeText: %s is required", field)
		}
		return SafeText{}, nil
	}
	normalized, err := normalizeString("NormalizeText: "+field, s)
	if err != nil {
		return SafeText{}, err
	}
	if len(normalized) > maxBytes {
		return SafeText{}, fmt.Errorf("cloudcontract.NormalizeText: %s is %d bytes after normalization, exceeds max %d", field, len(normalized), maxBytes)
	}
	if rc := utf8.RuneCountInString(normalized); rc > maxBytes {
		return SafeText{}, fmt.Errorf("cloudcontract.NormalizeText: %s is %d runes, exceeds max %d", field, rc, maxBytes)
	}
	return SafeText{v: normalized}, nil
}

// MarshalJSON emits the value as a plain JSON string, so a SafeText is
// wire-identical to the string it wraps (the result JSON shape is unchanged).
func (t SafeText) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.v)
}

// UnmarshalJSON parses a JSON string and NORMALIZES + VALIDATES it on the way
// in (UTF-8/control/bidi/NFC), so a SafeText decoded from a hostile stored row
// or wire message can never hold un-normalized bytes. It does NOT apply a byte
// bound (that is per-field, enforced by the owning struct's Validate). A
// non-string JSON value (number, object, null-as-value) is rejected.
func (t *SafeText) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("cloudcontract.SafeText.UnmarshalJSON: %w", err)
	}
	if s == "" {
		t.v = ""
		return nil
	}
	normalized, err := normalizeString("SafeText.UnmarshalJSON", s)
	if err != nil {
		return err
	}
	t.v = normalized
	return nil
}

// String returns the raw normalized value. It is safe by construction for a
// plain-text sink (no controls, no bidi). For a specific sink use the
// per-context helpers below.
func (t SafeText) String() string { return t.v }

// Empty reports whether the value is the zero/empty SafeText.
func (t SafeText) Empty() bool { return t.v == "" }

// ForTerminal returns a value safe to print to an ANSI terminal. Controls and
// bidi are already rejected at construction, so this is documented as an
// identity for a SafeText — it exists as an explicit contract so a call site
// records WHICH sink it targets, and it stays correct if the accepted character
// set ever widens.
func (t SafeText) ForTerminal() string { return t.v }

// ForJSON returns a value that is marshal-safe by construction: encoding/json
// handles quoting/escaping, and a SafeText carries no control characters that
// would need special handling. Prefer marshaling the SafeText directly (its
// MarshalJSON emits the string); this helper documents the contract for callers
// that hand a bare string to a JSON encoder.
func (t SafeText) ForJSON() string { return t.v }

// ForLog returns a value safe to embed in a single log line. Newlines and
// carriage returns are already rejected at construction (a SafeText cannot
// contain them), so this collapses nothing in practice — but it is retained as
// a defensive contract against log forging, and remains correct if the
// character policy ever admits an in-line separator.
func (t SafeText) ForLog() string {
	r := strings.NewReplacer("\n", " ", "\r", " ")
	return r.Replace(t.v)
}

// ForCSV returns a value safe to write into a CSV/spreadsheet cell. A leading
// '=', '+', '-', '@', TAB, or CR causes Excel/Sheets to interpret the cell as
// a formula (CSV injection); prefixing a single quote neutralizes that.
func (t SafeText) ForCSV() string {
	if t.v == "" {
		return ""
	}
	switch t.v[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + t.v
	}
	return t.v
}

// ForHTMLText returns a value safe to render as an HTML TEXT node: '<', '>',
// '&', '"', and '\” are entity-escaped so a stored-XSS-shaped payload becomes
// inert text. (React default-escapes text nodes, but a server-side or non-React
// sink MUST call this — the contract exists so no sink renders raw model text.)
func (t SafeText) ForHTMLText() string { return html.EscapeString(t.v) }

// ForHTMLAttr returns a value safe to place inside a DOUBLE-QUOTED HTML
// attribute value. html.EscapeString escapes '"', '\”, '&', '<', and '>',
// which neutralizes attribute breakout in a quoted attribute. The attribute
// MUST be double-quoted at the sink; an unquoted attribute is never safe and
// this helper does not make it so.
func (t SafeText) ForHTMLAttr() string { return html.EscapeString(t.v) }

// ForURLQuery returns a value percent-encoded for use as a URL query-parameter
// value (url.QueryEscape). Use it whenever result text is placed into a URL, so
// a value cannot inject additional parameters or break out of the query.
func (t SafeText) ForURLQuery() string { return url.QueryEscape(t.v) }
