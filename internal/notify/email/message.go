package email

import (
	"fmt"
	"html"
	"mime"
	"strings"
	"time"
)

// Field is one labelled value rendered into an alert email body. Fields carry
// only labels + bounded values (a scope name, a percentage, a metric) — never
// raw request/response content, mirroring the webhook payload's content-bounded
// posture.
type Field struct {
	Label string
	Value string
}

// Section is an OPTIONAL titled group of Fields rendered below the top-level
// field table. It exists so a multi-part body (the scheduled report digests,
// gap-register G13 — "spend by model", "top movers", …) can compose through the
// SAME seam as a flat alert email. A ComposeParams with no Sections renders
// byte-identically to the pre-G13 alert path.
type Section struct {
	Title  string
	Fields []Field
}

// Message is a composed, transport-ready email: the recipient list plus the
// subject and both body representations. It is produced by Compose and consumed
// by a Sender. To may be empty, in which case the Notifier fills the [email].to
// defaults before sending.
type Message struct {
	To      []string
	Subject string
	Text    string
	HTML    string
}

// ComposeParams is the input to Compose: everything needed to render an alert
// email from the SAME payload a consumer sends to its webhook. Keeping this a
// plain value (labels + bounded strings) lets every evaluator reuse the
// composer, and lets the future scheduled digests (gap-register G13) compose
// through the same seam.
type ComposeParams struct {
	// Subject is the full subject line (the caller applies the "[Observer] …"
	// convention).
	Subject string
	// Heading is a one-line human summary shown above the field table.
	Heading string
	// Fields are the labelled values (rendered as a text block and an HTML
	// table).
	Fields []Field
	// Sections are OPTIONAL titled sub-tables rendered below Fields, in order.
	// Empty leaves the body identical to a flat alert email (the digests use
	// them; the alert consumers do not).
	Sections []Section
	// Version is the Observer version stamped into the footer. Empty renders a
	// version-less footer.
	Version string
	// To overrides the recipient list. Empty leaves Message.To nil so the
	// Notifier applies the configured defaults.
	To []string
}

// footer is the shared sign-off line appended to every composed email.
func footer(version string) string {
	if strings.TrimSpace(version) == "" {
		return "Sent by SuperBased Observer"
	}
	return "Sent by SuperBased Observer " + version
}

// Compose renders a Message (plaintext + HTML) from an alert payload. It is
// PURE: no I/O, no clock read beyond the timestamp it stamps into the bodies.
// Composition is deliberately separate from delivery so the same call backs
// both the alert channel and the future report digests.
func Compose(p ComposeParams) Message {
	stamp := time.Now().UTC().Format(time.RFC3339)

	var text strings.Builder
	if p.Heading != "" {
		text.WriteString(p.Heading)
		text.WriteString("\n\n")
	}
	for _, f := range p.Fields {
		fmt.Fprintf(&text, "%s: %s\n", f.Label, f.Value)
	}
	for _, s := range p.Sections {
		text.WriteString("\n")
		text.WriteString(s.Title)
		text.WriteString("\n")
		for _, f := range s.Fields {
			fmt.Fprintf(&text, "  %s: %s\n", f.Label, f.Value)
		}
	}
	text.WriteString("\n")
	text.WriteString(footer(p.Version))
	text.WriteString(" · ")
	text.WriteString(stamp)
	text.WriteString("\n")

	var htmlB strings.Builder
	htmlB.WriteString(`<div style="font-family:-apple-system,Segoe UI,Helvetica,Arial,sans-serif;font-size:14px;color:#1a1a1a">`)
	if p.Heading != "" {
		fmt.Fprintf(&htmlB, `<p style="font-size:15px;font-weight:600;margin:0 0 12px">%s</p>`, html.EscapeString(p.Heading))
	}
	htmlB.WriteString(`<table cellpadding="4" style="border-collapse:collapse">`)
	for _, f := range p.Fields {
		fmt.Fprintf(&htmlB,
			`<tr><td style="color:#666;padding-right:12px;vertical-align:top">%s</td><td style="font-weight:500">%s</td></tr>`,
			html.EscapeString(f.Label), html.EscapeString(f.Value))
	}
	htmlB.WriteString(`</table>`)
	for _, s := range p.Sections {
		fmt.Fprintf(&htmlB, `<p style="font-size:14px;font-weight:600;margin:18px 0 6px">%s</p>`, html.EscapeString(s.Title))
		htmlB.WriteString(`<table cellpadding="4" style="border-collapse:collapse">`)
		for _, f := range s.Fields {
			fmt.Fprintf(&htmlB,
				`<tr><td style="color:#666;padding-right:12px;vertical-align:top">%s</td><td style="font-weight:500">%s</td></tr>`,
				html.EscapeString(f.Label), html.EscapeString(f.Value))
		}
		htmlB.WriteString(`</table>`)
	}
	fmt.Fprintf(&htmlB,
		`<p style="color:#999;font-size:12px;margin:16px 0 0">%s · %s</p></div>`,
		html.EscapeString(footer(p.Version)), stamp)

	return Message{To: p.To, Subject: p.Subject, Text: text.String(), HTML: htmlB.String()}
}

// render builds the RFC 5322 wire bytes for m sent from the given address. When
// both Text and HTML are present it emits a multipart/alternative body; a
// single representation is emitted directly. Line endings are CRLF as SMTP
// requires. from is the header/envelope From. now is injectable for tests.
func (m Message) render(from string, now time.Time) ([]byte, error) {
	var b strings.Builder
	if err := writeHeader(&b, "From", from); err != nil {
		return nil, err
	}
	if err := writeHeader(&b, "To", strings.Join(m.To, ", ")); err != nil {
		return nil, err
	}
	if err := writeHeader(&b, "Subject", encodeHeaderWord(m.Subject)); err != nil {
		return nil, err
	}
	if err := writeHeader(&b, "Date", now.Format(time.RFC1123Z)); err != nil {
		return nil, err
	}
	if err := writeHeader(&b, "MIME-Version", "1.0"); err != nil {
		return nil, err
	}

	hasText := strings.TrimSpace(m.Text) != ""
	hasHTML := strings.TrimSpace(m.HTML) != ""

	switch {
	case hasText && hasHTML:
		boundary := "sbo-boundary-" + fmt.Sprintf("%d", now.UnixNano())
		if err := writeHeader(&b, "Content-Type", `multipart/alternative; boundary="`+boundary+`"`); err != nil {
			return nil, err
		}
		b.WriteString("\r\n")
		if err := writePart(&b, boundary, "text/plain; charset=UTF-8", m.Text); err != nil {
			return nil, err
		}
		if err := writePart(&b, boundary, "text/html; charset=UTF-8", m.HTML); err != nil {
			return nil, err
		}
		b.WriteString("--")
		b.WriteString(boundary)
		b.WriteString("--\r\n")
	case hasHTML:
		if err := writeHeader(&b, "Content-Type", "text/html; charset=UTF-8"); err != nil {
			return nil, err
		}
		b.WriteString("\r\n")
		b.WriteString(normalizeCRLF(m.HTML))
		b.WriteString("\r\n")
	default:
		if err := writeHeader(&b, "Content-Type", "text/plain; charset=UTF-8"); err != nil {
			return nil, err
		}
		b.WriteString("\r\n")
		b.WriteString(normalizeCRLF(m.Text))
		b.WriteString("\r\n")
	}
	return []byte(b.String()), nil
}

// writeHeader writes one "Key: value\r\n" header line, or REFUSES.
//
// A header field is one line by definition, so a control character in a key
// or value is never legitimate and always dangerous: a CR or LF would end the
// field and let the rest of the value be read as another header (an injected
// Bcc:, or a premature blank line that turns the remainder into body). NUL and
// the other C0 codes plus DEL have no meaning in a field either, and a TAB is
// only meaningful as folding whitespace, which nothing here emits.
//
// The refusal is structural rather than sanitising: silently stripping would
// deliver a message whose recipient or subject is not the one the caller
// asked for. Callers upstream should validate their own inputs; this is the
// last line, and it fails closed.
//
// Nothing written to b before the refusal matters: every caller discards the
// builder on error.
func writeHeader(b *strings.Builder, key, value string) error {
	if i := indexControlChar(key); i >= 0 {
		return fmt.Errorf("email: header name %q contains a control character at byte %d", key, i)
	}
	if i := indexControlChar(value); i >= 0 {
		// The value is NOT echoed: it may carry the injection payload, and a
		// header value can be a recipient address. The name and offset are
		// enough to diagnose.
		return fmt.Errorf("email: header %s value contains a control character at byte %d", key, i)
	}
	b.WriteString(key)
	b.WriteString(": ")
	b.WriteString(value)
	b.WriteString("\r\n")
	return nil
}

// indexControlChar returns the byte offset of the first C0 control character
// (anything below 0x20, including CR, LF and TAB) or DEL (0x7F) in s, or -1.
// It scans BYTES, not runes: a control character is a single byte in UTF-8 and
// can never be part of a multi-byte sequence, so this cannot false-positive on
// non-ASCII text.
func indexControlChar(s string) int {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7F {
			return i
		}
	}
	return -1
}

// writePart writes one multipart section with its own Content-Type.
func writePart(b *strings.Builder, boundary, contentType, body string) error {
	b.WriteString("--")
	b.WriteString(boundary)
	b.WriteString("\r\n")
	if err := writeHeader(b, "Content-Type", contentType); err != nil {
		return err
	}
	b.WriteString("\r\n")
	b.WriteString(normalizeCRLF(body))
	b.WriteString("\r\n")
	return nil
}

// encodeHeaderWord RFC 2047-encodes a header value when it contains non-ASCII,
// so a UTF-8 subject survives transit. Pure ASCII passes through untouched.
func encodeHeaderWord(s string) string {
	for _, r := range s {
		if r > 127 {
			return mime.QEncoding.Encode("utf-8", s)
		}
	}
	return s
}

// normalizeCRLF ensures every line ending is CRLF (SMTP DATA requires it) and
// dot-stuffs any line that begins with a '.' so a body line can never be read
// as the end-of-data marker.
func normalizeCRLF(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	lines := strings.Split(s, "\n")
	for i, ln := range lines {
		if strings.HasPrefix(ln, ".") {
			lines[i] = "." + ln
		}
	}
	return strings.Join(lines, "\r\n")
}
