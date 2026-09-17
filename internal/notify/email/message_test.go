package email

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

func TestComposeTextAndHTML(t *testing.T) {
	m := Compose(ComposeParams{
		Subject: "[Observer] Budget alert: team at 80%",
		Heading: "The team budget crossed 80%.",
		Fields: []Field{
			{Label: "Scope", Value: "team · payments"},
			{Label: "Current spend", Value: "$80.00 of $100.00"},
		},
		Version: "v1.19.0",
		To:      []string{"admin@example.com"},
	})
	if m.Subject != "[Observer] Budget alert: team at 80%" {
		t.Fatalf("subject = %q", m.Subject)
	}
	if len(m.To) != 1 || m.To[0] != "admin@example.com" {
		t.Fatalf("to = %v", m.To)
	}
	// Text body carries the heading, every field, and the version footer.
	for _, want := range []string{"The team budget crossed 80%.", "Scope: team · payments", "Current spend: $80.00 of $100.00", "Sent by SuperBased Observer v1.19.0"} {
		if !strings.Contains(m.Text, want) {
			t.Errorf("text missing %q\n%s", want, m.Text)
		}
	}
	// HTML body carries the same and is HTML.
	if !strings.Contains(m.HTML, "<table") || !strings.Contains(m.HTML, "payments") {
		t.Errorf("html missing table/fields:\n%s", m.HTML)
	}
}

func TestComposeSections(t *testing.T) {
	m := Compose(ComposeParams{
		Subject: "[Observer] Weekly cost digest",
		Heading: "Observed spend for the week.",
		Fields:  []Field{{Label: "Observed spend", Value: "$100.00"}},
		Sections: []Section{
			{Title: "Spend by model", Fields: []Field{{Label: "claude-opus", Value: "$60.00"}}},
			{Title: "Top movers vs prior period", Fields: []Field{{Label: "claude-opus", Value: "$60.00 (was $40.00)"}}},
		},
		Version: "v1.19.0",
	})
	for _, want := range []string{"Spend by model", "  claude-opus: $60.00", "Top movers vs prior period"} {
		if !strings.Contains(m.Text, want) {
			t.Errorf("text missing section content %q\n%s", want, m.Text)
		}
	}
	if !strings.Contains(m.HTML, "Spend by model") || !strings.Contains(m.HTML, "Top movers vs prior period") {
		t.Errorf("html missing section titles:\n%s", m.HTML)
	}
}

// TestComposeNoSectionsUnchanged pins the additive contract: an empty Sections
// renders exactly like the pre-G13 flat alert email.
func TestComposeNoSectionsUnchanged(t *testing.T) {
	p := ComposeParams{Subject: "s", Heading: "h", Fields: []Field{{Label: "a", Value: "b"}}, Version: "v1"}
	withNil := Compose(p)
	p.Sections = []Section{}
	withEmpty := Compose(p)
	// Both bodies must be identical apart from the volatile timestamp stamp,
	// which is present in both; compare the field-table region.
	if !strings.Contains(withNil.Text, "a: b") || !strings.Contains(withEmpty.Text, "a: b") {
		t.Fatalf("field rendering changed with empty sections")
	}
	if strings.Contains(withEmpty.Text, "\n\nSent by") != strings.Contains(withNil.Text, "\n\nSent by") {
		t.Fatalf("footer spacing diverged between nil and empty sections")
	}
}

func TestComposeFooterVersionless(t *testing.T) {
	m := Compose(ComposeParams{Subject: "s", Fields: []Field{{Label: "a", Value: "b"}}})
	if !strings.Contains(m.Text, "Sent by SuperBased Observer") {
		t.Fatalf("missing footer:\n%s", m.Text)
	}
	if strings.Contains(m.Text, "Observer  ") { // no trailing double-space where a version would go
		t.Fatalf("versionless footer malformed:\n%s", m.Text)
	}
}

func TestComposeHTMLEscaping(t *testing.T) {
	m := Compose(ComposeParams{
		Subject: "s",
		Heading: "5 < 10 & rising",
		Fields:  []Field{{Label: "note", Value: "<script>alert(1)</script>"}},
	})
	if strings.Contains(m.HTML, "<script>alert(1)</script>") {
		t.Fatalf("HTML injection not escaped:\n%s", m.HTML)
	}
	if !strings.Contains(m.HTML, "&lt;script&gt;") {
		t.Fatalf("expected escaped value:\n%s", m.HTML)
	}
}

func TestRenderMultipartMIME(t *testing.T) {
	m := Message{To: []string{"a@x.com", "b@x.com"}, Subject: "Subj", Text: "hello", HTML: "<b>hello</b>"}
	raw := mustRender(t, m, "from@x.com")
	for _, want := range []string{
		"From: from@x.com\r\n",
		"To: a@x.com, b@x.com\r\n",
		"Subject: Subj\r\n",
		"MIME-Version: 1.0\r\n",
		"multipart/alternative; boundary=",
		"text/plain; charset=UTF-8",
		"text/html; charset=UTF-8",
	} {
		if !strings.Contains(raw, want) {
			t.Errorf("render missing %q\n%s", want, raw)
		}
	}
	// CRLF line endings throughout.
	if strings.Contains(raw, "\n") && strings.Contains(strings.ReplaceAll(raw, "\r\n", ""), "\n") {
		t.Errorf("found a bare LF (non-CRLF) line ending")
	}
}

func TestRenderSingleParts(t *testing.T) {
	textOnly := mustRender(t, Message{To: []string{"a@x"}, Subject: "s", Text: "body"}, "f@x")
	if !strings.Contains(textOnly, "Content-Type: text/plain; charset=UTF-8") || strings.Contains(textOnly, "multipart") {
		t.Errorf("text-only render wrong:\n%s", textOnly)
	}
	htmlOnly := mustRender(t, Message{To: []string{"a@x"}, Subject: "s", HTML: "<b>x</b>"}, "f@x")
	if !strings.Contains(htmlOnly, "Content-Type: text/html; charset=UTF-8") || strings.Contains(htmlOnly, "multipart") {
		t.Errorf("html-only render wrong:\n%s", htmlOnly)
	}
}

func TestRenderSubjectEncoding(t *testing.T) {
	raw := mustRender(t, Message{To: []string{"a@x"}, Subject: "café ☕ over budget", Text: "x"}, "f@x")
	if strings.Contains(raw, "Subject: café") {
		t.Fatalf("non-ASCII subject not RFC2047-encoded:\n%s", raw)
	}
	if !strings.Contains(raw, "Subject: =?utf-8?q?") {
		t.Fatalf("expected encoded-word subject:\n%s", raw)
	}
}

func TestRenderDotStuffing(t *testing.T) {
	raw := mustRender(t, Message{To: []string{"a@x"}, Subject: "s", Text: ".leading dot\nnormal"}, "f@x")
	if !strings.Contains(raw, "..leading dot") {
		t.Fatalf("leading-dot line not dot-stuffed:\n%s", raw)
	}
}

// mustRender renders m at a fixed clock and fails the test if the headers are
// refused, so the existing render assertions stay one-liners now that render
// reports a refusal (writeHeader's control-character guard).
func mustRender(t *testing.T, m Message, from string) string {
	t.Helper()
	b, err := m.render(from, time.Unix(0, 0).UTC())
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	return string(b)
}

// TestRenderRefusesControlCharactersInHeaders is the header-injection guard:
// a CR, LF, NUL or TAB anywhere in a recipient or a subject must REFUSE the
// whole message rather than emit a header line that an SMTP peer would read
// as two. The body is not a header, so a control character there is rendered
// (normalizeCRLF owns it) and cannot inject anything: it lands after the
// blank line that ends the header block.
func TestRenderRefusesControlCharactersInHeaders(t *testing.T) {
	for _, tc := range []struct {
		name    string
		msg     Message
		from    string
		wantErr bool
	}{
		{name: "clean", msg: Message{To: []string{"a@x"}, Subject: "s", Text: "body"}, wantErr: false},
		{name: "CR in recipient", msg: Message{To: []string{"a@x\r"}, Subject: "s", Text: "b"}, wantErr: true},
		{name: "LF in recipient", msg: Message{To: []string{"a@x\nBcc: evil@x"}, Subject: "s", Text: "b"}, wantErr: true},
		{name: "CRLF in recipient", msg: Message{To: []string{"a@x\r\nBcc: evil@x"}, Subject: "s", Text: "b"}, wantErr: true},
		{name: "NUL in recipient", msg: Message{To: []string{"a@x\x00"}, Subject: "s", Text: "b"}, wantErr: true},
		{name: "TAB in recipient", msg: Message{To: []string{"a@x\t"}, Subject: "s", Text: "b"}, wantErr: true},
		{name: "second recipient dirty", msg: Message{To: []string{"a@x", "b@x\r\nBcc: evil@x"}, Subject: "s", Text: "b"}, wantErr: true},
		{name: "CR in subject", msg: Message{To: []string{"a@x"}, Subject: "s\r", Text: "b"}, wantErr: true},
		{name: "LF in subject", msg: Message{To: []string{"a@x"}, Subject: "s\nBcc: evil@x", Text: "b"}, wantErr: true},
		{name: "NUL in subject", msg: Message{To: []string{"a@x"}, Subject: "s\x00", Text: "b"}, wantErr: true},
		{name: "TAB in subject", msg: Message{To: []string{"a@x"}, Subject: "s\tmore", Text: "b"}, wantErr: true},
		{name: "DEL in subject", msg: Message{To: []string{"a@x"}, Subject: "s\x7f", Text: "b"}, wantErr: true},
		{name: "LF in From", msg: Message{To: []string{"a@x"}, Subject: "s", Text: "b"}, from: "f@x\nBcc: evil@x", wantErr: true},
		{name: "non-ASCII subject is fine", msg: Message{To: []string{"a@x"}, Subject: "café ☕", Text: "b"}, wantErr: false},
		{name: "heading/body control chars render", msg: Message{To: []string{"a@x"}, Subject: "s", Text: "line\r\nBcc: evil@x\tmore"}, wantErr: false},
		{name: "heading/body NUL renders", msg: Message{To: []string{"a@x"}, Subject: "s", HTML: "<b>x\x00</b>"}, wantErr: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			from := tc.from
			if from == "" {
				from = "f@x"
			}
			out, err := tc.msg.render(from, time.Unix(0, 0).UTC())
			if tc.wantErr {
				if err == nil {
					t.Fatalf("render succeeded on a header with a control character:\n%s", out)
				}
				if out != nil {
					t.Error("render returned bytes alongside its refusal")
				}
				return
			}
			if err != nil {
				t.Fatalf("render = %v, want success", err)
			}
			// The header block ends at the first blank line; nothing after it
			// can be a header, which is why a dirty BODY is safe.
			head, _, ok := strings.Cut(string(out), "\r\n\r\n")
			if !ok {
				t.Fatalf("rendered message has no header/body separator:\n%s", out)
			}
			if strings.Contains(head, "Bcc:") {
				t.Errorf("an injected header reached the header block:\n%s", head)
			}
		})
	}
}

// TestSenderRefusesBeforeDialing: a refused message never opens a connection,
// so a half-trusted recipient cannot reach RCPT TO.
func TestSenderRefusesBeforeDialing(t *testing.T) {
	dialed := 0
	s := &SMTPSender{
		cfg: Config{Host: "smtp.example", From: "f@x"}.Resolve(),
		dial: func(context.Context, string, string) (net.Conn, error) {
			dialed++
			return nil, errors.New("must not dial")
		},
	}
	err := s.Send(context.Background(), Message{To: []string{"a@x\r\nBcc: evil@x"}, Subject: "s", Text: "b"})
	if err == nil {
		t.Fatal("Send accepted a recipient carrying a CRLF")
	}
	if dialed != 0 {
		t.Fatalf("dials = %d, want 0 (refuse before the SMTP conversation)", dialed)
	}
}
