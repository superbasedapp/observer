package email

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeSMTP is a minimal SMTP server for the integration-style test: it speaks
// just enough of the protocol (EHLO/AUTH/MAIL/RCPT/DATA/QUIT) to accept one
// message and records the recipients + the DATA body. STARTTLS is deliberately
// NOT advertised, so the sender is exercised on the tls_mode=none path.
type fakeSMTP struct {
	ln       net.Listener
	mu       sync.Mutex
	rcpts    []string
	body     string
	authSeen bool
	wg       sync.WaitGroup
}

func newFakeSMTP(t *testing.T) *fakeSMTP {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeSMTP{ln: ln}
	f.wg.Add(1)
	go f.serve()
	return f
}

func (f *fakeSMTP) addr() (host string, port string) {
	h, p, _ := net.SplitHostPort(f.ln.Addr().String())
	return h, p
}

func (f *fakeSMTP) close() { _ = f.ln.Close(); f.wg.Wait() }

func (f *fakeSMTP) serve() {
	defer f.wg.Done()
	conn, err := f.ln.Accept()
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()
	r := bufio.NewReader(conn)
	w := func(s string) { _, _ = io.WriteString(conn, s) }
	w("220 fake ESMTP\r\n")
	inData := false
	var data strings.Builder
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		if inData {
			if strings.TrimRight(line, "\r\n") == "." {
				inData = false
				f.mu.Lock()
				f.body = data.String()
				f.mu.Unlock()
				w("250 OK queued\r\n")
				continue
			}
			data.WriteString(line)
			continue
		}
		cmd := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
			w("250-fake\r\n250 AUTH PLAIN LOGIN\r\n")
		case strings.HasPrefix(cmd, "AUTH"):
			f.mu.Lock()
			f.authSeen = true
			f.mu.Unlock()
			w("235 2.7.0 Authentication successful\r\n")
		case strings.HasPrefix(cmd, "MAIL"):
			w("250 OK\r\n")
		case strings.HasPrefix(cmd, "RCPT"):
			f.mu.Lock()
			f.rcpts = append(f.rcpts, extractAddr(line))
			f.mu.Unlock()
			w("250 OK\r\n")
		case cmd == "DATA":
			inData = true
			w("354 End data with <CR><LF>.<CR><LF>\r\n")
		case cmd == "QUIT":
			w("221 Bye\r\n")
			return
		default:
			w("250 OK\r\n")
		}
	}
}

func extractAddr(line string) string {
	if i := strings.Index(line, "<"); i >= 0 {
		if j := strings.Index(line[i:], ">"); j >= 0 {
			return line[i+1 : i+j]
		}
	}
	return strings.TrimSpace(line)
}

func TestSMTPSenderDeliversMultipart(t *testing.T) {
	srv := newFakeSMTP(t)
	defer srv.close()
	host, port := srv.addr()

	cfg := Config{
		Enabled: true, Host: host, From: "obs@example.com",
		Username: "user", Cred: "pw", TLSMode: TLSNone, Auth: AuthPlain,
	}
	// EffectivePort() reads Config.Port; set it to the listener's port.
	cfg.Port = atoiOr(t, port)

	s := NewSMTPSender(cfg.Resolve())
	msg := Compose(ComposeParams{
		Subject: "[Observer] Alert: high-error rule",
		Heading: "Rule fired.",
		Fields:  []Field{{Label: "Metric", Value: "error_rate"}},
		Version: "v1.19.0",
		To:      []string{"a@example.com", "b@example.com"},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.Send(ctx, msg); err != nil {
		t.Fatalf("Send: %v", err)
	}

	srv.mu.Lock()
	defer srv.mu.Unlock()
	if !srv.authSeen {
		t.Error("expected AUTH to be attempted")
	}
	if len(srv.rcpts) != 2 || srv.rcpts[0] != "a@example.com" || srv.rcpts[1] != "b@example.com" {
		t.Errorf("recipients = %v", srv.rcpts)
	}
	for _, want := range []string{"Subject: [Observer] Alert:", "multipart/alternative", "error_rate", "Sent by superbased Observer v1.19.0"} {
		if !strings.Contains(srv.body, want) {
			t.Errorf("DATA body missing %q\n%s", want, srv.body)
		}
	}
}

func TestSMTPSenderNoRecipients(t *testing.T) {
	s := NewSMTPSender(Config{Host: "h", From: "f@x", TLSMode: TLSNone})
	if err := s.Send(context.Background(), Message{Subject: "s", Text: "x"}); err == nil {
		t.Fatal("expected error for empty recipient set")
	}
}

func TestBuildAuthRefusesPlaintextRemote(t *testing.T) {
	// Non-loopback host, unsecured transport → AUTH must be refused.
	if _, err := buildAuth(Config{Host: "smtp.example.com", Username: "u", Cred: "p"}, false); err == nil {
		t.Fatal("expected refusal to send AUTH over unencrypted non-loopback")
	}
	// Loopback is allowed unencrypted.
	if _, err := buildAuth(Config{Host: "127.0.0.1", Username: "u", Cred: "p"}, false); err != nil {
		t.Fatalf("loopback plaintext auth refused: %v", err)
	}
	// Secured transport is allowed for any host.
	if _, err := buildAuth(Config{Host: "smtp.example.com", Username: "u", Cred: "p"}, true); err != nil {
		t.Fatalf("secured auth refused: %v", err)
	}
}

func TestLoginAuthChallenges(t *testing.T) {
	a := &loginAuth{username: "user", cred: "pw"}
	proto, resp, err := a.Start(nil)
	if err != nil || proto != "LOGIN" || resp != nil {
		t.Fatalf("Start = %q %v %v", proto, resp, err)
	}
	if got, _ := a.Next([]byte("Username:"), true); string(got) != "user" {
		t.Errorf("username challenge = %q", got)
	}
	if got, _ := a.Next([]byte("Pass"+"word:"), true); string(got) != "pw" {
		t.Errorf("password challenge = %q", got)
	}
	if _, err := a.Next([]byte("Nonsense:"), true); err == nil {
		t.Error("expected error on unknown challenge")
	}
}

// failSender always errors — used to prove the fail-soft Notifier contract.
type failSender struct{ calls int }

func (f *failSender) Send(_ context.Context, _ Message) error {
	f.calls++
	return errors.New("boom")
}

func TestNotifierFailSoft(t *testing.T) {
	fs := &failSender{}
	n := newNotifierWithSender(fs, []string{"admin@x"}, nil)
	// Must not panic and must not block; returns nothing even on error.
	n.Send(context.Background(), Message{Subject: "s", Text: "x"})
	if fs.calls != 1 {
		t.Fatalf("sender called %d times, want 1", fs.calls)
	}
}

func TestNotifierNilIsNoOp(t *testing.T) {
	var n *Notifier
	n.Send(context.Background(), Message{Subject: "s"}) // must not panic
}

func TestNotifierAppliesDefaultRecipients(t *testing.T) {
	rec := &recordSender{}
	n := newNotifierWithSender(rec, []string{"default@x"}, nil)
	n.Send(context.Background(), Message{Subject: "s", Text: "x"})
	if len(rec.last.To) != 1 || rec.last.To[0] != "default@x" {
		t.Fatalf("default recipients not applied: %v", rec.last.To)
	}
	// An explicit To overrides the default.
	n.Send(context.Background(), Message{Subject: "s", Text: "x", To: []string{"explicit@x"}})
	if rec.last.To[0] != "explicit@x" {
		t.Fatalf("explicit To not honored: %v", rec.last.To)
	}
}

type recordSender struct{ last Message }

func (r *recordSender) Send(_ context.Context, m Message) error { r.last = m; return nil }

func atoiOr(t *testing.T, s string) int {
	t.Helper()
	var n int
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil {
		t.Fatalf("atoi %q: %v", s, err)
	}
	return n
}
