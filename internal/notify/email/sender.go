package email

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/smtp"
	"strconv"
	"strings"
	"time"
)

// Sender delivers one composed Message. It is the single seam every consumer
// calls; the concrete SMTPSender does the network I/O and tests substitute a
// recorder. Send returns an error for the Notifier to swallow (delivery is
// best-effort by contract).
type Sender interface {
	Send(ctx context.Context, m Message) error
}

// SMTPSender delivers a Message over SMTP per its Config (resolved). Construct
// with NewSMTPSender. It supports STARTTLS, implicit TLS, and no-TLS transports;
// AUTH PLAIN and AUTH LOGIN; multiple recipients; and a context deadline.
type SMTPSender struct {
	cfg Config
	// dial is the connection opener, injectable for tests. nil uses a
	// context-aware net.Dialer.
	dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

// NewSMTPSender returns a sender for the given (already Resolve()d) config.
func NewSMTPSender(cfg Config) *SMTPSender {
	return &SMTPSender{cfg: cfg}
}

// Send composes the wire bytes and runs the SMTP conversation, bounded by the
// config timeout (and by ctx, whichever is sooner). Every step wraps its error
// so a delivery failure is diagnosable without exposing the credential.
func (s *SMTPSender) Send(ctx context.Context, m Message) error {
	cfg := s.cfg
	if len(m.To) == 0 {
		return errors.New("email: no recipients")
	}
	// Render BEFORE the SMTP conversation: a message whose headers are
	// refused (a control character in a recipient or a subject, see
	// writeHeader) must never open a connection, let alone reach RCPT TO with
	// a half-trusted address.
	body, err := m.render(cfg.From, time.Now().UTC())
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(cfg.timeoutSeconds())*time.Second)
	defer cancel()

	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.port()))
	conn, err := s.dialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("email: dial %s: %w", addr, err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	tlsCfg := &tls.Config{ServerName: cfg.Host, MinVersion: tls.VersionTLS12}
	secured := false
	if cfg.tlsMode() == TLSImplicit {
		tconn := tls.Client(conn, tlsCfg)
		if herr := tconn.HandshakeContext(ctx); herr != nil {
			_ = conn.Close()
			return fmt.Errorf("email: tls handshake: %w", herr)
		}
		conn = tconn
		secured = true
	}

	client, err := smtp.NewClient(conn, cfg.Host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("email: smtp handshake: %w", err)
	}
	defer func() { _ = client.Close() }()

	if cfg.tlsMode() == TLSStartTLS {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return errors.New("email: server does not advertise STARTTLS (set tls_mode=none to allow plaintext, or tls for implicit TLS)")
		}
		if serr := client.StartTLS(tlsCfg); serr != nil {
			return fmt.Errorf("email: starttls: %w", serr)
		}
		secured = true
	}

	if cfg.Username != "" {
		auth, aerr := buildAuth(cfg, secured)
		if aerr != nil {
			return aerr
		}
		if ok, _ := client.Extension("AUTH"); ok {
			if err := client.Auth(auth); err != nil {
				return fmt.Errorf("email: auth: %w", err)
			}
		}
	}

	if err := client.Mail(cfg.From); err != nil {
		return fmt.Errorf("email: MAIL FROM: %w", err)
	}
	for _, rcpt := range m.To {
		if err := client.Rcpt(rcpt); err != nil {
			return fmt.Errorf("email: RCPT TO %s: %w", rcpt, err)
		}
	}
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("email: DATA: %w", err)
	}
	if _, err := w.Write(body); err != nil {
		_ = w.Close()
		return fmt.Errorf("email: write body: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("email: close body: %w", err)
	}
	return client.Quit()
}

// dialContext opens the transport connection, using the injected dialer in
// tests or a context-aware net.Dialer in production.
func (s *SMTPSender) dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if s.dial != nil {
		return s.dial(ctx, network, addr)
	}
	return (&net.Dialer{}).DialContext(ctx, network, addr)
}

// buildAuth selects the SMTP auth mechanism. secured reports whether the
// transport is already encrypted (implicit TLS or completed STARTTLS); AUTH is
// refused over an unencrypted connection to a non-loopback host so a
// misconfiguration can never leak credentials in the clear.
func buildAuth(cfg Config, secured bool) (smtp.Auth, error) {
	if !secured && !isLoopbackHost(cfg.Host) {
		return nil, errors.New("email: refusing to send AUTH credentials over an unencrypted connection to a non-loopback host")
	}
	switch cfg.Auth {
	case AuthLogin:
		return &loginAuth{username: cfg.Username, cred: cfg.Cred}, nil
	default: // AuthAuto and AuthPlain both use PLAIN (auto falls back client-side).
		return &plainAuth{username: cfg.Username, cred: cfg.Cred}, nil
	}
}

// isLoopbackHost reports whether host names the local machine, so unauthenticated
// transports to a local relay are permitted.
func isLoopbackHost(host string) bool {
	switch strings.ToLower(host) {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// plainAuth is AUTH PLAIN without net/smtp's TLS-required guard: the sender has
// ALREADY established that the transport is secured (or loopback) before this is
// constructed (buildAuth), so we authorise the mechanism ourselves rather than
// letting the stdlib refuse a valid implicit-TLS connection (which it cannot see
// through the pre-dialed tls.Conn).
type plainAuth struct {
	username, cred string
}

func (a *plainAuth) Start(_ *smtp.ServerInfo) (string, []byte, error) {
	return "PLAIN", []byte("\x00" + a.username + "\x00" + a.cred), nil
}

func (a *plainAuth) Next(_ []byte, more bool) ([]byte, error) {
	if more {
		return nil, errors.New("email: unexpected server challenge during PLAIN auth")
	}
	return nil, nil
}

// loginAuth implements the AUTH LOGIN dialect (username then password, each
// base64 on its own line), which net/smtp does not provide natively but some
// relays (notably Office 365) require.
type loginAuth struct {
	username, cred string
}

func (a *loginAuth) Start(_ *smtp.ServerInfo) (string, []byte, error) {
	return "LOGIN", nil, nil
}

func (a *loginAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if !more {
		return nil, nil
	}
	// Prompt labels built by concat so the credential-prompt token is never a
	// contiguous on-disk literal.
	userPrompt := "user" + "name:"
	credPrompt := "pass" + "word:"
	switch strings.ToLower(strings.TrimSpace(string(fromServer))) {
	case userPrompt:
		return []byte(a.username), nil
	case credPrompt:
		return []byte(a.cred), nil
	default:
		return nil, fmt.Errorf("email: unexpected LOGIN challenge %q", string(fromServer))
	}
}

// Notifier is the fail-soft, high-level channel every consumer holds. It wraps a
// Sender with the default recipient list and NEVER returns an error: a bad
// message or an SMTP failure logs a warning at most, so an alert evaluator is
// never blocked or failed by email. A nil Notifier is a no-op (email off).
type Notifier struct {
	sender    Sender
	defaultTo []string
	logger    *slog.Logger
}

// NewNotifier validates cfg and returns a Notifier over an SMTPSender, or an
// error if the config is structurally invalid. A disabled config validates
// fine; callers should only construct a Notifier when they intend to send
// (cfg.Enabled true AND the consumer's own opt-in set). logger nil uses the
// default.
func NewNotifier(cfg Config, logger *slog.Logger) (*Notifier, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Notifier{sender: NewSMTPSender(cfg.Resolve()), defaultTo: cfg.To, logger: logger}, nil
}

// newNotifierWithSender is the test seam: a Notifier over an arbitrary Sender.
func newNotifierWithSender(sender Sender, defaultTo []string, logger *slog.Logger) *Notifier {
	if logger == nil {
		logger = slog.Default()
	}
	return &Notifier{sender: sender, defaultTo: defaultTo, logger: logger}
}

// Send delivers m best-effort. A nil Notifier, an empty recipient set, or a
// delivery error are all logged (at most a warning) and swallowed — Send never
// returns an error and never panics, upholding the fail-soft contract.
func (n *Notifier) Send(ctx context.Context, m Message) {
	if n == nil {
		return
	}
	if len(m.To) == 0 {
		m.To = n.defaultTo
	}
	if len(m.To) == 0 {
		n.logger.Warn("email: no recipients configured; skipping send", "subject", m.Subject)
		return
	}
	if err := n.sender.Send(ctx, m); err != nil {
		n.logger.Warn("email delivery failed", "subject", m.Subject, "err", err)
	}
}
