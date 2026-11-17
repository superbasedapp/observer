package email

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
)

// recordingSender counts sends and remembers the last message.
type recordingSender struct {
	mu   sync.Mutex
	sent []Message
	err  error
}

func (r *recordingSender) Send(_ context.Context, m Message) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sent = append(r.sent, m)
	return r.err
}

func (r *recordingSender) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.sent)
}

func usableConfig() Config {
	return Config{Enabled: true, Host: "smtp.example.test", From: "observer@example.test"}
}

// TestStatusOfTable pins one case per row of statusRules (W14-D7: unset is
// "not configured", never an error at start).
func TestStatusOfTable(t *testing.T) {
	with := func(mut func(*Config)) Config { c := usableConfig(); mut(&c); return c }
	cases := []struct {
		name       string
		cfg        Config
		rule       string
		configured bool
	}{
		{"disabled", Config{}, StatusRuleDisabled, false},
		{"host_unset", with(func(c *Config) { c.Host = " " }), StatusRuleHostUnset, false},
		{"from_unset", with(func(c *Config) { c.From = "" }), StatusRuleFromUnset, false},
		{"invalid", with(func(c *Config) { c.TLSMode = "bogus" }), StatusRuleInvalid, false},
		{"configured", usableConfig(), StatusRuleConfigured, true},
	}
	if got := StatusRuleNames(); len(got) != len(cases) {
		t.Fatalf("status rules = %v, want one case per row", got)
	}
	for i, c := range cases {
		if StatusRuleNames()[i] != c.rule {
			t.Fatalf("case %d names rule %q, table row is %q", i, c.rule, StatusRuleNames()[i])
		}
		st := StatusOf(c.cfg)
		if st.Rule != c.rule || st.Configured != c.configured {
			t.Errorf("%s: StatusOf = %+v, want rule %s configured %v", c.name, st, c.rule, c.configured)
		}
		if !c.configured && !strings.HasPrefix(st.Reason, NotConfigured+": ") {
			t.Errorf("%s: reason %q does not say %q", c.name, st.Reason, NotConfigured)
		}
	}
}

// TestMailerNotConfiguredNeverDials: an unset block yields an inert Mailer
// that answers ErrNotConfigured for every message and never reaches the
// sender.
func TestMailerNotConfiguredNeverDials(t *testing.T) {
	rec := &recordingSender{}
	for _, cfg := range []Config{{}, {Enabled: true}, {Enabled: true, Host: "h"}} {
		m := newMailerWithSender(cfg, rec)
		if m.Configured() {
			t.Fatalf("config %+v reports configured", cfg)
		}
		err := m.Deliver(t.Context(), Message{To: []string{"a@example.test"}, Subject: "s", Text: "t"})
		if !errors.Is(err, ErrNotConfigured) {
			t.Fatalf("Deliver on %+v = %v, want ErrNotConfigured", cfg, err)
		}
	}
	if rec.count() != 0 {
		t.Fatalf("an unconfigured mailer reached the sender %d times", rec.count())
	}
	var nilMailer *Mailer
	if nilMailer.Configured() || !errors.Is(nilMailer.Deliver(t.Context(), Message{To: []string{"a@x"}}), ErrNotConfigured) {
		t.Fatal("a nil Mailer must be not configured")
	}
	if st := NewMailer(Config{}, nil).Status(); st.Configured || st.Rule != StatusRuleDisabled {
		t.Fatalf("NewMailer on the zero config = %+v", st)
	}
}

// TestMailerConfiguredDelivers: a usable block hands the message to the
// sender and returns its outcome; a message with no recipient is refused.
func TestMailerConfiguredDelivers(t *testing.T) {
	rec := &recordingSender{}
	m := newMailerWithSender(usableConfig(), rec)
	if !m.Configured() {
		t.Fatal("usable config reports not configured")
	}
	if err := m.Deliver(t.Context(), Message{To: []string{"a@example.test"}, Subject: "s", Text: "t"}); err != nil {
		t.Fatal(err)
	}
	if err := m.Deliver(t.Context(), Message{Subject: "s"}); err == nil || errors.Is(err, ErrNotConfigured) {
		t.Fatalf("no recipient = %v, want a plain refusal", err)
	}
	rec.err = errors.New("relay down")
	if err := m.Deliver(t.Context(), Message{To: []string{"a@example.test"}}); err == nil || err.Error() != "relay down" {
		t.Fatalf("relay failure = %v", err)
	}
	if rec.count() != 2 {
		t.Fatalf("sender saw %d messages, want 2", rec.count())
	}
}
