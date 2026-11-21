package email

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
)

// status.go is the mail channel's "configured or not" answer (managed-SaaS
// plan 07 wave 14, lead decision W14-D7: SMTP is not provisioned, so every
// mail consumer is built behind config, inert while it is unset, and reports
// "not configured" rather than failing or pretending to send).
//
// Notifier (sender.go) stays the fail-soft channel the alert evaluators hold:
// it swallows every outcome. A consumer that must SAY what happened (the
// intelligence digest email records a per-member outcome; an invite keeps its
// copy-link path when mail is off) holds a Mailer instead, whose Deliver
// returns ErrNotConfigured for an unset or unusable [email] block and never
// opens a connection in that case.

// NotConfigured is the word every surface uses for an unset mail channel.
const NotConfigured = "not configured"

// ErrNotConfigured is Deliver's answer while the [email] block is unset or
// unusable. The wrapped text names why (Status.Reason).
var ErrNotConfigured = errors.New("email: " + NotConfigured)

// Status is the mail channel's state as a surface reports it.
type Status struct {
	// Configured is true when a message would be handed to the SMTP relay.
	Configured bool `json:"configured"`
	// Rule names the status rule that decided (one per row of statusRules).
	Rule string `json:"rule"`
	// Reason is the operator-facing sentence: "configured" or
	// "not configured: <why>".
	Reason string `json:"reason"`
}

// The status rule names.
const (
	StatusRuleDisabled   = "disabled"
	StatusRuleHostUnset  = "host_unset"
	StatusRuleFromUnset  = "from_unset"
	StatusRuleInvalid    = "invalid"
	StatusRuleConfigured = "configured"
)

// statusRule is one row of statusRules.
type statusRule struct {
	name string
	// match reports whether the row decides cfg; why is the reason detail.
	match func(cfg Config) (bool, string)
}

// statusRules decide the channel's status, walked top-down, first match wins.
// The last row always matches. A function, not a package variable, so the
// table is never shared mutable state.
func statusRules() []statusRule {
	return []statusRule{
		{name: StatusRuleDisabled, match: func(c Config) (bool, string) {
			return !c.Enabled, "[email].enabled is false"
		}},
		{name: StatusRuleHostUnset, match: func(c Config) (bool, string) {
			return strings.TrimSpace(c.Host) == "", "[email].host is unset"
		}},
		{name: StatusRuleFromUnset, match: func(c Config) (bool, string) {
			return strings.TrimSpace(c.From) == "", "[email].from is unset"
		}},
		{name: StatusRuleInvalid, match: func(c Config) (bool, string) {
			if err := c.Validate(); err != nil {
				return true, err.Error()
			}
			return false, ""
		}},
		{name: StatusRuleConfigured, match: func(Config) (bool, string) { return true, "" }},
	}
}

// StatusRuleNames lists statusRules' rows in order (for tests and docs).
func StatusRuleNames() []string {
	rules := statusRules()
	out := make([]string, 0, len(rules))
	for _, r := range rules {
		out = append(out, r.name)
	}
	return out
}

// StatusOf decides whether cfg is a usable mail channel. It reads no secret:
// a missing password is a delivery failure, not a configuration state (a
// local relay needs none).
func StatusOf(cfg Config) Status {
	for _, r := range statusRules() {
		ok, why := r.match(cfg)
		if !ok {
			continue
		}
		if r.name == StatusRuleConfigured {
			return Status{Configured: true, Rule: r.name, Reason: "configured"}
		}
		return Status{Rule: r.name, Reason: NotConfigured + ": " + why}
	}
	return Status{Rule: StatusRuleConfigured, Configured: true, Reason: "configured"}
}

// Mailer delivers composed messages and reports every outcome. A Mailer over
// an unset or unusable config is inert: Deliver returns ErrNotConfigured and
// never dials. The zero value and a nil Mailer are not configured.
type Mailer struct {
	sender Sender
	status Status
	logger *slog.Logger
}

// NewMailer builds the Mailer for cfg. It never fails: a config StatusOf
// rejects yields an inert Mailer that reports why, so a server with no SMTP
// relay starts and says "not configured" (W14-D7). logger nil uses the
// default.
func NewMailer(cfg Config, logger *slog.Logger) *Mailer {
	if logger == nil {
		logger = slog.Default()
	}
	st := StatusOf(cfg)
	m := &Mailer{status: st, logger: logger}
	if st.Configured {
		m.sender = NewSMTPSender(cfg.Resolve())
	}
	return m
}

// newMailerWithSender is the test seam: a Mailer over an arbitrary Sender
// with the status cfg decides.
func newMailerWithSender(cfg Config, sender Sender) *Mailer {
	st := StatusOf(cfg)
	m := &Mailer{status: st, logger: slog.Default()}
	if st.Configured {
		m.sender = sender
	}
	return m
}

// Status reports the channel's state (not configured for a nil Mailer).
func (m *Mailer) Status() Status {
	if m == nil {
		return Status{Rule: StatusRuleDisabled, Reason: NotConfigured + ": no mail channel"}
	}
	return m.status
}

// Configured reports whether Deliver would hand a message to the relay.
func (m *Mailer) Configured() bool { return m.Status().Configured }

// Deliver sends msg to its own recipients. It returns ErrNotConfigured
// (wrapped with the reason) without dialing when the channel is not
// configured, an error for a message with no recipient, and the relay's
// error otherwise. The error never carries the credential.
func (m *Mailer) Deliver(ctx context.Context, msg Message) error {
	st := m.Status()
	if !st.Configured || m.sender == nil {
		return fmt.Errorf("%w: %s", ErrNotConfigured, strings.TrimPrefix(st.Reason, NotConfigured+": "))
	}
	if len(msg.To) == 0 {
		return errors.New("email: no recipients")
	}
	if err := m.sender.Send(ctx, msg); err != nil {
		m.logger.Warn("email delivery failed", "subject", msg.Subject, "err", err)
		return err
	}
	return nil
}
