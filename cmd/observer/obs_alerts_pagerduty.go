package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/alertspec"
	"github.com/marmutapp/superbased-observer/internal/config"
)

// obs_alerts_pagerduty.go is the machine's PagerDuty delivery for
// observability alerts (Plane A W5-5, lane C9) and the alert rule CLI B9
// deferred. PagerDuty rides the machine's existing alert lane (the
// cmd/observer composition row of tests/invariant/egress_lanes_test.go names
// events.pagerduty.com), off by default: nothing is sent unless the owner set
// [observability.alerts].pagerduty_routing_key. The key is a secret and never
// reaches a log line or an error string.

// pagerDutyClient posts to PagerDuty. No redirects: the Events API answers
// directly, and the body carries the routing key, so a 307 or 308 must never
// re-post it elsewhere. A 3xx comes back as the response, a permanent
// refusal.
var pagerDutyClient = &http.Client{
	Timeout:       10 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

// pagerDutyEndpoint is the Events API v2 URL; a test swaps it for a local
// server (never real PagerDuty).
var pagerDutyEndpoint = alertspec.PagerDutyEventsURL

// errPagerDutyDelivery is the key-free error of a failed post a later attempt
// can fix: a transport error, a 5xx or a 429.
var errPagerDutyDelivery = errors.New("pagerduty delivery failed")

// errPagerDutyRejected is a permanent refusal by PagerDuty (a 4xx other than
// 429, a redirect): retrying the same body cannot succeed.
var errPagerDutyRejected = errors.New("pagerduty refused the event")

// retryablePagerDuty reports whether a post failed in a way a later attempt
// can fix (the org's obsalert.RetryablePagerDuty, R-C20). nil, a permanent
// refusal and an invalid key are not retryable.
func retryablePagerDuty(err error) bool {
	return err != nil && !errors.Is(err, errPagerDutyRejected) && !errors.Is(err, alertspec.ErrPagerDutyKey)
}

// machinePagerDutyScope is the dedup scope of a machine rule's incidents.
const machinePagerDutyScope = "machine"

// machineDedupKey is a machine rule's incident key: its name and dimensions.
func machineDedupKey(rule string, d alertspec.Dimensions) string {
	return alertspec.PagerDutyDedupKey(machinePagerDutyScope, rule, d)
}

// postPagerDuty sends one Events API v2 event. The error never carries the
// key.
func postPagerDuty(ctx context.Context, key, dedup string, a alertspec.SlackAlert) error {
	body, err := alertspec.PagerDutyEvent(key, dedup, a)
	if err != nil {
		return err
	}
	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, pagerDutyEndpoint, bytes.NewReader(body))
	if err != nil {
		return errPagerDutyDelivery
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := pagerDutyClient.Do(req)
	if err != nil {
		return errPagerDutyDelivery
	}
	defer func() { _ = resp.Body.Close() }()
	switch {
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
		return fmt.Errorf("%w: pagerduty returned %d", errPagerDutyDelivery, resp.StatusCode)
	case resp.StatusCode >= 300:
		return fmt.Errorf("%w: pagerduty returned %d", errPagerDutyRejected, resp.StatusCode)
	}
	return nil
}

// deliverPagerDutyFired triggers the incident of each fired alert, under the
// dedup key its firing episode opened with (episodes, from
// obsAlertTransitions) when it has one, else the rule's own key. A rule whose
// dimensions were edited while it fired keeps triggering the incident its
// resolve will close (review finding E-43).
func deliverPagerDutyFired(ctx context.Context, key string, fired []obsFiredAlert, episodes map[string]string, logger *slog.Logger) {
	if key == "" {
		return
	}
	for _, f := range fired {
		dedup := episodes[f.RuleName]
		if dedup == "" {
			dedup = machineDedupKey(f.RuleName, f.Dimensions)
		}
		if err := postPagerDuty(ctx, key, dedup, slackAlertFor(f)); err != nil {
			logger.Warn("obs-alert pagerduty trigger failed", "rule", f.RuleName, "err", err)
		}
	}
}

// deliverPagerDutyResolved posts each owed resolve under the dedup key its
// episode opened with and returns what each attempt did, so the caller keeps
// the debt of every resolve not delivered (review finding R-C20). With no
// routing key nothing is posted and every owed resolve is reported as not sent,
// which the caller drops with a warning (FR-M13): the incident stays open in
// PagerDuty until it is resolved there.
func deliverPagerDutyResolved(ctx context.Context, key string, owed []obsClearedAlert, logger *slog.Logger) []obsResolveAttempt {
	out := make([]obsResolveAttempt, 0, len(owed))
	for _, c := range owed {
		if c.DedupKey == "" {
			continue
		}
		if key == "" {
			out = append(out, obsResolveAttempt{Alert: c})
			continue
		}
		err := postPagerDuty(ctx, key, c.DedupKey, alertspec.SlackAlert{Event: "resolved", RuleName: c.RuleName, Source: "this machine"})
		if err != nil {
			logger.Warn("obs-alert pagerduty resolve failed", "rule", c.RuleName, "retryable", retryablePagerDuty(err), "err", err)
		}
		out = append(out, obsResolveAttempt{Alert: c, Sent: true, Err: err})
	}
	return out
}

// obsClearedAlert is a machine rule that owes a resolve: it stopped breaching
// (or left the config while firing) and its incident is not resolved yet.
type obsClearedAlert struct {
	RuleName string
	DedupKey string
}

// obsResolveAttempt is one owed resolve and what posting it did: Sent false
// when no routing key is configured, else Err is the post's error (nil on
// success).
type obsResolveAttempt struct {
	Alert obsClearedAlert
	Sent  bool
	Err   error
}

// testPagerDuty sends a test trigger and resolves it at once, so the test
// leaves no open incident.
func testPagerDuty(ctx context.Context, key string, now time.Time) error {
	var b [6]byte
	_, _ = rand.Read(b[:])
	dedup := "sbo-test-" + hex.EncodeToString(b[:])
	a := alertspec.SlackAlert{Event: "test", RuleName: "test from superbased", Source: "this machine", FiredAt: now.UTC().Format(time.RFC3339)}
	if err := postPagerDuty(ctx, key, dedup, a); err != nil {
		return err
	}
	a.Event = "resolved"
	return postPagerDuty(ctx, key, dedup, a)
}

// readSecretLine reads one trimmed line of stdin (8 KiB at most).
func readSecretLine(r io.Reader, what string) (string, error) {
	line, err := bufio.NewReader(io.LimitReader(r, 8<<10)).ReadString('\n')
	if err != nil && line == "" {
		return "", fmt.Errorf("no %s on stdin", what)
	}
	return strings.TrimSpace(line), nil
}

// newObsAlertsPagerDutyCmd is `observer obs alerts pagerduty set|clear|test`,
// the CLI path for the routing key (the generic `observer config set`
// refuses secret-tier keys). `set` reads the key from stdin so it never lands
// in argv or shell history.
func newObsAlertsPagerDutyCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "pagerduty",
		Short: "Set, clear or test the PagerDuty Events API v2 routing key for observability alerts",
	}
	cmd.PersistentFlags().StringVar(&configPath, "config", "", "path to config.toml")
	cmd.AddCommand(&cobra.Command{
		Use:   "set",
		Short: "Read a PagerDuty routing key from stdin and store it",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			key, err := readSecretLine(c.InOrStdin(), "routing key")
			if err != nil {
				return err
			}
			if key == "" {
				return errors.New("empty key: use `observer obs alerts pagerduty clear` to remove it")
			}
			if err := alertspec.ValidPagerDutyRoutingKey(key); err != nil {
				return err
			}
			if err := obsAlertConfigEdit(configPath, func(cfg *config.Config) { cfg.Observability.Alerts.PagerDutyRoutingKey = key }); err != nil {
				return err
			}
			fmt.Fprintln(c.OutOrStdout(), "pagerduty routing key stored")
			return nil
		},
	}, &cobra.Command{
		Use:   "clear",
		Short: "Remove the PagerDuty routing key",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			if err := obsAlertConfigEdit(configPath, func(cfg *config.Config) { cfg.Observability.Alerts.PagerDutyRoutingKey = "" }); err != nil {
				return err
			}
			fmt.Fprintln(c.OutOrStdout(), "pagerduty routing key cleared")
			return nil
		},
	}, &cobra.Command{
		Use:   "test",
		Short: "Send one test event to PagerDuty (and resolve it at once)",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
			if err != nil {
				return err
			}
			key := cfg.Observability.Alerts.PagerDutyRoutingKey
			if key == "" {
				return errors.New("pagerduty is not configured: run `observer obs alerts pagerduty set`")
			}
			if err := testPagerDuty(c.Context(), key, time.Now()); err != nil {
				return err
			}
			fmt.Fprintln(c.OutOrStdout(), "test event delivered and resolved")
			return nil
		},
	})
	return cmd
}

// newObsAlertsRulesCmd is `observer obs alerts rules list|set`: the CLI path
// for the machine's alert rule table (B9's open question 3), through the one
// config write owner. `set` reads the whole rule list as JSON on stdin (the
// shape of PUT /api/obs/alerts/rules) and validates it like the dashboard.
func newObsAlertsRulesCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "rules",
		Short: "Print or replace the machine's observability alert rules",
	}
	cmd.PersistentFlags().StringVar(&configPath, "config", "", "path to config.toml")
	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "Print the alert rules as JSON (the input shape of `rules set`)",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
			if err != nil {
				return err
			}
			enc := json.NewEncoder(c.OutOrStdout())
			enc.SetIndent("", "  ")
			return enc.Encode(map[string]any{"rules": alertRulesJSON(cfg.Observability.Alerts.Rules)})
		},
	}, &cobra.Command{
		Use:   "set",
		Short: `Replace the alert rules from JSON on stdin: {"rules":[{name, metric, comparator, threshold, window_minutes, cooldown_minutes, dimensions}]}`,
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			rules, err := parseAlertRulesJSON(c.InOrStdin())
			if err != nil {
				return err
			}
			if err := obsAlertConfigEdit(configPath, func(cfg *config.Config) { cfg.Observability.Alerts.Rules = rules }); err != nil {
				return err
			}
			fmt.Fprintf(c.OutOrStdout(), "%d alert rule(s) stored; the running daemon applies them on its next tick\n", len(rules))
			return nil
		},
	})
	return cmd
}

// alertRuleJSON is one rule in the CLI's JSON (the dashboard route's shape).
type alertRuleJSON struct {
	Name            string               `json:"name"`
	Metric          string               `json:"metric"`
	Comparator      string               `json:"comparator"`
	Threshold       float64              `json:"threshold"`
	WindowMinutes   int                  `json:"window_minutes"`
	CooldownMinutes int                  `json:"cooldown_minutes"`
	Dimensions      alertspec.Dimensions `json:"dimensions"`
}

func alertRulesJSON(in []config.ObservabilityAlertRuleConfig) []alertRuleJSON {
	out := make([]alertRuleJSON, 0, len(in))
	for _, r := range in {
		out = append(out, alertRuleJSON{
			Name: r.Name, Metric: r.Metric, Comparator: r.Comparator, Threshold: r.Threshold,
			WindowMinutes: r.WindowMinutes, CooldownMinutes: r.CooldownMinutes,
			Dimensions: alertspec.Dimensions{Model: r.Model, User: r.User, Tag: r.Tag, Service: r.Service},
		})
	}
	return out
}

// parseAlertRulesJSON reads and validates a rule list. Validation is the
// config loader's own (config.ValidateObservabilityAlerts' rules), run on a
// candidate config so the CLI and the file agree.
func parseAlertRulesJSON(r io.Reader) ([]config.ObservabilityAlertRuleConfig, error) {
	var body struct {
		Rules []alertRuleJSON `json:"rules"`
	}
	dec := json.NewDecoder(io.LimitReader(r, 256<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		return nil, fmt.Errorf("rules set: the input is not {\"rules\": [...]}: %w", err)
	}
	out := make([]config.ObservabilityAlertRuleConfig, 0, len(body.Rules))
	seen := map[string]bool{}
	for i, r := range body.Rules {
		d := r.Dimensions.Normalize()
		if err := d.Validate(); err != nil {
			return nil, fmt.Errorf("rules set: rules[%d]: %w", i, err)
		}
		name := strings.TrimSpace(r.Name)
		if name == "" || seen[name] {
			return nil, fmt.Errorf("rules set: rules[%d]: name must be non-empty and unique", i)
		}
		seen[name] = true
		out = append(out, config.ObservabilityAlertRuleConfig{
			Name: name, Metric: r.Metric, Comparator: r.Comparator, Threshold: r.Threshold,
			WindowMinutes: r.WindowMinutes, CooldownMinutes: r.CooldownMinutes,
			Model: d.Model, User: d.User, Tag: d.Tag, Service: d.Service,
		})
	}
	candidate := config.Default()
	candidate.Observability.Alerts.Enabled = true
	candidate.Observability.Alerts.Rules = out
	if err := config.Validate(candidate); err != nil {
		return nil, fmt.Errorf("rules set: %w", err)
	}
	return out, nil
}
