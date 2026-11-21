package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/alertspec"
	"github.com/marmutapp/superbased-observer/internal/config"
)

// obs_alerts_slack.go is the node's Slack delivery for observability alerts
// (Plane A W3-5, lane B9). It rides the node's existing alert lane (the
// cmd/observer composition row of tests/invariant/egress_lanes_test.go:
// "[observability.alerts] webhooks"), off by default: nothing is sent unless
// the owner set [observability.alerts].slack_webhook_url. The URL is a secret
// and never reaches a log line or an error string.

// slackClient posts to Slack. No redirects: a hook URL that redirects is not a
// Slack incoming webhook.
var slackClient = &http.Client{
	Timeout:       10 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

// slackHookCheck validates a hook before any post; a test swaps it to reach
// a local server.
var slackHookCheck = alertspec.ValidSlackWebhookURL

// errSlackDelivery is the URL-free error a failed Slack post reports.
var errSlackDelivery = errors.New("slack delivery failed")

// postSlack sends one alert to a Slack incoming webhook. The returned error
// never carries the URL (a *url.Error is unwrapped to its cause).
func postSlack(ctx context.Context, hook string, a alertspec.SlackAlert) error {
	if err := slackHookCheck(hook); err != nil || hook == "" {
		return alertspec.ErrSlackURL
	}
	body, err := alertspec.SlackPayload(a)
	if err != nil {
		return err
	}
	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, hook, bytes.NewReader(body))
	if err != nil {
		return errSlackDelivery
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := slackClient.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) && ue.Err != nil {
			if errors.Is(ue.Err, context.DeadlineExceeded) {
				return fmt.Errorf("%w: timeout", errSlackDelivery)
			}
		}
		return errSlackDelivery
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("slack returned %d", resp.StatusCode)
	}
	return nil
}

// slackAlertFor renders one fired node alert for Slack.
func slackAlertFor(f obsFiredAlert) alertspec.SlackAlert {
	return alertspec.SlackAlert{
		Event: "fired", RuleName: f.RuleName, Metric: f.Metric, Comparator: f.Comparator,
		Threshold: f.Threshold, Value: f.Value,
		Window:     fmt.Sprintf("%d minute(s)", f.WindowMinutes),
		Dimensions: f.Dimensions, Source: "this machine",
		FiredAt: f.FiredAt.UTC().Format(time.RFC3339),
	}
}

// slackTestAlert is the message the Slack test route sends.
func slackTestAlert(now time.Time) alertspec.SlackAlert {
	return alertspec.SlackAlert{Event: "test", RuleName: "test from superbased", Source: "this machine", FiredAt: now.UTC().Format(time.RFC3339)}
}

// obsAlertConfigEdit applies edit to the daemon's config file under the
// process-wide config lock and writes it back.
func obsAlertConfigEdit(configPath string, edit func(*config.Config)) error {
	return config.WithConfigLock(func() error {
		path, err := config.ResolveGlobalPath(configPath)
		if err != nil {
			return fmt.Errorf("obs alerts: resolve config path: %w", err)
		}
		cfg, err := loadConfigForSetup(path)
		if err != nil {
			return fmt.Errorf("obs alerts: load config: %w", err)
		}
		edit(&cfg)
		if err := config.WriteToml(path, cfg); err != nil {
			// WriteToml's error names the path, never a value.
			return fmt.Errorf("obs alerts: write config: %w", err)
		}
		return nil
	})
}

// newObsAlertsSlackCmd is `observer obs alerts slack set|clear|test`, the CLI
// path for the Slack secret (the generic `observer config set` refuses
// secret-tier keys). `set` reads the URL from stdin so it never lands in
// argv or shell history.
func newObsAlertsSlackCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "slack",
		Short: "Set, clear or test the Slack incoming webhook for observability alerts",
	}
	cmd.PersistentFlags().StringVar(&configPath, "config", "", "path to config.toml")
	cmd.AddCommand(&cobra.Command{
		Use:   "set",
		Short: "Read a Slack incoming-webhook URL from stdin and store it",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			line, err := bufio.NewReader(c.InOrStdin()).ReadString('\n')
			if err != nil && line == "" {
				return errors.New("no URL on stdin")
			}
			hook := strings.TrimSpace(line)
			if hook == "" {
				return errors.New("empty URL: use `observer obs alerts slack clear` to remove it")
			}
			if err := alertspec.ValidSlackWebhookURL(hook); err != nil {
				return err
			}
			if err := obsAlertConfigEdit(configPath, func(cfg *config.Config) { cfg.Observability.Alerts.SlackWebhookURL = hook }); err != nil {
				return err
			}
			c.Println("Slack webhook stored. The running daemon picks it up on its next alert tick.")
			return nil
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "clear",
		Short: "Remove the Slack incoming webhook",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			if err := obsAlertConfigEdit(configPath, func(cfg *config.Config) { cfg.Observability.Alerts.SlackWebhookURL = "" }); err != nil {
				return err
			}
			c.Println("Slack webhook removed.")
			return nil
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "test",
		Short: "Send a test message to the configured Slack webhook",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
			if err != nil {
				return err
			}
			hook := cfg.Observability.Alerts.SlackWebhookURL
			if hook == "" {
				return errors.New("slack is not configured: run `observer obs alerts slack set`")
			}
			if err := postSlack(c.Context(), hook, slackTestAlert(time.Now())); err != nil {
				return err
			}
			c.Println("Test message delivered.")
			return nil
		},
	})
	return cmd
}
