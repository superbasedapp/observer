package main

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/api"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/entitlementwork"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/seatbilling/paddleapi"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// paddleconfig.go reads the Paddle settings that are secrets, or that both
// serve and worker need, once at startup (wave 17 paddle-live; E1.6;
// docs/security.md PADDLELIVE-1). Glue only: the rules are tables, the
// values never reach a log line or an error.
//
// SECRETS BY FILE. The webhook secrets may come from SBCI_PADDLE_WEBHOOK_SECRET
// (the pre-wave-17 setting, kept for existing deployments) or from a file
// named by SBCI_PADDLE_WEBHOOK_SECRET_FILE, never both. The server-side API
// key comes ONLY from the file named by SBCI_PADDLE_API_KEY_FILE: a plain
// SBCI_PADDLE_API_KEY is refused, so the key is never in a container's
// environment (`docker inspect` lists the environment, not mounted files).
// The cloud kit mounts the files read-only (deploy/saas-ovh/cloud-app
// docker-compose.paddle.yaml).

// paddleSecretSetting is one secret setting and how it may be given.
type paddleSecretSetting struct {
	name string
	// plainAllowed: the value may also come from the variable itself.
	plainAllowed bool
}

var (
	settingWebhookSecret         = paddleSecretSetting{name: "SBCI_PADDLE_WEBHOOK_SECRET", plainAllowed: true}
	settingWebhookSecretPrevious = paddleSecretSetting{name: "SBCI_PADDLE_WEBHOOK_SECRET_PREVIOUS", plainAllowed: true}
	settingAPIKey                = paddleSecretSetting{name: "SBCI_PADDLE_API_KEY", plainAllowed: false}
)

// maxPaddleSecretBytes bounds a secret file (a Paddle key is under 100
// bytes; a larger file is a wrong path, not a key).
const maxPaddleSecretBytes = 4096

// readPaddleSecret returns a secret setting's value ("" when unset).
func readPaddleSecret(st paddleSecretSetting, getenv func(string) string, readFile func(string) ([]byte, error)) (string, error) {
	plain := strings.TrimSpace(getenv(st.name))
	path := strings.TrimSpace(getenv(st.name + "_FILE"))
	switch {
	case plain != "" && !st.plainAllowed:
		return "", fmt.Errorf("%s is not read from the environment; put the key in a file and name it in %s_FILE", st.name, st.name)
	case plain != "" && path != "":
		return "", fmt.Errorf("both %s and %s_FILE are set; set one", st.name, st.name)
	case path == "":
		return plain, nil
	}
	b, err := readFile(path)
	if err != nil {
		// The path is configuration, not a secret; the error names it.
		return "", fmt.Errorf("%s_FILE: %w", st.name, err)
	}
	if len(b) > maxPaddleSecretBytes {
		return "", fmt.Errorf("%s_FILE: the file is over %d bytes; it does not hold one key", st.name, maxPaddleSecretBytes)
	}
	v := strings.TrimSpace(string(b))
	if v == "" {
		return "", fmt.Errorf("%s_FILE: the file is empty", st.name)
	}
	if strings.ContainsAny(v, " \t\r\n") {
		return "", fmt.Errorf("%s_FILE: the file holds more than one line or word; it must hold the value only", st.name)
	}
	return v, nil
}

// paddleSecrets are the Paddle secrets of one process.
type paddleSecrets struct {
	webhookSecret         string
	webhookSecretPrevious string
	apiKey                string
}

// readPaddleSecrets reads every Paddle secret setting.
func readPaddleSecrets(getenv func(string) string, readFile func(string) ([]byte, error)) (paddleSecrets, error) {
	var out paddleSecrets
	var err error
	if out.webhookSecret, err = readPaddleSecret(settingWebhookSecret, getenv, readFile); err != nil {
		return paddleSecrets{}, err
	}
	if out.webhookSecretPrevious, err = readPaddleSecret(settingWebhookSecretPrevious, getenv, readFile); err != nil {
		return paddleSecrets{}, err
	}
	if out.apiKey, err = readPaddleSecret(settingAPIKey, getenv, readFile); err != nil {
		return paddleSecrets{}, err
	}
	return out, nil
}

// apiKeyEnvironment is the API key's environment for
// api.PaddleCheckoutEnv.APIKeyEnvironment: "" (no key), "live", "sandbox"
// or "unknown".
func (p paddleSecrets) apiKeyEnvironment() string {
	if p.apiKey == "" {
		return ""
	}
	if e := paddleapi.KeyEnvironment(p.apiKey); e != "" {
		return e
	}
	return "unknown"
}

// paddleEnvironment is SBCI_PADDLE_ENV normalized the way
// api.ValidatePaddleCheckoutEnv normalizes it ("" is sandbox).
func paddleEnvironment(getenv func(string) string) string {
	e := strings.ToLower(strings.TrimSpace(getenv("SBCI_PADDLE_ENV")))
	if e == "" {
		return paddleapi.EnvSandbox
	}
	return e
}

// paddleAPITimeout bounds one Paddle API call.
const paddleAPITimeout = 15 * time.Second

// newPaddleAPIClient builds the Paddle API client for SBCI_PADDLE_ENV's API
// with the configured key, or nil when no key is configured. A key of the
// other environment fails (paddleapi.New's table).
func newPaddleAPIClient(env string, sec paddleSecrets) (*paddleapi.Client, error) {
	if sec.apiKey == "" {
		return nil, nil
	}
	base, err := paddleapi.BaseURLFor(env)
	if err != nil {
		return nil, fmt.Errorf("SBCI_PADDLE_ENV: %w", err)
	}
	c, err := paddleapi.New(base, sec.apiKey, &http.Client{Timeout: paddleAPITimeout})
	if err != nil {
		return nil, fmt.Errorf("SBCI_PADDLE_API_KEY_FILE: %w", err)
	}
	return c, nil
}

// paddlePastDueGrace reads SBCI_PADDLE_PAST_DUE_GRACE_DAYS (W16-D5; unset:
// entitlementwork.DefaultPastDueGrace, 14 days; 1..90).
func paddlePastDueGrace(getenv func(string) string) (time.Duration, error) {
	raw := strings.TrimSpace(getenv("SBCI_PADDLE_PAST_DUE_GRACE_DAYS"))
	if raw == "" {
		return entitlementwork.DefaultPastDueGrace, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 || n > 90 {
		return 0, fmt.Errorf("SBCI_PADDLE_PAST_DUE_GRACE_DAYS must be a whole number of days from 1 to 90, got %q", raw)
	}
	return time.Duration(n) * 24 * time.Hour, nil
}

// The seat sync modes (SBCI_PADDLE_SEAT_SYNC).
const (
	seatSyncOff    = "off"
	seatSyncReport = "report"
	seatSyncOn     = "on"
)

var errSeatSyncNeedsKey = errors.New("SBCI_PADDLE_SEAT_SYNC needs the Paddle API key (SBCI_PADDLE_API_KEY_FILE)")

// seatSyncModeFrom reads SBCI_PADDLE_SEAT_SYNC: off (default: nothing runs
// and nothing is read), report (decide and log, change nothing at Paddle)
// or on (send the quantity changes). report and on need the API key.
func seatSyncModeFrom(getenv func(string) string, haveKey bool) (string, error) {
	m := strings.ToLower(strings.TrimSpace(getenv("SBCI_PADDLE_SEAT_SYNC")))
	switch m {
	case "", seatSyncOff:
		return seatSyncOff, nil
	case seatSyncReport, seatSyncOn:
		if !haveKey {
			return "", errSeatSyncNeedsKey
		}
		return m, nil
	}
	return "", fmt.Errorf("SBCI_PADDLE_SEAT_SYNC must be off, report or on, got %q", m)
}

// paddleServe is serve's resolved Paddle configuration.
type paddleServe struct {
	checkout     api.PaddleCheckout
	secrets      paddleSecrets
	portal       api.PaddlePortalAPI
	pastDueGrace time.Duration
}

// paddleServeConfigFromEnv reads serve's Paddle settings once (wave 17):
// the secrets by file, the validated checkout (A4: SBCI_PADDLE_ENV=live
// without the rest of the go-live settings fails startup here), the API
// client for portal sessions (nil without a key) and the dunning grace. It
// logs the posture, never a value.
func paddleServeConfigFromEnv(pm map[string]store.PaddlePlan, externalBase string, log *slog.Logger) (paddleServe, error) {
	sec, err := readPaddleSecrets(os.Getenv, os.ReadFile)
	if err != nil {
		return paddleServe{}, fmt.Errorf("observer-cloud: Paddle secrets: %w", err)
	}
	checkout, err := paddleCheckoutFromEnv(pm, externalBase, sec)
	if err != nil {
		return paddleServe{}, fmt.Errorf("observer-cloud: Paddle checkout configuration: %w", err)
	}
	client, err := newPaddleAPIClient(checkout.Environment, sec)
	if err != nil {
		return paddleServe{}, fmt.Errorf("observer-cloud: Paddle API: %w", err)
	}
	grace, err := paddlePastDueGrace(os.Getenv)
	if err != nil {
		return paddleServe{}, fmt.Errorf("observer-cloud: %w", err)
	}
	out := paddleServe{checkout: checkout, secrets: sec, pastDueGrace: grace}
	if client != nil {
		out.portal = client
	}
	noTrial := len(pm) - len(checkout.Prices)
	if checkout.TrialDays > 0 {
		// fu/billing-trial: with a trial advertised, a scope that has had
		// its trial buys through the plan's trial-less price; a catalogue
		// price without one refuses it (409 trial_already_used). A price
		// Paddle gives no trial (Team, Business by default) needs none, so
		// this is a warning, not a startup refusal.
		if missing := store.PaddleCataloguePricesWithoutNoTrial(pm); len(missing) > 0 {
			log.Warn("observer-cloud: a trial is advertised and these prices have no trial-less price in SBCI_PADDLE_NO_TRIAL_PRICES; if Paddle gives them a trial, a customer who has had one cannot buy them (409 trial_already_used)",
				"prices", strings.Join(missing, ","))
		}
	}
	log.Info("observer-cloud: Paddle checkout configuration",
		"environment", checkout.Environment, "prices", len(checkout.Prices), "no_trial_prices", noTrial,
		"trial_days", checkout.TrialDays, "checkout_available", checkout.Available(),
		"webhook_configured", sec.webhookSecret != "" || sec.webhookSecretPrevious != "",
		"portal_sessions", out.portal != nil, "past_due_grace_days", int(grace/(24*time.Hour)))
	return out, nil
}
