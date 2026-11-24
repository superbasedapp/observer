package main

import (
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// filesMap is a readFile over a map (a missing path is fs.ErrNotExist).
func filesMap(m map[string]string) func(string) ([]byte, error) {
	return func(p string) ([]byte, error) {
		v, ok := m[p]
		if !ok {
			return nil, fs.ErrNotExist
		}
		return []byte(v), nil
	}
}

const fakeLiveKey = "pdl_live_apikey_not_a_real_key_000000"

// TestReadPaddleSecrets: one row per way a secret may and may not be given;
// no error ever carries a value.
func TestReadPaddleSecrets(t *testing.T) {
	t.Parallel()
	files := filesMap(map[string]string{
		"/s/wh":     "whsec_value\n",
		"/s/key":    fakeLiveKey + "\n",
		"/s/empty":  "  \n",
		"/s/two":    "a\nb\n",
		"/s/big":    strings.Repeat("x", maxPaddleSecretBytes+1),
		"/s/whprev": "whsec_prev",
	})
	for _, tc := range []struct {
		name    string
		env     map[string]string
		want    paddleSecrets
		wantErr string
	}{
		{"nothing set", nil, paddleSecrets{}, ""},
		{"webhook secret plain (pre-wave-17)", map[string]string{"SBCI_PADDLE_WEBHOOK_SECRET": "whsec_plain"}, paddleSecrets{webhookSecret: "whsec_plain"}, ""},
		{"webhook secret by file", map[string]string{"SBCI_PADDLE_WEBHOOK_SECRET_FILE": "/s/wh", "SBCI_PADDLE_WEBHOOK_SECRET_PREVIOUS_FILE": "/s/whprev"}, paddleSecrets{webhookSecret: "whsec_value", webhookSecretPrevious: "whsec_prev"}, ""},
		{"api key by file", map[string]string{"SBCI_PADDLE_API_KEY_FILE": "/s/key"}, paddleSecrets{apiKey: fakeLiveKey}, ""},
		{"api key plain refused", map[string]string{"SBCI_PADDLE_API_KEY": fakeLiveKey}, paddleSecrets{}, "not read from the environment"},
		{"both plain and file refused", map[string]string{"SBCI_PADDLE_WEBHOOK_SECRET": "a", "SBCI_PADDLE_WEBHOOK_SECRET_FILE": "/s/wh"}, paddleSecrets{}, "set one"},
		{"missing file", map[string]string{"SBCI_PADDLE_API_KEY_FILE": "/s/none"}, paddleSecrets{}, "SBCI_PADDLE_API_KEY_FILE"},
		{"empty file", map[string]string{"SBCI_PADDLE_API_KEY_FILE": "/s/empty"}, paddleSecrets{}, "empty"},
		{"two lines", map[string]string{"SBCI_PADDLE_WEBHOOK_SECRET_FILE": "/s/two"}, paddleSecrets{}, "more than one line"},
		{"oversized file", map[string]string{"SBCI_PADDLE_API_KEY_FILE": "/s/big"}, paddleSecrets{}, "over"},
	} {
		got, err := readPaddleSecrets(envMap(tc.env), files)
		switch {
		case tc.wantErr == "" && err != nil:
			t.Errorf("%s: err = %v", tc.name, err)
		case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
			t.Errorf("%s: err = %v, want %q", tc.name, err, tc.wantErr)
		case tc.wantErr == "" && got != tc.want:
			t.Errorf("%s: got %+v", tc.name, got)
		}
		if err != nil {
			for _, v := range []string{fakeLiveKey, "whsec_value", "whsec_plain", "xxxx"} {
				if strings.Contains(err.Error(), v) {
					t.Errorf("%s: the error carries a value", tc.name)
				}
			}
		}
	}
}

func TestAPIKeyEnvironmentAndClient(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		key, env, keyEnv string
		clientErr        bool
		client           bool
	}{
		{"", "live", "", false, false},
		{fakeLiveKey, "live", "live", false, true},
		{"pdl_sdbx_apikey_x", "sandbox", "sandbox", false, true},
		{"pdl_sdbx_apikey_x", "live", "sandbox", true, false},
		{fakeLiveKey, "sandbox", "live", true, false},
		{"legacy0123", "live", "unknown", true, false},
		{fakeLiveKey, "staging", "live", true, false},
	} {
		sec := paddleSecrets{apiKey: tc.key}
		if got := sec.apiKeyEnvironment(); got != tc.keyEnv {
			t.Errorf("apiKeyEnvironment(%q) = %q, want %q", tc.key, got, tc.keyEnv)
		}
		c, err := newPaddleAPIClient(tc.env, sec)
		if (err != nil) != tc.clientErr || (c != nil) != tc.client {
			t.Errorf("newPaddleAPIClient(%s, %q) = %v, %v", tc.env, tc.keyEnv, c != nil, err)
		}
		if err != nil && tc.key != "" && strings.Contains(err.Error(), tc.key) {
			t.Errorf("the client error carries the key")
		}
	}
}

func TestPaddlePastDueGraceAndSeatSyncMode(t *testing.T) {
	t.Parallel()
	for raw, want := range map[string]time.Duration{"": 14 * 24 * time.Hour, "7": 7 * 24 * time.Hour, "90": 90 * 24 * time.Hour} {
		if got, err := paddlePastDueGrace(envMap(map[string]string{"SBCI_PADDLE_PAST_DUE_GRACE_DAYS": raw})); err != nil || got != want {
			t.Errorf("grace %q = %v, %v", raw, got, err)
		}
	}
	for _, raw := range []string{"0", "91", "x", "-1", "1.5"} {
		if _, err := paddlePastDueGrace(envMap(map[string]string{"SBCI_PADDLE_PAST_DUE_GRACE_DAYS": raw})); err == nil {
			t.Errorf("grace %q accepted", raw)
		}
	}
	for _, tc := range []struct {
		raw     string
		haveKey bool
		want    string
		err     error
	}{
		{"", false, seatSyncOff, nil},
		{"off", false, seatSyncOff, nil},
		{"report", true, seatSyncReport, nil},
		{"ON", true, seatSyncOn, nil},
		{"on", false, "", errSeatSyncNeedsKey},
		{"report", false, "", errSeatSyncNeedsKey},
	} {
		got, err := seatSyncModeFrom(envMap(map[string]string{"SBCI_PADDLE_SEAT_SYNC": tc.raw}), tc.haveKey)
		if got != tc.want || !errors.Is(err, tc.err) {
			t.Errorf("mode %q key=%v = %q, %v", tc.raw, tc.haveKey, got, err)
		}
	}
	if _, err := seatSyncModeFrom(envMap(map[string]string{"SBCI_PADDLE_SEAT_SYNC": "yes"}), true); err == nil {
		t.Error("mode yes accepted")
	}
}

// TestPaddleServeWiresDeletionBilling (ORGDEL-7): serve's Paddle
// configuration hands the account deletion the org deletion's billing seam
// over its API client exactly when an API key is configured; without one the
// seam stays nil and the store refuses a deletion that must cancel.
func TestPaddleServeWiresDeletionBilling(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	for _, tc := range []struct {
		name string
		key  string
		want bool
	}{
		{"no key", "", false},
		{"a sandbox key", "pdl_sdbx_apikey_not_a_real_key_000000", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SBCI_PADDLE_ENV", "sandbox")
			t.Setenv("SBCI_PADDLE_API_KEY_FILE", "")
			if tc.key != "" {
				path := filepath.Join(t.TempDir(), "key")
				if err := os.WriteFile(path, []byte(tc.key+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				t.Setenv("SBCI_PADDLE_API_KEY_FILE", path)
			}
			ps, err := paddleServeConfigFromEnv(nil, "http://127.0.0.1:8090", log)
			if err != nil {
				t.Fatal(err)
			}
			if got := ps.deletionBilling != nil; got != tc.want {
				t.Fatalf("deletion billing wired = %v, want %v", got, tc.want)
			}
			if tc.want {
				if _, ok := ps.deletionBilling.(deletionBilling); !ok {
					t.Fatalf("deletion billing is %T, want the org deletion's deletionBilling", ps.deletionBilling)
				}
			}
		})
	}
}
