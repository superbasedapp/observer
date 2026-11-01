package main

import (
	"errors"
	"strings"
	"testing"
)

// fakeEnv is a map-backed getenv.
func fakeEnv(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

// fakeFiles is a map-backed readFile; a missing path is an error.
func fakeFiles(m map[string]string) func(string) ([]byte, error) {
	return func(p string) ([]byte, error) {
		v, ok := m[p]
		if !ok {
			return nil, errors.New("no such file")
		}
		return []byte(v), nil
	}
}

func TestReadExclusiveSecret(t *testing.T) {
	files := fakeFiles(map[string]string{
		"/run/secrets/key":   "file-value\n",
		"/run/secrets/blank": "  \n",
	})
	cases := []struct {
		name    string
		env     map[string]string
		want    string
		wantErr string
	}{
		{name: "neither set", env: map[string]string{}, want: ""},
		{name: "plain only", env: map[string]string{"K": " plain "}, want: "plain"},
		{name: "file only, trimmed", env: map[string]string{"K_FILE": "/run/secrets/key"}, want: "file-value"},
		{name: "both set is refused", env: map[string]string{"K": "plain", "K_FILE": "/run/secrets/key"}, wantErr: "not both"},
		{name: "missing file fails closed", env: map[string]string{"K_FILE": "/run/secrets/absent"}, wantErr: "K_FILE"},
		{name: "empty file fails closed", env: map[string]string{"K_FILE": "/run/secrets/blank"}, wantErr: "empty"},
		{name: "whitespace plain counts as unset", env: map[string]string{"K": "   ", "K_FILE": "/run/secrets/key"}, want: "file-value"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := readExclusiveSecret(fakeEnv(tc.env), files, "K", "K_FILE")
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err=%v, want one containing %q", err, tc.wantErr)
				}
				if strings.Contains(err.Error(), "file-value") {
					t.Fatalf("error leaks a secret value: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestWorkOSSettingsFromEnv(t *testing.T) {
	files := fakeFiles(map[string]string{
		"/run/secrets/workos_api_key":        "sk_test_fake",
		"/run/secrets/workos_webhook_secret": "whsec_fake",
	})
	env := fakeEnv(map[string]string{
		envWorkOSClientID:          "client_fake",
		envWorkOSAPIKeyFile:        "/run/secrets/workos_api_key",
		envWorkOSWebhookSecretFile: "/run/secrets/workos_webhook_secret",
	})
	got, err := workOSSettingsFromEnv(env, files)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := workOSSettings{ClientID: "client_fake", APIKey: "sk_test_fake", WebhookSecret: "whsec_fake"}
	if got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}

	// A broken webhook mount fails the whole resolution (fail closed).
	env = fakeEnv(map[string]string{
		envWorkOSAPIKey:            "sk_test_fake",
		envWorkOSWebhookSecretFile: "/run/secrets/missing",
	})
	if _, err := workOSSettingsFromEnv(env, files); err == nil || !strings.Contains(err.Error(), envWorkOSWebhookSecretFile) {
		t.Fatalf("err=%v, want a %s error", err, envWorkOSWebhookSecretFile)
	}
}

func TestRequireWorkOSComplete(t *testing.T) {
	full := workOSSettings{ClientID: "client_fake", APIKey: "sk_test_fake"}
	cases := []struct {
		name      string
		requested bool
		s         workOSSettings
		wantErr   string
	}{
		{name: "not requested, nothing set", requested: false, s: workOSSettings{}},
		{name: "requested and complete", requested: true, s: full},
		{name: "requested, webhook optional", requested: true, s: full},
		{name: "requested, no client id", requested: true, s: workOSSettings{APIKey: "sk_test_fake"}, wantErr: envWorkOSClientID},
		{name: "requested, no api key", requested: true, s: workOSSettings{ClientID: "client_fake"}, wantErr: envWorkOSAPIKeyFile},
		{name: "requested, nothing", requested: true, s: workOSSettings{}, wantErr: " and "},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := requireWorkOSComplete(tc.requested, tc.s)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err=%v, want one containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestPortalWorkOSRequested(t *testing.T) {
	cases := []struct {
		value string
		want  bool
	}{
		{"", false}, {"0", false}, {"1", true}, {"true", true}, {"  1	", true}, {"yes", false},
	}
	for _, tc := range cases {
		if got := portalWorkOSRequested(fakeEnv(map[string]string{envPortalWorkOS: tc.value})); got != tc.want {
			t.Errorf("SBCI_PORTAL_WORKOS=%q: got %v, want %v", tc.value, got, tc.want)
		}
	}
}
