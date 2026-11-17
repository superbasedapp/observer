//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
)

// hostedConnectRig sets a temp HOME, a fake keystore, an active hosted
// driver and the e2b registration, and returns the route handler.
func hostedConnectRig(t *testing.T) (http.HandlerFunc, *fakeHostedKeys, string) {
	t.Helper()
	obs, _ := hostedLeftoverEnv(t)
	keys := hostedTestEnv(t, map[string]string{})
	hostedActiveForTest(t, true)
	cfgPath := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(cfgPath, []byte("[terminal.sandbox]\nenabled = true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var h http.HandlerFunc
	for _, rt := range hostedDashboardRoutes(cfgPath) {
		if rt.Pattern == "POST /api/terminal/sandbox/hosted/connect" {
			if rt.Capability.String() != "local" {
				t.Fatalf("connect route is %s, want local", rt.Capability)
			}
			h = rt.Handler
		}
	}
	if h == nil {
		t.Fatal("the hosted route list has no connect route")
	}
	return h, keys, obs
}

func hostedConnectPost(h http.HandlerFunc, body string, confirm bool) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/terminal/sandbox/hosted/connect", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if confirm {
		tok := strings.Repeat("ab", 32)
		req.AddCookie(&http.Cookie{Name: hostedConfirmCookie, Value: tok})
		req.Header.Set(hostedConfirmHeader, tok)
	}
	w := httptest.NewRecorder()
	h(w, req)
	return w
}

// TestHostedConnectRouteStoresTheKey: a confirmed POST stores the key in the
// (fake) keystore, bound to the endpoint, and writes the connected marker;
// the answer never echoes the key and the log never names it.
func TestHostedConnectRouteStoresTheKey(t *testing.T) {
	h, keys, obs := hostedConnectRig(t)
	var logs syncBuffer // the default logger is process-wide: a relay goroutine from another test may write it (L-4)
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(old) })
	const key = "e2b_SECRET_typed_key_1"
	w := hostedConnectPost(h, `{"provider":"e2b","key":"`+key+`"}`, true)
	if w.Code != http.StatusOK {
		t.Fatalf("connect = %d %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), key) || strings.Contains(logs.String(), key) {
		t.Fatalf("the key leaked: body %q logs %q", w.Body.String(), logs.String())
	}
	raw, ok := keys.m[sandboxremote.KeystoreName]
	if !ok || !strings.Contains(raw, key) {
		t.Fatalf("the keystore holds %q", raw)
	}
	if _, err := os.Stat(hostedConnectedMarker(obs, sandboxremote.VendorE2B)); err != nil {
		t.Fatalf("no connected marker: %v", err)
	}
}

// TestHostedConnectRouteRefusals: no confirm token, an unknown field, an
// unknown provider and an empty key are refused, nothing is stored and the
// key is never echoed.
func TestHostedConnectRouteRefusals(t *testing.T) {
	h, keys, _ := hostedConnectRig(t)
	const key = "e2b_SECRET_never_echoed"
	cases := []struct {
		name    string
		body    string
		confirm bool
		want    int
	}{
		{"no confirm token", `{"provider":"e2b","key":"` + key + `"}`, false, http.StatusForbidden},
		{"unknown field", `{"provider":"e2b","key":"` + key + `","argv":["x"]}`, true, http.StatusBadRequest},
		{"unknown provider", `{"provider":"nope","key":"` + key + `"}`, true, http.StatusBadRequest},
		{"empty key", `{"provider":"e2b","key":"  "}`, true, http.StatusBadRequest},
		{"two objects", `{"provider":"e2b","key":"` + key + `"} {}`, true, http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := hostedConnectPost(h, tc.body, tc.confirm)
			if w.Code != tc.want {
				t.Fatalf("= %d %s", w.Code, w.Body.String())
			}
			if strings.Contains(w.Body.String(), key) {
				t.Fatalf("the key was echoed: %s", w.Body.String())
			}
		})
	}
	if len(keys.m) != 0 {
		t.Fatalf("a refused request stored something: %v", keys.m)
	}
}

// TestHostedConnectStoreRefusesWhenInactive: with no hosted driver active
// the store path refuses, as the CLI verbs do.
func TestHostedConnectStoreRefusesWhenInactive(t *testing.T) {
	hostedConnectRig(t)
	hostedActiveForTest(t, false)
	err := hostedConnectStore(context.Background(), "", sandboxremote.VendorE2B, map[string]string{"": "k"})
	if err == nil || !strings.Contains(err.Error(), "not active") {
		t.Fatalf("err = %v", err)
	}
}
