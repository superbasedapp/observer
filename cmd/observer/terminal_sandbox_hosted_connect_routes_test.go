//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
)

// terminal_sandbox_hosted_connect_routes_test.go pins the Hosted sandboxes
// panel's Connect form (dashboard CLI parity item B-G2): the fields are
// checked by name, a refusal never carries a value, the write needs the
// confirm token, and the credential is stored bound to the endpoint like the
// CLI's connect.

func TestHostedConnectFields(t *testing.T) {
	modal, _ := sandboxremote.VendorFor(sandboxremote.VendorModal)
	const secret = "tok_FAKEVALUE_42"
	cases := []struct {
		name string
		in   map[string]string
		want string // a word of the refusal; "" passes
	}{
		{"both fields", map[string]string{"MODAL_TOKEN_ID": "ak-1", "MODAL_TOKEN_SECRET": secret}, ""},
		{"a field missing", map[string]string{"MODAL_TOKEN_ID": "ak-1"}, "MODAL_TOKEN_SECRET is required"},
		{"a blank field", map[string]string{"MODAL_TOKEN_ID": "  ", "MODAL_TOKEN_SECRET": secret}, "MODAL_TOKEN_ID is required"},
		{"an unknown field", map[string]string{"MODAL_TOKEN_ID": "ak-1", "MODAL_TOKEN_SECRET": secret, "HOME": "/x"}, "not HOME"},
		{"a line break", map[string]string{"MODAL_TOKEN_ID": "ak-1", "MODAL_TOKEN_SECRET": secret + "\nX"}, "not a credential value"},
		{"too long", map[string]string{"MODAL_TOKEN_ID": "ak-1", "MODAL_TOKEN_SECRET": strings.Repeat("a", hostedConnectMaxValue+1)}, "not a credential value"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := hostedConnectFields(modal, tc.in)
			if tc.want == "" {
				if err != nil || got["MODAL_TOKEN_SECRET"] != secret {
					t.Fatalf("fields = %v, %v", len(got), err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("refusal = %v, want %q", err, tc.want)
			}
			if strings.Contains(err.Error(), "FAKEVALUE") {
				t.Fatalf("a refusal carries a value: %v", err)
			}
		})
	}
}

// hostedConnectPostTo posts body to h at path with or without the confirm
// token.
func hostedConnectPostTo(h http.HandlerFunc, path, body string, confirm bool) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
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

func TestHostedConnectRoute(t *testing.T) {
	obs, c := hostedLeftoverEnv(t)
	hostedActiveForTest(t, true)
	keys := hostedTestEnv(t, nil)
	cfgPath := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(cfgPath, []byte("[terminal.sandbox]\nenabled = true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	connect := hostedConnectHandler(cfgPath)
	const secret = "e2b_FAKEVALUE_connect"
	body := `{"provider":"e2b","fields":{"E2B_API_KEY":"` + secret + `"}}`

	if w := hostedConnectPostTo(connect, "/api/terminal/sandbox/hosted/connect", body, false); w.Code != http.StatusForbidden || len(keys.m) != 0 {
		t.Fatalf("a connect without the confirm token: %d, stored %d", w.Code, len(keys.m))
	}
	if w := hostedConnectPostTo(connect, "/api/terminal/sandbox/hosted/connect", `{"provider":"nope","fields":{}}`, true); w.Code != http.StatusBadRequest {
		t.Fatalf("an unknown provider: %d %s", w.Code, w.Body.String())
	}
	// A field the provider does not take is refused by name (hostedConnectFields).
	if w := hostedConnectPostTo(connect, "/api/terminal/sandbox/hosted/connect", `{"provider":"e2b","fields":{"E2B_API_KEY":"`+secret+`","HOME":"/x"}}`, true); w.Code != http.StatusBadRequest || strings.Contains(w.Body.String(), "FAKEVALUE") || len(keys.m) != 0 {
		t.Fatalf("an unknown field: %d %s, stored %d", w.Code, w.Body.String(), len(keys.m))
	}
	w := hostedConnectPostTo(connect, "/api/terminal/sandbox/hosted/connect", body, true)
	if w.Code != http.StatusOK {
		t.Fatalf("connect = %d %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "FAKEVALUE") || !strings.Contains(w.Body.String(), `"endpoint":"https://`) {
		t.Fatalf("connect answer = %s (a value, or no endpoint)", w.Body.String())
	}
	v, _ := sandboxremote.VendorFor(sandboxremote.VendorE2B)
	if hostedCredentialSource(obs, v) != sandboxremote.SourceKeystore || len(keys.m) != 1 {
		t.Fatalf("connect did not store the credential: source %q, keys %d", hostedCredentialSource(obs, v), len(keys.m))
	}
	cred, err := hostedResolveCredential(obs, v)
	if err != nil || cred.Fields["E2B_API_KEY"] != secret || cred.Endpoint == "" {
		t.Fatalf("stored credential = endpoint %q, %v", cred.Endpoint, err)
	}

	if w := hostedConnectPostTo(hostedDisconnectHandler, "/api/terminal/sandbox/hosted/disconnect", `{"provider":"e2b"}`, true); w.Code != http.StatusNoContent {
		t.Fatalf("disconnect = %d %s", w.Code, w.Body.String())
	}
	if hostedCredentialSource(obs, v) == sandboxremote.SourceKeystore || len(keys.m) != 0 {
		t.Fatal("disconnect left the credential or its marker")
	}
	if len(c.calls) != 0 {
		t.Fatalf("connect or disconnect called the provider: %v", c.calls)
	}
}
