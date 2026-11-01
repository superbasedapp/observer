//go:build !sbo_omit_cloud_intelligence

package main

import (
	"context"
	"testing"
)

// TestCloudResultCursorResetOnAccountEvents pins T-962: the hosted results
// cursor ("v2:<n>") is a per-ACCOUNT sequence, so a cursor kept across a
// sign-in, a sign-out or an account deletion skips that many results of the
// next account (seen live: v2:13 against a fresh server). Every one of those
// commands clears the host's cursor; the full local wipes clear every host's.
func TestCloudResultCursorResetOnAccountEvents(t *testing.T) {
	const otherHost = "staging-cloud.example.test"
	cases := []struct {
		name string
		// login runs a dev-token sign-in first (the command needs a token).
		login     bool
		args      func(cfgPath, baseURL string) []string
		wantOther bool // true: the OTHER host's cursor survives
	}{
		{
			name: "login",
			args: func(c, u string) []string {
				return []string{"login", "--config", c, "--base-url", u, "--dev-token", "wtok"}
			},
			wantOther: true,
		},
		{
			name:      "logout",
			login:     true,
			args:      func(c, u string) []string { return []string{"logout", "--config", c, "--base-url", u} },
			wantOther: true,
		},
		{
			name:      "logout all hosts",
			login:     true,
			args:      func(c, u string) []string { return []string{"logout", "--config", c, "--base-url", u, "--all-hosts"} },
			wantOther: false,
		},
		{
			name:      "delete-account",
			login:     true,
			args:      func(c, u string) []string { return []string{"delete-account", "--config", c, "--base-url", u, "--yes"} },
			wantOther: true,
		},
		{
			name:      "delete-account local-only",
			args:      func(c, u string) []string { return []string{"delete-account", "--config", c, "--local-only"} },
			wantOther: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeCloudServer(t)
			cfgPath, dbPath, _ := writeCloudTestConfig(t)
			if tc.login {
				if out, err := runCloudCmd(t, "login", "--config", cfgPath, "--base-url", f.srv.URL, "--dev-token", "wtok"); err != nil {
					t.Fatalf("login: %v\n%s", err, out)
				}
			}
			host := cloudHostKey(f.srv.URL)
			ctx := context.Background()
			st, cleanup := openCloudTestStore(t, dbPath)
			if err := st.SaveCloudResultCursor(ctx, host, "v2:13"); err != nil {
				t.Fatalf("seed cursor: %v", err)
			}
			if err := st.SaveCloudResultCursor(ctx, otherHost, "v2:6"); err != nil {
				t.Fatalf("seed other cursor: %v", err)
			}
			cleanup()

			if out, err := runCloudCmd(t, tc.args(cfgPath, f.srv.URL)...); err != nil {
				t.Fatalf("%s: %v\n%s", tc.name, err, out)
			}

			st, cleanup = openCloudTestStore(t, dbPath)
			defer cleanup()
			if v, err := st.LoadCloudResultCursor(ctx, host); err != nil || v != "" {
				t.Errorf("host cursor after %s = %q (err %v), want cleared", tc.name, v, err)
			}
			other, err := st.LoadCloudResultCursor(ctx, otherHost)
			if err != nil {
				t.Fatalf("load other cursor: %v", err)
			}
			if tc.wantOther && other != "v2:6" {
				t.Errorf("other host's cursor = %q, want it kept (v2:6)", other)
			}
			if !tc.wantOther && other != "" {
				t.Errorf("other host's cursor = %q, want it cleared by the full wipe", other)
			}
		})
	}
}
