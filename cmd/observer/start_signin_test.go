package main

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/frontdoor"
)

func TestStartSignInHint(t *testing.T) {
	cases := []struct {
		name      string
		id        frontdoor.Identity
		connected bool
		dashboard bool
		want      string
	}{
		{"signed out, dashboard", frontdoor.IdentitySignedOut, false, true, "sign in on the dashboard, or run `observer connect`"},
		{"signed out, headless", frontdoor.IdentitySignedOut, false, false, "run `observer connect` to sign in"},
		{"signed in", frontdoor.IdentitySignedIn, false, true, ""},
		{"connected to a server", frontdoor.IdentitySignedOut, true, true, ""},
		{"no sign-in in this build", frontdoor.IdentityUnknown, false, true, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := strings.Join(startSignInHint(tc.id, tc.connected, tc.dashboard), "\n")
			if tc.want == "" {
				if got != "" {
					t.Fatalf("hint = %q, want none", got)
				}
				return
			}
			if !strings.Contains(got, tc.want) || !strings.Contains(got, "data stays on this machine until you connect it") {
				t.Fatalf("hint = %q", got)
			}
		})
	}
}

func TestWelcomeSignInLine(t *testing.T) {
	if got := welcomeSignInLine(frontdoor.IdentitySignedOut, false); got != "Not signed in. Run `observer connect` to see this machine online." {
		t.Fatalf("line = %q", got)
	}
	for _, tc := range []struct {
		id        frontdoor.Identity
		connected bool
	}{{frontdoor.IdentitySignedIn, false}, {frontdoor.IdentitySignedOut, true}, {frontdoor.IdentityUnknown, false}} {
		if got := welcomeSignInLine(tc.id, tc.connected); got != "" {
			t.Fatalf("%v/%v: line = %q, want none", tc.id, tc.connected, got)
		}
	}
}
