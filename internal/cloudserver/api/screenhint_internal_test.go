package api

import (
	"net/url"
	"testing"
)

// TestParseScreenHint is one case per screenHints row plus every refused
// shape: the start route accepts a closed enum and refuses anything else.
func TestParseScreenHint(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		query string
		want  string
		ok    bool
	}{
		{"absent", "", "", true},
		{"sign-in (the default screen, sends nothing)", "screen_hint=sign-in", "", true},
		{"sign-up", "screen_hint=sign-up", "sign-up", true},
		{"unknown value", "screen_hint=register", "", false},
		{"empty value", "screen_hint=", "", false},
		{"wrong case", "screen_hint=Sign-Up", "", false},
		{"repeated", "screen_hint=sign-up&screen_hint=sign-up", "", false},
	}
	seen := map[string]bool{}
	for _, tc := range cases {
		q, err := url.ParseQuery(tc.query)
		if err != nil {
			t.Fatalf("%s: parse %q: %v", tc.name, tc.query, err)
		}
		got, ok := parseScreenHint(q)
		if got != tc.want || ok != tc.ok {
			t.Errorf("%s: parseScreenHint(%q) = %q,%v, want %q,%v", tc.name, tc.query, got, ok, tc.want, tc.ok)
		}
		if ok {
			if v := q.Get(screenHintParam); v != "" {
				seen[v] = true
			}
		}
	}
	for k := range screenHints {
		if !seen[k] {
			t.Errorf("screenHints row %q has no accepting case", k)
		}
	}
}

// TestWorkOSAuthorizeURLScreenHint pins that the authorize request carries
// screen_hint=sign-up only for a sign-up, always beside provider=authkit (the
// only provider WorkOS accepts screen_hint with), and that the rest of the
// request is the same with or without it.
func TestWorkOSAuthorizeURLScreenHint(t *testing.T) {
	t.Parallel()
	s := &Server{workOSAuthorizeURL: "https://api.workos.com/user_management/authorize", workOSClientID: "client_test"}
	cases := []struct {
		name       string
		screenHint string
		reauth     bool
		wantHint   string
	}{
		{"plain sign-in", "", false, ""},
		{"sign-up", workOSScreenSignUp, false, "sign-up"},
		{"sign-up with a forced fresh sign-in", workOSScreenSignUp, true, "sign-up"},
		{"forced fresh sign-in alone", "", true, ""},
	}
	for _, tc := range cases {
		raw := s.workOSAuthorizeURLFor("https://cloud.example/portal/auth/workos/callback", "chal", "st", "no", tc.reauth, tc.screenHint)
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("%s: parse %q: %v", tc.name, raw, err)
		}
		q := u.Query()
		_, has := q[screenHintParam]
		if q.Get(screenHintParam) != tc.wantHint || has != (tc.wantHint != "") {
			t.Errorf("%s: screen_hint=%q present=%v, want %q", tc.name, q.Get(screenHintParam), has, tc.wantHint)
		}
		if q.Get("provider") != "authkit" {
			t.Errorf("%s: provider=%q, want authkit", tc.name, q.Get("provider"))
		}
		if q.Get("response_type") != "code" || q.Get("client_id") != "client_test" || q.Get("code_challenge_method") != "S256" ||
			q.Get("state") != "st" || q.Get("nonce") != "no" {
			t.Errorf("%s: authorize request malformed: %v", tc.name, q)
		}
		if (q.Get("prompt") == "login") != tc.reauth {
			t.Errorf("%s: prompt=%q with reauth=%v", tc.name, q.Get("prompt"), tc.reauth)
		}
	}
}
