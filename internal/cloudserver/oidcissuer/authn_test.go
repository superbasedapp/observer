package oidcissuer

import (
	"net/url"
	"strconv"
	"testing"
	"time"
)

// authn_test.go: one case per authnRules row (each matched by that row and
// no earlier one), the coverage check, and the parsers the rows read.

func TestAuthnRulesOneCasePerRow(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	session := func(age time.Duration) authnFacts {
		return authnFacts{SignedIn: true, AuthTime: now.Add(-age), Now: now}
	}
	cases := []struct {
		rule string
		f    authnFacts
		want authnDecision
	}{
		{"no-session-prompt-none", authnFacts{PromptNone: true, Now: now}, authnLoginRequired},
		{"no-session-freshness-asked", authnFacts{PromptLogin: true, Now: now}, authnFreshSignIn},
		{"no-session", authnFacts{Now: now}, authnSignIn},
		{"reauth-done", func() authnFacts {
			f := session(5 * time.Second)
			f.PromptLogin, f.HasMaxAge, f.ReauthAt = true, true, now.Add(-30*time.Second)
			return f
		}(), authnIssue},
		{"prompt-login", func() authnFacts { f := session(time.Second); f.PromptLogin = true; return f }(), authnFreshSignIn},
		{"stale-prompt-none", func() authnFacts {
			f := session(10 * time.Minute)
			f.PromptNone, f.HasMaxAge, f.MaxAge = true, true, 5*time.Minute
			return f
		}(), authnLoginRequired},
		{"stale", func() authnFacts {
			f := session(10 * time.Minute)
			f.HasMaxAge, f.MaxAge = true, 5*time.Minute
			return f
		}(), authnFreshSignIn},
		{"session-fresh-enough", session(time.Hour), authnIssue},
	}
	seen := map[string]bool{}
	for _, tc := range cases {
		d, rule := decideAuthn(tc.f)
		if rule != tc.rule || d != tc.want {
			t.Errorf("case %s: got %v (%s), want %v", tc.rule, d, rule, tc.want)
		}
		seen[tc.rule] = true
	}
	var ids []string
	for _, r := range authnRules {
		ids = append(ids, r.ID)
	}
	coverage(t, "authnRules", ids, seen)
}

// TestAuthnDecisions walks the decisions that matter for conformance through
// factsFor, from a request's prompt / max_age and the session.
func TestAuthnDecisions(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	marker := func(d time.Duration) string { return strconv.FormatInt(now.Add(d).Unix(), 10) }
	cases := []struct {
		name                     string
		prompt, maxAge, reauthAt string
		account                  string
		authAge                  time.Duration // session authenticated this long ago
		unknownAuthTime          bool
		want                     authnDecision
	}{
		{name: "no session, nothing asked", want: authnSignIn},
		{name: "no session, max_age", maxAge: "600", want: authnFreshSignIn},
		{name: "no session, prompt=none", prompt: "none", want: authnLoginRequired},
		{name: "session, nothing asked", account: "a", authAge: 20 * time.Hour, want: authnIssue},
		{name: "session within max_age", account: "a", maxAge: "300", authAge: 299 * time.Second, want: authnIssue},
		{name: "session older than max_age", account: "a", maxAge: "300", authAge: 301 * time.Second, want: authnFreshSignIn},
		{name: "max_age=0 always re-authenticates", account: "a", maxAge: "0", authAge: time.Second, want: authnFreshSignIn},
		{name: "prompt=login re-authenticates a brand-new session", account: "a", prompt: "login", want: authnFreshSignIn},
		{name: "prompt=none and stale", account: "a", prompt: "none", maxAge: "0", authAge: time.Second, want: authnLoginRequired},
		{name: "prompt=none and fresh enough", account: "a", prompt: "none", maxAge: "60", authAge: time.Second, want: authnIssue},
		// An unknown authentication time (an ordinary AuthKit sign-in) is
		// fine when nobody asked, and never good enough when someone did.
		{name: "unknown session auth time, nothing asked", account: "a", unknownAuthTime: true, want: authnIssue},
		{name: "unknown session auth time, prompt=none alone", account: "a", prompt: "none", unknownAuthTime: true, want: authnIssue},
		{name: "unknown session auth time, max_age", account: "a", maxAge: "86400", unknownAuthTime: true, want: authnFreshSignIn},
		{name: "unknown session auth time, prompt=login", account: "a", prompt: "login", unknownAuthTime: true, want: authnFreshSignIn},
		{
			name: "unknown session auth time, prompt=none and max_age", account: "a", prompt: "none", maxAge: "86400",
			unknownAuthTime: true, want: authnLoginRequired,
		},
		{
			name: "unknown session auth time is never the demanded sign-in", account: "a", prompt: "login", maxAge: "0",
			reauthAt: marker(-20 * time.Second), unknownAuthTime: true, want: authnFreshSignIn,
		},
		{
			name: "resumed after the demanded sign-in", account: "a", prompt: "login", maxAge: "0",
			reauthAt: marker(-20 * time.Second), authAge: 5 * time.Second, want: authnIssue,
		},
		{
			name: "resumed, but the session predates the demand", account: "a", prompt: "login", maxAge: "0",
			reauthAt: marker(-20 * time.Second), authAge: 20*time.Second + ReauthSkew + time.Second, want: authnFreshSignIn,
		},
		{
			name: "resumed within the skew before the demand", account: "a", prompt: "login",
			reauthAt: marker(-20 * time.Second), authAge: 20*time.Second + ReauthSkew - time.Second, want: authnIssue,
		},
		{
			name: "marker older than the window is ignored", account: "a", prompt: "login",
			reauthAt: marker(-ReauthWindow - time.Second), authAge: ReauthWindow, want: authnFreshSignIn,
		},
		{
			name: "marker from the future is ignored", account: "a", prompt: "login",
			reauthAt: marker(ReauthSkew + time.Minute), authAge: time.Second, want: authnFreshSignIn,
		},
		{name: "garbage marker is ignored", account: "a", prompt: "login", reauthAt: "yesterday", want: authnFreshSignIn},
	}
	for _, tc := range cases {
		s := Session{AccountID: tc.account}
		if tc.account != "" && !tc.unknownAuthTime {
			s.AuthTime = now.Add(-tc.authAge)
		}
		r := validAuthorize()
		r.Prompt, r.MaxAge, r.ReauthAt = tc.prompt, tc.maxAge, tc.reauthAt
		if e := checkAuthorizeRequest(r); e != nil {
			t.Fatalf("%s: request refused: %v", tc.name, e)
		}
		if d, rule := decideAuthn(factsFor(r, s, now)); d != tc.want {
			t.Errorf("%s: got %v (%s), want %v", tc.name, d, rule, tc.want)
		}
	}
}

// TestAuthnNeverIssuesUnknownTimeWhenFreshnessAsked walks every combination
// of the facts the rules read and checks the property Issuer.Authorize also
// asserts: no row issues a code from a session of unknown authentication time
// when the request asked for freshness (prompt=login or max_age), so a token
// for such a request always carries auth_time (OIDC Core 3.1.2.1).
func TestAuthnNeverIssuesUnknownTimeWhenFreshnessAsked(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	bools := []bool{false, true}
	authTimes := []time.Time{{}, now.Add(-time.Second), now.Add(-2 * time.Hour)}
	maxAges := []struct {
		d   time.Duration
		has bool
	}{{0, false}, {0, true}, {5 * time.Minute, true}}
	reauths := []time.Time{{}, now.Add(-time.Minute)}
	for _, signedIn := range bools {
		for _, at := range authTimes {
			for _, none := range bools {
				for _, login := range bools {
					for _, ma := range maxAges {
						for _, ra := range reauths {
							f := authnFacts{
								SignedIn: signedIn, AuthTime: at, PromptNone: none, PromptLogin: login,
								MaxAge: ma.d, HasMaxAge: ma.has, ReauthAt: ra, Now: now,
							}
							if !signedIn {
								f.AuthTime = time.Time{}
							}
							d, rule := decideAuthn(f)
							if d == authnIssue && f.freshnessAsked() && f.AuthTime.IsZero() {
								t.Errorf("%+v: issued by %s with no authentication time", f, rule)
							}
							if d == authnIssue && !signedIn {
								t.Errorf("%+v: issued by %s with no session", f, rule)
							}
						}
					}
				}
			}
		}
	}
}

func TestParseMaxAge(t *testing.T) {
	t.Parallel()
	cases := []struct {
		raw         string
		d           time.Duration
		present, ok bool
	}{
		{"", 0, false, true},
		{"0", 0, true, true},
		{"900", 900 * time.Second, true, true},
		{"0012", 12 * time.Second, true, true},
		{"3153600000", maxMaxAge, true, true},
		{"9999999999", maxMaxAge, true, true},
		{"10000000000", 0, false, false},
		{"-1", 0, false, false},
		{"+5", 0, false, false},
		{"1.5", 0, false, false},
		{" 5", 0, false, false},
		{"5s", 0, false, false},
	}
	for _, tc := range cases {
		d, present, ok := parseMaxAge(tc.raw)
		if d != tc.d || present != tc.present || ok != tc.ok {
			t.Errorf("parseMaxAge(%q) = %v %v %v, want %v %v %v", tc.raw, d, present, ok, tc.d, tc.present, tc.ok)
		}
	}
}

func TestPromptValues(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		prompt          string
		supported, none bool
	}{
		{"", true, false},
		{"login", true, false},
		{"none", true, false},
		{"login none", true, true},
		{"consent", false, false},
		{"select_account", false, false},
		{"create", false, false},
		{"login  login", true, false},
	} {
		if got := promptSupported(tc.prompt); got != tc.supported {
			t.Errorf("promptSupported(%q) = %v", tc.prompt, got)
		}
		if got := promptNoneWithOthers(tc.prompt); got != tc.none {
			t.Errorf("promptNoneWithOthers(%q) = %v", tc.prompt, got)
		}
	}
}

func TestResumeQueryMarksTheRequest(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	q := url.Values{"client_id": {"org:x"}, "prompt": {"login"}, ReauthParam: {"1"}}
	got, err := url.ParseQuery(ResumeQuery(q, at))
	if err != nil {
		t.Fatal(err)
	}
	if got.Get(ReauthParam) != strconv.FormatInt(at.Unix(), 10) || len(got[ReauthParam]) != 1 ||
		got.Get("client_id") != "org:x" || got.Get("prompt") != "login" {
		t.Errorf("ResumeQuery = %v", got)
	}
	if q.Get(ReauthParam) != "1" {
		t.Error("ResumeQuery mutated its input")
	}
	// The marker the issuer adds is a parameter the request rules see, so a
	// duplicated marker is refused like any other parameter.
	dup := url.Values{ReauthParam: {"1", "2"}}
	if d := ParseAuthorizeQuery(dup).Duplicated; len(d) != 1 || d[0] != ReauthParam {
		t.Errorf("duplicated marker = %v", d)
	}
}
