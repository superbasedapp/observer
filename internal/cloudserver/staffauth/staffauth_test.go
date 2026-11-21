package staffauth

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestAuthorizeTable(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	fresh := now.Add(-FreshAssertionWindow + time.Second)
	stale := now.Add(-FreshAssertionWindow - time.Second)
	cases := []struct {
		name     string
		role     Role
		action   Action
		asserted time.Time
		want     Decision
	}{
		{"support reads self", RoleSupport, ActionReadSelf, stale, Decision{Allowed: true}},
		{"support signs out", RoleSupport, ActionSignOut, stale, Decision{Allowed: true}},
		{"support reads the log", RoleSupport, ActionReadLog, stale, Decision{Allowed: true}},
		{"support reads availability", RoleSupport, ActionReadAvailability, stale, Decision{Allowed: true}},
		{"support may not write availability", RoleSupport, ActionWriteAvailability, fresh, Decision{Code: CodeForbiddenRole}},
		{"ops writes availability when fresh", RoleOps, ActionWriteAvailability, fresh, Decision{Allowed: true}},
		{"ops refused when stale", RoleOps, ActionWriteAvailability, stale, Decision{Code: CodeReauthRequired}},
		{"admin writes availability when fresh", RoleAdmin, ActionWriteAvailability, fresh, Decision{Allowed: true}},
		{"admin refused when stale", RoleAdmin, ActionWriteAvailability, stale, Decision{Code: CodeReauthRequired}},
		{"zero assertion time is stale", RoleAdmin, ActionWriteAvailability, time.Time{}, Decision{Code: CodeReauthRequired}},
		{"exactly at the window is fresh", RoleAdmin, ActionWriteAvailability, now.Add(-FreshAssertionWindow), Decision{Allowed: true}},
		{"support signs in as support when fresh", RoleSupport, ActionSupportSignIn, fresh, Decision{Allowed: true}},
		{"support sign-in refused when stale", RoleSupport, ActionSupportSignIn, stale, Decision{Code: CodeReauthRequired}},
		{"ops signs in as support when fresh", RoleOps, ActionSupportSignIn, fresh, Decision{Allowed: true}},
		{"support reads the deletions", RoleSupport, ActionReadDeletions, stale, Decision{Allowed: true}},
		{"support reads the team allow-list", RoleSupport, ActionReadTeamAllowlist, stale, Decision{Allowed: true}},
		{"support may not change the team allow-list", RoleSupport, ActionWriteTeamAllowlist, fresh, Decision{Code: CodeForbiddenRole}},
		{"ops changes the team allow-list when fresh", RoleOps, ActionWriteTeamAllowlist, fresh, Decision{Allowed: true}},
		{"team allow-list change refused when stale", RoleAdmin, ActionWriteTeamAllowlist, stale, Decision{Code: CodeReauthRequired}},
		{"support reads orgs when stale", RoleSupport, ActionReadOrgs, stale, Decision{Allowed: true}},
		{"admin reads orgs", RoleAdmin, ActionReadOrgs, stale, Decision{Allowed: true}},
		{"unknown role", Role("root"), ActionReadSelf, fresh, Decision{Code: CodeForbiddenRole}},
		{"unknown action", RoleAdmin, Action("orgs.delete"), fresh, Decision{Code: CodeUnknownAction}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if got := Authorize(c.role, c.action, c.asserted, now); got != c.want {
				t.Fatalf("Authorize(%s, %s) = %+v, want %+v", c.role, c.action, got, c.want)
			}
		})
	}
}

// TestEveryActionHasOneRule pins that each declared action has exactly one
// row and that every mutation row requires a fresh assertion.
func TestEveryActionHasOneRule(t *testing.T) {
	t.Parallel()
	// A support sign-in is held to the mutation rule: it mints a credential
	// for a tenant (design m6.0 4.9, the claim only with a fresh assertion).
	mutations := map[Action]bool{ActionWriteAvailability: true, ActionSupportSignIn: true, ActionWriteTeamAllowlist: true}
	all := []Action{
		ActionReadSelf, ActionSignOut, ActionReadLog, ActionReadAvailability, ActionWriteAvailability, ActionSupportSignIn,
		ActionReadDeletions, ActionReadTeamAllowlist, ActionWriteTeamAllowlist, ActionReadOrgs,
	}
	for _, a := range all {
		n := 0
		for _, r := range actionRules {
			if r.action == a {
				n++
				if mutations[a] && !r.fresh {
					t.Errorf("mutation %s does not require a fresh assertion", a)
				}
			}
		}
		if n != 1 {
			t.Errorf("action %s has %d rules, want 1", a, n)
		}
	}
	if len(actionRules) != len(all) {
		t.Errorf("actionRules has %d rows, %d actions declared", len(actionRules), len(all))
	}
}

func TestParseRole(t *testing.T) {
	t.Parallel()
	for _, r := range KnownRoles {
		if got, err := ParseRole(string(r)); err != nil || got != r {
			t.Errorf("ParseRole(%s) = %s, %v", r, got, err)
		}
	}
	for _, bad := range []string{"", "Admin", "root", "admin "} {
		if _, err := ParseRole(bad); err == nil {
			t.Errorf("ParseRole(%q) accepted", bad)
		}
	}
}

func TestCheckSignCountTable(t *testing.T) {
	t.Parallel()
	cases := []struct {
		stored, presented uint32
		ok                bool
	}{
		{0, 0, true},
		{0, 1, true},
		{5, 6, true},
		{5, 5, false},
		{5, 4, false},
		{5, 0, false},
		{4294967294, 4294967295, true},
	}
	for _, c := range cases {
		err := CheckSignCount(c.stored, c.presented)
		if (err == nil) != c.ok {
			t.Errorf("CheckSignCount(%d, %d) = %v, want ok=%v", c.stored, c.presented, err, c.ok)
		}
		if err != nil && !errors.Is(err, ErrCounterRegression) {
			t.Errorf("CheckSignCount(%d, %d) error %v is not ErrCounterRegression", c.stored, c.presented, err)
		}
	}
}

func TestCredentialID(t *testing.T) {
	t.Parallel()
	id := []byte("credential-0123456789")
	enc := base64.RawURLEncoding.EncodeToString(id)
	long := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, MaxCredentialIDBytes+1))
	cases := []struct {
		name string
		body string
		ok   bool
	}{
		{"well formed", `{"id":"` + enc + `","rawId":"` + enc + `","type":"public-key","response":{}}`, true},
		{"wrong type", `{"id":"` + enc + `","rawId":"` + enc + `","type":"password"}`, false},
		{"id differs from rawId", `{"id":"AAAA","rawId":"` + enc + `","type":"public-key"}`, false},
		{"empty id", `{"id":"","rawId":"","type":"public-key"}`, false},
		{"padded base64", `{"id":"` + enc + `==","rawId":"` + enc + `==","type":"public-key"}`, false},
		{"too long", `{"id":"` + long + `","rawId":"` + long + `","type":"public-key"}`, false},
		{"not JSON", `nope`, false},
		{"empty", ``, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			got, err := CredentialID([]byte(c.body))
			if c.ok {
				if err != nil || !bytes.Equal(got, id) {
					t.Fatalf("CredentialID = %x, %v; want %x", got, err, id)
				}
				return
			}
			if !errors.Is(err, ErrMalformedCredential) {
				t.Fatalf("CredentialID = %v, want ErrMalformedCredential", err)
			}
		})
	}
	if _, err := CredentialID(bytes.Repeat([]byte(" "), MaxResponseBytes+1)); !errors.Is(err, ErrMalformedCredential) {
		t.Fatalf("oversized response = %v, want ErrMalformedCredential", err)
	}
}

func TestCeremonyOptions(t *testing.T) {
	t.Parallel()
	challenge := bytes.Repeat([]byte{7}, ChallengeBytes)
	handle := bytes.Repeat([]byte{9}, 16)
	c := NewCreationOptions(RegistrationCeremony{RPID: "app.example", Origin: "https://app.example", Challenge: challenge, UserHandle: handle},
		"Ops One", [][]byte{{1, 2, 3}}, 2*time.Minute)
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`"rp":{"id":"app.example","name":"` + RPName + `"}`,
		`"challenge":"` + base64.RawURLEncoding.EncodeToString(challenge) + `"`,
		`"user":{"id":"` + base64.RawURLEncoding.EncodeToString(handle) + `","name":"Ops One","displayName":"Ops One"}`,
		`"excludeCredentials":[{"type":"public-key","id":"AQID"}]`,
		`"residentKey":"required"`, `"userVerification":"required"`, `"attestation":"none"`,
		`"timeout":120000`, `{"type":"public-key","alg":-7}`,
	} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("creation options missing %s:\n%s", want, raw)
		}
	}
	r := NewRequestOptions(AssertionCeremony{RPID: "app.example", Challenge: challenge}, time.Minute)
	raw, err = json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"rpId":"app.example"`, `"allowCredentials":[]`, `"userVerification":"required"`, `"timeout":60000`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("request options missing %s:\n%s", want, raw)
		}
	}
}

func TestNewChallenge(t *testing.T) {
	t.Parallel()
	c, err := NewChallenge(bytes.NewReader(bytes.Repeat([]byte{3}, ChallengeBytes)))
	if err != nil || len(c) != ChallengeBytes {
		t.Fatalf("NewChallenge = %d bytes, %v", len(c), err)
	}
	if _, err := NewChallenge(bytes.NewReader([]byte{1})); err == nil {
		t.Fatal("a short reader was accepted")
	}
}

func TestUnavailableVerifiesNothing(t *testing.T) {
	t.Parallel()
	var v Verifier = Unavailable{}
	if v.Available() {
		t.Fatal("Unavailable reports available")
	}
	if _, err := v.VerifyRegistration(RegistrationCeremony{}, []byte("{}")); !errors.Is(err, ErrNotAvailable) {
		t.Fatalf("VerifyRegistration = %v", err)
	}
	if _, err := v.VerifyAssertion(AssertionCeremony{}, StoredCredential{}, []byte("{}")); !errors.Is(err, ErrNotAvailable) {
		t.Fatalf("VerifyAssertion = %v", err)
	}
}

func TestValidateReason(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"incident 42: pause ingest", "incident 42: pause ingest", true},
		{"  padded\n", "padded", true},
		{"line one\nline two\ttabbed", "line one\nline two\ttabbed", true},
		{"", "", false},
		{"   \n\t", "", false},
		{"bell\a", "", false},
		{"del\x7f", "", false},
		{strings.Repeat("é", MaxReasonRunes), strings.Repeat("é", MaxReasonRunes), true},
		{strings.Repeat("x", MaxReasonRunes+1), "", false},
		{"bad \xff utf8", "", false},
	}
	for _, c := range cases {
		got, err := ValidateReason(c.in)
		if (err == nil) != c.ok || got != c.want {
			t.Errorf("ValidateReason(%q) = %q, %v; want %q ok=%v", c.in, got, err, c.want, c.ok)
		}
	}
	if _, err := ValidateReason(" "); !errors.Is(err, ErrReasonRequired) {
		t.Errorf("blank reason error = %v, want ErrReasonRequired", err)
	}
}

func TestValidateAvailabilityInput(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, section, key, value string
		want                      string
		ok                        bool
	}{
		{"component reach", "components", "codeintel", `{ "reach": "cohort", "cohort": "internal" }`, `{"reach":"cohort","cohort":"internal"}`, true},
		{"org control", "org_controls", "1b4e28ba-2fa1-11d2-883f-0016d3cca427", `{"ingest":"pause"}`, `{"ingest":"pause"}`, true},
		{"release flag", "release_flags", "new.ui:v2", `{}`, `{}`, true},
		{"unknown section", "kill_switches", "x", `{}`, "", false},
		{"key with a slash", "components", "a/b", `{}`, "", false},
		{"empty key", "components", "", `{}`, "", false},
		{"array value", "components", "x", `[1]`, "", false},
		{"string value", "components", "x", `"on"`, "", false},
		{"null value", "components", "x", `null`, "", false},
		{"broken JSON", "components", "x", `{"a":`, "", false},
		{"empty value", "components", "x", ``, "", false},
		{"too large", "components", "x", `{"a":"` + strings.Repeat("z", MaxAvailabilityValueBytes) + `"}`, "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			got, err := ValidateAvailabilityInput(c.section, c.key, []byte(c.value))
			if (err == nil) != c.ok {
				t.Fatalf("err = %v, want ok=%v", err, c.ok)
			}
			if c.ok && (string(got.Value) != c.want || string(got.Section) != c.section || got.Key != c.key) {
				t.Fatalf("got %+v (%s), want value %s", got, got.Value, c.want)
			}
		})
	}
}

func TestVocabularies(t *testing.T) {
	t.Parallel()
	for _, v := range KnownVerbs {
		if !v.Known() {
			t.Errorf("verb %s not Known", v)
		}
	}
	if Verb("staff.deleted").Known() {
		t.Error("an undeclared verb is Known")
	}
	for _, s := range KnownSections {
		if got, err := ParseSection(string(s)); err != nil || got != s {
			t.Errorf("ParseSection(%s) = %s, %v", s, got, err)
		}
	}
	if Actor("abc") != "staff:abc" || ActorOperator != "operator" {
		t.Error("actor forms changed")
	}
}

// TestCheckPasskeyCap pins ruling Staff 2 (L-83): five active passkeys at
// most, one case per side of the boundary.
func TestCheckPasskeyCap(t *testing.T) {
	t.Parallel()
	if MaxActivePasskeys != 5 {
		t.Fatalf("MaxActivePasskeys = %d, want 5 (operator ruling Staff 2)", MaxActivePasskeys)
	}
	for _, c := range []struct {
		active int
		refuse bool
	}{{0, false}, {1, false}, {4, false}, {5, true}, {6, true}, {12, true}} {
		got := CheckPasskeyCap(c.active)
		if c.refuse != errors.Is(got, ErrPasskeyLimit) || (!c.refuse && got != nil) {
			t.Errorf("CheckPasskeyCap(%d) = %v, want refused=%v", c.active, got, c.refuse)
		}
	}
	if !strings.Contains(ErrPasskeyLimit.Error(), "at most 5") {
		t.Errorf("the refusal does not name the cap: %v", ErrPasskeyLimit)
	}
}

// TestCapabilitiesAgreeWithAuthorize: the UI's capability view never says
// more or less than the gate, for every role and action.
func TestCapabilitiesAgreeWithAuthorize(t *testing.T) {
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	for _, role := range append(KnownRoles, Role("root")) {
		caps := Capabilities(role)
		if len(caps) != len(actionRules) {
			t.Fatalf("%s: %d capabilities, want %d", role, len(caps), len(actionRules))
		}
		for _, c := range caps {
			fresh := Authorize(role, c.Action, now, now)
			stale := Authorize(role, c.Action, now.Add(-time.Hour), now)
			if c.Permitted != fresh.Allowed {
				t.Errorf("%s %s: permitted=%v, Authorize(fresh)=%+v", role, c.Action, c.Permitted, fresh)
			}
			if c.Permitted && c.Fresh == stale.Allowed {
				t.Errorf("%s %s: fresh=%v, Authorize(stale)=%+v", role, c.Action, c.Fresh, stale)
			}
		}
	}
}
