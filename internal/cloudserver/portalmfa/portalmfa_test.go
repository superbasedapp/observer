package portalmfa

import (
	"bytes"
	"crypto/rand"
	"errors"
	"reflect"
	"regexp"
	"testing"
	"time"
)

func TestUserHandle(t *testing.T) {
	t.Parallel()
	a, b := UserHandle("acct-a"), UserHandle("acct-b")
	if len(a) != 32 || bytes.Equal(a, b) || !bytes.Equal(a, UserHandle("acct-a")) || bytes.Contains(a, []byte("acct-a")) {
		t.Fatalf("UserHandle: %x %x", a, b)
	}
}

func TestRecoveryCodes(t *testing.T) {
	t.Parallel()
	codes, err := NewRecoveryCodes(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	shape := regexp.MustCompile(`^[a-z2-7]{5}-[a-z2-7]{5}$`)
	seen := map[string]bool{}
	for _, c := range codes {
		if !shape.MatchString(c) || seen[c] {
			t.Fatalf("code %q (dup %v)", c, seen[c])
		}
		seen[c] = true
	}
	if len(codes) != RecoveryCodeCount {
		t.Fatalf("%d codes", len(codes))
	}
	// Typing variants hash alike; another code does not.
	h1, _ := HashRecoveryCode(codes[0])
	up := []byte(codes[0])
	for i := range up {
		if up[i] >= 'a' && up[i] <= 'z' {
			up[i] -= 32
		}
	}
	h2, err := HashRecoveryCode(" " + string(bytes.ReplaceAll(up, []byte("-"), []byte(" "))) + " ")
	if err != nil || h1 != h2 || len(h1) != 64 {
		t.Fatalf("normalised hash %s vs %s (%v)", h1, h2, err)
	}
	if h3, _ := HashRecoveryCode(codes[1]); h3 == h1 {
		t.Fatal("two codes hash alike")
	}
	for _, bad := range []string{"", "abcde-fghi", "abcde-fghijk", "abcde-fgh1j", "abcde_fghij"} {
		if _, err := HashRecoveryCode(bad); !errors.Is(err, ErrRecoveryCodeShape) {
			t.Errorf("HashRecoveryCode(%q) = %v", bad, err)
		}
	}
	// A short reader is an error, never a weak code.
	if _, err := NewRecoveryCodes(bytes.NewReader(make([]byte, 15))); err == nil {
		t.Fatal("short entropy accepted")
	}
}

func TestAMRFor(t *testing.T) {
	t.Parallel()
	cases := []struct {
		m    Method
		be   bool
		want []string
	}{
		{MethodPasskey, true, []string{"swk", "mfa"}},
		{MethodPasskey, false, []string{"hwk", "mfa"}},
		{MethodRecoveryCode, false, nil},
		{MethodRecoveryCode, true, nil},
		{MethodNone, false, nil},
	}
	for _, c := range cases {
		if got := AMRFor(c.m, c.be); !reflect.DeepEqual(got, c.want) {
			t.Errorf("AMRFor(%q, %v) = %v, want %v", c.m, c.be, got, c.want)
		}
	}
	if !MultiFactor([]string{"hwk", "mfa"}) || MultiFactor(nil) || MultiFactor([]string{"hwk"}) {
		t.Fatal("MultiFactor")
	}
}

func TestAllowedWhilePending(t *testing.T) {
	t.Parallel()
	cases := []struct {
		method, path string
		want         bool
	}{
		{"GET", "/portal/api/session", true},
		{"HEAD", "/portal/api/session", true},
		{"GET", "/portal/api/mfa", true},
		{"POST", "/portal/api/mfa/assert/begin", true},
		{"POST", "/portal/api/mfa/assert/finish", true},
		{"POST", "/portal/api/mfa/recover", true},
		{"POST", "/portal/auth/logout", true},
		{"POST", "/portal/api/mfa/passkeys/register/begin", false},
		{"DELETE", "/portal/api/mfa/passkeys/x", false},
		{"GET", "/portal/api/orgs", false},
		{"GET", "/portal/api/me/orgs", false},
		{"POST", "/portal/api/session", false},
		{"GET", "/portal/api/mfa/assert/begin", false},
	}
	for _, c := range cases {
		if got := AllowedWhilePending(c.method, c.path); got != c.want {
			t.Errorf("%s %s = %v, want %v", c.method, c.path, got, c.want)
		}
	}
}

func TestDecide(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	passkey := SessionState{Enrolled: true, Method: MethodPasskey, AMR: AMRFor(MethodPasskey, false)}
	recovery := SessionState{Enrolled: true, Method: MethodRecoveryCode}
	pending := SessionState{Enrolled: true}
	none := SessionState{}
	cases := []struct {
		name string
		a    Action
		f    Facts
		want string
	}{
		{"first enrol, fresh", ActionEnrol, Facts{Session: none, AuthTime: now.Add(-time.Minute), Now: now}, ""},
		{"first enrol, at the window", ActionEnrol, Facts{Session: none, AuthTime: now.Add(-FreshEnrolWindow), Now: now}, ""},
		{"first enrol, stale", ActionEnrol, Facts{Session: none, AuthTime: now.Add(-FreshEnrolWindow - time.Second), Now: now}, CodeReauthRequired},
		{"first enrol, unknown auth time", ActionEnrol, Facts{Session: none, Now: now}, CodeReauthRequired},
		{"first enrol, auth time in the future", ActionEnrol, Facts{Session: none, AuthTime: now.Add(time.Hour), Now: now}, CodeReauthRequired},
		{"second enrol, pending", ActionEnrol, Facts{Session: pending, ActivePasskeys: 1, AuthTime: now, Now: now}, CodeSecondFactorRequired},
		{"second enrol, after passkey", ActionEnrol, Facts{Session: passkey, ActivePasskeys: 1, Now: now}, ""},
		{"enrol after a recovery code", ActionEnrol, Facts{Session: recovery, ActivePasskeys: 1, Now: now}, ""},
		{"enrol at the cap", ActionEnrol, Facts{Session: passkey, ActivePasskeys: MaxActivePasskeys, Now: now}, CodePasskeyLimit},
		{"manage, pending", ActionManage, Facts{Session: pending, Now: now}, CodeSecondFactorRequired},
		{"manage, not enrolled", ActionManage, Facts{Session: none, Now: now}, CodeSecondFactorRequired},
		{"manage, after recovery", ActionManage, Facts{Session: recovery, Now: now}, ""},
		{"manage, after passkey", ActionManage, Facts{Session: passkey, Now: now}, ""},
		{"org policy, after passkey", ActionOrgPolicy, Facts{Session: passkey, Now: now}, ""},
		{"org policy, after recovery", ActionOrgPolicy, Facts{Session: recovery, Now: now}, CodePasskeySignInRequired},
		{"org policy, not enrolled", ActionOrgPolicy, Facts{Session: none, Now: now}, CodePasskeySignInRequired},
	}
	for _, c := range cases {
		if got, _ := Decide(c.a, c.f); got != c.want {
			t.Errorf("%s: Decide = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestIssueRule(t *testing.T) {
	t.Parallel()
	cases := []struct {
		f    IssueFacts
		want IssueVerdict
		id   string
	}{
		{IssueFacts{}, IssueAllowed, "allowed"},
		{IssueFacts{MultiFactor: true}, IssueAllowed, "allowed"},
		{IssueFacts{Pending: true}, IssueSecondFactor, "account-second-factor-pending"},
		{IssueFacts{Pending: true, OrgRequires: true}, IssueSecondFactor, "account-second-factor-pending"},
		{IssueFacts{OrgRequires: true}, IssueSecondFactor, "org-requires-second-factor"},
		{IssueFacts{OrgRequires: true, MultiFactor: true}, IssueAllowed, "allowed"},
	}
	for _, c := range cases {
		if got, id := IssueRule(c.f); got != c.want || id != c.id {
			t.Errorf("IssueRule(%+v) = %v %s, want %v %s", c.f, got, id, c.want, c.id)
		}
	}
	if !(SessionState{Enrolled: true}).Pending() || (SessionState{Enrolled: true, Method: MethodRecoveryCode}).Pending() || (SessionState{}).Pending() {
		t.Fatal("Pending")
	}
}
