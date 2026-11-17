package tenantctx

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"
)

var (
	testKey      = bytes.Repeat([]byte{0x5a}, 32)
	testOtherKey = bytes.Repeat([]byte{0xa5}, 32)
)

const (
	acctA = "0f3a9c1e-1111-4222-8333-444455556666"
	acctB = "0f3a9c1e-aaaa-4bbb-8ccc-ddddeeeeffff"
)

// testClock is the fixed clock of the native tests.
func testClock() time.Time { return time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC) }

// subjectFor returns a valid subject of kind k.
func subjectFor(t *testing.T, k Kind) string {
	t.Helper()
	switch k {
	case KindOrg:
		return "acme.eu"
	case KindAccount:
		return acctA
	default:
		t.Fatalf("no test subject for %s", k)
		return ""
	}
}

// TestKindTable: one case per kind row (in table order) naming its setting
// and domain, and an unknown kind is refused everywhere.
func TestKindTable(t *testing.T) {
	t.Parallel()
	cases := []struct {
		kind    Kind
		name    string
		setting string
		domain  string
	}{
		{kind: KindOrg, name: "org", setting: "sbo.tenant", domain: ""},
		{kind: KindAccount, name: "account", setting: "sbci.account_id", domain: "sbci-account-v1\n"},
	}
	kinds := Kinds()
	if len(kinds) != len(cases) {
		t.Fatalf("%d cases for %d kinds", len(cases), len(kinds))
	}
	for i, c := range cases {
		if kinds[i] != c.kind {
			t.Fatalf("row %d is %s, case is %s", i, kinds[i], c.kind)
		}
		if c.kind.String() != c.name || c.kind.Setting() != c.setting || c.kind.Domain() != c.domain {
			t.Errorf("%s: name %q setting %q domain %q", c.name, c.kind.String(), c.kind.Setting(), c.kind.Domain())
		}
		if want := "SELECT set_config('" + c.setting + "', $1, true)"; c.kind.SetLocalSQL() != want {
			t.Errorf("%s: SetLocalSQL %q, want %q", c.name, c.kind.SetLocalSQL(), want)
		}
		if want := "SELECT set_config('" + c.setting + "', '', true)"; c.kind.ClearLocalSQL() != want {
			t.Errorf("%s: ClearLocalSQL %q, want %q", c.name, c.kind.ClearLocalSQL(), want)
		}
	}
	for _, bad := range []Kind{0, 3, 255} {
		if bad.Valid() || bad.Setting() != "" || bad.SetLocalSQL() != "" || bad.ClearLocalSQL() != "" {
			t.Errorf("kind %d is treated as valid", bad)
		}
		if err := bad.CheckSubject("x"); !errors.Is(err, ErrInvalidContext) {
			t.Errorf("kind %d CheckSubject = %v", bad, err)
		}
		if _, err := Encode(bad, "x", testClock(), testKey); !errors.Is(err, ErrInvalidContext) {
			t.Errorf("kind %d Encode = %v", bad, err)
		}
		if _, _, _, err := Parse(bad, "x.1."+strings.Repeat("ab", 32)); !errors.Is(err, ErrInvalidContext) {
			t.Errorf("kind %d Parse = %v", bad, err)
		}
		if _, err := Verify(bad, "x.1."+strings.Repeat("ab", 32), [][]byte{testKey}, testClock()); !errors.Is(err, ErrInvalidContext) {
			t.Errorf("kind %d Verify = %v", bad, err)
		}
		if s, err := NewSigner(bad, testKey, 0, testClock); s != nil || !errors.Is(err, ErrInvalidContext) {
			t.Errorf("kind %d NewSigner = %v, %v", bad, s, err)
		}
	}
}

// TestKindDomainsAreDisjoint pins doc.go's "Kinds never cross" rule on the
// table itself: at most one kind has the empty domain; every other domain
// ends in a newline, has no other control character and is unique; and the
// subject rules of every kind refuse a newline. Together they make the MAC
// inputs of two kinds disjoint.
func TestKindDomainsAreDisjoint(t *testing.T) {
	t.Parallel()
	seen := map[string]Kind{}
	empty := 0
	for _, k := range Kinds() {
		d := k.Domain()
		if prev, dup := seen[d]; dup {
			t.Errorf("%s and %s share the domain %q", prev, k, d)
		}
		seen[d] = k
		if err := k.CheckSubject("a\nb"); !errors.Is(err, ErrInvalidContext) {
			t.Errorf("%s accepts a newline in a subject", k)
		}
		if d == "" {
			empty++
			continue
		}
		if !strings.HasSuffix(d, "\n") || strings.ContainsAny(d[:len(d)-1], "\n\r\x00") {
			t.Errorf("%s domain %q must end in its only newline", k, d)
		}
		for _, r := range d[:len(d)-1] {
			if r < 0x20 || r == 0x7f {
				t.Errorf("%s domain %q has a control character", k, d)
			}
		}
	}
	if empty > 1 {
		t.Errorf("%d kinds have the empty domain, want at most one", empty)
	}
}

// TestSubjectRules has one case per subject rule row of each kind, in table
// order, each decided by the row it names, plus accepted subjects.
func TestSubjectRules(t *testing.T) {
	t.Parallel()
	common := []struct{ row, subject string }{
		{row: "empty", subject: ""},
		{row: "too long", subject: strings.Repeat("a", MaxSubjectBytes+1)},
		{row: "not UTF-8", subject: "org-\xff"},
		{row: "whitespace or control character", subject: "org a"},
	}
	cases := map[Kind][]struct{ row, subject string }{
		KindOrg:     common,
		KindAccount: append(append([]struct{ row, subject string }{}, common...), struct{ row, subject string }{row: "not a lower-case canonical UUID", subject: strings.ToUpper(acctA)}),
	}
	for _, k := range Kinds() {
		spec, err := k.spec()
		if err != nil {
			t.Fatal(err)
		}
		cs := cases[k]
		if len(cs) != len(spec.rules) {
			t.Fatalf("%s: %d cases for %d rows", k, len(cs), len(spec.rules))
		}
		for i, c := range cs {
			if spec.rules[i].name != c.row {
				t.Fatalf("%s: case %d is %q, row %d is %q", k, i, c.row, i, spec.rules[i].name)
			}
			err := k.CheckSubject(c.subject)
			if !errors.Is(err, ErrInvalidContext) || !strings.Contains(err.Error(), c.row) {
				t.Errorf("%s: CheckSubject(%q) = %v, want refusal by %q", k, c.subject, err, c.row)
			}
		}
	}
	for _, ok := range []string{"org-a", "0f3a9c", "acme.eu.1", strings.Repeat("a", MaxSubjectBytes), "ünïcode", acctA} {
		if err := KindOrg.CheckSubject(ok); err != nil {
			t.Errorf("org CheckSubject(%q) = %v", ok, err)
		}
	}
	for _, bad := range []string{"org\ta", "org\na", "org\x00a"} {
		if err := KindOrg.CheckSubject(bad); err == nil {
			t.Errorf("org CheckSubject(%q) = nil", bad)
		}
	}
	if err := KindAccount.CheckSubject(acctB); err != nil {
		t.Errorf("account CheckSubject(%q) = %v", acctB, err)
	}
	for _, bad := range []string{
		"org-a", "{" + acctA + "}", strings.ReplaceAll(acctA, "-", ""), acctA[:35] + "g",
		acctA[:8] + "_" + acctA[9:], acctA + "0",
	} {
		if err := KindAccount.CheckSubject(bad); !errors.Is(err, ErrInvalidContext) {
			t.Errorf("account CheckSubject(%q) = %v", bad, err)
		}
	}
}

// TestEncodeShape: the token is <subject>.<unix expiry>.<lower hex
// HMAC-SHA256 of the domain then "<subject>.<expiry>">. The org kind's token
// is byte for byte the M3b.1 format org pgmigrations 0189 verifies.
func TestEncodeShape(t *testing.T) {
	t.Parallel()
	expiry := testClock().Add(time.Minute)
	for _, k := range Kinds() {
		subject := subjectFor(t, k)
		token, err := Encode(k, subject, expiry, testKey)
		if err != nil {
			t.Fatal(err)
		}
		body := subject + "." + strconv.FormatInt(expiry.Unix(), 10)
		m := hmac.New(sha256.New, testKey)
		m.Write([]byte(k.Domain() + body))
		if want := body + "." + hex.EncodeToString(m.Sum(nil)); token != want {
			t.Errorf("%s: token %q, want %q", k, token, want)
		}
	}
	// The M3b.1 org vector: no domain at all.
	org, err := Encode(KindOrg, "acme.eu", expiry, testKey)
	if err != nil {
		t.Fatal(err)
	}
	m := hmac.New(sha256.New, testKey)
	m.Write([]byte("acme.eu." + strconv.FormatInt(expiry.Unix(), 10)))
	if !strings.HasSuffix(org, "."+hex.EncodeToString(m.Sum(nil))) {
		t.Fatalf("the org token %q is not the M3b.1 format", org)
	}
	for _, c := range []struct {
		name   string
		expiry time.Time
		key    []byte
	}{
		{name: "short key", expiry: expiry, key: testKey[:31]},
		{name: "huge key", expiry: expiry, key: make([]byte, MaxKeyBytes+1)},
		{name: "expiry before 1970", expiry: time.Unix(-5, 0), key: testKey},
		{name: "expiry zero", expiry: time.Unix(0, 0), key: testKey},
	} {
		if _, err := Encode(KindOrg, "org-a", c.expiry, c.key); !errors.Is(err, ErrInvalidContext) {
			t.Errorf("%s: Encode = %v", c.name, err)
		}
	}
}

// TestVerify: a valid token of each kind verifies under a key list holding
// its key, and never as another kind, under the same key.
func TestVerify(t *testing.T) {
	t.Parallel()
	now := testClock()
	for _, k := range Kinds() {
		subject := subjectFor(t, k)
		valid, err := Encode(k, subject, now.Add(time.Minute), testKey)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := Verify(k, valid, [][]byte{testOtherKey, testKey}, now); err != nil || got != subject {
			t.Errorf("%s: Verify(valid) = %q, %v", k, got, err)
		}
		if _, err := Verify(k, valid, [][]byte{testOtherKey}, now); !errors.Is(err, ErrInvalidContext) {
			t.Errorf("%s: Verify under the wrong key = %v", k, err)
		}
		if _, err := Verify(k, valid, nil, now); !errors.Is(err, ErrInvalidContext) {
			t.Errorf("%s: Verify with no key = %v", k, err)
		}
		if _, err := Verify(k, valid, [][]byte{testKey}, now.Add(time.Minute)); !errors.Is(err, ErrInvalidContext) {
			t.Errorf("%s: Verify at the expiry = %v", k, err)
		}
		for _, other := range Kinds() {
			if other == k {
				continue
			}
			if got, err := Verify(other, valid, [][]byte{testKey}, now); err == nil {
				t.Errorf("a %s token verified as %s: %q", k, other, got)
			}
		}
	}
	// An account-shaped subject in an org token (a UUID is a valid org id):
	// the MAC still proves the org kind.
	orgUUID, err := Encode(KindOrg, acctA, now.Add(time.Minute), testKey)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := Verify(KindAccount, orgUUID, [][]byte{testKey}, now); err == nil {
		t.Fatalf("an org token for a UUID verified as an account token: %q", got)
	}
}

// TestParseShapes: dots in the subject are kept (the split is from the
// right); a missing segment, a non-digit or over-long expiry and a bad MAC
// are refused.
func TestParseShapes(t *testing.T) {
	t.Parallel()
	mac := strings.Repeat("ab", 32)
	subject, exp, _, err := Parse(KindOrg, "a.b.c.123."+mac)
	if err != nil || subject != "a.b.c" || exp != 123 {
		t.Fatalf("Parse = %q, %d, %v", subject, exp, err)
	}
	for _, bad := range []string{
		"a.123", "a." + mac, ".123." + mac, "a.12x." + mac, "a.1234567890123456789." + mac,
		"a.123." + mac[:62], "a.123." + strings.Repeat("zz", 32), "a.123." + strings.ToUpper(mac), "a..", "",
		strings.Repeat("a", MaxTokenBytes) + ".1." + mac,
	} {
		if _, _, _, err := Parse(KindOrg, bad); !errors.Is(err, ErrInvalidContext) {
			t.Errorf("Parse(%q) = %v", bad, err)
		}
	}
	if _, _, _, err := Parse(KindAccount, "org-a.123."+mac); !errors.Is(err, ErrInvalidContext) {
		t.Errorf("an org id parsed as an account token: %v", err)
	}
}

// TestKeyID: the id is 16 lower-case hex digits, the same for the same key,
// different for another key.
func TestKeyID(t *testing.T) {
	t.Parallel()
	a, b := KeyID(testKey), KeyID(testOtherKey)
	if len(a) != 16 || strings.Trim(a, "0123456789abcdef") != "" {
		t.Fatalf("KeyID = %q", a)
	}
	if a != KeyID(append([]byte(nil), testKey...)) || a == b {
		t.Fatalf("KeyID not a function of the key: %q %q", a, b)
	}
}

// TestSigner: the TTL default and bounds, the key length, the key is copied,
// Token expires TTL after the clock, and Step returns the kind's statement.
func TestSigner(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name string
		key  []byte
		ttl  time.Duration
	}{
		{name: "short key", key: testKey[:31]},
		{name: "negative TTL", key: testKey, ttl: -time.Second},
		{name: "sub-second TTL", key: testKey, ttl: time.Millisecond},
		{name: "TTL over a day", key: testKey, ttl: MaxTTL + time.Second},
	} {
		if s, err := NewSigner(KindOrg, c.key, c.ttl, testClock); err == nil || s != nil || !errors.Is(err, ErrInvalidContext) {
			t.Errorf("%s: NewSigner = %v, %v", c.name, s, err)
		}
	}
	for _, k := range Kinds() {
		key := append([]byte(nil), testKey...)
		s, err := NewSigner(k, key, 0, testClock)
		if err != nil {
			t.Fatal(err)
		}
		key[0] ^= 0xff // the signer must have copied the key
		subject := subjectFor(t, k)
		token, err := s.Token(subject)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := Verify(k, token, [][]byte{testKey}, testClock().Add(DefaultTTL-time.Second)); err != nil || got != subject {
			t.Errorf("%s: token before its expiry: %q, %v", k, got, err)
		}
		if _, err := Verify(k, token, [][]byte{testKey}, testClock().Add(DefaultTTL)); err == nil {
			t.Errorf("%s: token at its expiry still verifies", k)
		}
		query, stepToken, err := s.Step(subject)
		if err != nil || query != k.SetLocalSQL() || stepToken != token {
			t.Errorf("%s: Step = %q, %q, %v", k, query, stepToken, err)
		}
		if s.Kind() != k || s.KeyID() != KeyID(testKey) {
			t.Errorf("%s: Kind %s KeyID %q", k, s.Kind(), s.KeyID())
		}
		if _, err := s.Token("bad subject"); !errors.Is(err, ErrInvalidContext) {
			t.Errorf("%s: Token of a bad subject = %v", k, err)
		}
		if _, _, err := s.Step("bad subject"); !errors.Is(err, ErrInvalidContext) {
			t.Errorf("%s: Step of a bad subject = %v", k, err)
		}
	}
	var nilSigner *Signer
	if _, err := nilSigner.Token("org-a"); err == nil {
		t.Fatal("nil signer minted a token")
	}
	if nilSigner.Kind() != 0 || nilSigner.KeyID() != "" {
		t.Fatal("nil signer reports a kind or key")
	}
}
