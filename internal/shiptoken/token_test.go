package shiptoken

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestGenerateParseHash(t *testing.T) {
	m, err := Generate(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(m.Token, Prefix) || strings.Contains(m.Token, ".") {
		t.Fatalf("token shape %q", m.Token)
	}
	if !ValidID(m.ID) {
		t.Fatalf("id shape %q", m.ID)
	}
	if m.Hash != Hash(m.Token) || len(m.Hash) != 64 {
		t.Fatalf("hash %q", m.Hash)
	}
	got, err := Parse("  " + m.Token + "\n")
	if err != nil || got != m.Token {
		t.Fatalf("Parse = %q, %v", got, err)
	}
	got, err = FromAuthorization("bearer " + m.Token)
	if err != nil || got != m.Token {
		t.Fatalf("FromAuthorization = %q, %v", got, err)
	}
	m2, _ := Generate(rand.Reader)
	if m2.Token == m.Token || m2.ID == m.ID {
		t.Fatal("two mints collided")
	}
}

func TestGenerateShortRandFails(t *testing.T) {
	if _, err := Generate(bytes.NewReader(make([]byte, 5))); err == nil {
		t.Fatal("short rand accepted")
	}
}

func TestParseRefusesOtherCredentials(t *testing.T) {
	m, _ := Generate(rand.Reader)
	for _, tc := range []struct{ name, raw string }{
		{"empty", ""},
		{"ed25519 bearer shape", "eyJpc3MiOiJ4In0.c2lnbmF0dXJl"},
		{"wrong prefix", "sboxx_" + m.Token[len(Prefix):]},
		{"truncated", m.Token[:len(m.Token)-1]},
		{"extended", m.Token + "A"},
		{"bad alphabet", Prefix + strings.Repeat("*", encodedSecretLen)},
		{"enrolment token shape", "sbo_enrol_abcdef"},
	} {
		if _, err := Parse(tc.raw); err == nil {
			t.Errorf("%s: Parse accepted %q", tc.name, tc.raw)
		}
	}
	for _, h := range []string{"", m.Token, "Basic " + m.Token, "Bearer"} {
		if _, err := FromAuthorization(h); err == nil {
			t.Errorf("FromAuthorization accepted %q", h)
		}
	}
}

func TestValidID(t *testing.T) {
	for id, want := range map[string]bool{
		"cst_0123456789abcdef01234567": true,
		"cst_0123456789ABCDEF01234567": false,
		"cst_0123":                     false,
		"xyz_0123456789abcdef01234567": false,
		"cst_0123456789abcdef0123456g": false,
	} {
		if got := ValidID(id); got != want {
			t.Errorf("ValidID(%q) = %v, want %v", id, got, want)
		}
	}
}

func TestClampLifetime(t *testing.T) {
	for _, tc := range []struct {
		in, want time.Duration
	}{
		{0, DefaultLifetime},
		{-time.Hour, DefaultLifetime},
		{time.Minute, MinLifetime},
		{MinLifetime, MinLifetime},
		{3 * time.Hour, 3 * time.Hour},
		{MaxLifetime, MaxLifetime},
		{30 * 24 * time.Hour, MaxLifetime},
	} {
		if got := ClampLifetime(tc.in); got != tc.want {
			t.Errorf("ClampLifetime(%v) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestValidLabel(t *testing.T) {
	for label, want := range map[string]bool{
		"":                         true,
		"claude-code web env":      true,
		"ünïcödé ok":               true,
		strings.Repeat("a", 64):    true,
		strings.Repeat("a", 65):    false,
		"line\nbreak":              false,
		"tab\there":                false,
		string([]byte{0xff, 0xfe}): false,
	} {
		if got := ValidLabel(label); got != want {
			t.Errorf("ValidLabel(%q) = %v, want %v", label, got, want)
		}
	}
}

func TestStatusAt(t *testing.T) {
	now := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name             string
		expires, revoked time.Time
		want, refusal    string
	}{
		{"active", now.Add(time.Minute), time.Time{}, StatusActive, ""},
		{"expired exactly now", now, time.Time{}, StatusExpired, CodeExpired},
		{"expired", now.Add(-time.Minute), time.Time{}, StatusExpired, CodeExpired},
		{"revoked and live", now.Add(time.Hour), now.Add(-time.Hour), StatusRevoked, CodeRevoked},
		{"revoked beats expired", now.Add(-time.Hour), now.Add(-2 * time.Hour), StatusRevoked, CodeRevoked},
	} {
		got := StatusAt(now, tc.expires, tc.revoked)
		if got != tc.want || RefusalCode(got) != tc.refusal {
			t.Errorf("%s: status %q code %q, want %q %q", tc.name, got, RefusalCode(got), tc.want, tc.refusal)
		}
	}
	if RefusalCode("weird") != CodeInvalid {
		t.Error("unknown status must refuse as invalid")
	}
}

func TestDecodeBody(t *testing.T) {
	plain := []byte(`{"agent_version":"` + strings.Repeat("9", 4000) + `","cursor_to":3,"sessions":[{"id":"s1"}]}`)
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write(plain)
	_ = zw.Close()
	for _, tc := range []struct {
		name, enc string
		raw       []byte
		max       int
		want      error
	}{
		{"plain", "", plain, 1 << 13, nil},
		{"identity", "identity", plain, 1 << 13, nil},
		{"gzip", "gzip", gz.Bytes(), 1 << 13, nil},
		{"compressed over cap", "gzip", gz.Bytes(), 4, ErrTooLarge},
		{"inflated over cap", "gzip", gz.Bytes(), 1 << 10, ErrTooLarge},
		{"bad gzip", "gzip", plain, 1 << 13, ErrBadEnvelope},
		{"bad json", "", []byte("{"), 1 << 10, ErrBadEnvelope},
		{"brotli refused", "br", plain, 1 << 13, ErrBadEnvelope},
	} {
		env, err := DecodeBody(tc.raw, tc.enc, tc.max)
		if !errors.Is(err, tc.want) {
			t.Errorf("%s: err %v, want %v", tc.name, err, tc.want)
			continue
		}
		if err == nil && (len(env.Sessions) != 1 || env.CursorTo != 3) {
			t.Errorf("%s: env %+v", tc.name, env)
		}
	}
}

// TestShortDefaultLifetime pins CA-D18's short default: a working session,
// well under a day, and never longer than the ceiling.
func TestShortDefaultLifetime(t *testing.T) {
	if DefaultLifetime != 8*time.Hour || DefaultLifetime > MaxLifetime || DefaultLifetime < MinLifetime {
		t.Fatalf("DefaultLifetime = %v", DefaultLifetime)
	}
}

func TestClampRowCap(t *testing.T) {
	cases := []struct{ in, want int64 }{
		{0, DefaultRowCap},
		{-5, DefaultRowCap},
		{10, MinRowCap},
		{MinRowCap, MinRowCap},
		{50_000, 50_000},
		{MaxRowCap, MaxRowCap},
		{MaxRowCap + 1, MaxRowCap},
	}
	for _, tc := range cases {
		if got := ClampRowCap(tc.in); got != tc.want {
			t.Errorf("ClampRowCap(%d) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestValidEnvironmentLabel(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"", false},
		{"   ", false},
		{"claude-code web env", true},
		{"tab\there", false},
		{strings.Repeat("e", MaxLabelRunes+1), false},
	}
	for _, tc := range cases {
		if got := ValidEnvironmentLabel(tc.in); got != tc.want {
			t.Errorf("ValidEnvironmentLabel(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
	if EnvironmentKey("  Web Env ") != EnvironmentKey("web env") {
		t.Fatal("EnvironmentKey must fold case and trim")
	}
}
