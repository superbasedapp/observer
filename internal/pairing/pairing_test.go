package pairing

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

// secret32 is a 32-byte (256-bit) base64url secret, the size the org server
// mints.
var secret32 = base64.RawURLEncoding.EncodeToString(make([]byte, 32))

const tokenID = "0123456789abcdef0123456789abcdef"

func TestFormatParseRoundTrip(t *testing.T) {
	t.Parallel()
	for _, org := range []string{"org-1", "acme.example", "a"} {
		code, err := Format(org, tokenID+"."+secret32)
		if err != nil {
			t.Fatalf("Format(%q): %v", org, err)
		}
		if !strings.HasPrefix(code, Prefix+".") || len(code) > MaxCodeLen {
			t.Fatalf("Format(%q) = %q", org, code)
		}
		c, err := Parse("  " + code + "\n")
		if err != nil {
			t.Fatalf("Parse(%q): %v", code, err)
		}
		if c.OrgID != org || c.TokenID != tokenID || c.Secret != secret32 || c.Compound() != tokenID+"."+secret32 {
			t.Fatalf("Parse(%q) = %+v", code, c)
		}
		if c.String() != code {
			t.Fatalf("String() = %q, want %q", c.String(), code)
		}
	}
}

func TestParseRefusals(t *testing.T) {
	t.Parallel()
	org := base64.RawURLEncoding.EncodeToString([]byte("org-1"))
	short := base64.RawURLEncoding.EncodeToString(make([]byte, 15)) // 120 bits
	cases := []struct {
		name string
		in   string
		want error
	}{
		{"plain enrolment code", tokenID + "." + secret32, ErrNotPairingCode},
		{"empty", "", ErrNotPairingCode},
		{"too few parts", Prefix + "." + org + "." + tokenID, ErrMalformed},
		{"too many parts", Prefix + "." + org + "." + tokenID + "." + secret32 + ".x", ErrMalformed},
		{"org not base64", Prefix + ".org*1." + tokenID + "." + secret32, ErrMalformed},
		{"empty org", Prefix + ".." + tokenID + "." + secret32, ErrMalformed},
		{"token id not hex", Prefix + "." + org + ".XYZ0123456789abcdef." + secret32, ErrMalformed},
		{"secret under 128 bits", Prefix + "." + org + "." + tokenID + "." + short, ErrMalformed},
		{"secret not base64url", Prefix + "." + org + "." + tokenID + ".!!!!", ErrMalformed},
		{"too long", Prefix + "." + org + "." + tokenID + "." + strings.Repeat("A", MaxCodeLen), ErrMalformed},
	}
	for _, tc := range cases {
		if _, err := Parse(tc.in); !errors.Is(err, tc.want) {
			t.Errorf("%s: Parse = %v, want %v", tc.name, err, tc.want)
		}
	}
}

func TestSecretBitsFloor(t *testing.T) {
	t.Parallel()
	if got := SecretBits(base64.RawURLEncoding.EncodeToString(make([]byte, 16))); got != MinSecretBits {
		t.Fatalf("16 bytes = %d bits, want %d", got, MinSecretBits)
	}
	if got := SecretBits(secret32); got != 256 {
		t.Fatalf("32 bytes = %d bits", got)
	}
	if MinSecretBits < 128 {
		t.Fatal("the plan's entropy floor is at least 128 bits")
	}
	if TTL != 15*time.Minute {
		t.Fatalf("TTL = %s, the plan's lifetime is 15 minutes", TTL)
	}
}

func TestFormatRefusesACredentialWithNoID(t *testing.T) {
	t.Parallel()
	if _, err := Format("org", "nodot"); !errors.Is(err, ErrMalformed) {
		t.Fatalf("Format = %v", err)
	}
}

// TestHandoffRules is one case per row of handoffRules.
func TestHandoffRules(t *testing.T) {
	t.Parallel()
	code, err := Format("org-1", tokenID+"."+secret32)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{"code.txt": code + "\n", "junk.txt": "not a code", "big.txt": strings.Repeat("x", 4096)}
	read := func(p string) ([]byte, error) {
		v, ok := files[p]
		if !ok {
			return nil, errors.New("no such file")
		}
		return []byte(v), nil
	}
	cases := []struct {
		row     string
		h       Handoff
		source  Source
		wantErr error
		anyErr  bool
	}{
		{row: "both sources", h: Handoff{Env: code, PairFile: "code.txt", ReadFile: read}, wantErr: ErrTwoSources},
		{row: "pair file", h: Handoff{PairFile: "code.txt", ReadFile: read}, source: SourceFile},
		{row: "pair file: not a code", h: Handoff{PairFile: "junk.txt", ReadFile: read}, wantErr: ErrNotPairingCode},
		{row: "pair file: too large", h: Handoff{PairFile: "big.txt", ReadFile: read}, wantErr: ErrMalformed},
		{row: "pair file: unreadable", h: Handoff{PairFile: "missing.txt", ReadFile: read}, anyErr: true},
		{row: "environment", h: Handoff{Env: code}, source: SourceEnv},
		{row: "environment: malformed", h: Handoff{Env: Prefix + ".x"}, wantErr: ErrMalformed},
		{row: "none", h: Handoff{Env: "  "}, source: SourceNone},
	}
	if len(handoffRules) != 4 {
		t.Fatalf("handoffRules has %d rows; this test covers 4", len(handoffRules))
	}
	for _, tc := range cases {
		got, err := Take(tc.h)
		switch {
		case tc.wantErr != nil:
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("%s: err = %v, want %v", tc.row, err, tc.wantErr)
			}
		case tc.anyErr:
			if err == nil {
				t.Errorf("%s: no error", tc.row)
			}
		case err != nil:
			t.Errorf("%s: %v", tc.row, err)
		case got.Source != tc.source:
			t.Errorf("%s: source = %q, want %q", tc.row, got.Source, tc.source)
		case tc.source != SourceNone && got.Code.String() != code:
			t.Errorf("%s: code = %q", tc.row, got.Code.String())
		}
	}
}

func TestRefuseArgument(t *testing.T) {
	t.Parallel()
	code, _ := Format("org-1", tokenID+"."+secret32)
	if err := RefuseArgument(code); !errors.Is(err, ErrArgument) {
		t.Fatalf("a pairing code argument = %v", err)
	}
	for _, ok := range []string{"https://org.example", tokenID + "." + secret32, ""} {
		if err := RefuseArgument(ok); err != nil {
			t.Fatalf("RefuseArgument(%q) = %v", ok, err)
		}
	}
}

func TestThrottlePerSourceAndPerOrg(t *testing.T) {
	t.Parallel()
	now := time.Unix(1000, 0)
	th := NewThrottle([]Limit{
		{Scope: ScopeSource, Burst: 2, Per: time.Minute},
		{Scope: ScopeOrg, Burst: 3, Per: time.Minute},
	}, func() time.Time { return now })
	allow := func(src, org string) (bool, Scope) {
		return th.Allow(map[Scope]string{ScopeSource: src, ScopeOrg: org})
	}
	for i := 0; i < 2; i++ {
		if ok, _ := allow("1.1.1.1", "org-a"); !ok {
			t.Fatalf("attempt %d from one source refused", i+1)
		}
	}
	if ok, scope := allow("1.1.1.1", "org-a"); ok || scope != ScopeSource {
		t.Fatalf("third attempt from one source = %v %q, want refused by source", ok, scope)
	}
	// A second source still reaches the org's bucket (one left of three).
	if ok, _ := allow("2.2.2.2", "org-a"); !ok {
		t.Fatal("another source refused before the org limit")
	}
	if ok, scope := allow("3.3.3.3", "org-a"); ok || scope != ScopeOrg {
		t.Fatalf("org over its limit = %v %q, want refused by org", ok, scope)
	}
	// Another org is untouched.
	if ok, _ := allow("4.4.4.4", "org-b"); !ok {
		t.Fatal("another org was throttled")
	}
	// A refill after the window admits again.
	now = now.Add(time.Minute)
	if ok, _ := allow("1.1.1.1", "org-a"); !ok {
		t.Fatal("no refill after the window")
	}
}

func TestDefaultLimitsShape(t *testing.T) {
	t.Parallel()
	ls := DefaultLimits()
	if len(ls) != 2 || ls[0].Scope != ScopeSource || ls[1].Scope != ScopeOrg {
		t.Fatalf("DefaultLimits = %+v; want source then org", ls)
	}
	for _, l := range ls {
		if l.Burst <= 0 || l.Per <= 0 {
			t.Fatalf("limit %+v throttles nothing", l)
		}
	}
}
