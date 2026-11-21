package scrub

import (
	"strings"
	"testing"
)

// TestBearerProseStaysAndTokensGo pins the prose rule of the Bearer rows:
// one English word after "Bearer" stays (it is prose), every other value is
// still redacted by the storage scrubber and found by the detector.
func TestBearerProseStaysAndTokensGo(t *testing.T) {
	s := New()
	cases := []struct {
		name, in string
		stays    string // text that must survive the scrub; "" = check gone
		gone     string // text that must not survive; "" = check stays
		detect   bool   // the bearer_token detector must report it
	}{
		{name: "plural prose", in: "Bearer tokens are accepted without verifying their HMAC signature", stays: "Bearer tokens are accepted"},
		{name: "singular prose with period", in: "send a Bearer token.", stays: "Bearer token."},
		{name: "long prose word", in: "uses Bearer authentication", stays: "Bearer authentication"},
		{name: "mixed case prose", in: "BEARER Authorization header", stays: "BEARER Authorization"},
		{name: "the Bearer of", in: "the Bearer of bad news", stays: "Bearer of"},
		{name: "short value", in: "use Bearer abc123 here", gone: "abc123"},
		{name: "header value", in: "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9abcdef", gone: "eyJhbGci", detect: true},
		{name: "word plus suffix is a value", in: "Bearer tokens123456", gone: "tokens123456", detect: true},
		{name: "word glued by a dot is a value", in: "Bearer token.abcdefghij", gone: "token.abcdefghij", detect: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := s.String(tc.in)
			if tc.stays != "" && !strings.Contains(out, tc.stays) {
				t.Fatalf("prose was redacted: %q -> %q", tc.in, out)
			}
			if tc.gone != "" && strings.Contains(out, tc.gone) {
				t.Fatalf("value survived: %q -> %q", tc.in, out)
			}
			found := false
			for _, f := range DetectSecrets(tc.in) {
				if f.Type == "bearer_token" {
					found = true
				}
			}
			if found != tc.detect {
				t.Fatalf("bearer_token detected = %v, want %v for %q", found, tc.detect, tc.in)
			}
		})
	}
}

// TestBearerProseWordsAreProse keeps the list honest: every entry is a
// lowercase letters-only word (a token-shaped entry would hide a secret).
func TestBearerProseWordsAreProse(t *testing.T) {
	for w := range bearerProseWords {
		if w == "" || strings.ToLower(w) != w || strings.Trim(w, "abcdefghijklmnopqrstuvwxyz") != "" || len(w) > 14 {
			t.Errorf("bearerProseWords entry %q is not a short lowercase word", w)
		}
	}
}
