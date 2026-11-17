package api

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestNewProviderEmail is the A4 decision on what WorkOS's user object said,
// one case per row: the flag (verified, unverified, missing) and the address
// shapes the issuer must never sign. It decodes the same struct shape
// exchangeWorkOSCode decodes, from the user object WorkOS returns.
func TestNewProviderEmail(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name         string
		user         string
		wantAddress  string
		wantVerified bool
	}{
		{"verified", `{"email":"ada@example.test","email_verified":true}`, "ada@example.test", true},
		{"unverified", `{"email":"ada@example.test","email_verified":false}`, "ada@example.test", false},
		{"flag missing is unverified", `{"email":"ada@example.test"}`, "ada@example.test", false},
		{"flag null is unverified", `{"email":"ada@example.test","email_verified":null}`, "ada@example.test", false},
		{"trimmed, never normalized", `{"email":"  Ada@Example.test ","email_verified":true}`, "Ada@Example.test", true},
		{"no address", `{"email_verified":true}`, "", true},
		{"no at sign", `{"email":"ada.example.test","email_verified":true}`, "", true},
		{"no local part", `{"email":"@example.test","email_verified":true}`, "", true},
		{"control character", `{"email":"ada\u0007@example.test","email_verified":true}`, "", true},
		{"over 254 bytes is cleared, never cut", `{"email":"` + strings.Repeat("a", 250) + `@example.test","email_verified":true}`, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var u struct {
				Email         string `json:"email"`
				EmailVerified *bool  `json:"email_verified"`
			}
			if err := json.Unmarshal([]byte(tc.user), &u); err != nil {
				t.Fatal(err)
			}
			got := newProviderEmail(u.Email, u.EmailVerified)
			if got.address != tc.wantAddress || got.verified != tc.wantVerified {
				t.Fatalf("got %+v, want address %q verified %v", got, tc.wantAddress, tc.wantVerified)
			}
		})
	}
}
