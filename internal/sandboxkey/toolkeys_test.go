package sandboxkey

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// opencodeFields mirror OpenCode's grounded row (auth.json keyed by
// provider id, an API entry {"type":"api","key":...}).
var opencodeFields = []SavedKeyField{
	{Provider: "openai", Pointer: "/openai/key", TypePointer: "/openai/type", TypeValue: "api"},
	{Provider: "anthropic", Pointer: "/anthropic/key", TypePointer: "/anthropic/type", TypeValue: "api"},
}

func TestSavedKeys(t *testing.T) {
	t.Parallel()
	doc := []byte(`{"openai":{"type":"api","key":" sk-o "},"anthropic":{"type":"oauth","refresh":"r","access":"a","expires":1}}`)
	cases := []struct {
		name string
		doc  []byte
		want []string
		got  map[string]string
	}{
		{"an api entry is a key", doc, []string{"openai", "anthropic"}, map[string]string{"openai": "sk-o"}},
		{"an oauth entry is never a key", doc, []string{"anthropic"}, map[string]string{}},
		{"a provider not wanted is not read", doc, []string{"google"}, map[string]string{}},
		{"a file that does not parse gives nothing", []byte("{"), []string{"openai"}, nil},
		{"an empty key is skipped", []byte(`{"openai":{"type":"api","key":""}}`), []string{"openai"}, map[string]string{}},
		{"a key that is not a string is skipped", []byte(`{"openai":{"type":"api","key":7}}`), []string{"openai"}, map[string]string{}},
	}
	for _, tc := range cases {
		got := SavedKeys(tc.doc, opencodeFields, tc.want)
		if len(got) != len(tc.got) {
			t.Fatalf("%s: %v, want %v", tc.name, got, tc.got)
		}
		for k, v := range tc.got {
			if got[k] != v {
				t.Fatalf("%s: %v, want %v", tc.name, got, tc.got)
			}
		}
	}
}

var claudeSeed = LoginSeedSpec{Object: "claudeAiOauth", Access: "accessToken", Expiry: "expiresAt", ExpiryMillis: true, Keep: []string{"scopes", "subscriptionType", "rateLimitTier", "refreshToken"}}

// TestSeedLoginRules is one case per row of loginSeedRules plus the seed.
func TestSeedLoginRules(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	doc := func(exp int64) []byte {
		b, _ := json.Marshal(map[string]any{
			"claudeAiOauth": map[string]any{"accessToken": "at", "refreshToken": "rt", "expiresAt": exp, "scopes": []string{"user:inference"}, "subscriptionType": "max"},
			"mcpOAuth":      map[string]any{"x": map[string]any{"accessToken": "other"}},
		})
		return b
	}
	cases := []struct {
		name string
		doc  []byte
		code string
	}{
		{"unreadable", []byte("{"), LoginSeedUnreadable},
		{"no login object", []byte(`{"other":{}}`), LoginSeedNoLogin},
		{"no expiry", []byte(`{"claudeAiOauth":{"accessToken":"at","refreshToken":"rt"}}`), LoginSeedNoExpiry},
		{"expired", doc(now.Add(-time.Minute).UnixMilli()), LoginSeedExpired},
		{"expires within the margin", doc(now.Add(30 * time.Second).UnixMilli()), LoginSeedExpired},
		{"fresh", doc(now.Add(time.Hour).UnixMilli()), LoginSeedOK},
	}
	for _, tc := range cases {
		r := SeedLogin(tc.doc, claudeSeed, now, time.Minute)
		if r.Code != tc.code {
			t.Fatalf("%s: %s, want %s", tc.name, r.Code, tc.code)
		}
		if tc.code != LoginSeedOK {
			if r.Doc != nil {
				t.Fatalf("%s: a refused seed returned a file", tc.name)
			}
			continue
		}
		s := string(r.Doc)
		for _, banned := range []string{"rt", "refresh", "mcpOAuth", "other"} {
			if strings.Contains(s, banned) {
				t.Fatalf("the seeded file %s carries %q", s, banned)
			}
		}
		if !strings.Contains(s, `"accessToken":"at"`) || !strings.Contains(s, `"subscriptionType":"max"`) || !r.ExpiresAt.Equal(now.Add(time.Hour).Truncate(time.Millisecond)) {
			t.Fatalf("the seeded file %s / %v", s, r.ExpiresAt)
		}
	}
}
