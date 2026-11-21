package configschema

import (
	"strings"
	"testing"
)

type fakeGov struct{ hidden, readOnly map[string]bool }

func (g fakeGov) IsSettingsSectionHidden(s string) bool   { return g.hidden[s] }
func (g fakeGov) IsSettingsSectionReadOnly(s string) bool { return g.readOnly[s] }

func TestCheckKey(t *testing.T) {
	gov := fakeGov{hidden: map[string]bool{"freshness": true}, readOnly: map[string]bool{"watcher": true}}
	cases := []struct {
		name    string
		key     string
		gov     KeyGovernance
		want    KeyVerdict
		confirm bool
		leaf    string
	}{
		{"plain leaf", "observer.log_level", nil, KeyOK, false, "observer.log_level"},
		{"sensitive leaf needs confirm", "observer.secrets.enable_scrubbing", nil, KeyOK, true, "observer.secrets.enable_scrubbing"},
		{"secret refused", "email.password", nil, KeySecret, false, "email.password"},
		{"Plane A content key is settable and sensitive", "observability.store_content", nil, KeyOK, true, "observability.store_content"},
		{"secret table refused", "routing.key_pool", nil, KeySecret, false, "routing.key_pool"},
		{"owner elsewhere", "org_client.enabled", nil, KeyOwnerElsewhere, false, "org_client.enabled"},
		{"unknown", "no.such.key", nil, KeyUnknown, false, ""},
		{"unknown on a governed node fails closed", "no.such.key", gov, KeyGovernanceUnmapped, false, ""},
		{"map entry resolves to its map", "profiles.by_provider.openai", nil, KeyOK, false, "profiles.by_provider"},
		{"hidden section", "observer.freshness.enable_content_hashing", gov, KeyGovernanceHidden, false, "observer.freshness.enable_content_hashing"},
		{"read-only section", "observer.watch.poll_interval_seconds", gov, KeyGovernanceReadOnly, false, "observer.watch.poll_interval_seconds"},
		{"secret wins over governance", "email.password", fakeGov{readOnly: map[string]bool{"observer": true}}, KeySecret, false, "email.password"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := CheckKey(tc.key, tc.gov)
			if c.Verdict != tc.want || c.NeedsConfirm != tc.confirm || c.Leaf.Path != tc.leaf {
				t.Fatalf("CheckKey(%q) = %+v", tc.key, c)
			}
			if c.Verdict != KeyOK && c.Message == "" {
				t.Fatal("a refusal must carry a message")
			}
		})
	}
}

func TestSecretShaped(t *testing.T) {
	detect := func(s string) bool { return strings.HasPrefix(s, "sk-") }
	cases := []struct {
		name string
		v    any
		want bool
	}{
		{"plain string", "info", false},
		{"detected string", "sk-abc", true},
		{"list with one secret", []string{"a", "sk-1"}, true},
		{"credential-named map key", map[string]string{"API_KEY": "x"}, true},
		{"token count is not a credential", map[string]string{"max_tokens": "100"}, false},
		{"env reference name", map[string]string{"token_env": "MY_TOKEN"}, false},
		{"number", 3, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := SecretShaped(tc.v, detect); got != tc.want {
				t.Fatalf("SecretShaped(%v) = %v", tc.v, got)
			}
		})
	}
}

func TestMaskTOMLSecrets(t *testing.T) {
	detect := func(s string) bool { return strings.HasPrefix(s, "sk-live") }
	in := `# comment kept
[observer]
log_level = "info"

[email]
password = "hunter2"
host = "smtp.example"

[proxy.upstreams]
openrouter = "https://openrouter.ai/api"

[routing]
key_pool = [
  "one",
  "two",
]
enabled = false

[custom]
api_key = "abc"
note = "sk-live-123"
max_tokens = 10
`
	got := MaskTOMLSecrets(in, detect)
	for _, leak := range []string{"hunter2", `"one"`, `"two"`, `"abc"`, "sk-live-123"} {
		if strings.Contains(got, leak) {
			t.Fatalf("masked text leaks %s:\n%s", leak, got)
		}
	}
	for _, keep := range []string{"# comment kept", `log_level = "info"`, `host = "smtp.example"`, "enabled = false", "max_tokens = 10", "openrouter"} {
		if !strings.Contains(got, keep) {
			t.Fatalf("masked text lost %q:\n%s", keep, got)
		}
	}
	if strings.Count(got, SecretPlaceholder) != 4 {
		t.Fatalf("want 4 placeholders:\n%s", got)
	}
	// Idempotent: masking twice changes nothing, so a diff of two masked
	// renderings is stable.
	if MaskTOMLSecrets(got, detect) != got {
		t.Fatal("masking is not idempotent")
	}
}
