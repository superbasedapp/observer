package agentconfig

import (
	"reflect"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

// TestDotenvKeysPresent pins the key-presence reader (CLI-6, CLI-7): names
// only, comments skipped, export allowed, an empty value counts.
func TestDotenvKeysPresent(t *testing.T) {
	keys := []string{"OPENAI_API_BASE", "AIDER_OPENAI_API_BASE", "GOOGLE_GENAI_USE_GCA"}
	cases := []struct {
		body string
		want []string
	}{
		{"OPENAI_API_KEY=sk-x\nOPENAI_API_BASE=https://h/v1\n", []string{"OPENAI_API_BASE"}},
		{"# OPENAI_API_BASE=x\n", nil},
		{"export AIDER_OPENAI_API_BASE = x\r\nGOOGLE_GENAI_USE_GCA=\n", []string{"AIDER_OPENAI_API_BASE", "GOOGLE_GENAI_USE_GCA"}},
		{"\xef\xbb\xbfOPENAI_API_BASE=x", []string{"OPENAI_API_BASE"}},
		{"OPENAI_API_BASEX=x\n=x\nOPENAI_API_BASE\n", nil},
	}
	for _, tc := range cases {
		if got := DotenvKeysPresent([]byte(tc.body), keys); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%q: got %v, want %v", tc.body, got, tc.want)
		}
	}
}

// TestRouteGateAuthSettingFilesAreCatalogued pins every registry
// AuthSettingKey (CLI-6) to a catalogue row of the same tool, so the
// launcher resolves the path through the one owner.
func TestRouteGateAuthSettingFilesAreCatalogued(t *testing.T) {
	rows := fileRowsByID()
	n := 0
	for _, c := range integration.Capabilities() {
		if c.Proxy == nil || c.Proxy.Gate == nil {
			continue
		}
		for _, k := range c.Proxy.Gate.AuthSettingKeys {
			n++
			r, ok := rows[k.File]
			if !ok || r.Tool != c.Tool {
				t.Errorf("%s: AuthSettingKey file %s is not a catalogue row of the tool", c.Tool, k.File)
			}
		}
	}
	if n == 0 {
		t.Fatal("no AuthSettingKeys in the registry: the CLI-6 gemini-cli rows are gone")
	}
}

// TestKeyPresentClassesSet: a key seen set in a .env file classes as set,
// never as a host it was not read for.
func TestKeyPresentClassesSet(t *testing.T) {
	if c, ok := classifyURL(KeyPresent{}, ClassifyContext{}); !ok || c != classSet {
		t.Fatalf("KeyPresent = %q %v, want set", c, ok)
	}
}
