package zedhost

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
)

func TestToolForExtensionAgent(t *testing.T) {
	cases := []struct {
		extension, key string
		want           string
		ok             bool
	}{
		{"kilo", "opencode", models.ToolKiloCodeCLI, true},
		// The server key alone never decides: "opencode" under another
		// extension (or none) is not Kilo and is not assumed to be OpenCode.
		{"opencode", "opencode", "", false},
		{"", "opencode", "", false},
		{"kilo", "kilo", "", false},
	}
	for _, tc := range cases {
		got, ok := ToolForExtensionAgent(tc.extension, tc.key)
		if got != tc.want || ok != tc.ok {
			t.Errorf("ToolForExtensionAgent(%q, %q) = %q, %v; want %q, %v", tc.extension, tc.key, got, ok, tc.want, tc.ok)
		}
	}
}
