package locate

import (
	"strings"
	"testing"
)

// TestRelativeRelocationNamesNoMCPFile pins R-188 F6 in the locate table: a
// relocation variable holding a relative path names no MCP file (Path is
// empty, Unresolved is the variable, Refusal names it), never the vendor
// default under the home; a client the variable does not move still
// resolves under the home.
func TestRelativeRelocationNamesNoMCPFile(t *testing.T) {
	home := t.TempDir()
	cases := []struct{ client, env string }{
		{"claude-code", "CLAUDE_CONFIG_DIR"},
		{"codex", "CODEX_HOME"},
		{"cline", "CLINE_DIR"},
		{"cline", "CLINE_DATA_DIR"},
	}
	for _, tc := range cases {
		t.Run(tc.client+"/"+tc.env, func(t *testing.T) {
			getenv := func(k string) string {
				if k == tc.env {
					return "observer-r188-rel"
				}
				return ""
			}
			loc, ok := ForClientEnv(tc.client, home, getenv)
			if !ok {
				t.Fatalf("no %s row", tc.client)
			}
			if loc.Path != "" || loc.Unresolved != tc.env {
				t.Errorf("Path %q, Unresolved %q; want no path and %s", loc.Path, loc.Unresolved, tc.env)
			}
			if err := loc.Refusal(); err == nil || !strings.Contains(err.Error(), tc.env) {
				t.Errorf("Refusal() = %v, want an error naming %s", err, tc.env)
			}
			other, _ := ForClientEnv("cursor", home, getenv)
			if other.Path == "" || other.Unresolved != "" || other.Refusal() != nil {
				t.Errorf("cursor, which %s does not move: %+v", tc.env, other)
			}
		})
	}
}
