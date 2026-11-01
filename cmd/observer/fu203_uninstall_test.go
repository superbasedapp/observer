package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// TestFU203UninstallKeepsAForeignBinaryInObserversShape runs `observer
// uninstall --claude-code --cursor` in an isolated home holding the MAC-6
// stand-ins (entries in Observer's `hook <tool> <event>` shape that run
// `lc-hook.sh`): they are kept byte for byte and reported with the FU-192
// reason, with and without --force; a moved Observer's entry beside them is
// still removed.
func TestFU203UninstallKeepsAForeignBinaryInObserversShape(t *testing.T) {
	home := t.TempDir()
	pinToolHomesAt(t, home)
	t.Setenv(crossmount.EnvDisableForeignHomes, "1")
	standIn := filepath.Join(home, "lc", "lc-hook.sh")
	moved := "/usr/lib/observer-new/observer"
	claude := filepath.Join(home, ".claude", "settings.json")
	cursor := filepath.Join(home, ".cursor", "hooks.json")
	foreignOnly := map[string]string{
		claude: `{
  "hooks": {
    "PreToolUse": [
      {"matcher": "*", "hooks": [{"type": "command", "command": "` + standIn + ` hook claude-code pre-tool"}]}
    ]
  }
}
`,
		cursor: `{
  "version": 1,
  "hooks": {
    "preToolUse": [{"command": "` + standIn + ` hook cursor preToolUse"}]
  }
}
`,
	}
	withMoved := map[string]string{
		claude: `{
  "hooks": {
    "PreToolUse": [
      {"matcher": "*", "hooks": [{"type": "command", "command": "` + standIn + ` hook claude-code pre-tool"}]}
    ],
    "Stop": [
      {"hooks": [{"type": "command", "command": "` + moved + ` hook claude-code stop"}]}
    ]
  }
}
`,
		cursor: `{
  "version": 1,
  "hooks": {
    "preToolUse": [{"command": "` + standIn + ` hook cursor preToolUse"}],
    "stop": [{"command": "` + moved + ` hook cursor stop"}]
  }
}
`,
	}
	plant := func(t *testing.T, files map[string]string) {
		t.Helper()
		for p, body := range files {
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	uninstall := func(t *testing.T, extra ...string) string {
		t.Helper()
		cmd := newUninstallCmd()
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&out)
		cmd.SetArgs(append([]string{"--claude-code", "--cursor", "--skip-mcp", "--skip-proxy-route"}, extra...))
		if err := cmd.Execute(); err != nil {
			t.Fatalf("observer uninstall: %v\n%s", err, out.String())
		}
		return out.String()
	}

	for _, force := range []bool{false, true} {
		var extra []string
		name := "without --force"
		if force {
			extra, name = []string{"--force"}, "with --force"
		}
		t.Run("foreign only "+name, func(t *testing.T) {
			plant(t, foreignOnly)
			out := uninstall(t, extra...)
			for p, body := range foreignOnly {
				if got, _ := os.ReadFile(p); string(got) != body {
					t.Errorf("%s changed:\n%s", p, got)
				}
			}
			for _, tool := range []string{"claude-code", "cursor"} {
				reported := false
				for _, l := range strings.Split(out, "\n") {
					if strings.HasPrefix(l, tool+" ") && strings.Contains(l, " hook kept ") && strings.Contains(l, "the entry runs a binary that is not an observer binary") {
						reported = true
					}
				}
				if !reported {
					t.Errorf("uninstall does not report %s's kept entry with the reason:\n%s", tool, out)
				}
			}
		})
	}
	// The planted file has no install record, so the checksum guard asks for
	// --force before anything is removed (unchanged); with it the moved
	// Observer's entry goes and the foreign one stays.
	t.Run("foreign beside a moved Observer", func(t *testing.T) {
		plant(t, withMoved)
		out := uninstall(t, "--force")
		for _, p := range []string{claude, cursor} {
			got, _ := os.ReadFile(p)
			if !strings.Contains(string(got), standIn) {
				t.Errorf("%s lost the foreign entry:\n%s", p, got)
			}
			if strings.Contains(string(got), moved) {
				t.Errorf("%s kept the moved Observer's entry:\n%s\n%s", p, got, out)
			}
		}
	})
}
