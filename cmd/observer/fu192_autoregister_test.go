package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// TestFU192StartKeepsAForeignBinaryInObserversShape (ruling AW-117) runs
// `observer start`'s auto-registration in an isolated home holding the MAC-6
// stand-ins: hook entries in Observer's `hook <tool> <event>` shape that run
// another binary (`lc-hook.sh`). Without --force every such file stays byte
// for byte and the refusal names the reason; the dashboard's install path
// takes the same rule.
func TestFU192StartKeepsAForeignBinaryInObserversShape(t *testing.T) {
	// Registration runs only for active adapters; a stamped edition that
	// leaves them inactive by default (minimal, managed) registers nothing
	// (RB1 gate: these failed under the minimal edition's tag set).
	requireActiveAdapters(t, "claude-code", "cursor", "gemini-cli")
	home := t.TempDir()
	pinToolHomesAt(t, home)
	t.Setenv(crossmount.EnvDisableForeignHomes, "1")
	standIn := filepath.Join(home, "lc", "lc-hook.sh")
	files := map[string]string{
		filepath.Join(".claude", "settings.json"): `{
  "hooks": {
    "PreToolUse": [
      {"matcher": "*", "hooks": [{"type": "command", "command": "` + standIn + ` hook claude-code pre-tool"}]}
    ]
  }
}
`,
		filepath.Join(".cursor", "hooks.json"): `{
  "version": 1,
  "hooks": {
    "preToolUse": [{"command": "` + standIn + ` hook cursor preToolUse"}]
  }
}
`,
		filepath.Join(".gemini", "settings.json"): `{
  "hooks": {
    "BeforeTool": [
      {"matcher": "*", "hooks": [{"type": "command", "command": "` + standIn + ` hook gemini-cli BeforeTool"}]}
    ]
  }
}
`,
	}
	for rel, body := range files {
		p := filepath.Join(home, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cfg := filepath.Join(home, ".observer", "config.toml")
	if err := os.MkdirAll(filepath.Dir(cfg), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	check := func(t *testing.T, stderr string, tools ...string) {
		t.Helper()
		for rel, body := range files {
			got, err := os.ReadFile(filepath.Join(home, rel))
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != body {
				t.Errorf("%s changed without --force:\n%s", rel, got)
			}
		}
		for _, tool := range tools {
			if !strings.Contains(stderr, "WARN auto-register "+tool+":") || !strings.Contains(stderr, "the entry runs a binary that is not an observer binary") {
				t.Errorf("stderr does not report %s's refusal with the reason:\n%s", tool, stderr)
			}
		}
	}

	t.Run("observer start", func(t *testing.T) {
		var out, errb bytes.Buffer
		autoRegisterHooks(&out, &errb, cfg, true)
		check(t, errb.String(), "claude-code", "cursor", "gemini-cli")
		if strings.Contains(out.String(), "rewrote hook") {
			t.Errorf("start reported a rewrite:\n%s", out.String())
		}
	})
	t.Run("dashboard install path", func(t *testing.T) {
		var out, errb bytes.Buffer
		autoRegisterInstalledTool(&out, &errb, cfg, true, "claude-code")
		check(t, errb.String(), "claude-code")
	})
}
