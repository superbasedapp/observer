package integration_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

// TestDarwinSandboxStateRows pins D-MU6 (live macOS user install
// 2026-10-29): on darwin each tool's box binds the state it was seen to
// need, and the extra rows apply only on darwin.
func TestDarwinSandboxStateRows(t *testing.T) {
	cases := []struct {
		tool string
		want string
	}{
		{"opencode", ".local/state/opencode"},
		{"opencode", ".cache/opencode"},
		{"goose", ".local/state/goose"},
		{"copilot-cli", "Library/Caches/copilot"},
	}
	for _, c := range cases {
		spec, ok := integration.For(c.tool)
		if !ok {
			t.Fatalf("%s: no registry row", c.tool)
		}
		mac := spec.Sandbox.ForOS("darwin")
		if !slices.Contains(mac.StateRW, c.want) {
			t.Errorf("%s on darwin: StateRW = %v, want %s", c.tool, mac.StateRW, c.want)
		}
		for _, p := range spec.Sandbox.StateRW {
			if !slices.Contains(mac.StateRW, p) {
				t.Errorf("%s on darwin lost %s", c.tool, p)
			}
		}
		if slices.Contains(spec.Sandbox.ForOS("linux").StateRW, c.want) {
			t.Errorf("%s: the darwin row %s leaked onto linux", c.tool, c.want)
		}
	}
}

// TestGeminiDarwinLimitationRecorded pins the conservative /bin/ps decision:
// the profile keeps refusing the setuid program and the gemini-cli row says
// so for darwin only.
func TestGeminiDarwinLimitationRecorded(t *testing.T) {
	spec, _ := integration.For("gemini-cli")
	if n := spec.Sandbox.OSNote("darwin"); !strings.Contains(n, "/bin/ps") {
		t.Errorf("gemini-cli darwin note = %q", n)
	}
	if spec.Sandbox.OSNote("linux") != "" {
		t.Error("the note is darwin-only")
	}
}

// TestForOSDoesNotAlias pins that ForOS returns a fresh StateRW and drops
// the OS tables.
func TestForOSDoesNotAlias(t *testing.T) {
	s := integration.SandboxSpec{StateRW: []string{".a"}, StateRWByOS: map[string][]string{"darwin": {".b", ".a"}}}
	got := s.ForOS("darwin")
	if !slices.Equal(got.StateRW, []string{".a", ".b"}) || got.StateRWByOS != nil {
		t.Fatalf("ForOS = %+v", got)
	}
	got.StateRW[0] = "x"
	if s.StateRW[0] != ".a" {
		t.Error("ForOS aliased the row's StateRW")
	}
}
