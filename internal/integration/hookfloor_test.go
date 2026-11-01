package integration

import (
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"
)

// hostDefault names a host's own hook timeout for the registered bindings
// that leave HostTimeout unset. Default is zero where the vendor states
// none (the named sentence says so); a stated default must itself meet
// the floor.
type hostDefault struct {
	Default time.Duration
	Named   string
}

// hostDefaultTimeouts names the host default of every tool with a
// registered binding whose HostTimeout is unset (lane shr-hookseam2,
// milestone 2). A new unset binding on a tool not listed here fails
// TestHookTimeoutFloor until its host default is named.
var hostDefaultTimeouts = map[string]hostDefault{
	"codex":            {hookCodexHostTimeout, "600 s, Codex's command-hook default (codex-rs/hooks/src/engine/discovery.rs normalize_command_hook)"},
	"cursor":           {hookCursorHostTimeout, "60 s, logged by Cursor (\"Running hook 1 with timeout 60000ms\")"},
	"gemini-cli":       {hookGeminiHostTimeout, "60 s, Gemini CLI's documented default (60000 ms)"},
	"poolside":         {hookPoolsideHostTimeout, "60 s, Poolside's documented default"},
	"hermes":           {30 * time.Second, "30 s, Hermes plugins.hook_callback_timeout default; Observer's own plugin bounds its gate at 10 s"},
	"qwen-code":        {0, "not stated in the vendor doc (fetched 2026-10-02); Observer writes none, so the host default applies"},
	"qoder":            {0, "not stated in the vendor doc (fetched 2026-10-02); Observer writes none, so the host default applies"},
	"droid":            {0, "not stated in the vendor doc (fetched 2026-10-02); Observer writes none, so the host default applies"},
	"devin":            {0, "Windsurf Cascade states none; its only grounded install channel is macOS, so it has no Windows target"},
	"open-interpreter": {0, "not stated in the vendor doc (fetched 2026-10-02); Observer writes none, so the host default applies"},
	"zcode":            {0, "not stated in the vendor doc (fetched 2026-10-02); Observer writes none, so the host default applies"},
	"opencode":         {0, "plugin shim run in the host's process, which wraps it in no timeout; the shim's own deadline is 10 s (gate) and 5 s (observe)"},
	"kilo-code-cli":    {0, "plugin shim run in the host's process, which wraps it in no timeout; the shim's own deadline is 10 s (gate) and 5 s (observe)"},
	"pi":               {0, "plugin shim run in the host's process, which wraps it in no timeout; the shim's own deadline is 10 s (gate) and 5 s (observe)"},
	"command-code":     {0, "TypeScript mod run in the host's process; the mod's own gate deadline is 5 s"},
	"cline-cli":        {0, "plugin run in a sandbox subprocess that no timeout wraps; the shim's own deadline is 10 s"},
}

// floorRules is the floor check for one registered binding, walked top to
// bottom; the first matching row decides.
var floorRules = []struct {
	when    func(b HookBinding, d hostDefault, named bool) bool
	problem func(tool string, b HookBinding, d hostDefault) string
}{
	{
		func(b HookBinding, _ hostDefault, _ bool) bool { return !b.Registered },
		nil,
	},
	{
		func(b HookBinding, _ hostDefault, _ bool) bool {
			return b.HostTimeout > 0 && b.HostTimeout < WindowsFirstHookFloor
		},
		func(tool string, b HookBinding, _ hostDefault) string {
			return fmt.Sprintf("%s %s: host timeout %s is below the %s Windows first-hook floor", tool, b.NativeEvent, b.HostTimeout, WindowsFirstHookFloor)
		},
	},
	{
		func(b HookBinding, _ hostDefault, named bool) bool { return b.HostTimeout == 0 && !named },
		func(tool string, b HookBinding, _ hostDefault) string {
			return fmt.Sprintf("%s %s: host timeout unset and the host default is not named in hostDefaultTimeouts", tool, b.NativeEvent)
		},
	},
	{
		func(b HookBinding, d hostDefault, _ bool) bool {
			return b.HostTimeout == 0 && d.Default > 0 && d.Default < WindowsFirstHookFloor
		},
		func(tool string, b HookBinding, d hostDefault) string {
			return fmt.Sprintf("%s %s: the host default %s (%s) is below the %s floor", tool, b.NativeEvent, d.Default, d.Named, WindowsFirstHookFloor)
		},
	},
}

// floorProblems checks every registered binding of caps against the floor
// and reports any named default no binding needs any more.
func floorProblems(caps []Capability, defaults map[string]hostDefault) []string {
	var out []string
	used := map[string]bool{}
	for _, c := range caps {
		for _, b := range c.Hook.Bindings {
			d, named := defaults[c.Tool]
			if b.Registered && b.HostTimeout == 0 && named {
				used[c.Tool] = true
			}
			for _, r := range floorRules {
				if !r.when(b, d, named) {
					continue
				}
				if r.problem != nil {
					out = append(out, r.problem(c.Tool, b, d))
				}
				break
			}
		}
	}
	for tool := range defaults {
		if !used[tool] {
			out = append(out, fmt.Sprintf("%s: named in hostDefaultTimeouts but has no registered binding with an unset host timeout", tool))
		}
	}
	sort.Strings(out)
	return out
}

// TestHookTimeoutFloor is milestone 2's table check: every registered hook
// binding either sets a host timeout of at least WindowsFirstHookFloor or
// leaves it unset with the host default named (and, where stated, at
// least the floor). Registration is the same on Windows as elsewhere for
// every row (the cross-OS -windows targets write the same events), so
// every registered row is checked.
func TestHookTimeoutFloor(t *testing.T) {
	if WindowsFirstHookFloor != 4*time.Second {
		t.Fatalf("WindowsFirstHookFloor = %s; the JSP-2 laptop half ruled at least 4 s", WindowsFirstHookFloor)
	}
	for _, p := range floorProblems(Capabilities(), hostDefaultTimeouts) {
		t.Error(p)
	}
	for tool, d := range hostDefaultTimeouts {
		if strings.TrimSpace(d.Named) == "" {
			t.Errorf("%s: the host default must be named", tool)
		}
	}
}

// TestHookTimeoutFloorRules proves each rule fires, so a binding below the
// floor cannot pass by accident.
func TestHookTimeoutFloorRules(t *testing.T) {
	reg := func(tool string, timeout time.Duration) Capability {
		return Capability{Tool: tool, Hook: HookSpec{Bindings: []HookBinding{{NativeEvent: "PreToolUse", Registered: true, HostTimeout: timeout}}}}
	}
	cases := []struct {
		name     string
		cap      Capability
		defaults map[string]hostDefault
		want     string
	}{
		{"set at the floor", reg("a", 4*time.Second), nil, ""},
		{"set below the floor", reg("a", 2*time.Second), nil, "below the 4s Windows first-hook floor"},
		{"unset and unnamed", reg("a", 0), nil, "host default is not named"},
		{"unset, named, unstated", reg("a", 0), map[string]hostDefault{"a": {0, "not stated"}}, ""},
		{"unset, named, stated below", reg("a", 0), map[string]hostDefault{"a": {3 * time.Second, "3 s"}}, "is below the 4s floor"},
		{"stale name", reg("a", 30*time.Second), map[string]hostDefault{"a": {0, "x"}}, "has no registered binding with an unset host timeout"},
		{"not registered", Capability{Tool: "a", Hook: HookSpec{Bindings: []HookBinding{{NativeEvent: "X", HostTimeout: time.Second}}}}, nil, ""},
	}
	for _, tc := range cases {
		got := strings.Join(floorProblems([]Capability{tc.cap}, tc.defaults), "\n")
		if tc.want == "" && got != "" || tc.want != "" && !strings.Contains(got, tc.want) {
			t.Errorf("%s: problems %q, want %q", tc.name, got, tc.want)
		}
	}
}
