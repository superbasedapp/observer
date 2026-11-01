package integration_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/BurntSushi/toml"
	"gopkg.in/yaml.v3"

	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/integration"
)

// timeoutKeyUnits are the keys a registration writer uses for a hook
// timeout and the unit each is in. Plugin shim profiles carry gate_ms and
// observe_ms (the shim's own deadlines, which stand in for the host
// timeout a plugin host does not have).
var timeoutKeyUnits = map[string]time.Duration{
	"timeout":         time.Second,
	"timeout_sec":     time.Second,
	"timeoutSec":      time.Second,
	"timeout_seconds": time.Second,
	"timeoutSeconds":  time.Second,
	"timeout_ms":      time.Millisecond,
	"timeoutMs":       time.Millisecond,
	"timeoutMS":       time.Millisecond,
	"gate_ms":         time.Millisecond,
	"observe_ms":      time.Millisecond,
}

// hostTimeoutWrite says, for one tool with a registered binding whose
// HostTimeout is set, how that value reaches the host: Observer writes it
// under Key in Unit (the key and unit that tool's host reads), or Observer
// writes none and the host's own default is HostTimeout (Default names it).
type hostTimeoutWrite struct {
	Key     string
	Unit    time.Duration
	Default string
	// Stage lists directories (relative to the throwaway home) created
	// before the tool's targets register, for a writer that writes only
	// when its host's directory exists.
	Stage []string
}

// hostTimeoutWrites is the writer side of the binding table (audit finding
// 3 of lane shr-hookseam2). Every tool with a registered binding whose
// HostTimeout is set has a row, and every row has such a tool
// (TestRegistrationWritersWriteTheHostTimeout): a Key row's written config
// must carry exactly that HostTimeout under Key in Unit, and a Default row
// must write no timeout at all. The Unit here, not a file name, is what
// the floor scan reads that tool's Key in.
var hostTimeoutWrites = map[string]hostTimeoutWrite{
	"antigravity-cli": {Key: "timeout", Unit: time.Second},
	"command-code":    {Key: "gate_ms", Unit: time.Millisecond},
	"copilot-cli":     {Key: "timeoutSec", Unit: time.Second},
	"crush":           {Key: "timeout", Unit: time.Second},
	"goose":           {Key: "timeout", Unit: time.Second},
	"grok":            {Key: "timeout", Unit: time.Second},
	"junie":           {Key: "timeout", Unit: time.Second},
	"kimi-code":       {Key: "timeout", Unit: time.Second},
	"kiro-cli":        {Key: "timeout_ms", Unit: time.Millisecond},
	"mistral-code":    {Key: "timeout", Unit: time.Second},
	"muse":            {Key: "timeout", Unit: time.Second},
	"zcode":           {Key: "timeoutMs", Unit: time.Millisecond},
	// The 2026-10-21 wave's writers (merged into the plans line 2026-10-25).
	"autohand":        {Key: "timeout", Unit: time.Millisecond},
	"codebuddy":       {Key: "timeout", Unit: time.Second},
	"deepagents-code": {Key: "timeout", Unit: time.Second},
	"dimcode":         {Key: "timeout", Unit: time.Second},
	"ibm-bob":         {Key: "timeout", Unit: time.Second},
	"vtcode":          {Key: "timeout_seconds", Unit: time.Second},
	"dirac":           {Default: "10 s, Dirac's fixed per-script hook timeout; Observer writes no timeout"},
	"kimchi":          {Default: "5 s, Kimchi's bash-hook timeout; Observer writes no timeout"},
	"claude-code":     {Default: "60 s, Claude Code's command-hook default; Observer writes no timeout"},
	"codex":           {Default: "600 s, Codex's command-hook default; Observer writes no timeout"},
	"cursor":          {Default: "60 s, logged by Cursor; Observer writes no timeout"},
	"gemini-cli":      {Default: "60000 ms, Gemini CLI's documented default; Observer writes no timeout"},
	"poolside":        {Default: "60 s, Poolside's documented default; Observer writes no timeout"},
	"hermes":          {Default: "30 s, Hermes plugins.hook_callback_timeout default; Observer's plugin writes no timeout"},
	// The Devin CLI handler carries the timeout; its writer runs only when
	// the CLI's config directory exists (both OS spellings staged, and
	// Windsurf's so the Cascade file is written too).
	"devin": {Key: "timeout", Unit: time.Second, Stage: []string{
		filepath.Join(".config", "devin"), filepath.Join("AppData", "Roaming", "devin"), filepath.Join(".codeium", "windsurf"),
	}},
}

// writtenTimeout is one timeout value found in a written config file.
type writtenTimeout struct {
	file, key string
	value     time.Duration
}

// unitsFor is timeoutKeyUnits with one tool's own key read in that tool's
// own unit (hostTimeoutWrites), so a host that reads a plain "timeout" in
// milliseconds is scanned in milliseconds.
func unitsFor(tool string) map[string]time.Duration {
	w, ok := hostTimeoutWrites[tool]
	if !ok || w.Key == "" {
		return timeoutKeyUnits
	}
	return withKeyUnit(w.Key, w.Unit)
}

// withKeyUnit is timeoutKeyUnits with key read in unit.
func withKeyUnit(key string, unit time.Duration) map[string]time.Duration {
	units := map[string]time.Duration{}
	for k, v := range timeoutKeyUnits {
		units[k] = v
	}
	units[key] = unit
	return units
}

// timeoutsIn decodes one written file by its extension and returns every
// timeout it carries, reading each key in units. A file kind no writer puts
// a timeout in (an executable hook script, a Python plugin) is skipped.
func timeoutsIn(path string, body []byte, units map[string]time.Duration) ([]writtenTimeout, error) {
	var doc any
	switch ext := strings.ToLower(filepath.Ext(path)); ext {
	case ".json":
		if err := json.Unmarshal(body, &doc); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
	case ".toml":
		var m map[string]any
		if _, err := toml.Decode(string(body), &m); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		doc = m
	case ".yaml", ".yml":
		if err := yaml.Unmarshal(body, &doc); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
	case ".ts", ".js", ".mjs":
		const marker = "const PROFILE = "
		i := bytes.Index(body, []byte(marker))
		if i < 0 {
			return nil, nil
		}
		line := body[i+len(marker):]
		if j := bytes.IndexByte(line, '\n'); j >= 0 {
			line = line[:j]
		}
		if err := json.Unmarshal(bytes.TrimSuffix(bytes.TrimSpace(line), []byte(";")), &doc); err != nil {
			return nil, fmt.Errorf("%s PROFILE: %w", path, err)
		}
	default:
		return nil, nil
	}
	var out []writtenTimeout
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, val := range x {
				if unit, ok := units[k]; ok {
					if n, ok := number(val); ok {
						out = append(out, writtenTimeout{file: path, key: k, value: time.Duration(n * float64(unit))})
					}
				}
				walk(val)
			}
		case []any:
			for _, e := range x {
				walk(e)
			}
		case []map[string]any:
			for _, e := range x {
				walk(e)
			}
		}
	}
	walk(doc)
	return out, nil
}

func number(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int64:
		return float64(n), true
	case int:
		return float64(n), true
	}
	return 0, false
}

// belowFloor returns the written timeouts under the floor.
func belowFloor(found []writtenTimeout) []string {
	var out []string
	for _, w := range found {
		if w.value < integration.WindowsFirstHookFloor {
			out = append(out, fmt.Sprintf("%s: %s = %s is below the %s Windows first-hook floor", w.file, w.key, w.value, integration.WindowsFirstHookFloor))
		}
	}
	sort.Strings(out)
	return out
}

// targetWrites is what one registration target wrote into its own
// throwaway home pair.
type targetWrites struct {
	tool, target string
	registered   bool
	err          error
	// vendor is every timeout in a vendor file (the .observer directory,
	// Observer's own state, is left out).
	vendor []writtenTimeout
	// all is every timeout in every file, for the floor scan.
	all []writtenTimeout
}

// registerEveryTarget runs every registration writer (native and cross-OS
// -windows targets), each into its own throwaway home pair, so every file
// found under a home was written by that one target.
func registerEveryTarget(t *testing.T) []targetWrites {
	t.Helper()
	sandbox := t.TempDir()
	var out []targetWrites
	for _, c := range integration.Capabilities() {
		for _, target := range []string{c.Tool, c.Tool + "-windows"} {
			home := filepath.Join(sandbox, target, "home")
			win := filepath.Join(sandbox, target, "winhome")
			dirs := []string{home, win}
			for _, rel := range hostTimeoutWrites[c.Tool].Stage {
				dirs = append(dirs, filepath.Join(home, rel))
			}
			for _, d := range dirs {
				if err := os.MkdirAll(d, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			reg, err := hook.NewRegistry(hook.Options{
				BinaryPath: "/opt/observer/bin/observer", HomeDir: home,
				ConfigPath:        filepath.Join(home, ".observer", "config.toml"),
				ChecksumsPath:     filepath.Join(home, ".observer", "hook_checksums.json"),
				WSLDistro:         "Ubuntu",
				WindowsClaudeHome: win, WindowsCursorHome: filepath.Join(win, ".cursor"), WindowsCodexHome: win,
				WindowsGeminiHome: win, WindowsQwenHome: win, WindowsFactoryHome: win, WindowsQoderHome: win,
				WindowsPoolsideHome: win, WindowsCommandCodeHome: win,
			})
			if err != nil {
				t.Fatal(err)
			}
			res := reg.Register(target)
			if res.Error != nil && strings.Contains(res.Error.Error(), "not supported") {
				continue
			}
			tw := targetWrites{tool: c.Tool, target: target, err: res.Error, registered: res.Error == nil && len(res.HooksAdded) > 0}
			units := unitsFor(c.Tool)
			for _, root := range []string{home, win} {
				err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
					if err != nil || d.IsDir() {
						return err
					}
					body, err := os.ReadFile(p)
					if err != nil {
						return err
					}
					got, err := timeoutsIn(p, body, units)
					if err != nil {
						t.Errorf("decode %v", err)
					}
					tw.all = append(tw.all, got...)
					if rel, rerr := filepath.Rel(root, p); rerr == nil && !strings.HasPrefix(rel, ".observer"+string(filepath.Separator)) {
						tw.vendor = append(tw.vendor, got...)
					}
					return nil
				})
				if err != nil {
					t.Fatal(err)
				}
			}
			out = append(out, tw)
		}
	}
	return out
}

// TestRegistrationWritersKeepTheFloor checks every hook timeout the
// registration writers put into the vendor configs is at least
// integration.WindowsFirstHookFloor (lane shr-hookseam2, milestone 2). A
// writer that writes a smaller value fails here.
func TestRegistrationWritersKeepTheFloor(t *testing.T) {
	writes := registerEveryTarget(t)
	registered := 0
	var found []writtenTimeout
	for _, w := range writes {
		if w.err != nil {
			t.Logf("Register(%s): %v", w.target, w.err)
		}
		if w.registered {
			registered++
		}
		found = append(found, w.all...)
	}
	if registered < 20 {
		t.Fatalf("only %d targets registered anything; the scan would prove little", registered)
	}
	if len(found) < 10 {
		t.Fatalf("found %d written timeouts across %d registered targets; the decoders miss the writers' shapes", len(found), registered)
	}
	for _, p := range belowFloor(found) {
		t.Error(p)
	}
	t.Logf("%d targets registered, %d written timeouts checked, smallest %s", registered, len(found), smallest(found))
}

// hostTimeoutsByTool is every distinct HostTimeout on a tool's registered
// bindings that the tool's own config carries (a binding the host reaches
// through another tool's config, ReplayedVia, is that tool's value).
func hostTimeoutsByTool() map[string][]time.Duration {
	out := map[string][]time.Duration{}
	for _, c := range integration.Capabilities() {
		seen := map[time.Duration]bool{}
		for _, b := range c.Hook.Bindings {
			if !b.Registered || b.HostTimeout <= 0 || b.ReplayedVia != "" || seen[b.HostTimeout] {
				continue
			}
			seen[b.HostTimeout] = true
			out[c.Tool] = append(out[c.Tool], b.HostTimeout)
		}
	}
	return out
}

// TestRegistrationWritersWriteTheHostTimeout (audit finding 3): for every
// tool whose registered bindings set a HostTimeout, the native target's
// written config carries exactly that value under the key and unit
// hostTimeoutWrites names, or, for a host-default row, no timeout at all.
// A writer that moves to a new key spelling, a new unit, or a new value
// fails here instead of being skipped by the floor scan.
func TestRegistrationWritersWriteTheHostTimeout(t *testing.T) {
	want := hostTimeoutsByTool()
	for tool := range want {
		if _, ok := hostTimeoutWrites[tool]; !ok {
			t.Errorf("%s: registered bindings set a HostTimeout %v but hostTimeoutWrites has no row saying how it is written", tool, want[tool])
		}
	}
	for tool, w := range hostTimeoutWrites {
		if _, ok := want[tool]; !ok {
			t.Errorf("%s: row in hostTimeoutWrites but no registered binding sets a HostTimeout", tool)
		}
		if (w.Key == "") == (w.Default == "") || (w.Key != "" && w.Unit <= 0) {
			t.Errorf("%s: a row names either a Key with its Unit or a Default, not both or neither: %+v", tool, w)
		}
	}
	native := map[string]targetWrites{}
	for _, tw := range registerEveryTarget(t) {
		if tw.target == tw.tool {
			native[tw.tool] = tw
		}
		// A host timeout written by a tool with no Key row has no named
		// unit, so the floor scan would read it in a guessed one. The
		// plugin shim deadlines (gate_ms, observe_ms) carry their unit in
		// the key.
		if hostTimeoutWrites[tw.tool].Key != "" {
			continue
		}
		for _, got := range tw.vendor {
			if got.key != "gate_ms" && got.key != "observe_ms" {
				t.Errorf("%s: wrote %s = %s in %s, but hostTimeoutWrites has no Key row naming its unit", tw.target, got.key, got.value, got.file)
			}
		}
	}
	exact := 0
	for tool, timeouts := range want {
		w, ok := hostTimeoutWrites[tool]
		if !ok {
			continue
		}
		tw, ok := native[tool]
		if w.Key == "" {
			// A host-default row: whatever the target wrote carries no
			// timeout. (Hermes refuses a throwaway home whose config it
			// treats as credential-bearing; it then writes nothing.)
			if len(tw.vendor) > 0 {
				t.Errorf("%s: hostTimeoutWrites says Observer writes no timeout (%s), but it wrote %v", tool, w.Default, tw.vendor)
			}
			continue
		}
		if !ok || !tw.registered {
			t.Errorf("%s: the native target registered nothing (%v), so its host timeout is unproven", tool, tw.err)
			continue
		}
		for _, d := range timeouts {
			hit := false
			for _, got := range tw.vendor {
				if got.key == w.Key && got.value == d {
					hit = true
				}
			}
			if !hit {
				t.Errorf("%s: HostTimeout %s is not written as %s in %s (found %v)", tool, d, w.Key, w.Unit, tw.vendor)
				continue
			}
			exact++
		}
	}
	if exact < 10 {
		t.Fatalf("only %d host timeouts matched their written value; the check would prove little", exact)
	}
	t.Logf("%d host timeouts matched their written value exactly", exact)
}

func smallest(found []writtenTimeout) time.Duration {
	var m time.Duration
	for i, w := range found {
		if i == 0 || w.value < m {
			m = w.value
		}
	}
	return m
}

// TestTimeoutScanCatchesASmallValue proves the scan reads each shape and
// fails a value under the floor in each unit.
func TestTimeoutScanCatchesASmallValue(t *testing.T) {
	ms := withKeyUnit("timeout", time.Millisecond)
	cases := []struct {
		path, body string
		below      bool
		units      map[string]time.Duration
	}{
		{"a/hooks.json", `{"hooks":{"PreToolUse":[{"hooks":[{"command":"x","timeout":2}]}]}}`, true, nil},
		{"a/hooks.json", `{"hooks":{"PreToolUse":[{"hooks":[{"command":"x","timeout":10}]}]}}`, false, nil},
		{"a/agent.json", `{"hooks":[{"command":"x","timeout_ms":3000}]}`, true, nil},
		// A host whose row reads a plain "timeout" in milliseconds.
		{"a/settings.json", `{"hooks":{"BeforeAgent":[{"hooks":[{"timeout":30}]}]}}`, true, ms},
		{"a/settings.json", `{"hooks":{"BeforeAgent":[{"hooks":[{"timeout":30}]}]}}`, false, nil},
		{"a/config.toml", "[[hooks]]\nevent = \"PreToolUse\"\ncommand = \"x\"\ntimeout = 3\n", true, nil},
		{"a/config.toml", "[[hooks]]\nevent = \"PreToolUse\"\ncommand = \"x\"\ntimeout = 30\n", false, nil},
		{"a/settings.yaml", "hooks:\n  PreToolUse:\n    - command: x\n      timeout: 1\n", true, nil},
		{"a/shim.ts", "const PROFILE = {\"gate_ms\":2000,\"observe_ms\":5000};\n", true, nil},
		{"a/shim.ts", "const PROFILE = {\"gate_ms\":10000,\"observe_ms\":5000};\n", false, nil},
	}
	for _, tc := range cases {
		units := tc.units
		if units == nil {
			units = timeoutKeyUnits
		}
		found, err := timeoutsIn(tc.path, []byte(tc.body), units)
		if err != nil || len(found) == 0 {
			t.Errorf("%s %q: found %v, err %v", tc.path, tc.body, found, err)
			continue
		}
		if got := len(belowFloor(found)) > 0; got != tc.below {
			t.Errorf("%s %q: below floor = %v, want %v (%v)", tc.path, tc.body, got, tc.below, found)
		}
	}
}
