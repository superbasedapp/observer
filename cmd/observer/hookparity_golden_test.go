package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/integration"
)

// Hook-parity golden gate, cmd-layer facts (docs/plans/hook-parity-lane0-
// brief.md section 2). Generated on the PRE-CHANGE tree (Lane 0 step 1);
// Lane 0 steps 2 to 8 must leave every golden byte-identical. Regenerate
// only with
//
//	go test ./cmd/observer/ -run TestHookParityGolden -hookparity-update
//
// and a commit message that names the expected diff.

var hookParityUpdate = flag.Bool("hookparity-update", false, "rewrite the hook-parity goldens under testdata/hookparity")

const hookParityGoldenDir = "../../testdata/hookparity"

func checkHookParityGolden(t *testing.T, name string, v any) {
	t.Helper()
	var got []byte
	if s, ok := v.(string); ok {
		got = []byte(s)
	} else {
		b, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			t.Fatalf("marshal %s: %v", name, err)
		}
		b = append(b, '\n')
		got = b
	}
	path := filepath.Join(hookParityGoldenDir, name)
	if *hookParityUpdate {
		if err := os.MkdirAll(hookParityGoldenDir, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s: %v", path, err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("hook-parity golden %s changed (Lane 0 golden-equality gate).\n--- got ---\n%s\n--- want ---\n%s", name, got, want)
	}
}

// TestHookParityGolden_InitAndAutoRegister pins, for every registry tool and
// its -windows variant, the init/start predicates and the registry facts
// they read. autoRegisterDecision is the pure decision autoRegisterHooks
// applies (never the writer).
func TestHookParityGolden_InitAndAutoRegister(t *testing.T) {
	requireFullAdapterSet(t)
	// A Linux golden on every host (initOnlyHookTargets is per host OS).
	prevGOOS := autoRegisterHostGOOS
	autoRegisterHostGOOS = "linux"
	t.Cleanup(func() { autoRegisterHostGOOS = prevGOOS })
	out := map[string]any{}
	for _, c := range integration.Capabilities() {
		for _, target := range []string{c.Tool, c.Tool + "-windows"} {
			ac, isWin, ok := advertisedCapability(target)
			out[target] = map[string]any{
				"hook_supported":             hookSupported(target),
				"advertised_ok":              ok,
				"advertised_is_windows":      isWin,
				"enforcement":                string(ac.EnforcementChannel()),
				"prompt_lane":                string(ac.PromptLane),
				"prompt_lane_only":           ac.Hook.PromptLaneOnly,
				"auto_register_prompt_on":    autoRegisterDecision(target, true),
				"auto_register_prompt_off":   autoRegisterDecision(target, false),
				"auto_register_remediation":  autoRegisterRemediation(target),
				"receiver_registered_for_id": hookReceivers[c.Tool] != nil,
			}
		}
	}
	checkHookParityGolden(t, "init_autoregister.json", out)
}

// TestHookParityGolden_ReceiverTable pins hookReceivers' keys and, for every
// key, the function that handles it (anonymous closures are recorded by
// their compiler name, which is stable while no closure is added before
// them in this package's initialisers).
// constructedClosureRE matches a closure built by a named constructor and
// inlined into a package initialiser, capturing the constructor's name.
var constructedClosureRE = regexp.MustCompile(`^(?:init|glob)\.([A-Za-z_][A-Za-z0-9_]*)\.func[0-9]+(?:\.[0-9]+)*$`)

func TestHookParityGolden_ReceiverTable(t *testing.T) {
	requireFullAdapterSet(t)
	out := map[string]string{}
	for tool, fn := range hookReceivers {
		name := runtime.FuncForPC(reflect.ValueOf(fn).Pointer()).Name()
		name = strings.TrimPrefix(name, "github.com/marmutapp/superbased-observer/cmd/observer.")
		if strings.HasPrefix(name, "init.func") || strings.HasPrefix(name, "glob.func") {
			// An anonymous closure: its compiler number shifts whenever a
			// closure is added anywhere earlier in this package's
			// initialisers, so only its KIND is pinned here; what it does is
			// pinned by TestHookParityGolden_ReceiverReplies.
			name = "closure"
		} else if m := constructedClosureRE.FindStringSubmatch(name); m != nil {
			// A closure RETURNED by a named constructor and inlined into an
			// initialiser ("init.wavePromptReceiver.func294"): the number
			// differs between GOOS builds (a platform file adds or drops an
			// earlier closure), so only the constructor is pinned.
			name = m[1] + " closure"
		}
		out[tool] = name
	}
	checkHookParityGolden(t, "receiver_table.json", out)
}

// TestHookParityGolden_AdaptersMatrix pins the rendered `observer adapters`
// matrix (hook and prompt columns included).
func TestHookParityGolden_AdaptersMatrix(t *testing.T) {
	requireFullAdapterSet(t)
	var buf bytes.Buffer
	caps := integration.Capabilities()
	// Same order newAdaptersCmd renders (Capabilities() is map-ordered).
	sort.Slice(caps, func(i, j int) bool { return caps[i].Tool < caps[j].Tool })
	renderAdapterMatrix(&buf, caps, func(string) bool { return false })
	checkHookParityGolden(t, "adapters_matrix.txt", buf.String())
}

// hookParityInvocationRE pulls `hook <tool> <event>` out of a written hook
// config (JSON, YAML, TS) whatever its quoting.
var hookParityInvocationRE = regexp.MustCompile(`hook\s+([a-z0-9-]+)\s+([A-Za-z_-]+)`)

// hookParityInvocations is every (tool, event) argv pair a registered config
// can invoke today, read back out of the files each registration writer
// produces in a pinned throwaway home, plus the embedded-plugin transports
// that are not written by hook.Registry (Hermes' plugin hooks, commandcode's
// Mods bridge), plus two probe events for every registry tool without a
// receiver (the default HandleApprove path) and an unknown event for every
// receiver.
func hookParityInvocations(t *testing.T) []string {
	t.Helper()
	set := map[string]bool{}
	targets := []string{
		"claude-code", "cursor", "codex", "gemini-cli", "qwen-code", "droid",
		"qoder", "poolside", "devin", "command-code", "antigravity-cli",
	}
	for _, target := range targets {
		home, err := os.MkdirTemp("", "hookparity-cmd")
		if err != nil || home == "" {
			t.Fatalf("mkdtemp: %v", err)
		}
		for _, d := range []string{
			".claude", ".cursor", ".codex", ".gemini", filepath.Join(".gemini", "config"),
			".qwen", ".factory", ".qoder", filepath.Join(".config", "poolside"),
			filepath.Join(".codeium", "windsurf"), ".commandcode",
		} {
			if err := os.MkdirAll(filepath.Join(home, d), 0o755); err != nil {
				t.Fatalf("mkdir: %v", err)
			}
		}
		reg, err := hook.NewRegistry(hook.Options{
			BinaryPath:    "/opt/observer/bin/observer",
			HomeDir:       home,
			ChecksumsPath: filepath.Join(home, ".observer", "hook_checksums.json"),
		})
		if err != nil {
			t.Fatalf("NewRegistry: %v", err)
		}
		_ = reg.Register(target)
		_ = filepath.WalkDir(home, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			data, rerr := os.ReadFile(p)
			if rerr != nil {
				return nil
			}
			for _, m := range hookParityInvocationRE.FindAllStringSubmatch(string(data), -1) {
				// Only a real dispatch tool (comments in an embedded
				// plugin can match the pattern too).
				if _, ok := integration.For(m[1]); !ok {
					continue
				}
				set[m[1]+" "+m[2]] = true
			}
			return nil
		})
		_ = os.RemoveAll(home)
	}
	for _, ev := range []string{"on_session_start", "on_session_end", "post_tool_call", "post_api_request", "subagent_stop"} {
		set["hermes "+ev] = true
	}
	set["command-code transformInput"] = true
	for _, c := range integration.Capabilities() {
		if _, ok := hookReceivers[c.Tool]; ok {
			set[c.Tool+" no-such-event"] = true
			continue
		}
		set[c.Tool+" PreToolUse"] = true
		set[c.Tool+" UserPromptSubmit"] = true
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestHookParityGolden_ReceiverReplies runs a REAL observer binary for every
// invocable (tool, event) with a guard-off config and an empty JSON object
// on stdin, and pins the stdout bytes and exit code. Stderr is diagnostics
// (timestamps) and is not pinned.
func TestHookParityGolden_ReceiverReplies(t *testing.T) {
	requireFullAdapterSet(t)
	binary := probeHookTestBinary(t)
	dir := t.TempDir()
	home := filepath.Join(dir, "home")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "config.toml")
	cfg := "[observer]\ndb_path = " + strconv.Quote(filepath.ToSlash(filepath.Join(dir, "observer.db"))) + "\n\n" +
		"[guard]\nenabled = false\n"
	if err := os.WriteFile(configPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	type reply struct {
		Stdout   string `json:"stdout"`
		ExitCode int    `json:"exit_code"`
	}
	out := map[string]reply{}
	for _, inv := range hookParityInvocations(t) {
		parts := strings.SplitN(inv, " ", 2)
		c := exec.Command(binary, "hook", parts[0], parts[1], "--config", configPath)
		c.Stdin = strings.NewReader("{}")
		c.Env = append(os.Environ(), "HOME="+home, "USERPROFILE=")
		var stdout, stderr bytes.Buffer
		c.Stdout, c.Stderr = &stdout, &stderr
		code := 0
		if err := c.Run(); err != nil {
			var ee *exec.ExitError
			if !errors.As(err, &ee) {
				t.Fatalf("%s: %v (stderr=%s)", inv, err, stderr.String())
			}
			code = ee.ExitCode()
		}
		out[inv] = reply{Stdout: stdout.String(), ExitCode: code}
	}
	checkHookParityGolden(t, "receiver_replies.json", out)
}
