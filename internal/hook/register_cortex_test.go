package hook

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func cortexRegistry(t *testing.T, home string, env map[string]string) *Registry {
	t.Helper()
	reg, err := NewRegistry(Options{
		BinaryPath: "/usr/local/bin/observer", HomeDir: home,
		Getenv: func(k string) string { return env[k] },
	})
	if err != nil {
		t.Fatal(err)
	}
	return reg
}

// TestCortexWriterIsGated: by default the Cortex Code hooks.json writer
// refuses (DEC-12, LC18) and writes nothing, even with the data home there.
func TestCortexWriterIsGated(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".snowflake", "cortex"), 0o755); err != nil {
		t.Fatal(err)
	}
	res := cortexRegistry(t, home, nil).Register("cortex-code")
	if !res.Skipped || res.SkipKind != SkipLiveGated || !strings.Contains(res.SkipReason, "built, waiting on live check LC18") {
		t.Fatalf("Register = %+v, want the LC18 live-gate skip", res)
	}
	if _, err := os.Stat(filepath.Join(home, ".snowflake", "cortex", "hooks.json")); !os.IsNotExist(err) {
		t.Error("the gated writer created hooks.json")
	}
}

// TestCortexWriter runs the writer past its gate: Claude-shaped matcher
// groups under "hooks" running Observer's cortex-code command (FU-141: told
// apart from the Claude settings replay of the same call), the user's own
// entries and keys kept,
// SNOWFLAKE_HOME honoured, a second run AlreadySet, disableAllHooks
// respected, and Unregister gives back the file it found.
func TestCortexWriter(t *testing.T) {
	runLiveGatedHookWriters = true
	t.Cleanup(func() { runLiveGatedHookWriters = false })

	home := t.TempDir()
	snow := filepath.Join(t.TempDir(), "snow")
	dir := filepath.Join(snow, "cortex")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "hooks.json")
	orig := `{
  "hooks": {
    "PreToolUse": [
      {"matcher": "Bash", "hooks": [{"type": "command", "command": "/opt/mine/audit.sh"}]}
    ]
  },
  "userKey": 1
}
`
	if err := os.WriteFile(path, []byte(orig), 0o644); err != nil {
		t.Fatal(err)
	}
	reg := cortexRegistry(t, home, map[string]string{"SNOWFLAKE_HOME": snow})
	res := reg.Register("cortex-code")
	if res.Error != nil || res.Skipped || res.ConfigPath != path || len(res.HooksAdded) == 0 {
		t.Fatalf("Register = %+v", res)
	}
	raw, _ := os.ReadFile(path)
	var doc struct {
		Hooks   map[string][]map[string]any `json:"hooks"`
		UserKey int                         `json:"userKey"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("result does not parse: %v\n%s", err, raw)
	}
	if doc.UserKey != 1 || !strings.Contains(string(raw), "/opt/mine/audit.sh") {
		t.Errorf("the user's own entry or key was lost:\n%s", raw)
	}
	for _, ev := range res.HooksAdded {
		if !strings.Contains(string(raw), "hook cortex-code "+ev) || strings.Contains(string(raw), "hook claude-code "+ev) {
			t.Errorf("event %s: want a `hook cortex-code %s` command and no claude-code one:\n%s", ev, ev, raw)
		}
	}
	if _, err := os.Stat(filepath.Join(home, ".snowflake")); !os.IsNotExist(err) {
		t.Error("the writer ignored SNOWFLAKE_HOME and wrote under the home")
	}
	if again := reg.Register("cortex-code"); again.Error != nil || len(again.HooksAdded) != 0 || len(again.AlreadySet) == 0 {
		t.Errorf("second Register = %+v, want AlreadySet", again)
	}
	un := reg.Unregister("cortex-code")
	if un.Error != nil || len(un.HooksRemoved) == 0 {
		t.Fatalf("Unregister = %+v", un)
	}
	back, _ := os.ReadFile(path)
	var a, b any
	_ = json.Unmarshal([]byte(orig), &a)
	_ = json.Unmarshal(back, &b)
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	if string(ja) != string(jb) {
		t.Errorf("Unregister did not give back the original:\n%s", back)
	}

	off := `{"disableAllHooks": true}`
	if err := os.WriteFile(path, []byte(off), 0o644); err != nil {
		t.Fatal(err)
	}
	if res := reg.Register("cortex-code"); !res.Skipped || !strings.Contains(res.SkipReason, "disableAllHooks") {
		t.Errorf("disableAllHooks: %+v", res)
	}
	if got, _ := os.ReadFile(path); string(got) != off {
		t.Error("the writer touched a hooks.json that turns hooks off")
	}
}

// TestCortexWriterRefusesRelativeHome: a relative SNOWFLAKE_HOME names no
// file Observer can be sure of, so nothing is written.
func TestCortexWriterRefusesRelativeHome(t *testing.T) {
	runLiveGatedHookWriters = true
	t.Cleanup(func() { runLiveGatedHookWriters = false })
	home := t.TempDir()
	res := cortexRegistry(t, home, map[string]string{"SNOWFLAKE_HOME": "rel/snow"}).Register("cortex-code")
	if res.Error == nil || !strings.Contains(res.Error.Error(), "SNOWFLAKE_HOME") {
		t.Errorf("Register = %+v, want the relative-path refusal", res)
	}
}

// TestCortexInstallFollowsTheArtifact: Cortex Code is detected through the
// cortex-code/user-hooks artifact's directory, so the default home and a
// relocated SNOWFLAKE_HOME both count, and an unrelated home does not.
func TestCortexInstallFollowsTheArtifact(t *testing.T) {
	has := func(tools []string) bool {
		for _, x := range tools {
			if x == "cortex-code" {
				return true
			}
		}
		return false
	}
	home := t.TempDir()
	if has(cortexRegistry(t, home, nil).Installed()) {
		t.Fatal("cortex-code detected with no data home")
	}
	if err := os.MkdirAll(filepath.Join(home, ".snowflake", "cortex"), 0o755); err != nil {
		t.Fatal(err)
	}
	if !has(cortexRegistry(t, home, nil).Installed()) {
		t.Error("the default ~/.snowflake/cortex home is not detected")
	}
	home2 := t.TempDir()
	snow := filepath.Join(t.TempDir(), "snow")
	if err := os.MkdirAll(filepath.Join(snow, "cortex"), 0o755); err != nil {
		t.Fatal(err)
	}
	if !has(cortexRegistry(t, home2, map[string]string{"SNOWFLAKE_HOME": snow}).Installed()) {
		t.Error("a relocated SNOWFLAKE_HOME is not detected")
	}
}

// TestCortexUnregisterIsInertWhileGated: while LC18 gates the writer,
// Unregister reads nothing (a FIFO at the path would otherwise hang
// uninstall) and reports a skip.
func TestCortexUnregisterIsInertWhileGated(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".snowflake", "cortex")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// A directory where the file should be: any read would fail loudly.
	if err := os.Mkdir(filepath.Join(dir, "hooks.json"), 0o755); err != nil {
		t.Fatal(err)
	}
	un := cortexRegistry(t, home, nil).Unregister("cortex-code")
	if un.Error != nil || !un.Skipped || len(un.HooksRemoved) != 0 {
		t.Errorf("Unregister while gated = %+v, want an inert skip", un)
	}
}
