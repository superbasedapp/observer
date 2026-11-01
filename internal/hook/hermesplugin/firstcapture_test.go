package hermesplugin

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// slowObserver answers a capture event after FAKE_DELAY seconds and records
// that it finished.
const slowObserver = `#!/bin/sh
cat > /dev/null
sleep "$FAKE_DELAY"
echo done >> "$FAKE_DIR/finished"
`

// captureDriver fires one session_start capture through the plugin and
// prints how long it took.
const captureDriver = `
import importlib.util, json, sys, time
spec = importlib.util.spec_from_file_location("obsplugin", sys.argv[1])
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
m.FIRST_CAPTURE_TIMEOUT_SECONDS = 3.0
hooks = {}
class Ctx:
    def register_hook(self, name, fn): hooks[name] = fn
m.register(Ctx())
t = time.monotonic()
hooks["on_session_start"](session_id="s1", model="m", source="cli")
print(json.dumps({"elapsed": time.monotonic() - t}))
`

// TestFirstCaptureAfterAnUpdateGetsTheLongerBound (SHR-2, lane LEFT-SHARED):
// a capture event against an observer binary the plugin has not seen answer
// in time gets the first-capture bound, so a slow first answer (a new
// binary warming up) is not dropped; once it answered, the steady 0.5 s
// bound returns; a changed binary (an update) gets the longer bound again.
func TestFirstCaptureAfterAnUpdateGetsTheLongerBound(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake observer is a POSIX shell script")
	}
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not on PATH")
	}
	dir := t.TempDir()
	obsDir := filepath.Join(dir, "obs")
	if err := os.MkdirAll(obsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	fake := filepath.Join(dir, "observer")
	if err := os.WriteFile(fake, []byte(slowObserver), 0o755); err != nil {
		t.Fatal(err)
	}
	pluginDir := filepath.Join(dir, "plugin")
	if err := WritePlugin(pluginDir, fake); err != nil {
		t.Fatal(err)
	}
	drv := filepath.Join(dir, "drv.py")
	if err := os.WriteFile(drv, []byte(captureDriver), 0o600); err != nil {
		t.Fatal(err)
	}
	finished := func() int {
		b, _ := os.ReadFile(filepath.Join(dir, "finished"))
		return strings.Count(string(b), "done")
	}
	run := func() float64 {
		t.Helper()
		cmd := exec.Command(py, drv, filepath.Join(pluginDir, "__init__.py"))
		cmd.Env = append(os.Environ(), "FAKE_DIR="+dir, "FAKE_DELAY=1",
			"OBSERVER_CONFIG="+filepath.Join(obsDir, "config.toml"), "OBSERVER_BIN="+fake)
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("python driver: %v %s", err, out)
		}
		var r struct{ Elapsed float64 }
		if err := json.Unmarshal(out, &r); err != nil {
			t.Fatalf("driver output %s: %v", out, err)
		}
		return r.Elapsed
	}
	// First capture against an unseen binary: the 1 s answer lands.
	if e := run(); e < 0.9 {
		t.Fatalf("the first capture returned after %.2fs; it must wait for the 1 s answer", e)
	}
	if finished() != 1 {
		t.Fatalf("the first capture after an update was dropped (finished=%d)", finished())
	}
	seen, err := os.ReadFile(filepath.Join(obsDir, "hermes-plugin-seen"))
	if err != nil || len(strings.TrimSpace(string(seen))) == 0 {
		t.Fatalf("the seen binary was not recorded: %q %v", seen, err)
	}
	// Steady state: the same binary gets 0.5 s, so a 1 s answer is cut
	// (the plugin does not wait for it).
	if e := run(); e > 0.9 {
		t.Fatalf("the steady capture waited %.2fs; the bound is 0.5 s", e)
	}
	time.Sleep(1200 * time.Millisecond) // let a cut child that outlived the plugin end
	// An update (the binary changed): the longer bound again.
	if err := os.WriteFile(fake, []byte(slowObserver+"# v2\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	before := finished()
	if e := run(); e < 0.9 {
		t.Fatalf("the first capture after the second update returned after %.2fs", e)
	}
	if finished() < before+1 {
		t.Fatalf("the first capture after the second update was dropped (finished %d -> %d)", before, finished())
	}
}
