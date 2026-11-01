package sandboximage

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// vmrecipe_debug_test.go pins the debug variant of the microVM recipe
// (R-016): its self-check passes a good debug rootfs and /init and names a
// bad one, the release build never takes the debug files, and the hooks
// never read a trigger's content (no command text crosses to root).
func TestVMDebugRecipeSelfCheck(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the recipe checks are bash run on the Linux build host")
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("no bash")
	}
	script, err := filepath.Abs(filepath.Join("..", "..", "deploy", "sandbox-vm-image", "debug", "selfcheck-debug.sh"))
	if err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) (string, error) {
		out, err := exec.Command(bash, append([]string{script}, args...)...).CombinedOutput()
		return string(out), err
	}

	// The rootfs check: every hook a regular 0755 file under the debug dir.
	root := t.TempDir()
	dir := filepath.Join(root, "usr", "libexec", "observer-debug")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"init-wrapper", "debugd", "remount-root"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("#!/bin/bash\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if out, err := run("rootfs", root); err != nil {
		t.Fatalf("a good debug rootfs: %v %s", err, out)
	}
	if err := os.Chmod(filepath.Join(dir, "debugd"), 0o777); err != nil {
		t.Fatal(err)
	}
	if out, err := run("rootfs", root); err == nil || !strings.Contains(out, "debugd is mode 777") {
		t.Fatalf("a world-writable hook: %v %s", err, out)
	}
	if err := os.Remove(filepath.Join(dir, "remount-root")); err != nil {
		t.Fatal(err)
	}
	if out, err := run("rootfs", root); err == nil || !strings.Contains(out, "remount-root is missing") {
		t.Fatalf("a missing hook: %v %s", err, out)
	}

	// The /init check: the release /init with PID 1 handed to init-wrapper.
	release := readVMRecipe(t, "init")
	debugInit := strings.Replace(release, "switch_root /newroot /run/observer-boot/observer-guest", "switch_root /newroot /usr/libexec/observer-debug/init-wrapper /run/observer-boot/observer-guest", 1)
	if debugInit == release {
		t.Fatal("the release /init has no switch_root line to hand over")
	}
	p := filepath.Join(t.TempDir(), "init")
	for _, c := range []struct {
		name, body string
		ok         bool
	}{
		{"the derived debug /init", debugInit, true},
		{"the release /init unchanged", release, false},
		{"a debug /init with anything else changed", debugInit + "echo extra\n", false},
	} {
		if err := os.WriteFile(p, []byte(c.body), 0o755); err != nil {
			t.Fatal(err)
		}
		out, err := run("init", p)
		if (err == nil) != c.ok {
			t.Errorf("%s: err %v, want ok %v: %s", c.name, err, c.ok, out)
		}
	}
}

// TestVMDebugRecipeStaysOutOfTheReleaseBuild: build.sh takes the debug
// files only under --debug, the release recipe names none of them, and the
// hooks act on a trigger's name alone.
func TestVMDebugRecipeStaysOutOfTheReleaseBuild(t *testing.T) {
	build := readVMRecipe(t, "build.sh")
	for _, want := range []string{`--debug) debug=true`, `if [ "$debug" = true ]; then`, `selfcheck-debug.sh" rootfs`, `selfcheck-debug.sh" init`, `cp "$here/init" "$ird/init"`, `rm -f "$build/debug"`} {
		if !strings.Contains(build, want) {
			t.Errorf("build.sh lacks %q", want)
		}
	}
	if strings.Contains(readVMRecipe(t, "recipe.env"), "debug") {
		t.Error("recipe.env names the debug variant; the release recipe must not")
	}
	if strings.Contains(readVMRecipe(t, "init"), "observer-debug") {
		t.Error("the release /init names the debug hooks")
	}
	debugd := readVMRecipe(t, filepath.Join("debug", "debugd"))
	for _, bad := range []string{"cat \"$dir", "source ", ". \"$dir", "eval ", "$(cat"} {
		if strings.Contains(debugd, bad) {
			t.Errorf("debugd reads a trigger's content (%q); a hook acts on the name only", bad)
		}
	}
}

// debugdEnv runs debugd against temp paths with a fake hook directory: the
// trigger dir, the root-only work dir and a remount-root that prints a fixed
// line. It starts debugd and returns it with the paths.
func debugdStart(t *testing.T, plantDir, plantWork bool) (cmd *exec.Cmd, dir, work string) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("debugd is a Linux guest script")
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("no bash")
	}
	script, err := filepath.Abs(filepath.Join("..", "..", "deploy", "sandbox-vm-image", "debug", "debugd"))
	if err != nil {
		t.Fatal(err)
	}
	base := t.TempDir()
	dir, work = filepath.Join(base, "trigger"), filepath.Join(base, "work")
	hooks := filepath.Join(base, "hooks")
	if err := os.MkdirAll(hooks, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hooks, "remount-root"), []byte("#!/bin/bash\necho fake-remount-output\n"), 0o755); err != nil { //nolint:gosec // G306: a test hook script
		t.Fatal(err)
	}
	if plantDir {
		if err := os.Symlink(t.TempDir(), dir); err != nil {
			t.Fatal(err)
		}
	}
	if plantWork {
		if err := os.Mkdir(work, 0o777); err != nil {
			t.Fatal(err)
		}
	}
	cmd = exec.Command(bash, script) //nolint:gosec // G204: the repository's own script
	cmd.Env = append(os.Environ(), "OBSERVER_DEBUG_DIR="+dir, "OBSERVER_DEBUG_WORK="+work, "OBSERVER_DEBUG_HOOKS="+hooks, "OBSERVER_DEBUG_NO_WAIT=1")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })
	return cmd, dir, work
}

// TestDebugdFollowsNoPlantedPath (LEFT2 audit S6): debugd runs as root in
// the debug guest, and the agent can write the trigger directory. A link
// the agent planted at <hook>.out is replaced, never followed; debugd
// refuses to start over a trigger or work directory that already exists
// (a planted directory or link), so it never chmods one.
func TestDebugdFollowsNoPlantedPath(t *testing.T) {
	t.Run("a planted .out link is replaced, not followed", func(t *testing.T) {
		_, dir, _ := debugdStart(t, false, false)
		deadline := time.Now().Add(10 * time.Second)
		for {
			if fi, err := os.Lstat(dir); err == nil && fi.IsDir() {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("debugd never created its trigger directory")
			}
			time.Sleep(20 * time.Millisecond)
		}
		victim := filepath.Join(t.TempDir(), "victim")
		if err := os.WriteFile(victim, []byte("keep"), 0o600); err != nil {
			t.Fatal(err)
		}
		out := filepath.Join(dir, "remount-root.out")
		if err := os.Symlink(victim, out); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "remount-root"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		for {
			if fi, err := os.Lstat(out); err == nil && fi.Mode().IsRegular() {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("the hook's output never replaced the planted link")
			}
			time.Sleep(20 * time.Millisecond)
		}
		if b, _ := os.ReadFile(victim); string(b) != "keep" {
			t.Fatalf("debugd wrote through the planted link: the victim reads %q", b)
		}
		if b, _ := os.ReadFile(out); !strings.Contains(string(b), "fake-remount-output") {
			t.Fatalf("the output is %q", b)
		}
	})
	for _, c := range []struct {
		name             string
		plantDir, plantW bool
	}{{"a planted trigger directory link", true, false}, {"a planted work directory", false, true}} {
		t.Run(c.name, func(t *testing.T) {
			cmd, dir, _ := debugdStart(t, c.plantDir, c.plantW)
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("debugd started over a planted path")
				}
			case <-time.After(10 * time.Second):
				t.Fatal("debugd kept running over a planted path")
			}
			if c.plantDir {
				target, _ := os.Readlink(dir)
				if fi, err := os.Stat(target); err == nil && fi.Mode().Perm()&0o002 != 0 {
					t.Fatalf("debugd chmodded the planted directory's target: %v", fi.Mode())
				}
			}
		})
	}
}
