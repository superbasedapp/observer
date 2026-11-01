package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/setup"
)

// fakeSetupOS is an in-memory Path and sign-in entry, so the setup commands
// run against Windows-shaped state on any host.
type fakeSetupOS struct {
	path    string
	run     string
	spawned [][]string
	stopped []int
}

func (f *fakeSetupOS) sys() setupOS {
	return setupOS{
		readUserPath:  func() (string, error) { return f.path, nil },
		writeUserPath: func(v string) error { f.path = v; return nil },
		readRun:       func() (string, error) { return f.run, nil },
		writeRun:      func(v string) error { f.run = v; return nil },
		deleteRun:     func() error { f.run = ""; return nil },
		spawnDetached: func(argv []string, _ string) error { f.spawned = append(f.spawned, argv); return nil },
		stopPID:       func(pid int, _ time.Duration) error { f.stopped = append(f.stopped, pid); return nil },
		link:          os.Link,
	}
}

func setupWriteFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
}

func noOthers(string) setup.PreflightResult { return setup.PreflightResult{} }

func TestSetupInstallCopiesAliasAndAutostart(t *testing.T) {
	tmp := t.TempDir()
	src := filepath.Join(tmp, "payload", "observer-new")
	srcW := filepath.Join(tmp, "payload", "observerw-new")
	setupWriteFile(t, src, "v2")
	setupWriteFile(t, srcW, "w")
	dir := filepath.Join(tmp, "bin")
	setupWriteFile(t, filepath.Join(dir, binaryName("observer")), "v1")
	setupWriteFile(t, filepath.Join(dir, binaryName("observer")+".old-1"), "stale")

	f := &fakeSetupOS{path: `C:\a`}
	var out bytes.Buffer
	err := runSetupInstall(setupInstallOptions{
		dir: dir, source: src, observerw: srcW, addPath: true, autostart: true,
		out: &out, sys: f.sys(), preflight: noOthers,
		now: func() time.Time { return time.Unix(0, 0) },
	})
	if err != nil {
		t.Fatalf("install: %v\n%s", err, out.String())
	}
	got, _ := os.ReadFile(filepath.Join(dir, binaryName("observer")))
	if string(got) != "v2" {
		t.Errorf("observer = %q, want the new payload", got)
	}
	alias, _ := os.ReadFile(filepath.Join(dir, binaryName("superbased")))
	if string(alias) != "v2" {
		t.Errorf("superbased alias = %q, want it to match observer", alias)
	}
	if _, err := os.Stat(filepath.Join(dir, binaryName("observer")+".old-1")); !os.IsNotExist(err) {
		t.Error("a stale aside binary from an earlier upgrade was not removed")
	}
	if !setup.HasPathEntry(f.path, dir) || !strings.HasPrefix(f.path, `C:\a;`) {
		t.Errorf("user Path = %q, want %s appended", f.path, dir)
	}
	if want := setup.RunValue(filepath.Join(dir, setup.WindowlessName)); f.run != want {
		t.Errorf("sign-in entry = %q, want %q", f.run, want)
	}
	if !strings.Contains(out.String(), "Upgraded") {
		t.Errorf("an install over an existing binary should say Upgraded:\n%s", out.String())
	}
}

func TestSetupInstallRefusesASecondCopyUnlessForced(t *testing.T) {
	tmp := t.TempDir()
	src := filepath.Join(tmp, "observer-new")
	setupWriteFile(t, src, "v2")
	dir := filepath.Join(tmp, "bin")
	blocked := func(string) setup.PreflightResult {
		return setup.PreflightResult{Others: []setup.Other{{Path: "/usr/lib/node_modules/x/observer", Kind: "npm install", Upgrade: "npm i -g @superbased/observer@latest"}}}
	}
	f := &fakeSetupOS{}

	var out bytes.Buffer
	err := runSetupInstall(setupInstallOptions{dir: dir, source: src, out: &out, sys: f.sys(), preflight: blocked, exitCodes: true})
	var ec exitErr
	if !errors.As(err, &ec) || int(ec) != setupExitBlocked {
		t.Fatalf("err = %v, want exit code %d", err, setupExitBlocked)
	}
	if _, serr := os.Stat(filepath.Join(dir, binaryName("observer"))); !os.IsNotExist(serr) {
		t.Fatal("a refused install must write nothing")
	}
	for _, want := range []string{"npm install", "Nothing was installed", "/FORCE"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, out.String())
		}
	}

	out.Reset()
	if err := runSetupInstall(setupInstallOptions{dir: dir, source: src, out: &out, sys: f.sys(), preflight: blocked, force: true}); err != nil {
		t.Fatalf("forced install: %v", err)
	}
	if _, serr := os.Stat(filepath.Join(dir, binaryName("observer"))); serr != nil {
		t.Fatalf("forced install did not write the binary: %v", serr)
	}
}

func TestSetupInstallNamesTheRestartWhenOurDaemonRuns(t *testing.T) {
	tmp := t.TempDir()
	src := filepath.Join(tmp, "observer-new")
	setupWriteFile(t, src, "v2")
	dir := filepath.Join(tmp, "bin")
	setupWriteFile(t, filepath.Join(dir, binaryName("observer")), "v1")
	own := func(string) setup.PreflightResult {
		return setup.PreflightResult{OwnDaemon: &setup.DaemonInfo{PID: 4242, BinaryPath: filepath.Join(dir, binaryName("observer"))}}
	}
	f := &fakeSetupOS{}
	var out bytes.Buffer
	err := runSetupInstall(setupInstallOptions{dir: dir, source: src, out: &out, sys: f.sys(), preflight: own, exitCodes: true})
	var ec exitErr
	if !errors.As(err, &ec) || int(ec) != setupExitRestartNotice {
		t.Fatalf("err = %v, want exit code %d", err, setupExitRestartNotice)
	}
	for _, want := range []string{"pid 4242", "previous version", "route off first"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, out.String())
		}
	}
	if len(f.stopped) != 0 {
		t.Error("an install must never stop the daemon")
	}
}

func TestPlaceBinarySameFileIsANoop(t *testing.T) {
	tmp := t.TempDir()
	p := filepath.Join(tmp, "observer")
	setupWriteFile(t, p, "x")
	if err := placeBinary(p, p, "1"); err != nil {
		t.Fatalf("placeBinary onto itself: %v", err)
	}
	entries, _ := os.ReadDir(tmp)
	if len(entries) != 1 {
		t.Errorf("placing a binary onto itself left extra files: %v", entries)
	}
}

func TestSetupAutostartNeedsTheWindowlessLauncher(t *testing.T) {
	f := &fakeSetupOS{}
	err := setupAutostartOn(f.sys(), io.Discard, t.TempDir())
	if err == nil || !strings.Contains(err.Error(), setup.WindowlessName) {
		t.Fatalf("err = %v, want a pointer at %s", err, setup.WindowlessName)
	}
	if f.run != "" {
		t.Error("no sign-in entry may be written without the launcher")
	}
}

func TestSetupPathAndAutostartUnsupportedOffWindows(t *testing.T) {
	var none setupOS
	if err := setupPathAdd(none, io.Discard, "/x"); !errors.Is(err, errUserPathUnsupported) {
		t.Errorf("path add = %v, want errUserPathUnsupported", err)
	}
	if err := setupAutostartOn(none, io.Discard, "/x"); !errors.Is(err, errRunUnsupported) {
		t.Errorf("autostart on = %v, want errRunUnsupported", err)
	}
	if !strings.Contains(errRunUnsupported.Error(), "observer service install --now") {
		t.Error("the unsupported message must name the macOS and Linux route")
	}
}

func TestSetupUninstall(t *testing.T) {
	dir := t.TempDir()
	own := &setup.DaemonInfo{PID: 77, BinaryPath: filepath.Join(dir, binaryName("observer"))}

	t.Run("a running daemon from this install blocks without --stop-daemon", func(t *testing.T) {
		f := &fakeSetupOS{path: dir, run: "x"}
		unwired := false
		var out bytes.Buffer
		err := runSetupUninstall(setupUninstallOptions{
			dir: dir, out: &out, sys: f.sys(), exitCodes: true,
			daemon: func() *setup.DaemonInfo { return own },
			unwire: func(io.Writer, bool) error { unwired = true; return nil },
		})
		var ec exitErr
		if !errors.As(err, &ec) || int(ec) != setupExitDaemonRunning {
			t.Fatalf("err = %v, want exit code %d", err, setupExitDaemonRunning)
		}
		if unwired || f.run == "" || f.path == "" || len(f.stopped) != 0 {
			t.Error("a blocked uninstall must change nothing")
		}
	})

	t.Run("--stop-daemon stops it, then removes the entries", func(t *testing.T) {
		f := &fakeSetupOS{path: `C:\a;` + dir, run: "x"}
		var purged bool
		var out bytes.Buffer
		err := runSetupUninstall(setupUninstallOptions{
			dir: dir, out: &out, sys: f.sys(), stopDaemon: true, purge: true,
			daemon: func() *setup.DaemonInfo { return own },
			unwire: func(_ io.Writer, purge bool) error { purged = purge; return nil },
		})
		if err != nil {
			t.Fatalf("uninstall: %v\n%s", err, out.String())
		}
		if len(f.stopped) != 1 || f.stopped[0] != 77 {
			t.Errorf("stopped = %v, want [77]", f.stopped)
		}
		if f.run != "" || f.path != `C:\a` || !purged {
			t.Errorf("after uninstall run=%q path=%q purged=%v", f.run, f.path, purged)
		}
	})

	t.Run("an unwire failure keeps the binaries unless forced", func(t *testing.T) {
		f := &fakeSetupOS{}
		boom := func(io.Writer, bool) error { return errors.New("hook file locked") }
		err := runSetupUninstall(setupUninstallOptions{
			dir: dir, out: io.Discard, sys: f.sys(),
			daemon: func() *setup.DaemonInfo { return nil }, unwire: boom,
		})
		if err == nil || !strings.Contains(err.Error(), "binaries were kept") {
			t.Fatalf("err = %v", err)
		}
		if err := runSetupUninstall(setupUninstallOptions{
			dir: dir, out: io.Discard, sys: f.sys(), force: true,
			daemon: func() *setup.DaemonInfo { return nil }, unwire: boom,
		}); err != nil {
			t.Fatalf("forced uninstall: %v", err)
		}
	})
}

func TestSetupLaunch(t *testing.T) {
	t.Run("already running only opens the dashboard", func(t *testing.T) {
		f := &fakeSetupOS{}
		var opened []string
		var out bytes.Buffer
		err := runSetupLaunch(setupLaunchOptions{
			open: true, out: &out, sys: f.sys(),
			running: func() bool { return true }, browse: func(u string) { opened = append(opened, u) },
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(f.spawned) != 0 {
			t.Error("a running daemon must not be started twice")
		}
		if dashboardInBuild && (len(opened) != 1 || opened[0] != "http://"+defaultDashboardAddr) {
			t.Errorf("opened = %v", opened)
		}
	})

	t.Run("not running starts `observer start --no-open` detached and waits", func(t *testing.T) {
		f := &fakeSetupOS{}
		polls := 0
		var out bytes.Buffer
		err := runSetupLaunch(setupLaunchOptions{
			out: &out, sys: f.sys(), wait: time.Minute,
			running: func() bool { return false },
			ready:   func() bool { polls++; return polls > 2 },
			self:    func() (string, error) { return "/opt/observer", nil },
			logPath: func() string { return filepath.Join(t.TempDir(), "daemon.log") },
			sleep:   func(time.Duration) {},
			browse:  func(string) { t.Error("--open was not asked for") },
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(f.spawned) != 1 || strings.Join(f.spawned[0], " ") != "/opt/observer start --no-open" {
			t.Errorf("spawned = %v", f.spawned)
		}
	})

	t.Run("a daemon that never comes up is reported, not hidden", func(t *testing.T) {
		f := &fakeSetupOS{}
		err := runSetupLaunch(setupLaunchOptions{
			out: io.Discard, sys: f.sys(), wait: 0,
			running: func() bool { return false },
			ready:   func() bool { return false },
			self:    func() (string, error) { return "/opt/observer", nil },
			logPath: func() string { return filepath.Join(t.TempDir(), "daemon.log") },
			sleep:   func(time.Duration) {},
		})
		if err == nil || !strings.Contains(err.Error(), "daemon.log") {
			t.Fatalf("err = %v, want it to name the log", err)
		}
	})
}

func TestObserversOnPath(t *testing.T) {
	a, b := t.TempDir(), t.TempDir()
	name := "observer"
	if runtime.GOOS == "windows" {
		name = "observer.exe"
	}
	setupWriteFile(t, filepath.Join(b, name), "x")
	got := observersOnPath(strings.Join([]string{a, "", b}, string(os.PathListSeparator)))
	if len(got) != 1 || got[0] != filepath.Join(b, name) {
		t.Fatalf("observersOnPath = %v", got)
	}
}
