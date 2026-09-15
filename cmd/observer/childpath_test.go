package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/termsvc"
)

// cpAbs builds an ABSOLUTE path that filepath.IsAbs accepts on the HOST
// running the test (a bare "/x" is not absolute on Windows), so the PATH
// expectations below hold on both the Windows dev box and Linux CI.
func cpAbs(parts ...string) string {
	root := string(filepath.Separator)
	if runtime.GOOS == "windows" {
		root = `C:\`
	}
	return filepath.Join(append([]string{root}, parts...)...)
}

func cpJoin(dirs ...string) string {
	return strings.Join(dirs, string(os.PathListSeparator))
}

// TestChildPATH is the composition table (audit DI-04b): binDir first, then the
// login-only dirs, then EVERY daemon entry unchanged and in order, with empty
// and relative entries dropped and duplicates collapsed to their first (highest
// priority) occurrence.
func TestChildPATH(t *testing.T) {
	t.Parallel()

	var (
		usrBin  = cpAbs("usr", "bin")
		bin     = cpAbs("bin")
		nodeBin = cpAbs("opt", "node", "bin")
		localBn = cpAbs("home", "u", ".local", "bin")
	)

	cases := []struct {
		name        string
		processPath []string
		loginDirs   []string
		binDir      string
		want        string
	}{
		{
			name:        "no login dirs and no bin dir keeps the daemon path verbatim",
			processPath: []string{usrBin, bin},
			want:        cpJoin(usrBin, bin),
		},
		{
			name:        "bin dir goes first",
			processPath: []string{usrBin, bin},
			binDir:      nodeBin,
			want:        cpJoin(nodeBin, usrBin, bin),
		},
		{
			name:        "login dirs follow the bin dir and precede the daemon path",
			processPath: []string{usrBin, bin},
			loginDirs:   []string{localBn, nodeBin},
			binDir:      cpAbs("opt", "tool", "bin"),
			want:        cpJoin(cpAbs("opt", "tool", "bin"), localBn, nodeBin, usrBin, bin),
		},
		{
			name:        "duplicates collapse to the first occurrence, daemon order preserved",
			processPath: []string{usrBin, nodeBin, bin, usrBin},
			loginDirs:   []string{nodeBin},
			binDir:      nodeBin,
			want:        cpJoin(nodeBin, usrBin, bin),
		},
		{
			name:        "empty and relative entries are dropped",
			processPath: []string{"", usrBin, "node_modules/.bin", ".", bin},
			loginDirs:   []string{"", "relative/bin"},
			binDir:      "",
			want:        cpJoin(usrBin, bin),
		},
		{
			name:        "no absolute entry at all yields an empty value",
			processPath: []string{"", "rel"},
			want:        "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := childPATH(tc.processPath, tc.loginDirs, tc.binDir); got != tc.want {
				t.Fatalf("childPATH = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestChildPATHDedupIsCaseSensitiveOnlyOffWindows pins the platform-capability
// branch: POSIX exec matches path bytes exactly (two spellings are two dirs),
// Windows matches case-insensitively (one dir).
func TestChildPATHDedupIsCaseSensitiveOnlyOffWindows(t *testing.T) {
	t.Parallel()

	// Two spellings of one dir that differ ONLY in case. Built through cpAbs
	// so both are absolute by the host's rules (childPATHFor judges absoluteness
	// with the host's separator; only the dedup regime is injected).
	lower := cpAbs("opt", "node", "bin")
	upper := cpAbs("opt", "NODE", "bin")

	if got := childPATHFor("windows", []string{lower, upper}, nil, ""); got != lower {
		t.Errorf("windows dedup = %q, want the single dir %q", got, lower)
	}
	if got := childPATHFor("linux", []string{lower, upper}, nil, ""); got != cpJoin(lower, upper) {
		t.Errorf("posix dedup = %q, want both dirs kept", got)
	}
}

// TestApplyChildPATHReplacesOrAppends pins the env-block surgery: an existing
// PATH entry is rewritten IN PLACE keeping its original key spelling (so a
// Windows `Path=` never gains a `PATH=` twin), a block with no PATH gets one
// appended, and a call with nothing grounded to add returns the env untouched.
func TestApplyChildPATHReplacesOrAppends(t *testing.T) {
	t.Parallel()

	var (
		usrBin  = cpAbs("usr", "bin")
		nodeBin = cpAbs("opt", "node", "bin")
		shim    = filepath.Join(nodeBin, "codex")
		login   = cpAbs("home", "u", ".local", "bin")
	)

	t.Run("replaces in place", func(t *testing.T) {
		t.Parallel()
		env := []string{"HOME=" + cpAbs("home", "u"), "PATH=" + usrBin, "TERM=xterm"}
		out := applyChildPATH(env, []string{login}, shim)
		if len(out) != len(env) {
			t.Fatalf("len = %d, want %d (PATH replaced, not appended)", len(out), len(env))
		}
		want := "PATH=" + cpJoin(nodeBin, login, usrBin)
		if out[1] != want {
			t.Fatalf("out[1] = %q, want %q", out[1], want)
		}
		if env[1] != "PATH="+usrBin {
			t.Fatalf("input env mutated: %q", env[1])
		}
	})

	t.Run("keeps the original key spelling", func(t *testing.T) {
		t.Parallel()
		env := []string{"Path=" + usrBin}
		out := applyChildPATH(env, []string{login}, "")
		if !strings.HasPrefix(out[0], "Path=") {
			t.Fatalf("key spelling changed: %q", out[0])
		}
		if len(out) != 1 {
			t.Fatalf("len = %d, want 1 (no second PATH key)", len(out))
		}
	})

	t.Run("appends when the block has no PATH", func(t *testing.T) {
		t.Parallel()
		out := applyChildPATH([]string{"TERM=xterm"}, []string{login}, "")
		if len(out) != 2 || out[1] != "PATH="+login {
			t.Fatalf("out = %q, want an appended PATH=%s", out, login)
		}
	})

	t.Run("no-op with nothing to add", func(t *testing.T) {
		t.Parallel()
		env := []string{"PATH=" + usrBin, "TERM=xterm"}
		out := applyChildPATH(env, nil, "")
		if strings.Join(out, "\x00") != strings.Join(env, "\x00") {
			t.Fatalf("env changed: %q → %q", env, out)
		}
	})

	t.Run("last PATH wins like exec", func(t *testing.T) {
		t.Parallel()
		env := []string{"PATH=" + cpAbs("stale"), "PATH=" + usrBin}
		out := applyChildPATH(env, []string{login}, "")
		if !strings.Contains(out[1], usrBin) || strings.Contains(out[1], cpAbs("stale")) {
			t.Fatalf("out = %q, want the LAST PATH widened", out)
		}
	})

	t.Run("a bare program name contributes no directory", func(t *testing.T) {
		t.Parallel()
		env := []string{"PATH=" + usrBin}
		if out := applyChildPATH(env, nil, "npm"); strings.Join(out, "") != strings.Join(env, "") {
			t.Fatalf("out = %q, want unchanged (a relative dir is dropped)", out)
		}
	})
}

// TestLaunchChildEnvPrependsBinDirToPATH is the call-site proof: a daemon
// terminal launch hands the child a PATH that leads with the resolved binary's
// directory and the login-only dirs — the DI-04b fix — while the internal
// daemon-child / OOB variables stay single-valued (the widening must not
// duplicate the block it is layered into).
func TestLaunchChildEnvPrependsBinDirToPATH(t *testing.T) {
	prev := daemonLoginPathDirs
	t.Cleanup(func() { daemonLoginPathDirs = prev })
	loginDir := cpAbs("home", "u", ".hermes", "node", "bin")
	daemonLoginPathDirs = func() []string { return []string{loginDir} }

	nodeBin := cpAbs("opt", "node", "bin")
	req := termsvc.LaunchRequest{
		Tool:          "codex",
		RunID:         "run-di04b",
		BinPath:       filepath.Join(nodeBin, "codex"),
		LoginPathDirs: []string{loginDir},
	}
	out := launchChildEnv(req, "auth-token")

	path := ""
	counts := map[string]int{}
	for _, kv := range out {
		i := strings.IndexByte(kv, '=')
		if i <= 0 {
			continue
		}
		k := kv[:i]
		counts[strings.ToUpper(k)]++
		if isPathKey(k) {
			path = kv[i+1:]
		}
	}
	if path == "" {
		t.Fatal("child env carries no PATH")
	}
	dirs := filepath.SplitList(path)
	if len(dirs) < 2 || dirs[0] != nodeBin || dirs[1] != loginDir {
		t.Fatalf("PATH head = %v, want [%s %s ...]", dirs, nodeBin, loginDir)
	}
	for _, k := range []string{envDaemonChild, envOOBFD, envOOBAuth, envOOBRun, "PATH"} {
		if counts[strings.ToUpper(k)] != 1 {
			t.Errorf("%s appears %d times in the child env, want exactly 1", k, counts[strings.ToUpper(k)])
		}
	}
}

// TestLaunchChildEnvFallsBackToDaemonLoginDirs pins that a LaunchRequest with
// no per-tool dirs (the termsvc call sites that do not resolve a binary) still
// gets the daemon-wide login-only set — an empty request field is "use the
// daemon's", never "narrow this child's PATH".
func TestLaunchChildEnvFallsBackToDaemonLoginDirs(t *testing.T) {
	prev := daemonLoginPathDirs
	t.Cleanup(func() { daemonLoginPathDirs = prev })
	loginDir := cpAbs("opt", "fallback", "bin")
	daemonLoginPathDirs = func() []string { return []string{loginDir} }

	out := launchChildEnv(termsvc.LaunchRequest{Tool: "claude-code", RunID: "r"}, "auth")
	for _, kv := range out {
		i := strings.IndexByte(kv, '=')
		if i > 0 && isPathKey(kv[:i]) {
			if got := filepath.SplitList(kv[i+1:]); len(got) == 0 || got[0] != loginDir {
				t.Fatalf("PATH = %v, want the daemon login dir first", got)
			}
			return
		}
	}
	t.Fatal("child env carries no PATH")
}

// TestSetupChildEnvWidensPATHForTheInstallProgram pins the guided-install half
// (DI-04a/b): the setup PTY's PATH leads with the directory of the program the
// install plan resolved, so an npm shim there finds the node beside it.
func TestSetupChildEnvWidensPATHForTheInstallProgram(t *testing.T) {
	prev := daemonLoginPathDirs
	t.Cleanup(func() { daemonLoginPathDirs = prev })
	daemonLoginPathDirs = func() []string { return nil }

	npmDir := cpAbs("opt", "node", "bin")
	out := setupChildEnvFor(filepath.Join(npmDir, "npm"))
	for _, kv := range out {
		i := strings.IndexByte(kv, '=')
		if i > 0 && isPathKey(kv[:i]) {
			if got := filepath.SplitList(kv[i+1:]); len(got) == 0 || got[0] != npmDir {
				t.Fatalf("PATH = %v, want %s first", got, npmDir)
			}
			return
		}
	}
	t.Fatal("setup env carries no PATH")
}

// TestSetupProgramHeadOnly pins the tiny accessor CreateSetup feeds
// setupChildEnvFor: an empty argv contributes nothing (never a panic).
func TestSetupProgramHeadOnly(t *testing.T) {
	t.Parallel()
	if got := setupProgram(nil); got != "" {
		t.Errorf("setupProgram(nil) = %q, want empty", got)
	}
	if got := setupProgram([]string{"/opt/node/bin/npm", "install"}); got != "/opt/node/bin/npm" {
		t.Errorf("setupProgram = %q, want the head", got)
	}
}
