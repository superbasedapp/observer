package hook

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// FU-192 (ruling AW-117): one rule for every hook writer. An entry with
// Observer's `<bin> hook <tool> <event>` shape that runs a binary
// hook_equivalence does not judge an Observer binary is kept byte for byte
// without --force (the registration is refused with foreignBinaryReason);
// --force writes Observer's entry; an entry whose binary is a moved Observer
// is still repaired.

const (
	fu192Observer = "/opt/observer/bin/observer"
	fu192Moved    = "/usr/lib/observer-new/observer"
	fu192Foreign  = "/opt/lc/lc-hook.sh"
)

// fu192Case is one writer under test: register runs the target through a
// registry built for bin, force and keep; root is the tree it writes under.
type fu192Case struct {
	target   string
	root     string
	register func(bin string, force, keep bool) RegistrationResult
	// unregister runs the target's removal through a registry built for bin
	// and force (FU-203).
	unregister func(bin string, force bool) UnregistrationResult
	// observer and foreign are the spellings of fu192Observer and
	// fu192Foreign as the writer puts them in its files (a -wsl twin writes
	// the interop spelling of a Windows binary).
	observer, foreign, moved string
}

// fu192Snapshot reads every file under root but Observer's own state.
func fu192Snapshot(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".observer" {
				return filepath.SkipDir
			}
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		out[p] = string(b)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// fu192Rewrite replaces from with to in every file under root that holds it
// and reports whether any did.
func fu192Rewrite(t *testing.T, root, from, to string) bool {
	t.Helper()
	found := false
	for p, body := range fu192Snapshot(t, root) {
		if strings.Contains(body, from) {
			found = true
			if err := os.WriteFile(p, []byte(strings.ReplaceAll(body, from, to)), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	return found
}

// fu192ParityCases are the registry's hook targets in the hook-parity home
// (hookParityTargets: every native and -windows writer).
func fu192ParityCases(t *testing.T) []fu192Case {
	var out []fu192Case
	for _, target := range hookParityTargets {
		home := t.TempDir()
		win := filepath.Join(home, "win")
		for _, base := range []string{home, win} {
			for _, d := range hookParityToolDirs {
				if err := os.MkdirAll(filepath.Join(base, d), 0o755); err != nil {
					t.Fatal(err)
				}
			}
		}
		mk := func(bin string, force, keep bool) *Registry {
			r, err := NewRegistry(Options{
				BinaryPath: bin, HomeDir: home, ConfigPath: "/etc/observer/config.toml",
				ChecksumsPath: filepath.Join(home, ".observer", "hook_checksums.json"),
				WSLDistro:     "Ubuntu-Golden", WindowsCursorHome: win, WindowsClaudeHome: win,
				WindowsCodexHome: win, WindowsGeminiHome: win, WindowsQwenHome: win,
				WindowsFactoryHome: win, WindowsQoderHome: win, WindowsPoolsideHome: win,
				WindowsCommandCodeHome: win, WindowsCopilotHome: win, WindowsUserHome: win,
				GOOS: "linux", Force: force, KeepEquivalentHooks: keep,
			})
			if err != nil {
				t.Fatal(err)
			}
			return r
		}
		out = append(out, fu192Case{
			target: target, root: home,
			observer: fu192Observer, foreign: fu192Foreign, moved: fu192Moved,
			register: func(bin string, force, keep bool) RegistrationResult { return mk(bin, force, keep).Register(target) },
			unregister: func(bin string, force bool) UnregistrationResult {
				return mk(bin, force, false).Unregister(target)
			},
		})
	}
	return out
}

// fu192XcodeCases are the Xcode agent homes (darwin), the gated Gemini one
// through the ungated writer.
func fu192XcodeCases(t *testing.T) []fu192Case {
	var out []fu192Case
	for _, target := range []string{"claude-code-xcode", "codex-xcode", "gemini-cli-xcode"} {
		home := xcodeFixture(t)
		if err := os.MkdirAll(filepath.Join(home, xcodeGeminiHome), 0o755); err != nil {
			t.Fatal(err)
		}
		mk := func(bin string, force, keep bool) *Registry {
			r, err := NewRegistry(Options{
				BinaryPath: bin, HomeDir: home, GOOS: "darwin", ConfigPath: "/etc/observer/config.toml",
				ChecksumsPath: filepath.Join(home, ".observer", "hook_checksums.json"),
				Getenv:        func(string) string { return "" }, Force: force, KeepEquivalentHooks: keep,
			})
			if err != nil {
				t.Fatal(err)
			}
			return r
		}
		out = append(out, fu192Case{
			target: target, root: filepath.Join(home, "Library"),
			observer: fu192Observer, foreign: fu192Foreign, moved: fu192Moved,
			register: func(bin string, force, keep bool) RegistrationResult { return mk(bin, force, keep).register(target) },
			unregister: func(bin string, force bool) UnregistrationResult {
				return mk(bin, force, false).Unregister(target)
			},
		})
	}
	return out
}

// fu192WSLCases are the Windows to WSL twins (the gated ones through the
// ungated writer): a Windows observer.exe writing its interop spelling.
func fu192WSLCases(t *testing.T) []fu192Case {
	const (
		winObserver = `C:\Users\me\AppData\Local\observer\observer.exe`
		winMoved    = `D:\tools\observer\observer.exe`
	)
	var out []fu192Case
	for _, row := range wslTwinRows {
		row := row
		home := mkWSLHome(t, row.base)
		daemonHome := t.TempDir()
		mk := func(bin string, force, keep bool) *Registry {
			win := winObserver
			if bin == fu192Moved {
				win = winMoved
			}
			forceWSLHomes(t, map[string]bool{home: true}, home)
			r, err := NewRegistry(Options{
				BinaryPath: win, ConfigPath: wslTestWindowsConfig, HomeDir: daemonHome,
				ChecksumsPath: filepath.Join(daemonHome, ".observer", "hook_checksums.json"),
				Force:         force, KeepEquivalentHooks: keep,
			})
			if err != nil {
				t.Fatal(err)
			}
			return clearSandboxPin(r)
		}
		out = append(out, fu192Case{
			target: row.target, root: home,
			observer: wslTestInteropBinary, foreign: fu192Foreign, moved: "/mnt/d/tools/observer/observer.exe",
			register: func(bin string, force, keep bool) RegistrationResult {
				return mk(bin, force, keep).register(row.target)
			},
			unregister: func(bin string, force bool) UnregistrationResult {
				return mk(bin, force, false).Unregister(row.target)
			},
		})
	}
	return out
}

// fu192GatedCases are the writers still switched off behind a live check
// that are not in the hook-parity home (audit-report-arc-w11 row 9):
// antigravity-cli-windows, devin-windows and devin-jetbrains (the Wave 7 IDE
// targets) and cortex-code (LC18), run past their gate.
func fu192GatedCases(t *testing.T) []fu192Case {
	runLiveGatedHookWriters = true
	t.Cleanup(func() { runLiveGatedHookWriters = false })
	var out []fu192Case
	windowsTarget := func(target string, dirs ...string) {
		winHome := t.TempDir()
		mkdirs(t, winHome, dirs...)
		daemonHome := t.TempDir()
		mk := func(bin string, force, keep bool) *Registry {
			forceHookCrossmount(t, []crossmount.HomeRoot{{OS: crossmount.OSWindows, Path: winHome}}, map[string]bool{winHome: true})
			r, err := NewRegistry(Options{
				BinaryPath: bin, ConfigPath: "/etc/observer/config.toml", HomeDir: daemonHome,
				ChecksumsPath: filepath.Join(daemonHome, ".observer", "hook_checksums.json"),
				WSLDistro:     "Ubuntu", Force: force, KeepEquivalentHooks: keep,
			})
			if err != nil {
				t.Fatal(err)
			}
			return clearSandboxPin(r)
		}
		out = append(out, fu192Case{
			target: target, root: winHome,
			observer: fu192Observer, foreign: fu192Foreign, moved: fu192Moved,
			register:   func(bin string, force, keep bool) RegistrationResult { return mk(bin, force, keep).register(target) },
			unregister: func(bin string, force bool) UnregistrationResult { return mk(bin, force, false).Unregister(target) },
		})
	}
	windowsTarget("antigravity-cli-windows", filepath.Join(".gemini", "antigravity-cli"))
	windowsTarget("devin-windows", filepath.Join(".codeium", "windsurf"), filepath.Join("AppData", "Roaming", "devin"))
	nativeTarget := func(target string, dirs ...string) {
		home := t.TempDir()
		mkdirs(t, home, dirs...)
		mk := func(bin string, force, keep bool) *Registry {
			r, err := NewRegistry(Options{
				BinaryPath: bin, ConfigPath: "/etc/observer/config.toml", HomeDir: home,
				ChecksumsPath: filepath.Join(home, ".observer", "hook_checksums.json"),
				Getenv:        func(string) string { return "" }, Force: force, KeepEquivalentHooks: keep,
			})
			if err != nil {
				t.Fatal(err)
			}
			return r
		}
		out = append(out, fu192Case{
			target: target, root: home,
			observer: fu192Observer, foreign: fu192Foreign, moved: fu192Moved,
			register:   func(bin string, force, keep bool) RegistrationResult { return mk(bin, force, keep).register(target) },
			unregister: func(bin string, force bool) UnregistrationResult { return mk(bin, force, false).Unregister(target) },
		})
	}
	nativeTarget("devin-jetbrains", ".codeium")
	nativeTarget("cortex-code", filepath.Join(".snowflake", "cortex"))
	return out
}

// TestFU192ForeignBinaryEntryIsKeptByEveryWriter walks every hook writer:
// a foreign binary in Observer's command shape is kept byte for byte
// without --force (both with and without KeepEquivalentHooks: init and
// start), --force writes Observer's entry, and a moved Observer is
// repaired.
func TestFU192ForeignBinaryEntryIsKeptByEveryWriter(t *testing.T) {
	var cases []fu192Case
	cases = append(cases, fu192ParityCases(t)...)
	cases = append(cases, fu192XcodeCases(t)...)
	cases = append(cases, fu192WSLCases(t)...)
	cases = append(cases, fu192GatedCases(t)...)
	seen := map[string]bool{}
	for _, c := range cases {
		if seen[c.target] {
			t.Fatalf("target %s listed twice", c.target)
		}
		seen[c.target] = true
		t.Run(c.target, func(t *testing.T) {
			first := c.register(fu192Observer, false, false)
			if first.Error != nil || first.Skipped {
				t.Fatalf("first register = %+v", first)
			}
			clean := fu192Snapshot(t, c.root)
			if !fu192Rewrite(t, c.root, c.observer, c.foreign) {
				t.Fatalf("the written files never name %s:\n%v", c.observer, clean)
			}
			planted := fu192Snapshot(t, c.root)

			for _, keep := range []bool{false, true} {
				res := c.register(fu192Observer, false, keep)
				if res.Error == nil || !strings.Contains(res.Error.Error(), foreignBinaryReason) {
					t.Errorf("keep=%v: register over a foreign binary = %+v, want the %q refusal", keep, res, foreignBinaryReason)
				}
				if got := fu192Snapshot(t, c.root); !mapsEqual(got, planted) {
					t.Fatalf("keep=%v: the file changed without --force:\n%s", keep, fu192Diff(planted, got))
				}
			}

			forced := c.register(fu192Observer, true, false)
			if forced.Error != nil {
				t.Fatalf("--force register: %v", forced.Error)
			}
			if !fu192Holds(t, c.root, c.observer) {
				t.Errorf("--force did not write Observer's entry:\n%v", fu192Snapshot(t, c.root))
			}

			// A moved Observer: restore Observer's own entries, then
			// register from another install path.
			for p := range fu192Snapshot(t, c.root) {
				if _, ok := clean[p]; !ok {
					_ = os.Remove(p)
				}
			}
			for p, body := range clean {
				if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			for _, keep := range []bool{false, true} {
				moved := c.register(fu192Moved, false, keep)
				if moved.Error != nil {
					t.Fatalf("keep=%v: moved Observer register: %v", keep, moved.Error)
				}
				if !fu192Holds(t, c.root, c.moved) {
					t.Errorf("keep=%v: the moved Observer's entry was not repaired:\n%v", keep, fu192Snapshot(t, c.root))
				}
			}
		})
	}
}

// fu192Holds reports whether a file under root names bin.
func fu192Holds(t *testing.T, root, bin string) bool {
	t.Helper()
	for _, body := range fu192Snapshot(t, root) {
		if strings.Contains(body, bin) {
			return true
		}
	}
	return false
}

// fu192Diff names the files that differ.
func fu192Diff(a, b map[string]string) string {
	var out []string
	for p, v := range b {
		if a[p] != v {
			out = append(out, p)
		}
	}
	for p := range a {
		if _, ok := b[p]; !ok {
			out = append(out, p+" (removed)")
		}
	}
	sort.Strings(out)
	return strings.Join(out, "\n")
}

// TestFU192JudgedObserverBinary pins the binary test the rule shares with
// the equivalence table.
func TestFU192JudgedObserverBinary(t *testing.T) {
	for _, tc := range []struct {
		have, want string
		judged     bool
	}{
		{"/opt/observer/bin/observer", "/usr/bin/observer", true},
		{"/tmp/observer-v1.8.3", "/usr/bin/observer", true},
		{`C:\Users\me\observer.exe`, "/usr/bin/observer", true},
		{"/opt/x/sbo-dev", "/usr/local/bin/sbo-dev", true},
		{"/opt/lc/lc-hook.sh", "/usr/bin/observer", false},
		{"/bin/true", "/usr/bin/observer", false},
		{"", "/usr/bin/observer", false},
	} {
		if got := observerBinaryJudged(tc.have, tc.want); got != tc.judged {
			t.Errorf("observerBinaryJudged(%q, %q) = %v, want %v", tc.have, tc.want, got, tc.judged)
		}
	}
}

// TestFU192ShapedHooksInText pins the text scan on the shapes the writers
// put in their files.
func TestFU192ShapedHooksInText(t *testing.T) {
	for _, tc := range []struct {
		name, text, tool string
		want             []shapedHook
	}{
		{"json", `{"command":"/opt/lc/lc-hook.sh hook cursor stop"}`, "cursor", []shapedHook{{"/opt/lc/lc-hook.sh", "stop"}}},
		{"escaped quote", `{"command":"\"/opt/my dir/observer\" hook claude-code pre-tool --config x"}`, "claude-code", []shapedHook{{"dir/observer", "pre-tool"}}},
		{"bridge", `wsl.exe -d U -- //opt/lc/lc-hook.sh hook vtcode PreToolUse; exit $LASTEXITCODE`, "vtcode", []shapedHook{{"//opt/lc/lc-hook.sh", "PreToolUse"}}},
		{"script", "#!/bin/sh\nexec /opt/lc/lc-hook.sh hook dirac PreToolUse\n", "dirac", []shapedHook{{"/opt/lc/lc-hook.sh", "PreToolUse"}}},
		{"other tool", `{"command":"/opt/lc/lc-hook.sh hook cursor stop"}`, "codex", nil},
		{"hook-bridge", `observer.exe hook-bridge --tool codex --event Stop`, "codex", nil},
	} {
		got := shapedHooksInText([]byte(tc.text), tc.tool)
		if len(got) != len(tc.want) {
			t.Errorf("%s: got %+v, want %+v", tc.name, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("%s: got %+v, want %+v", tc.name, got[i], tc.want[i])
			}
		}
	}
	bins := shapedHooksInPluginProfile([]byte(`const PROFILE = {"bin":"observer","wsl_bin":"/opt/lc/lc-hook.sh","config":""};`))
	if len(bins) != 2 || bins[1].binary != fu192Foreign {
		t.Errorf("plugin PROFILE = %+v", bins)
	}
}
