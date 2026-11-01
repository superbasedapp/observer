package hook

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// wslTwinInstallDirs is each twin base's native install signal under a
// home (the directory Installed() probes for it).
var wslTwinInstallDirs = map[string][]string{
	"claude-code":     {".claude"},
	"cursor":          {".cursor"},
	"codex":           {".codex"},
	"gemini-cli":      {".gemini"},
	"qwen-code":       {".qwen"},
	"droid":           {".factory"},
	"qoder":           {".qoder"},
	"poolside":        {".config", "poolside"},
	"command-code":    {".commandcode"},
	"copilot-cli":     {".copilot"},
	"ibm-bob":         {".bob"},
	"codebuddy":       {".codebuddy"},
	"deepagents-code": {".deepagents"},
	"dimcode":         {".dimcode"},
	"dirac":           {".dirac"},
	"vtcode":          {".config", "vtcode"},
	"devin":           {".config", "devin"},
	"antigravity-cli": {".gemini", "antigravity-cli"},
}

const (
	wslTestWindowsBinary = `C:\Users\me\AppData\Local\observer\observer.exe`
	wslTestInteropBinary = "/mnt/c/Users/me/AppData/Local/observer/observer.exe"
	wslTestWindowsConfig = `C:\Users\me\.observer\config.toml`
)

// forceWSLHomes points the crossmount seams at fake WSL homes (as a Windows
// host would enumerate them) with a fixed ownership verdict.
func forceWSLHomes(t *testing.T, owned map[string]bool, homes ...string) {
	t.Helper()
	var roots []crossmount.HomeRoot
	for _, h := range homes {
		roots = append(roots, crossmount.HomeRoot{Path: h, OS: crossmount.OSLinux, Origin: "wslhost:Ubuntu/" + filepath.Base(h)})
	}
	prevHomes, prevOwned := allHomes, wslHomeOwned
	allHomes = func() []crossmount.HomeRoot { return roots }
	wslHomeOwned = func(home string) bool { return owned[home] }
	t.Cleanup(func() { allHomes, wslHomeOwned = prevHomes, prevOwned })
}

// mkWSLHome creates a fake WSL user home carrying base's install signal.
func mkWSLHome(t *testing.T, base string) string {
	t.Helper()
	home := filepath.Join(t.TempDir(), "me")
	if err := os.MkdirAll(filepath.Join(append([]string{home}, wslTwinInstallDirs[base]...)...), 0o755); err != nil {
		t.Fatal(err)
	}
	return home
}

// newWSLTestRegistry is a Windows observer's registry with the sandbox pin
// cleared (the crossmount seams are fakes).
func newWSLTestRegistry(t *testing.T, binary string) *Registry {
	t.Helper()
	daemonHome := t.TempDir()
	r, err := NewRegistry(Options{
		BinaryPath:    binary,
		ConfigPath:    wslTestWindowsConfig,
		HomeDir:       daemonHome,
		ChecksumsPath: filepath.Join(daemonHome, ".observer", "hook_checksums.json"),
	})
	if err != nil {
		t.Fatal(err)
	}
	return clearSandboxPin(r)
}

// TestWSLTwinTableMirrorsEveryWindowsTarget pins DEC-10: every
// "<tool>-windows" hook target has a "<tool>-wsl" twin with the same base,
// every twin row is gated on its live check (and a row whose live check has
// passed, with none, is not gated), and has an install signal in this test.
func TestWSLTwinTableMirrorsEveryWindowsTarget(t *testing.T) {
	windows := map[string]bool{}
	for target := range hookTargetWriters {
		if strings.HasSuffix(target, "-windows") {
			windows[target] = true
		}
	}
	for target := range toolGateWriters {
		if strings.HasSuffix(target, "-windows") {
			windows[target] = true
		}
	}
	mirrored := map[string]bool{}
	for _, row := range wslTwinRows {
		if row.target != row.base+"-wsl" || row.windows != row.base+"-windows" {
			t.Errorf("row %+v: target and windows must be <base>-wsl / <base>-windows", row)
		}
		mirrored[row.windows] = true
		id, gated := LiveCheckGate(row.target)
		switch {
		case row.liveCheck == "" && gated:
			t.Errorf("%s is switched on but still gated on %q", row.target, id)
		case row.liveCheck != "" && (!gated || id != row.liveCheck):
			t.Errorf("%s is not gated on %s (got %q, %v)", row.target, row.liveCheck, id, gated)
		}
		if _, ok := wslTwinInstallDirs[row.base]; !ok {
			t.Errorf("%s has no install signal in this test", row.target)
		}
		if b, ok := WSLTwinBase(row.target); !ok || b != row.base {
			t.Errorf("WSLTwinBase(%s) = %q, %v", row.target, b, ok)
		}
	}
	for w := range windows {
		if !mirrored[w] {
			t.Errorf("%s has no Windows to WSL twin (DEC-10)", w)
		}
	}
}

// TestWSLTwinRegistersEveryTool runs each twin's writer against a fake WSL
// home (a gated twin below the gate, a switched-on twin through the public
// Register): the hook lands in the distro's native file, runs the Windows
// observer.exe through interop, carries the Windows --config, never wraps in
// wsl.exe, and Unregister removes it again.
func TestWSLTwinRegistersEveryTool(t *testing.T) {
	for _, row := range wslTwinRows {
		t.Run(row.target, func(t *testing.T) {
			home := mkWSLHome(t, row.base)
			forceWSLHomes(t, map[string]bool{home: true}, home)
			r := newWSLTestRegistry(t, wslTestWindowsBinary)

			if !containsString(r.installedAll(true), row.target) {
				t.Fatalf("installedAll() = %v, want %s", r.installedAll(true), row.target)
			}
			register := r.register
			if row.liveCheck == "" {
				if !containsString(r.Installed(), row.target) {
					t.Fatalf("Installed() = %v, want the switched-on %s", r.Installed(), row.target)
				}
				register = r.Register
			} else {
				if containsString(r.Installed(), row.target) {
					t.Fatalf("Installed() lists the gated %s", row.target)
				}
				if g := r.Register(row.target); !g.Skipped || g.SkipKind != SkipLiveGated {
					t.Fatalf("Register(%s) = %+v, want the live-check skip", row.target, g)
				}
			}

			res := register(row.target)
			if res.Error != nil {
				t.Fatalf("register: %v", res.Error)
			}
			if res.Tool != row.target {
				t.Errorf("Tool = %q", res.Tool)
			}
			if res.Skipped {
				t.Fatalf("register skipped: %+v", res)
			}
			if !strings.HasPrefix(res.ConfigPath, home) {
				t.Fatalf("ConfigPath %q is not under the WSL home %q", res.ConfigPath, home)
			}
			body := readTwinFiles(t, home)
			if !strings.Contains(body, wslTestInteropBinary) {
				t.Errorf("no interop binary %q in the written files:\n%s", wslTestInteropBinary, body)
			}
			if strings.Contains(body, "wsl.exe -d") || strings.Contains(body, `"wsl_bin":"/`) {
				t.Errorf("a WSL twin must not wrap in wsl.exe:\n%s", body)
			}
			if !strings.Contains(body, "C:/Users/me/.observer/config.toml") {
				t.Errorf("the Windows --config (forward-slash spelling) is missing:\n%s", body)
			}
			if strings.Contains(body, `Users\me`) || strings.Contains(body, `Users\\me`) {
				t.Errorf("a backslash Windows path reached the hook shell:\n%s", body)
			}

			again := register(row.target)
			if again.Error != nil || len(again.HooksAdded) != 0 {
				t.Errorf("second register is not idempotent: added=%v err=%v", again.HooksAdded, again.Error)
			}

			un := r.Unregister(row.target)
			if un.Error != nil {
				t.Fatalf("Unregister: %v", un.Error)
			}
			if after := readTwinFiles(t, home); strings.Contains(after, wslTestInteropBinary) {
				t.Errorf("Unregister left Observer's entry:\n%s", after)
			}
		})
	}
}

// readTwinFiles concatenates every regular file under home.
func readTwinFiles(t *testing.T, home string) string {
	t.Helper()
	var b strings.Builder
	_ = filepath.WalkDir(home, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		data, rerr := os.ReadFile(p)
		if rerr == nil {
			b.WriteString(p + ":\n" + string(data) + "\n")
		}
		return nil
	})
	return b.String()
}

// TestWSLTwinDetection walks the home rules: an owned home with the tool is
// picked, an unowned or tool-less one is not, two owned homes are
// ambiguous, a non-WSL home never counts, and an explicit WSLUserHome wins.
func TestWSLTwinDetection(t *testing.T) {
	row, _ := wslTwinFor("claude-code-wsl")
	t.Run("owned home with the tool", func(t *testing.T) {
		home := mkWSLHome(t, "claude-code")
		forceWSLHomes(t, map[string]bool{home: true}, home)
		if got := newWSLTestRegistry(t, wslTestWindowsBinary).detectWSLHome(row, nil); got != home {
			t.Errorf("detectWSLHome = %q, want %q", got, home)
		}
	})
	t.Run("unowned home", func(t *testing.T) {
		home := mkWSLHome(t, "claude-code")
		forceWSLHomes(t, map[string]bool{}, home)
		if got := newWSLTestRegistry(t, wslTestWindowsBinary).detectWSLHome(row, nil); got != "" {
			t.Errorf("detectWSLHome = %q, want none", got)
		}
	})
	t.Run("tool not installed", func(t *testing.T) {
		home := mkWSLHome(t, "cursor")
		forceWSLHomes(t, map[string]bool{home: true}, home)
		if got := newWSLTestRegistry(t, wslTestWindowsBinary).detectWSLHome(row, nil); got != "" {
			t.Errorf("detectWSLHome = %q, want none", got)
		}
	})
	t.Run("two owned homes are ambiguous", func(t *testing.T) {
		a, b := mkWSLHome(t, "claude-code"), mkWSLHome(t, "claude-code")
		forceWSLHomes(t, map[string]bool{a: true, b: true}, a, b)
		if got := newWSLTestRegistry(t, wslTestWindowsBinary).detectWSLHome(row, nil); got != "" {
			t.Errorf("detectWSLHome = %q, want none", got)
		}
	})
	t.Run("native linux home never counts", func(t *testing.T) {
		home := mkWSLHome(t, "claude-code")
		prev := allHomes
		allHomes = func() []crossmount.HomeRoot {
			return []crossmount.HomeRoot{{Path: home, OS: crossmount.OSLinux, Origin: "native"}}
		}
		t.Cleanup(func() { allHomes = prev })
		if got := newWSLTestRegistry(t, wslTestWindowsBinary).detectWSLHome(row, nil); got != "" {
			t.Errorf("detectWSLHome = %q, want none", got)
		}
	})
	t.Run("explicit WSLUserHome wins", func(t *testing.T) {
		forceWSLHomes(t, nil)
		r := newWSLTestRegistry(t, wslTestWindowsBinary)
		r.opts.WSLUserHome = `\\wsl.localhost\Ubuntu\home\me`
		if got := r.detectWSLHome(row, nil); got != r.opts.WSLUserHome {
			t.Errorf("detectWSLHome = %q", got)
		}
	})
	t.Run("a pinned sandbox suppresses detection", func(t *testing.T) {
		home := mkWSLHome(t, "claude-code")
		forceWSLHomes(t, map[string]bool{home: true}, home)
		r, err := NewRegistry(Options{BinaryPath: wslTestWindowsBinary, HomeDir: t.TempDir()})
		if err != nil {
			t.Fatal(err)
		}
		if got := r.detectWSLHome(row, nil); got != "" {
			t.Errorf("detectWSLHome = %q under a pinned home", got)
		}
		res := r.register(row.target)
		if !res.Skipped || res.SkipKind != SkipNotApplicable {
			t.Errorf("register under a pinned home = %+v, want the sandbox skip", res)
		}
	})
}

// TestWSLTwinRefusesABinaryInteropCannotRun pins the binary rule: only a
// Windows drive path to an .exe can run from inside the distro.
func TestWSLTwinRefusesABinaryInteropCannotRun(t *testing.T) {
	cases := []struct {
		name   string
		binary string
		ok     bool
	}{
		{"windows exe", wslTestWindowsBinary, true},
		{"npm launcher", `C:\Users\me\AppData\Roaming\npm\observer.cmd`, false},
		{"posix binary", "/usr/local/bin/observer", false},
		{"quote in path", `C:\it's\observer.exe`, false},
	}
	t.Run("config with a dollar sign", func(t *testing.T) {
		home := mkWSLHome(t, "claude-code")
		forceWSLHomes(t, map[string]bool{home: true}, home)
		r := newWSLTestRegistry(t, wslTestWindowsBinary)
		r.opts.ConfigPath = `C:\Users\$me\config.toml`
		if res := r.register("claude-code-wsl"); res.Error == nil {
			t.Error("a config path with $ must be refused")
		}
	})
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			home := mkWSLHome(t, "claude-code")
			forceWSLHomes(t, map[string]bool{home: true}, home)
			res := newWSLTestRegistry(t, c.binary).register("claude-code-wsl")
			if c.ok != (res.Error == nil) {
				t.Errorf("register error = %v, want ok=%v", res.Error, c.ok)
			}
			if !c.ok {
				if _, err := os.Stat(filepath.Join(home, ".claude", "settings.json")); !os.IsNotExist(err) {
					t.Errorf("a refused twin wrote settings.json (stat err %v)", err)
				}
			}
		})
	}
}

// TestCodexWSLTrustKeyIsTheLinuxPath pins CX-5's trust record: the Codex in
// the distro loads hooks.json at its Linux path, so that is the trust key.
func TestCodexWSLTrustKeyIsTheLinuxPath(t *testing.T) {
	tw := &wslTwin{}
	cases := []struct {
		in, want string
		ok       bool
	}{
		{`\\wsl.localhost\Ubuntu\home\me\.codex\hooks.json`, "/home/me/.codex/hooks.json", true},
		{"/tmp/x/me/.codex/hooks.json", "/tmp/x/me/.codex/hooks.json", true},
		{`C:\Users\me\.codex\hooks.json`, "", false},
	}
	for _, c := range cases {
		got, ok := tw.linuxPath(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("linuxPath(%q) = %q, %v; want %q, %v", c.in, got, ok, c.want, c.ok)
		}
	}
}

// TestInstalledSpendsNoDetectionOnGatedTwins pins the performance rule:
// Installed (the maintain loop, init, the dashboard) never lists a gated twin
// and scans each WSL home at most once per pass, and only when some twin is
// switched on; InstalledLiveGated scans each WSL home once per pass whatever
// the number of twin rows.
func TestInstalledSpendsNoDetectionOnGatedTwins(t *testing.T) {
	home := filepath.Join(t.TempDir(), "me")
	for _, base := range []string{"claude-code", "codex", "gemini-cli"} {
		if err := os.MkdirAll(filepath.Join(append([]string{home}, wslTwinInstallDirs[base]...)...), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	forceWSLHomes(t, map[string]bool{home: true}, home)
	r := newWSLTestRegistry(t, wslTestWindowsBinary)

	wantScans := int64(0)
	for _, row := range wslTwinRows {
		if row.liveCheck == "" {
			wantScans = 1
		}
	}
	before := wslHomeScanCount.Load()
	for _, tool := range r.Installed() {
		if _, gated := LiveCheckGate(tool); gated && strings.HasSuffix(tool, "-wsl") {
			t.Errorf("Installed lists the gated %s", tool)
		}
	}
	if n := wslHomeScanCount.Load() - before; n != wantScans {
		t.Errorf("Installed scanned the one WSL home %d time(s), want %d", n, wantScans)
	}

	before = wslHomeScanCount.Load()
	gated := r.InstalledLiveGated()
	if n := wslHomeScanCount.Load() - before; n != 1 {
		t.Errorf("InstalledLiveGated scanned the one WSL home %d time(s), want 1", n)
	}
	var twins []string
	for _, g := range gated {
		if strings.HasSuffix(g.Target, "-wsl") {
			twins = append(twins, g.Target)
		}
	}
	if strings.Join(twins, ",") != "claude-code-wsl,codex-wsl,gemini-cli-wsl" {
		t.Errorf("gated twins = %v", twins)
	}
}

// TestWSLTwinQuotesBinaryWithShellCharacters pins the twin command quoting
// for a Windows observer.exe path a POSIX hook shell would split or expand
// unquoted (a space, $, &, parentheses): every twin writes it, and every
// writer that renders a shell command single-quotes the interop path (the
// command-code mod carries it as an argv string, Poolside's YAML escapes the
// single quotes it writes). The config path with a space is carried too.
func TestWSLTwinQuotesBinaryWithShellCharacters(t *testing.T) {
	binaries := map[string]string{
		`C:\Users\John Smith\AppData\Local\observer\observer.exe`: "/mnt/c/Users/John Smith/AppData/Local/observer/observer.exe",
		`C:\Users\a$HOME\observer.exe`:                            "/mnt/c/Users/a$HOME/observer.exe",
		`D:\Program Files (x86)\R&D\observer.exe`:                 "/mnt/d/Program Files (x86)/R&D/observer.exe",
	}
	shellQuoted := map[string]bool{
		"claude-code-wsl": true, "cursor-wsl": true, "codex-wsl": true, "copilot-cli-wsl": true,
		"dirac-wsl": true, "vtcode-wsl": true, "ibm-bob-wsl": true, "gemini-cli-wsl": true,
	}
	for win, mnt := range binaries {
		for _, row := range wslTwinRows {
			t.Run(row.target+"/"+mnt, func(t *testing.T) {
				home := mkWSLHome(t, row.base)
				forceWSLHomes(t, map[string]bool{home: true}, home)
				r := newWSLTestRegistry(t, win)
				r.opts.ConfigPath = `C:\Users\John Smith\.observer\config.toml`
				res := r.register(row.target)
				if res.Error != nil {
					t.Fatalf("register: %v", res.Error)
				}
				// JSON writers escape & as \u0026.
				body := strings.ReplaceAll(readTwinFiles(t, home), `\u0026`, "&")
				if !strings.Contains(body, mnt) {
					t.Fatalf("interop path %q missing:\n%s", mnt, body)
				}
				if shellQuoted[row.target] && !strings.Contains(body, "'"+mnt+"'") {
					t.Errorf("the interop path is not single-quoted for the hook shell:\n%s", body)
				}
				if !strings.Contains(body, "C:/Users/John Smith/.observer/config.toml") {
					t.Errorf("config path with a space missing:\n%s", body)
				}
			})
		}
	}
}

// TestHomeTargetsResolveTheirBase (FU-197): HomeTargetBase / HomeTargetsFor
// read the Xcode and WSL twin tables, so the callers resolve a "-wsl" twin
// exactly as an Xcode agent home, and no other target.
func TestHomeTargetsResolveTheirBase(t *testing.T) {
	for _, row := range wslTwinRows {
		if base, ok := HomeTargetBase(row.target); !ok || base != row.base {
			t.Errorf("HomeTargetBase(%s) = %q, %v; want %q", row.target, base, ok, row.base)
		}
		if !slices.Contains(HomeTargetsFor(row.base), row.target) || !slices.Contains(WSLTwinsFor(row.base), row.target) {
			t.Errorf("HomeTargetsFor(%s) = %v misses %s", row.base, HomeTargetsFor(row.base), row.target)
		}
	}
	for _, x := range xcodeHostTargets {
		if base, ok := HomeTargetBase(x.target); !ok || base != x.tool {
			t.Errorf("HomeTargetBase(%s) = %q, %v; want %q", x.target, base, ok, x.tool)
		}
	}
	for _, target := range []string{"cursor", "cursor-windows", "claude-code", "codex-windows"} {
		if base, ok := HomeTargetBase(target); ok {
			t.Errorf("HomeTargetBase(%s) = %q: not an other-home target", target, base)
		}
	}
}

// TestFU214TwinRunsTheObserverExeALauncherStarted (operator ruling option 1):
// on an npm or pip install BinaryPath is the package manager's launcher,
// which WSL interop cannot run; the twin registers the observer.exe that
// launcher started (WSLTwinBinaryPath) and re-points to it on every
// registration, so an upgrade that moves it is repaired at the next start
// (even with KeepEquivalentHooks, as `observer start` writes, and for a
// writer that keeps equivalent entries: Claude Code's). A launcher nothing
// resolved still refuses with the current reason.
func TestFU214TwinRunsTheObserverExeALauncherStarted(t *testing.T) {
	const (
		launcher = `C:\Users\me\AppData\Roaming\npm\observer.cmd`
		oldExe   = `C:\Users\me\AppData\Roaming\npm\node_modules\@superbased\observer-win32-x64\bin\observer.exe`
		newExe   = `C:\Users\me\AppData\Roaming\npm-2\node_modules\@superbased\observer-win32-x64\bin\observer.exe`
		oldMnt   = "/mnt/c/Users/me/AppData/Roaming/npm/node_modules/@superbased/observer-win32-x64/bin/observer.exe"
		newMnt   = "/mnt/c/Users/me/AppData/Roaming/npm-2/node_modules/@superbased/observer-win32-x64/bin/observer.exe"
	)
	for _, c := range []struct {
		target, base, tool string
		file               []string
	}{
		{"cursor-wsl", "cursor", "cursor", []string{".cursor", "hooks.json"}},
		{"claude-code-wsl", "claude-code", "claude-code", []string{".claude", "settings.json"}},
	} {
		t.Run(c.target, func(t *testing.T) {
			home := mkWSLHome(t, c.base)
			forceWSLHomes(t, map[string]bool{home: true}, home)
			file := filepath.Join(append([]string{home}, c.file...)...)
			read := func() string {
				b, _ := os.ReadFile(file)
				return string(b)
			}
			registerWith := func(exe string) RegistrationResult {
				r := newWSLTestRegistry(t, launcher)
				r.opts.WSLTwinBinaryPath = exe
				r.opts.KeepEquivalentHooks = true
				// The old observer.exe still answers as a working binary:
				// the re-point must not depend on the old path failing a
				// stat.
				r.opts.binaryWorks = func(string) bool { return true }
				return r.register(c.target)
			}

			if res := registerWith(oldExe); res.Error != nil {
				t.Fatalf("the launcher was not resolved to its observer.exe: %v", res.Error)
			}
			if got := read(); !strings.Contains(got, oldMnt+" hook "+c.tool+" ") || strings.Contains(got, "observer.cmd") {
				t.Fatalf("the twin does not run the observer.exe:\n%s", got)
			}

			// An upgrade moved the observer.exe: the next start re-points
			// the twin.
			res := registerWith(newExe)
			if res.Error != nil {
				t.Fatalf("re-point: %v", res.Error)
			}
			if got := read(); !strings.Contains(got, newMnt+" hook "+c.tool+" ") || strings.Contains(got, oldMnt) {
				t.Errorf("the twin was not re-pointed after the move:\n%s\nkept as equivalent: %v", got, res.KeptEquivalent)
			}

			// A launcher nothing resolved keeps today's refusal and writes
			// nothing.
			before := read()
			res = registerWith("")
			if res.Error == nil || !strings.Contains(res.Error.Error(), "which does not run a .cmd launcher; register from the observer.exe itself") {
				t.Errorf("an unresolved launcher = %v, want the current refusal", res.Error)
			}
			if read() != before {
				t.Error("a refused twin changed the file")
			}
		})
	}
}
