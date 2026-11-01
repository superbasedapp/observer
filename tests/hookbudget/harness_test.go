package hookbudget

import (
	"bytes"
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/hookbudget"
	"github.com/marmutapp/superbased-observer/internal/keystore"
	"github.com/marmutapp/superbased-observer/internal/secposture"
)

// Environment knobs (docs/hook-budget-harness.md).
const (
	envEnable = "SBO_HOOK_BUDGET"        // "1" runs the harness
	envBin    = "SBO_HOOK_BUDGET_BIN"    // a prebuilt observer binary (default: build ./cmd/observer)
	envPrefix = "SBO_HOOK_BUDGET_PREFIX" // a command prefix, e.g. "wsl.exe -d Ubuntu --" for the WSL bridge
	envCold   = "SBO_HOOK_BUDGET_COLD"   // cold launches per case (default 5)
	envWarm   = "SBO_HOOK_BUDGET_WARM"   // warm launches per case (default 30)
	envOut    = "SBO_HOOK_BUDGET_OUT"    // write the JSON report here
	envNote   = "SBO_HOOK_BUDGET_NOTE"   // free text recorded in the report (host, disk, AV state)
	// With a prefix, both are required: a scratch directory on the
	// prefixed binary's own filesystem, as this process reaches it (for
	// WSL, \\wsl.localhost\<distro>\tmp\sbo-hb) and as the binary sees it
	// (/tmp/sbo-hb).
	envBridgeDir    = "SBO_HOOK_BUDGET_BRIDGE_DIR"
	envBridgeTarget = "SBO_HOOK_BUDGET_BRIDGE_TARGET_DIR"
)

// launchTimeout bounds one launch so a hung hook fails the run instead of
// pinning it. It is not a budget: the hook's own watchdog is 30 s.
const launchTimeout = 60 * time.Second

// targetPATH is the PATH a prefixed (bridged) hook gets: the target's
// system directories, nothing from this process.
const targetPATH = "/usr/local/bin:/usr/bin:/bin"

// launchCase is one hook invocation: the `observer hook` arguments and the
// testdata payload fed on stdin.
type launchCase struct {
	name    string
	args    []string
	fixture string
}

var launchCases = []launchCase{
	{"claude-code pre-tool (guard flag)", []string{"claude-code", "pre-tool"}, "internal/hook/testdata/guard/claude-code/pretool_bash_rmrf.json"},
	{"claude-code pre-tool (read)", []string{"claude-code", "pre-tool"}, "internal/hook/testdata/guard/claude-code/pretool_read_sensitive.json"},
	{"cursor beforeShellExecution", []string{"cursor", "beforeShellExecution"}, "internal/hook/testdata/guard/cursor/before_shell_benign.json"},
}

// TestHookBudget runs the harness. Report-only: it fails only when a
// launch does not run (an error, a non-zero exit, no reply, or the
// launch timeout), never on a measured time.
func TestHookBudget(t *testing.T) {
	if os.Getenv(envEnable) != "1" {
		t.Skipf("report-only hook budget harness; set %s=1 to run it (docs/hook-budget-harness.md)", envEnable)
	}
	root := repoRoot(t)
	tg := resolveTarget(t)
	bin := os.Getenv(envBin)
	if bin == "" {
		if tg.bridged() {
			t.Fatalf("%s is set: set %s to the binary's path as the target sees it", envPrefix, envBin)
		}
		bin = buildObserver(t, root)
	}
	cold, warm := intEnv(t, envCold, 5), intEnv(t, envWarm, 30)

	samples := map[hookbudget.ID][]time.Duration{}
	for _, lc := range launchCases {
		body, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(lc.fixture)))
		if err != nil {
			t.Fatal(err)
		}
		for i := range cold {
			h := tg.freshHome(t)
			samples[hookbudget.HookCold] = append(samples[hookbudget.HookCold], launch(t, tg, bin, h, lc, body, fmt.Sprintf("cold %d", i)))
		}
		h := tg.freshHome(t)
		launch(t, tg, bin, h, lc, body, "warm prime")
		for i := range warm {
			samples[hookbudget.HookWarm] = append(samples[hookbudget.HookWarm], launch(t, tg, bin, h, lc, body, fmt.Sprintf("warm %d", i)))
		}
	}
	samples[hookbudget.Seam] = hookbudget.SeamSamples(5000)
	samples[hookbudget.SeamProviders] = hookbudget.SeamProviderSamples(5000)
	samples[hookbudget.Sidecar] = sidecarSamples(t, 5000)
	// The relay row at JSP-2's 16 KiB budget point (relay_probe_test.go).
	samples[hookbudget.Relay] = relaySamples(t, 2000, 16<<10)
	// The project audience row (projectmatch_probe_test.go, lane sec-p).
	samples[hookbudget.ProjectMatch] = projectMatchSamples(t, 1000)

	platform := runtime.GOOS + "/" + runtime.GOARCH
	if tg.bridged() {
		platform += " via " + strings.Join(tg.prefix, " ") + " env -i"
	}
	note := fmt.Sprintf("binary %s; %d cold and %d warm launches per case over %d cases", bin, cold, warm, len(launchCases))
	if n := os.Getenv(envNote); n != "" {
		note += "; " + n
	}
	report := hookbudget.NewReport(platform, note, samples)
	var text bytes.Buffer
	if err := report.Text(&text); err != nil {
		t.Fatal(err)
	}
	t.Log("\n" + text.String())
	if out := os.Getenv(envOut); out != "" {
		f, err := os.Create(out)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if err := report.JSON(f); err != nil {
			t.Fatal(err)
		}
	}
}

// target is where a launch runs. With no prefix the binary runs on this
// host and every home is a test temp dir. With a prefix (the WSL bridge)
// the binary runs where this process cannot set HOME (wsl.exe does not
// carry HOME across, even through WSLENV) or hand it a Windows path, so the
// homes live in a scratch directory on the target's own filesystem and the
// home, PATH and config path are passed as explicit arguments.
type target struct {
	prefix []string
	// local is the scratch directory as this process reaches it; remote is
	// the same directory as the prefixed binary sees it.
	local, remote string
}

func (tg target) bridged() bool { return len(tg.prefix) > 0 }

// resolveTarget reads the prefix and, with one, refuses to run unless both
// bridge directories are set: without them a bridged launch would run with
// the developer's real target-side HOME and could touch their real
// ~/.observer.
func resolveTarget(t *testing.T) target {
	t.Helper()
	prefix := strings.Fields(os.Getenv(envPrefix))
	if len(prefix) == 0 {
		return target{}
	}
	local, remote := os.Getenv(envBridgeDir), os.Getenv(envBridgeTarget)
	if local == "" || remote == "" {
		t.Fatalf("%s is set but %s and %s are not. A prefixed launch cannot be given a temp HOME through the environment (wsl.exe does not carry HOME across), so it would run against the real target-side ~/.observer; refusing. Set %s to a scratch directory on the target filesystem as this process reaches it (for WSL, \\\\wsl.localhost\\<distro>\\tmp\\sbo-hb) and %s to the same directory as the target sees it (/tmp/sbo-hb)",
			envPrefix, envBridgeDir, envBridgeTarget, envBridgeDir, envBridgeTarget)
	}
	if !path.IsAbs(remote) || strings.ContainsAny(remote, " \t") {
		t.Fatalf("%s=%q: want an absolute target-side path with no spaces", envBridgeTarget, remote)
	}
	if fi, err := os.Stat(local); err != nil || !fi.IsDir() {
		t.Fatalf("%s=%q: not a directory this process can reach (%v)", envBridgeDir, local, err)
	}
	return target{prefix: prefix, local: local, remote: remote}
}

// home is one launch home: dir is where this process writes it, path is
// what the binary is told.
type home struct {
	dir, path string
	bridged   bool
}

// join names a file inside the home as the binary sees it.
func (h home) join(name string) string {
	if h.bridged {
		return path.Join(h.path, name)
	}
	return filepath.Join(h.path, name)
}

// freshHome is an empty home with a config naming a database inside it.
func (tg target) freshHome(t *testing.T) home {
	t.Helper()
	var h home
	if tg.bridged() {
		d, err := os.MkdirTemp(tg.local, "home-")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(d) })
		h = home{dir: d, path: path.Join(tg.remote, filepath.Base(d)), bridged: true}
	} else {
		d := t.TempDir()
		h = home{dir: d, path: d}
		if err := os.MkdirAll(filepath.Join(d, "tmp"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	cfg := fmt.Sprintf("[observer]\ndb_path = %q\n", filepath.ToSlash(h.join("observer.db")))
	if err := os.WriteFile(filepath.Join(h.dir, "config.toml"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	return h
}

// hostCarry are the only variables a launch takes from this process: what
// the operating system needs to start a program. Everything else the hook
// sees is set explicitly below.
var hostCarry = []string{"PATH", "SystemRoot", "SYSTEMROOT", "windir", "SystemDrive", "ComSpec", "PATHEXT"}

// bridgeCarry are also carried to the prefix (wsl.exe), which runs on this
// host as the developer. None of it reaches the hook: WSLENV is emptied, and
// the hook's own environment is the explicit `env -i` list.
var bridgeCarry = []string{"TEMP", "TMP", "USERPROFILE", "LOCALAPPDATA", "APPDATA"}

// carried returns the named variables of this process's environment.
func carried(names ...[]string) []string {
	want := func(n string) bool {
		for _, list := range names {
			for _, w := range list {
				if n == w || (runtime.GOOS == "windows" && strings.EqualFold(n, w)) {
					return true
				}
			}
		}
		return false
	}
	var out []string
	for _, kv := range os.Environ() {
		n, _, ok := strings.Cut(kv, "=")
		if ok && n != "" && want(n) {
			out = append(out, kv)
		}
	}
	return out
}

// launchCommand builds one launch: the argv and the explicit environment.
func launchCommand(tg target, bin string, h home, lc launchCase) (argv, env []string) {
	if tg.bridged() {
		argv = append(append([]string{}, tg.prefix...), "env", "-i", "HOME="+h.path, "PATH="+targetPATH, "OBSERVER_HOOK_MAX_RUNTIME=", keystore.EnvTestKeystore+"="+keystore.TestKeystoreMemory, bin, "hook")
		argv = append(append(argv, lc.args...), "--config", h.join("config.toml"))
		return argv, append(carried(hostCarry, bridgeCarry), "WSLENV=")
	}
	argv = append(append([]string{bin, "hook"}, lc.args...), "--config", h.join("config.toml"))
	env = append(carried(hostCarry),
		"HOME="+h.path, "USERPROFILE="+h.path,
		"APPDATA="+filepath.Join(h.path, "AppData", "Roaming"), "LOCALAPPDATA="+filepath.Join(h.path, "AppData", "Local"),
		"XDG_CONFIG_HOME="+filepath.Join(h.path, ".config"), "XDG_DATA_HOME="+filepath.Join(h.path, ".local", "share"),
		"XDG_STATE_HOME="+filepath.Join(h.path, ".local", "state"), "XDG_CACHE_HOME="+filepath.Join(h.path, ".cache"),
		"TMPDIR="+filepath.Join(h.path, "tmp"), "TEMP="+filepath.Join(h.path, "tmp"), "TMP="+filepath.Join(h.path, "tmp"),
		"OBSERVER_HOOK_MAX_RUNTIME=",
		// The built binary uses the in-memory keyring, never the
		// developer's OS keychain (WINFIX2 audit finding 10).
		keystore.EnvTestKeystore+"="+keystore.TestKeystoreMemory)
	return argv, env
}

// launch runs one `observer hook` process and returns its wall time,
// process start to exit.
func launch(t *testing.T, tg target, bin string, h home, lc launchCase, body []byte, label string) time.Duration {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), launchTimeout)
	defer cancel()
	argv, env := launchCommand(tg, bin, h, lc)
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...) //nolint:gosec // the harness's own observer binary and fixed argv
	cmd.Env = env
	cmd.Stdin = bytes.NewReader(body)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	// The harness clock (QueryPerformanceCounter on Windows), not Go's
	// monotonic clock, whose step there is about 0.52 ms.
	start := hookbudget.Now()
	err := cmd.Run()
	el := hookbudget.Since(start)
	if err != nil || strings.TrimSpace(stdout.String()) == "" {
		t.Fatalf("%s %s: launch failed (%v); stdout %q; stderr %q", lc.name, label, err, stdout.String(), stderr.String())
	}
	return el
}

// TestLaunchCommandIsMinimal pins the launch environment and argv without
// running anything: a direct launch carries only the host start-up
// variables plus its own temp home, and a bridged one passes the home,
// PATH and config path as explicit target-side arguments and empties
// WSLENV.
func TestLaunchCommandIsMinimal(t *testing.T) {
	t.Setenv("SBO_HOOK_BUDGET_SHOULD_NOT_LEAK", "leak")
	lc := launchCases[0]

	h := target{}.freshHome(t)
	argv, env := launchCommand(target{}, "/bin/observer", h, lc)
	if got := strings.Join(argv, " "); got != "/bin/observer hook claude-code pre-tool --config "+filepath.Join(h.path, "config.toml") {
		t.Errorf("direct argv %q", got)
	}
	for _, kv := range env {
		n, v, _ := strings.Cut(kv, "=")
		if n == "SBO_HOOK_BUDGET_SHOULD_NOT_LEAK" {
			t.Errorf("direct launch inherited %s", kv)
		}
		if (n == "HOME" || n == "USERPROFILE") && v != h.path {
			t.Errorf("direct launch %s=%q, want the temp home %q", n, v, h.path)
		}
	}
	if !slicesContains(env, keystore.EnvTestKeystore+"="+keystore.TestKeystoreMemory) {
		t.Errorf("direct launch does not put the binary on the in-memory keyring: %q", env)
	}

	bridgeDir := t.TempDir()
	tg := target{prefix: []string{"wsl.exe", "-d", "Ubuntu", "--"}, local: bridgeDir, remote: "/tmp/sbo-hb"}
	bh := tg.freshHome(t)
	if !strings.HasPrefix(bh.path, "/tmp/sbo-hb/home-") {
		t.Fatalf("bridged home %q is not under the target dir", bh.path)
	}
	body, err := os.ReadFile(filepath.Join(bh.dir, "config.toml"))
	if err != nil || !strings.Contains(string(body), `"`+bh.path+`/observer.db"`) {
		t.Fatalf("bridged config %q does not name a target-side database (%v)", body, err)
	}
	argv, env = launchCommand(tg, "/home/u/bin/observer", bh, lc)
	want := "wsl.exe -d Ubuntu -- env -i HOME=" + bh.path + " PATH=" + targetPATH + " OBSERVER_HOOK_MAX_RUNTIME= SBO_TEST_KEYSTORE=memory /home/u/bin/observer hook claude-code pre-tool --config " + bh.path + "/config.toml"
	if got := strings.Join(argv, " "); got != want {
		t.Errorf("bridged argv\n got %q\nwant %q", got, want)
	}
	sawWSLENV := false
	for _, kv := range env {
		n, _, _ := strings.Cut(kv, "=")
		if n == "SBO_HOOK_BUDGET_SHOULD_NOT_LEAK" {
			t.Errorf("bridged launch inherited %s", kv)
		}
		if kv == "WSLENV=" {
			sawWSLENV = true
		}
	}
	if !sawWSLENV {
		t.Error("bridged launch does not empty WSLENV")
	}
}

func buildObserver(t *testing.T, root string) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "observer")
	if runtime.GOOS == "windows" {
		out += ".exe"
	}
	// go test puts the toolchain running it first on PATH.
	gobin, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("no go on PATH to build ./cmd/observer (set %s to a prebuilt binary): %v", envBin, err)
	}
	cmd := exec.Command(gobin, "build", "-o", out, "./cmd/observer") //nolint:gosec // the toolchain running this test, fixed argv
	cmd.Dir = root
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build ./cmd/observer: %v\n%s", err, b)
	}
	return out
}

func intEnv(t *testing.T, key string, def int) int {
	t.Helper()
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 {
		t.Fatalf("%s=%q: want a positive integer", key, v)
	}
	return n
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found above the test directory")
		}
		dir = parent
	}
}

// sidecarSamples times n warm, in-process runs of the hook's posture step on
// a write-capable event (the Sidecar row; security plan sections 4.8 and
// 6.4): read the key, the project's signed posture (20 blocking keys, about
// 2 KiB) and its seen mark, stat the dirty marker, derive the state, raise
// the seen mark and append one byte to the dirty marker. The posture's
// sequence advances before every timed run (outside the timing), so each
// run's Accept really writes the seen mark, as the hook does after every
// re-sign. The hook pays it in a fresh process; the fresh-process figure on
// native Windows and WSL is the JSP-2 laptop item.
func sidecarSamples(t *testing.T, n int) []time.Duration {
	t.Helper()
	return sidecarSamplesIn(t, secposture.Layout{Dir: filepath.Join(t.TempDir(), secposture.DirName)}, sidecarRoot, n)
}

// sidecarRoot is the project the Sidecar row times.
const sidecarRoot = "/work/project"

// sidecarSamplesIn is sidecarSamples over a given layout and root.
func sidecarSamplesIn(t *testing.T, l secposture.Layout, root string, n int) []time.Duration {
	t.Helper()
	key, err := secposture.LoadOrCreateKey(l.KeyPath())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	f := secposture.File{ProjectRootHash: secposture.ProjectRootHash(root), Packs: []string{"security"}, Sequence: 1, IssuedAt: now, ExpiresAt: now.Add(time.Hour)}
	for i := 0; i < 20; i++ {
		f.Blocking = append(f.Blocking, secposture.ProjectRootHash(strconv.Itoa(i)))
	}
	if _, err := secposture.Write(l, f, key); err != nil {
		t.Fatal(err)
	}
	out := make([]time.Duration, n)
	for i := range out {
		f.Sequence = uint64(i) + 2
		if _, err := secposture.Write(l, f, key); err != nil {
			t.Fatal(err)
		}
		start := hookbudget.Now()
		r := secposture.Load(l, root, secposture.ModuleActive, now, secposture.Versions{})
		if r.File == nil || r.File.Sequence != f.Sequence {
			t.Fatalf("run %d: posture not read: %+v", i, r.State)
		}
		_ = secposture.Accept(l, root, r)
		_ = secposture.RaiseDirty(l, secposture.ProjectRootHash(root))
		out[i] = hookbudget.Since(start)
	}
	return out
}

// TestSidecarRowWritesTheSeenMark: every timed Sidecar run reads a newer
// posture, so its Accept writes the seen mark (audit P-002 finding 4: the
// row must measure that write). It runs without the harness switch.
func TestSidecarRowWritesTheSeenMark(t *testing.T) {
	l := secposture.Layout{Dir: filepath.Join(t.TempDir(), secposture.DirName)}
	const n = 5
	if got := len(sidecarSamplesIn(t, l, sidecarRoot, n)); got != n {
		t.Fatalf("%d samples, want %d", got, n)
	}
	seen, err := secposture.ReadSeen(l, secposture.ProjectRootHash(sidecarRoot))
	if err != nil || seen != n+1 {
		t.Fatalf("seen mark = %d, %v; want %d (one raise per run)", seen, err, n+1)
	}
}

// TestTimingUsesTheHarnessClock pins milestone 1 of lane shr-hookseam2:
// every sample in the harness is timed with internal/hookbudget's clock
// (QueryPerformanceCounter on Windows), never Go's monotonic clock, whose
// step on Windows (about 0.52 ms) is a quarter of the 2 ms sidecar
// budget. A new probe that times with time.Since, time.Now().Sub, or a
// stored time.Now() subtracted later fails here (monotonicTimingUses).
func TestTimingUsesTheHarnessClock(t *testing.T) {
	root := repoRoot(t)
	dirs := []string{filepath.Join(root, "tests", "hookbudget"), filepath.Join(root, "internal", "hookbudget")}
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			name := e.Name()
			if !strings.HasSuffix(name, ".go") || name == "clock.go" || name == "clock_test.go" {
				continue
			}
			body, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				t.Fatal(err)
			}
			uses, err := monotonicTimingUses(name, body)
			if err != nil {
				t.Fatal(err)
			}
			for _, u := range uses {
				t.Errorf("%s:%s times with Go's monotonic clock; use hookbudget.Now and hookbudget.Since (docs/hook-budget-harness.md \"The clock\")", filepath.Join(filepath.Base(dir), name), u)
			}
		}
	}
}

// monotonicTimingUses parses one Go file and returns a "line: form" entry
// for every place it times with Go's clock: a time.Since call, a
// time.Now().Sub call, and a Sub call whose receiver or argument is a
// variable that was assigned time.Now() (matched by name within the file).
// A time.Now() kept as a timestamp and never subtracted is not timing.
func monotonicTimingUses(name string, src []byte) ([]string, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, name, src, 0)
	if err != nil {
		return nil, err
	}
	isTimeCall := func(e ast.Expr, fn string) bool {
		c, ok := e.(*ast.CallExpr)
		if !ok {
			return false
		}
		sel, ok := c.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != fn {
			return false
		}
		pkg, ok := sel.X.(*ast.Ident)
		return ok && pkg.Name == "time"
	}
	stored := map[string]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.AssignStmt:
			for i, rhs := range v.Rhs {
				if i < len(v.Lhs) && isTimeCall(rhs, "Now") {
					if id, ok := v.Lhs[i].(*ast.Ident); ok {
						stored[id.Name] = true
					}
				}
			}
		case *ast.ValueSpec:
			for i, val := range v.Values {
				if i < len(v.Names) && isTimeCall(val, "Now") {
					stored[v.Names[i].Name] = true
				}
			}
		}
		return true
	})
	isStored := func(e ast.Expr) bool {
		id, ok := e.(*ast.Ident)
		return ok && stored[id.Name]
	}
	var out []string
	ast.Inspect(f, func(n ast.Node) bool {
		c, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		line := fset.Position(c.Pos()).Line
		if isTimeCall(c, "Since") {
			out = append(out, fmt.Sprintf("%d: time.Since", line))
			return true
		}
		sel, ok := c.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Sub" {
			return true
		}
		switch {
		case isTimeCall(sel.X, "Now"):
			out = append(out, fmt.Sprintf("%d: time.Now().Sub", line))
		case isStored(sel.X):
			out = append(out, fmt.Sprintf("%d: a stored time.Now() .Sub", line))
		default:
			for _, a := range c.Args {
				if isStored(a) {
					out = append(out, fmt.Sprintf("%d: .Sub of a stored time.Now()", line))
					break
				}
			}
		}
		return true
	})
	return out, nil
}

// TestMonotonicTimingUses: one row per form the clock pin refuses, and the
// forms it must leave alone (audit finding 2 of lane shr-hookseam2).
func TestMonotonicTimingUses(t *testing.T) {
	cases := []struct {
		name string
		body string
		want int
	}{
		{"time.Since", "start := time.Now()\n_ = time.Since(start)", 1},
		{"time.Now().Sub", "var start time.Time\n_ = time.Now().Sub(start)", 1},
		{"a stored time.Now() subtracted later", "start := time.Now()\nwork()\nend := time.Now()\n_ = end.Sub(start)", 1},
		{"a stored time.Now() as the argument", "var start = time.Now()\nvar other time.Time\n_ = other.Sub(start)", 1},
		{"a timestamp, never subtracted", "now := time.Now()\nuse(now)\n_ = now.Add(time.Hour)", 0},
		{"the harness clock", "start := hookbudget.Now()\n_ = hookbudget.Since(start)", 0},
	}
	for _, tc := range cases {
		src := "package p\n\nfunc f() {\n" + tc.body + "\n}\n"
		got, err := monotonicTimingUses("row.go", []byte(src))
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if len(got) != tc.want {
			t.Errorf("%s: %v, want %d use(s)", tc.name, got, tc.want)
		}
	}
}

// slicesContains reports whether list holds v.
func slicesContains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
