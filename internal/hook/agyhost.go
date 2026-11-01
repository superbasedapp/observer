package hook

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/hookctx"
)

// Antigravity CLI (`agy`) host detection for the guard-enforcement fix
// (2026-10-15). Two agy decisions depend on WHICH agy process runs the hook,
// which the hook payloads do not say:
//
//   - PreToolUse ask: `{"decision":"force_ask"}` raises agy's own native
//     prompt in the interactive TUI, but auto-denies in headless `-p` and
//     RUNS the tool under --dangerously-skip-permissions (agy 1.3.5, demo
//     node 1, lead-verified). So an ask is answered with force_ask only when
//     the hook's ancestor is an interactive agy without those flags; in every
//     other case (a flag found, no agy ancestor, the desktop app or IDE, an
//     OS without /proc) the gate denies with a reason that says how to
//     confirm (fail safe).
//   - PreInvocation block: `{"injectSteps":[{}]}` aborts the turn before the
//     main model request on agy 1.3.5 through an UNDOCUMENTED error path
//     ("unknown injected step type"). It is only offered when the ancestor
//     agy reports a version at or above agyAbortMinVersion; otherwise the
//     seam degrades to its warning (recorded as a degrade, never a claimed
//     block).
//
// The process I/O is injected (procReader, agyVersionProbe) so the decision
// logic is table-driven and testable without a live agy.

// procInfo is one process of the hook's ancestor chain.
type procInfo struct {
	PID  int
	Argv []string
	// Exe is the resolved executable path ("" when unknown).
	Exe string
}

// procReader is the /proc-style I/O the ancestry walk reads.
type procReader struct {
	root     string
	readFile func(name string) ([]byte, error)
	readlink func(name string) (string, error)
}

// ancestryMaxDepth bounds the walk: the hook's parent is usually a shell
// agy spawned the command with, then agy itself.
const ancestryMaxDepth = 8

// walkAncestry returns the process chain starting at pid, nearest first.
// ok is false when not even pid could be read (no /proc on this OS, or the
// process is gone): the caller then treats the host as unknown.
func walkAncestry(r procReader, pid int) ([]procInfo, bool) {
	var out []procInfo
	for depth := 0; depth < ancestryMaxDepth && pid > 1; depth++ {
		dir := path.Join(r.root, strconv.Itoa(pid))
		raw, err := r.readFile(path.Join(dir, "cmdline"))
		if err != nil {
			break
		}
		p := procInfo{PID: pid, Argv: splitCmdline(raw)}
		if exe, err := r.readlink(path.Join(dir, "exe")); err == nil {
			p.Exe = strings.TrimSuffix(exe, " (deleted)")
		}
		out = append(out, p)
		status, err := r.readFile(path.Join(dir, "status"))
		if err != nil {
			break
		}
		ppid, ok := parsePPid(status)
		if !ok {
			break
		}
		pid = ppid
	}
	return out, len(out) > 0
}

// splitCmdline splits a NUL-separated /proc cmdline into argv.
func splitCmdline(raw []byte) []string {
	raw = bytes.TrimRight(raw, "\x00")
	if len(raw) == 0 {
		return nil
	}
	parts := bytes.Split(raw, []byte{0})
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		out = append(out, string(p))
	}
	return out
}

// parsePPid reads the PPid line of a /proc status file.
func parsePPid(status []byte) (int, bool) {
	for _, line := range strings.Split(string(status), "\n") {
		if v, ok := strings.CutPrefix(line, "PPid:"); ok {
			n, err := strconv.Atoi(strings.TrimSpace(v))
			return n, err == nil
		}
	}
	return 0, false
}

// osProcReader is the production reader.
var osProcReader = procReader{root: "/proc", readFile: os.ReadFile, readlink: os.Readlink}

// hostAncestry returns the hook process's ancestor chain (memoized: one
// hook invocation asks at most once). The walk starts at the parent id the
// hook context seam's host default reports (internal/hookctx). A test
// replaces it.
var hostAncestry = sync.OnceValues(func() ([]procInfo, bool) {
	return walkAncestry(osProcReader, hookctx.Process().ParentPID())
})

// agyBinaryNames are the executable base names agy installs as (Unix
// "agy", the Windows installer's "agy.exe").
var agyBinaryNames = map[string]bool{"agy": true, "agy.exe": true}

// agyNoNativeAskFlags are the agy arguments under which force_ask does not
// reach a developer: --dangerously-skip-permissions RUNS the tool (live,
// agy 1.2.16 and 1.3.5) and -p / --print (headless) auto-deny it without
// telling the model why (live, agy 1.3.5). --yolo is not grounded for agy;
// it is listed because a flag that skips approvals can only make the gate
// stricter (deny), never weaker.
var agyNoNativeAskFlags = []string{"--dangerously-skip-permissions", "-p", "--print", "--yolo"}

// isAgyProcess reports whether p is an agy process (by its executable or
// its argv[0]).
func isAgyProcess(p procInfo) bool {
	if p.Exe != "" && agyBinaryNames[filepath.Base(p.Exe)] {
		return true
	}
	return len(p.Argv) > 0 && agyBinaryNames[filepath.Base(p.Argv[0])]
}

// findAgyHost returns the nearest agy process in chain.
func findAgyHost(chain []procInfo) (procInfo, bool) {
	for _, p := range chain {
		if isAgyProcess(p) {
			return p, true
		}
	}
	return procInfo{}, false
}

// argvHasFlag reports whether argv (after argv[0]) carries flag, alone or
// as flag=value.
func argvHasFlag(argv []string, flag string) bool {
	if len(argv) < 2 {
		return false
	}
	for _, a := range argv[1:] {
		if a == flag || strings.HasPrefix(a, flag+"=") {
			return true
		}
	}
	return false
}

// agyNativeAskAvailable is the PreToolUse ask capability: true only when
// the nearest agy ancestor is found and carries none of
// agyNoNativeAskFlags. Unknown is false (deny, fail safe).
func agyNativeAskAvailable(chain []procInfo, ok bool) bool {
	if !ok {
		return false
	}
	p, found := findAgyHost(chain)
	if !found {
		return false
	}
	for _, f := range agyNoNativeAskFlags {
		if argvHasFlag(p.Argv, f) {
			return false
		}
	}
	return true
}

// agyAskProbe is the production ask capability probe.
func agyAskProbe() bool { return agyNativeAskAvailable(hostAncestry()) }

// agyAbortMinVersion is the first agy build the PreInvocation abort
// (`{"injectSteps":[{}]}`) was proven on (agy 1.3.5, demo node 1, isolated
// HOME and a loopback mock, 2026-10-15).
const agyAbortMinVersion = "1.3.5"

// agyVersionRe finds a dotted version in `agy --version` output.
var agyVersionRe = regexp.MustCompile(`\b(\d+)\.(\d+)\.(\d+)\b`)

// parseAgyVersion returns the first x.y.z triple in out.
func parseAgyVersion(out string) ([3]int, bool) {
	m := agyVersionRe.FindStringSubmatch(out)
	if m == nil {
		return [3]int{}, false
	}
	var v [3]int
	for i := 0; i < 3; i++ {
		n, err := strconv.Atoi(m[i+1])
		if err != nil {
			return [3]int{}, false
		}
		v[i] = n
	}
	return v, true
}

// versionAtLeast reports whether have >= want (both x.y.z strings); an
// unparseable value is false.
func versionAtLeast(have, want string) bool {
	h, ok := parseAgyVersion(have)
	if !ok {
		return false
	}
	w, ok := parseAgyVersion(want)
	if !ok {
		return false
	}
	for i := 0; i < 3; i++ {
		if h[i] != w[i] {
			return h[i] > w[i]
		}
	}
	return true
}

// agyAbortSupported reports whether the agy running this hook can take the
// PreInvocation abort: an agy ancestor whose version probe answers at least
// agyAbortMinVersion. Unknown is false (the seam warns instead).
func agyAbortSupported(chain []procInfo, ok bool, version func(exe string) (string, bool)) bool {
	if !ok {
		return false
	}
	p, found := findAgyHost(chain)
	if !found {
		return false
	}
	exe := p.Exe
	if exe == "" && len(p.Argv) > 0 {
		exe = p.Argv[0]
	}
	if exe == "" {
		return false
	}
	v, ok := version(exe)
	return ok && versionAtLeast(v, agyAbortMinVersion)
}

// agyVersionProbe runs `<exe> --version` (cached by executable identity).
// A test replaces it.
var agyVersionProbe = cachedAgyVersion

// agyVersionTimeout bounds the version probe, well inside the hook budget.
const agyVersionTimeout = 3 * time.Second

// agyVersionCache is the on-disk memo of the version probe: one entry per
// executable path, invalidated by size or mtime.
type agyVersionCache struct {
	Exe     string `json:"exe"`
	Size    int64  `json:"size"`
	ModUnix int64  `json:"mod_unix"`
	Version string `json:"version"`
}

// cachedAgyVersion returns exe's version, from the cache file when the
// executable is unchanged, else by running it. Any failure is "unknown".
func cachedAgyVersion(exe string) (string, bool) {
	resolved, err := exec.LookPath(exe)
	if err != nil {
		return "", false
	}
	fi, err := os.Stat(resolved)
	if err != nil {
		return "", false
	}
	cachePath := ""
	if dir, err := os.UserCacheDir(); err == nil {
		cachePath = filepath.Join(dir, "superbased-observer", "agy-version.json")
		if raw, err := os.ReadFile(cachePath); err == nil {
			var c agyVersionCache
			if json.Unmarshal(raw, &c) == nil && c.Exe == resolved && c.Size == fi.Size() &&
				c.ModUnix == fi.ModTime().Unix() && c.Version != "" {
				return c.Version, true
			}
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), agyVersionTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, resolved, "--version").CombinedOutput() //nolint:gosec // the agy executable that is this hook's own ancestor, constant argv
	if err != nil {
		return "", false
	}
	v, ok := parseAgyVersion(string(out))
	if !ok {
		return "", false
	}
	version := strconv.Itoa(v[0]) + "." + strconv.Itoa(v[1]) + "." + strconv.Itoa(v[2])
	if cachePath != "" {
		if b, err := json.Marshal(agyVersionCache{Exe: resolved, Size: fi.Size(), ModUnix: fi.ModTime().Unix(), Version: version}); err == nil {
			if os.MkdirAll(filepath.Dir(cachePath), 0o700) == nil {
				_ = os.WriteFile(cachePath, b, 0o600)
			}
		}
	}
	return version, true
}

// agyAbortProbe is the production PreInvocation abort capability probe.
func agyAbortProbe() bool {
	chain, ok := hostAncestry()
	return agyAbortSupported(chain, ok, agyVersionProbe)
}
