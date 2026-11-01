package diag

import (
	"debug/buildinfo"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/hook/pluginshim"
	"github.com/marmutapp/superbased-observer/internal/remedy"
)

// binaryfreshness.go holds two doctor rows for a stale observer left behind
// by an update (SHR-HOOKSEAM2 leftover, lane LEFT-SHARED). Both only report;
// nothing here changes a file, a hook or a decision.
//
//   - hooks.plugin_shims: every in-process plugin shim Observer wrote
//     (internal/hook/pluginshim) names the observer binary its host runs on
//     each tool call. A shim naming a binary that is gone, or an observer
//     older than the running one, keeps the host on the old build.
//   - observer.path: an `observer` on PATH that is not the running binary
//     and is older than it, so a shell, a script or a host that runs
//     `observer` by name gets the older build.
//
// A binary's version is read from its Go build information (the release
// build stamps it with -X main.version=...), never by running it.

// ldflagsVersion finds the stamped version in a -ldflags build setting.
var ldflagsVersion = regexp.MustCompile(`-X[ =]main\.version=([^\s'"]+)`)

// BinaryVersionOf is the release version stamped into an observer binary at
// build time, read from its Go build information; "" when the file is not a
// Go binary, carries no stamp, or cannot be read.
func BinaryVersionOf(path string) string {
	bi, err := buildinfo.ReadFile(path)
	if err != nil {
		return ""
	}
	for _, s := range bi.Settings {
		if s.Key == "-ldflags" {
			if m := ldflagsVersion.FindStringSubmatch(s.Value); m != nil {
				return m[1]
			}
		}
	}
	return ""
}

// olderThan reports whether version a is a strictly older release than b
// ("v"-optional "X.Y.Z[-pre][+build]"); false when either does not parse. A
// pre-release is older than its own release; two pre-releases of one release
// compare equal (doctor only asks "is this one older").
func olderThan(a, b string) bool {
	ca, pa, oka := releaseCore(a)
	cb, pb, okb := releaseCore(b)
	if !oka || !okb {
		return false
	}
	for i := range ca {
		if ca[i] != cb[i] {
			return ca[i] < cb[i]
		}
	}
	return pa && !pb
}

// releaseCore parses a version's numeric core and whether it carries a
// pre-release.
func releaseCore(v string) (core [3]int, pre, ok bool) {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if i := strings.IndexByte(v, '+'); i >= 0 {
		v = v[:i]
	}
	coreStr, preStr, hasPre := strings.Cut(v, "-")
	parts := strings.Split(coreStr, ".")
	if len(parts) != 3 || (hasPre && preStr == "") {
		return core, false, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return core, false, false
		}
		core[i] = n
	}
	return core, hasPre, true
}

// staleBinaryReason says why path is not the running observer cliVersion
// names, "" when it is the running one or nothing is wrong with it.
func staleBinaryReason(path string, id HookBinaryIdentity, cliVersion string, versionOf func(string) string) string {
	if HookBinaryMatches(path, id) {
		return ""
	}
	if _, err := os.Stat(path); err != nil {
		return "names " + path + ", which is missing"
	}
	if v := versionOf(path); v != "" && olderThan(v, cliVersion) {
		return fmt.Sprintf("names %s, which is v%s, older than the running v%s", path, strings.TrimPrefix(v, "v"), strings.TrimPrefix(cliVersion, "v"))
	}
	return ""
}

// checkPluginShimBinaries is the hooks.plugin_shims row.
func checkPluginShimBinaries(homeDir string, getenv func(string) string, id HookBinaryIdentity, cliVersion string, versionOf func(string) string) Check {
	const name = "hooks.plugin_shims"
	if homeDir == "" {
		return Check{Name: name, Status: StatusOK, Message: "no home directory: no plugin shim to check"}
	}
	var stale []string
	seen := 0
	for _, tool := range pluginshim.Tools() {
		h, ok := pluginshim.HostFor(tool)
		if !ok || !h.Writable() {
			continue
		}
		dir, err := h.Dir(homeDir, getenv)
		if err != nil {
			continue
		}
		path := filepath.Join(dir, h.File())
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		bin, _, ours := pluginshim.RenderedBinaries(raw)
		if !ours || bin == "" {
			continue
		}
		seen++
		if why := staleBinaryReason(bin, id, cliVersion, versionOf); why != "" {
			stale = append(stale, tool+" ("+path+") "+why)
		}
	}
	sort.Strings(stale)
	switch {
	case len(stale) > 0:
		return Check{
			Name: name, Status: StatusWarn,
			Message:      fmt.Sprintf("%d plugin shim(s) run a missing or older observer - re-run %s to rewrite them", len(stale), remedy.Quote(initAll)),
			Details:      stale,
			Remediations: []remedy.Remediation{initAll},
		}
	case seen == 0:
		return Check{Name: name, Status: StatusOK, Message: "no plugin shim written by observer"}
	}
	return Check{Name: name, Status: StatusOK, Message: fmt.Sprintf("%d plugin shim(s) run the current observer", seen)}
}

// checkPathObserver is the observer.path row: lookObserver finds `observer`
// the way a shell does (pathObserver).
func checkPathObserver(lookObserver func() (string, error), id HookBinaryIdentity, cliVersion string, versionOf func(string) string) Check {
	const name = "observer.path"
	p, err := lookObserver()
	if err != nil || p == "" {
		return Check{Name: name, Status: StatusOK, Message: "no observer on PATH (hooks name the binary directly)"}
	}
	if why := staleBinaryReason(p, id, cliVersion, versionOf); why != "" && !strings.Contains(why, "missing") {
		return Check{
			Name: name, Status: StatusWarn,
			Message: "the observer on PATH " + strings.TrimPrefix(why, "names ") + ": a shell or tool that runs `observer` by name gets the older build - update or remove it",
			Details: []string{"on PATH: " + p, "running: " + id.Command},
		}
	}
	return Check{Name: name, Status: StatusOK, Message: "the observer on PATH is the running one, or not older (" + p + ")"}
}

// pathObserver finds `observer` on PATH (LookPath only, nothing is started).
func pathObserver() (string, error) { return exec.LookPath("observer") }
