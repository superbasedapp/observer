package crossmount

import (
	"os"
	"sort"
	"strings"
	"sync"
)

// # The Windows side's environment, read from WSL (surface-gap FU-32, FU-70)
//
// A tool on Windows reads its relocation variables (CLAUDE_CONFIG_DIR,
// CODEX_HOME, CLINE_DIR, ...) from the Windows environment, which a WSL
// process does not inherit. WindowsPersistentEnv reads the persistent
// values a newly launched Windows program gets (the user's, else the
// machine's), so the doctor can say when a "-windows" target writes a
// default the Windows tool does not read. This package owns the rules (when
// to ask, which names, the script, the parse, the memo); the caller injects
// the one process that runs the script (internal/diag, the package declared
// to start powershell.exe for its doctor rows). It never asks from a test
// binary, an isolated home or with foreign discovery off, and only plain
// variable names reach the script.

// WindowsEnvProbe runs a PowerShell script on the Windows side and returns
// its standard output; ok is false on any failure.
type WindowsEnvProbe func(script string) (out string, ok bool)

// windowsEnvCache memoizes one read per name set per process.
var windowsEnvCache sync.Map // key: joined names -> windowsEnvResult

type windowsEnvResult struct {
	vals map[string]string
	ok   bool
}

// WindowsPersistentEnv returns the set ones among names of the Windows
// user's persistent environment (user value first, else machine), read from
// WSL through probe. ok is false when it cannot be read: not WSL, discovery
// suppressed or isolated, no probe, or the probe failed. Invalid names are
// dropped.
func WindowsPersistentEnv(names []string, probe WindowsEnvProbe) (map[string]string, bool) {
	if probe == nil || windowsEnvSuppressed() || !windowsUserIsWSL() {
		return nil, false
	}
	return windowsPersistentEnvWith(names, probe)
}

// windowsEnvSuppressed applies the foreign-discovery rules (testguard.go,
// isolation.go): no probe from a test binary, an isolated home, or with
// discovery disabled.
func windowsEnvSuppressed() bool {
	if stagedForeign.Load() != nil {
		return true
	}
	return foreignSuppressedWith(nil, os.Getenv(EnvDisableForeignHomes), testBinaryGuard) || IsolationReason() != ""
}

// windowsPersistentEnvWith is the memoized core with the probe injected.
func windowsPersistentEnvWith(names []string, probe func(script string) (string, bool)) (map[string]string, bool) {
	valid := validEnvNames(names)
	if len(valid) == 0 {
		return map[string]string{}, true
	}
	key := strings.Join(valid, ",")
	if v, ok := windowsEnvCache.Load(key); ok {
		r := v.(windowsEnvResult)
		return r.vals, r.ok
	}
	out, ok := probe(windowsEnvScript(valid))
	res := windowsEnvResult{ok: ok}
	if ok {
		res.vals = parseEnvLines(out, valid)
	}
	windowsEnvCache.Store(key, res)
	return res.vals, res.ok
}

// validEnvNames keeps the plain variable names ([A-Za-z_][A-Za-z0-9_]*),
// sorted and distinct, so nothing a caller passes can reach the script as
// code.
func validEnvNames(names []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, n := range names {
		if !isPlainEnvName(n) || seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func isPlainEnvName(n string) bool {
	if n == "" {
		return false
	}
	for i, r := range n {
		switch {
		case r == '_', r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}

// windowsEnvScript prints NAME=value for each set name.
func windowsEnvScript(names []string) string {
	quoted := make([]string, len(names))
	for i, n := range names {
		quoted[i] = "'" + n + "'"
	}
	return "foreach($n in @(" + strings.Join(quoted, ",") + ")){" +
		"$v=[Environment]::GetEnvironmentVariable($n,'User');" +
		"if(-not $v){$v=[Environment]::GetEnvironmentVariable($n,'Machine')};" +
		"if($v){[Console]::Out.WriteLine($n+'='+$v)}}"
}

// parseEnvLines reads NAME=value lines, keeping only the asked names.
func parseEnvLines(out string, names []string) map[string]string {
	want := map[string]bool{}
	for _, n := range names {
		want[n] = true
	}
	vals := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		k, v, found := strings.Cut(line, "=")
		if !found || !want[k] || strings.TrimSpace(v) == "" {
			continue
		}
		vals[k] = v
	}
	return vals
}
