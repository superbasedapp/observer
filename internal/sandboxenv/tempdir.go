package sandboxenv

import (
	"net/url"
	"sort"
	"strings"
)

// TempDirRow is one tool's temp-dir capability: the names of the
// environment variables the tool reads for its OWN temp folder, in place of
// the operating system's TMPDIR / TEMP. A backend that gives a run its own
// temp folder (TMPDIR on Landlock and Seatbelt, TEMP and TMP on
// mxc-process) sets every name to that folder, so the tool never falls back
// to a hard-coded path the box hides (macOS live run 2026-10-28, D-UC1).
type TempDirRow struct {
	// Tool is the integration registry id the row describes.
	Tool string
	// Names are the variable NAMES (never values) the tool reads.
	Names []string
	// JVMOptionVars names variables that carry JVM options (the JVM form,
	// D-MU6): a JVM ignores TMPDIR and reads java.io.tmpdir, so the run's
	// folder is set there as -Djava.io.tmpdir=<dir>, merged into any value
	// the variable already has, the run's value winning. A JVM ignores
	// HTTPS_PROXY / HTTP_PROXY as well, so the run's gateway is set there
	// too as the http(s).proxyHost / proxyPort properties (JVMProxyOptions;
	// junie hung on "Proxy connection failed" without them, live Mac
	// 2026-10-29, N3).
	JVMOptionVars []string
	// Grounding is where the name was read.
	Grounding string
}

// tempDirTable is THE per-tool temp-dir table, one test case per row, keyed
// by the registry id as data (a capability row, never a tool-name branch in
// a backend). A tool with no row gets nothing extra.
var tempDirTable = []TempDirRow{
	{
		Tool:  "claude-code",
		Names: []string{"CLAUDE_CODE_TMPDIR"},
		Grounding: "Claude Code 2.1.312 makes /tmp/claude-<uid> unless CLAUDE_CODE_TMPDIR is set; " +
			"under the Seatbelt profile /private/tmp is hidden and the start failed with EEXIST/EPERM (macOS live run 2026-10-28, D-UC1)",
	},
	{
		Tool:          "junie",
		JVMOptionVars: []string{"JAVA_TOOL_OPTIONS"},
		Grounding: "Junie's CLI runs on a JVM, which ignores TMPDIR: under Seatbelt java.io.tmpdir stayed " +
			"/var/folders/.../T, which the profile hides (macOS live user install 2026-10-29, D-MU6); " +
			"JAVA_TOOL_OPTIONS is read by every HotSpot JVM at start",
	},
}

// TempDirTable returns a copy of the per-tool temp-dir table, for tests.
func TempDirTable() []TempDirRow {
	out := make([]TempDirRow, len(tempDirTable))
	for i, r := range tempDirTable {
		r.Names = append([]string(nil), r.Names...)
		r.JVMOptionVars = append([]string(nil), r.JVMOptionVars...)
		out[i] = r
	}
	return out
}

// TempDirEnv is the names tool reads for its own temp folder (nil when the
// tool declares none). The slice is the caller's.
func TempDirEnv(tool string) []string {
	for _, r := range tempDirTable {
		if r.Tool == tool {
			return append([]string(nil), r.Names...)
		}
	}
	return nil
}

// TempDirJVMEnv is the names of the variables carrying JVM options in which
// the run's temp folder is set for tool (nil when the tool declares none).
func TempDirJVMEnv(tool string) []string {
	for _, r := range tempDirTable {
		if r.Tool == tool {
			return append([]string(nil), r.JVMOptionVars...)
		}
	}
	return nil
}

// jvmTmpdirOption is the JVM system property the JVM form sets.
const jvmTmpdirOption = "-Djava.io.tmpdir="

// WithJVMTempDir returns env with -Djava.io.tmpdir=<dir> set in every
// variable of vars (WithJVMOptions): an existing value is kept verbatim and
// the run's option goes last, so the JVM's last-wins rule for a repeated
// system property makes the run's folder win. A dir holding whitespace is
// not set (it would need quoting the option list may not support; the
// TMPDIR form still applies). No vars or an empty dir return env unchanged.
func WithJVMTempDir(env, vars []string, dir string) []string {
	if dir == "" || strings.ContainsAny(dir, " \t\n\r") {
		return env
	}
	return WithJVMOptions(env, vars, []string{jvmTmpdirOption + dir})
}

// WithJVMOptions returns env with opts appended to every variable of vars.
// An existing value is never parsed or split (a quoted option holding a
// path with spaces stays intact, MACUSER merge L4): the run's options are
// appended after it, and a JVM takes the LAST value of a repeated -D
// system property, so the run's value wins. A second entry of the same
// variable is dropped (the first, now merged, is the one a program sees).
// No vars or no opts return env unchanged.
func WithJVMOptions(env, vars, opts []string) []string {
	if len(vars) == 0 || len(opts) == 0 {
		return env
	}
	want := map[string]bool{}
	for _, v := range vars {
		if v = strings.TrimSpace(v); v != "" {
			want[v] = true
		}
	}
	if len(want) == 0 {
		return env
	}
	opt := strings.Join(opts, " ")
	done := map[string]bool{}
	out := make([]string, 0, len(env)+len(want))
	for _, kv := range env {
		k, v, ok := strings.Cut(kv, "=")
		switch {
		case !ok || !want[k]:
			out = append(out, kv)
			continue
		case done[k]:
			// A second entry of the same variable is dropped: the
			// first, now merged, is the one the program sees.
			continue
		}
		if v = strings.TrimRight(v, " \t"); v != "" {
			out = append(out, k+"="+v+" "+opt)
		} else {
			out = append(out, k+"="+opt)
		}
		done[k] = true
	}
	names := make([]string, 0, len(want))
	for k := range want {
		if !done[k] {
			names = append(names, k)
		}
	}
	sort.Strings(names)
	for _, k := range names {
		out = append(out, k+"="+opt)
	}
	return out
}

// jvmLoopbackNonProxy is the http.nonProxyHosts value set when the run's
// env exempts loopback from its proxy (the box reaches its own port
// directly).
const jvmLoopbackNonProxy = "-Dhttp.nonProxyHosts=localhost|127.*|[::1]"

// JVMProxyOptions returns the JVM system properties that send a JVM through
// the proxy env names (the run's egress gateway): -Dhttps.proxyHost /
// -Dhttps.proxyPort from HTTPS_PROXY (or https_proxy), -Dhttp.proxyHost /
// -Dhttp.proxyPort from HTTP_PROXY (or http_proxy), each falling back to
// the other, and -Dhttp.nonProxyHosts for loopback when NO_PROXY (or
// no_proxy) exempts it. A JVM reads none of those variables itself. A
// proxy URL that is not plain http(s)://host[:port], or carries
// credentials, sets nothing. nil when env names no usable proxy.
func JVMProxyOptions(env []string) []string {
	get := func(names ...string) string {
		for _, n := range names {
			for _, kv := range env {
				if k, v, ok := strings.Cut(kv, "="); ok && k == n && v != "" {
					return v
				}
			}
		}
		return ""
	}
	https, http := get("HTTPS_PROXY", "https_proxy"), get("HTTP_PROXY", "http_proxy")
	if https == "" {
		https = http
	}
	if http == "" {
		http = https
	}
	var out []string
	for _, p := range []struct{ scheme, raw string }{{"https", https}, {"http", http}} {
		if host, port, ok := jvmProxyHostPort(p.raw); ok {
			out = append(out, "-D"+p.scheme+".proxyHost="+host, "-D"+p.scheme+".proxyPort="+port)
		}
	}
	if len(out) > 0 && noProxyHasLoopback(get("NO_PROXY", "no_proxy")) {
		out = append(out, jvmLoopbackNonProxy)
	}
	return out
}

// jvmProxyHostPort splits a proxy URL into the host and port a JVM's proxy
// properties take.
func jvmProxyHostPort(raw string) (host, port string, ok bool) {
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return "", "", false
	}
	host, port = u.Hostname(), u.Port()
	if port == "" {
		port = map[string]string{"http": "80", "https": "443"}[u.Scheme]
	}
	if host == "" || strings.ContainsAny(host+port, " \t\r\n\"'|") {
		return "", "", false
	}
	return host, port, true
}

// noProxyHasLoopback reports whether a NO_PROXY list names a loopback host.
func noProxyHasLoopback(list string) bool {
	for _, h := range strings.Split(list, ",") {
		switch strings.TrimSpace(h) {
		case "localhost", "127.0.0.1", "::1", "[::1]":
			return true
		}
	}
	return false
}

// WithTempDir returns env with every name in names set to dir: any value
// already there (the user's own, through pass_env) is removed first, matched
// without regard to case so a Windows spelling cannot survive either, and
// the run's folder always wins. No names or an empty dir return env
// unchanged.
func WithTempDir(env, names []string, dir string) []string {
	if len(names) == 0 || dir == "" {
		return env
	}
	set := make([]string, 0, len(names))
	for _, n := range names {
		if n = strings.TrimSpace(n); n != "" {
			set = append(set, n)
		}
	}
	if len(set) == 0 {
		return env
	}
	sort.Strings(set)
	out := make([]string, 0, len(env)+len(set))
	for _, kv := range env {
		k, _, _ := strings.Cut(kv, "=")
		if tempDirNamed(set, k) {
			continue
		}
		out = append(out, kv)
	}
	seen := map[string]bool{}
	for _, n := range set {
		u := strings.ToUpper(n)
		if seen[u] {
			continue
		}
		seen[u] = true
		out = append(out, n+"="+dir)
	}
	return out
}

// tempDirNamed reports whether k is one of names, ignoring case.
func tempDirNamed(names []string, k string) bool {
	for _, n := range names {
		if strings.EqualFold(n, k) {
			return true
		}
	}
	return false
}
