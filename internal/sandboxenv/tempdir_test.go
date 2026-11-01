package sandboxenv

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

var tempDirName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// TestTempDirTableWellFormed pins every row of the per-tool temp-dir table:
// a registry-shaped id, at least one bare variable name (or JVM option
// variable, the JVM form), no duplicate, no
// name of the operating system's own temp variables or of Observer's own,
// and a grounding.
func TestTempDirTableWellFormed(t *testing.T) {
	seenTool := map[string]bool{}
	for _, r := range TempDirTable() {
		if r.Tool == "" || seenTool[r.Tool] {
			t.Errorf("row %+v: empty or duplicate tool", r)
		}
		seenTool[r.Tool] = true
		if len(r.Names)+len(r.JVMOptionVars) == 0 || r.Grounding == "" {
			t.Errorf("tool %q: a row needs names (or the JVM form) and a grounding", r.Tool)
		}
		for _, n := range r.JVMOptionVars {
			if !tempDirName.MatchString(n) {
				t.Errorf("tool %q: JVM option variable %q is not a variable name", r.Tool, n)
			}
		}
		seen := map[string]bool{}
		for _, n := range r.Names {
			if !tempDirName.MatchString(n) {
				t.Errorf("tool %q: %q is not a variable name", r.Tool, n)
			}
			switch n {
			case "TMPDIR", "TEMP", "TMP", EnvAllow, EnvPassed, EnvSignInShared:
				t.Errorf("tool %q: %q is set by the backend itself", r.Tool, n)
			}
			if seen[n] {
				t.Errorf("tool %q: duplicate %q", r.Tool, n)
			}
			seen[n] = true
		}
	}
}

// TestWithTempDir is the composition table: the run's folder always wins
// over a value already present, in any case spelling; a tool declaring
// nothing gets nothing extra.
func TestWithTempDir(t *testing.T) {
	cases := []struct {
		name  string
		env   []string
		names []string
		dir   string
		want  []string
	}{
		{"declared, absent", []string{"PATH=/bin"}, []string{"CLAUDE_CODE_TMPDIR"}, "/r/t", []string{"PATH=/bin", "CLAUDE_CODE_TMPDIR=/r/t"}},
		{"declared, user value replaced", []string{"CLAUDE_CODE_TMPDIR=/private/tmp", "PATH=/bin"}, []string{"CLAUDE_CODE_TMPDIR"}, "/r/t", []string{"PATH=/bin", "CLAUDE_CODE_TMPDIR=/r/t"}},
		{"declared, other case replaced", []string{"claude_code_tmpdir=C:/x", "PATH=/bin"}, []string{"CLAUDE_CODE_TMPDIR"}, "/r/t", []string{"PATH=/bin", "CLAUDE_CODE_TMPDIR=/r/t"}},
		{"nothing declared", []string{"CLAUDE_CODE_TMPDIR=/private/tmp", "PATH=/bin"}, nil, "/r/t", []string{"CLAUDE_CODE_TMPDIR=/private/tmp", "PATH=/bin"}},
		{"no run folder", []string{"PATH=/bin"}, []string{"CLAUDE_CODE_TMPDIR"}, "", []string{"PATH=/bin"}},
		{"duplicate names set once", []string{"PATH=/bin"}, []string{"A_TMP", "a_tmp", "A_TMP"}, "/r", []string{"PATH=/bin", "A_TMP=/r"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := WithTempDir(c.env, c.names, c.dir); !slices.Equal(got, c.want) {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}

// TestTempDirEnvLookup: the declaring row answers its names, every other
// tool answers nothing, and the slice is the caller's.
func TestTempDirEnvLookup(t *testing.T) {
	if got := TempDirEnv("claude-code"); !slices.Equal(got, []string{"CLAUDE_CODE_TMPDIR"}) {
		t.Errorf("claude-code: %q", got)
	}
	for _, tool := range []string{"codex", "", "no-such-tool"} {
		if got := TempDirEnv(tool); got != nil {
			t.Errorf("%q declares %q", tool, got)
		}
	}
	got := TempDirEnv("claude-code")
	got[0] = "X"
	if TempDirEnv("claude-code")[0] != "CLAUDE_CODE_TMPDIR" {
		t.Error("the caller's slice aliases the table")
	}
}

// TestWithJVMTempDir pins the JVM form of the temp-dir table (D-MU6): the
// run's folder is set as -Djava.io.tmpdir, appended last to an existing
// value (kept verbatim, so the JVM's last-wins rule makes the run's value
// win and a quoted option survives, MACUSER merge L4), set when absent, and
// the variable never duplicated.
func TestWithJVMTempDir(t *testing.T) {
	const dir = "/private/var/folders/x/T/obsbx-tmp/r1"
	cases := []struct {
		name string
		env  []string
		want []string
	}{
		{"absent", []string{"PATH=/usr/bin"}, []string{"PATH=/usr/bin", "JAVA_TOOL_OPTIONS=-Djava.io.tmpdir=" + dir}},
		{"merged", []string{"JAVA_TOOL_OPTIONS=-Xmx2g -Dfile.encoding=UTF-8"}, []string{"JAVA_TOOL_OPTIONS=-Xmx2g -Dfile.encoding=UTF-8 -Djava.io.tmpdir=" + dir}},
		{"run wins (last)", []string{"JAVA_TOOL_OPTIONS=-Djava.io.tmpdir=/tmp -Xss1m"}, []string{"JAVA_TOOL_OPTIONS=-Djava.io.tmpdir=/tmp -Xss1m -Djava.io.tmpdir=" + dir}},
		{"quoted path with spaces kept", []string{`JAVA_TOOL_OPTIONS=-Djava.io.tmpdir="/Users/a b/tmp" -Dlog="/x  y/l.txt"`}, []string{`JAVA_TOOL_OPTIONS=-Djava.io.tmpdir="/Users/a b/tmp" -Dlog="/x  y/l.txt" -Djava.io.tmpdir=` + dir}},
		{"duplicate entries collapse", []string{"JAVA_TOOL_OPTIONS=-Xss1m", "JAVA_TOOL_OPTIONS=-Xmx1g"}, []string{"JAVA_TOOL_OPTIONS=-Xss1m -Djava.io.tmpdir=" + dir}},
	}
	for _, c := range cases {
		got := WithJVMTempDir(c.env, []string{"JAVA_TOOL_OPTIONS"}, dir)
		if strings.Join(got, "|") != strings.Join(c.want, "|") {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
	if got := WithJVMTempDir([]string{"A=1"}, []string{"JAVA_TOOL_OPTIONS"}, "/with space"); len(got) != 1 {
		t.Errorf("a dir with whitespace must not be set: %v", got)
	}
	if got := TempDirJVMEnv("junie"); len(got) != 1 || got[0] != "JAVA_TOOL_OPTIONS" {
		t.Errorf("junie JVM vars = %v", got)
	}
	if TempDirJVMEnv("claude-code") != nil {
		t.Error("claude-code has no JVM form")
	}
}

// TestJVMProxyOptions pins N3 (live Mac 2026-10-29: junie's JVM ignored
// https_proxy and hung): the run's gateway becomes the JVM proxy
// properties, loopback stays direct, and they are appended after a user's
// own value so the run's wins.
func TestJVMProxyOptions(t *testing.T) {
	gateway := []string{
		"HTTP_PROXY=http://127.0.0.1:50123", "HTTPS_PROXY=http://127.0.0.1:50123",
		"http_proxy=http://127.0.0.1:50123", "https_proxy=http://127.0.0.1:50123",
		"NO_PROXY=127.0.0.1,localhost,::1", "no_proxy=127.0.0.1,localhost,::1",
	}
	want := []string{
		"-Dhttps.proxyHost=127.0.0.1", "-Dhttps.proxyPort=50123",
		"-Dhttp.proxyHost=127.0.0.1", "-Dhttp.proxyPort=50123",
		"-Dhttp.nonProxyHosts=localhost|127.*|[::1]",
	}
	cases := []struct {
		name string
		env  []string
		want []string
	}{
		{"the run's gateway", gateway, want},
		{"lower case only, no no_proxy", []string{"https_proxy=http://127.0.0.1:50123"}, want[:4]},
		{"http only, default port", []string{"HTTP_PROXY=http://gw"}, []string{"-Dhttps.proxyHost=gw", "-Dhttps.proxyPort=80", "-Dhttp.proxyHost=gw", "-Dhttp.proxyPort=80"}},
		{"credentials set nothing", []string{"HTTPS_PROXY=http://u:p@gw:3128"}, nil},
		{"socks sets nothing", []string{"HTTPS_PROXY=socks5://gw:1080"}, nil},
		{"no proxy", []string{"PATH=/usr/bin", "NO_PROXY=localhost"}, nil},
	}
	for _, c := range cases {
		if got := JVMProxyOptions(c.env); strings.Join(got, " ") != strings.Join(c.want, " ") {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
	env := WithJVMOptions(append([]string{"JAVA_TOOL_OPTIONS=-Dhttps.proxyHost=corp -Xmx1g"}, gateway...), []string{"JAVA_TOOL_OPTIONS"}, JVMProxyOptions(gateway))
	if env[0] != "JAVA_TOOL_OPTIONS=-Dhttps.proxyHost=corp -Xmx1g "+strings.Join(want, " ") {
		t.Errorf("merged = %q, want the run's proxy appended last", env[0])
	}
}
