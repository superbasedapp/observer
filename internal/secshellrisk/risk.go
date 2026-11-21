package secshellrisk

import (
	"regexp"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// Kind is one risk class.
type Kind string

// The Kind values.
const (
	// OSInstallUnpinned: an OS package manager installs a package with no
	// version.
	OSInstallUnpinned Kind = "os_install_unpinned"
	// LangInstallUnpinned: a language package manager installs a named
	// package with no version (an install from a lockfile or manifest names
	// no package and is not a hit).
	LangInstallUnpinned Kind = "lang_install_unpinned"
	// RemotePipe: remote content piped into an interpreter (R-170's shapes).
	RemotePipe Kind = "remote_pipe"
)

// Hit is one risk on one logical line of the script.
type Hit struct {
	Kind Kind
	// Line is the 0-based line offset in the script where the logical line
	// (backslash continuations joined) starts.
	Line int
	// Detail is a fixed word from this package's tables (the package
	// manager's name, or "pipe"), never script text.
	Detail string
}

// LangInstalls is the language-install detector: it reports the ecosystem
// of the first install in cmds that names a package with no version (or
// "latest"). The parser belongs to the security.deps component
// (internal/secfeed), so this package does not link it: cmd/observer
// registers secfeed.UnpinnedInstallEcosystem here when that component is
// built, and a build without it reports no LangInstallUnpinned hit. Set it
// once at program start, never while Analyze runs.
var LangInstalls func(cmds []policy.Command) (ecosystem string, ok bool)

// MaxScriptBytes caps the script text read; a longer script is cut there
// and Analyze reports it (truncated).
const MaxScriptBytes = 256 << 10

// osInstallRow is one OS package manager's install verb.
type osInstallRow struct {
	base string
	// verbs are the subcommands that install ("" for a manager whose
	// install is the base itself).
	verbs []string
	// valueFlags take the next word as their value.
	valueFlags map[string]bool
	// pinned reports a package word that names a version.
	pinned func(word string) bool
}

// eqPinned: apt (pkg=1.2-3) and apk (pkg=1.2-r0) pin with "=".
func eqPinned(w string) bool { return strings.Contains(w, "=") }

// rpmVersioned matches name-version (dnf, yum, tdnf: openssl-3.0.7) or a
// zypper/dnf comparison (pkg=1.2, pkg>=1.2 is a range, not a pin).
var rpmVersioned = regexp.MustCompile(`^[A-Za-z0-9._+]+-[0-9][A-Za-z0-9._+~:-]*$`)

func rpmPinned(w string) bool {
	if strings.ContainsAny(w, "<>") {
		return false
	}
	return strings.Contains(w, "=") || rpmVersioned.MatchString(w)
}

// osInstallTable is THE OS install table, walked in order.
var osInstallTable = []osInstallRow{
	{base: "apt-get", verbs: []string{"install"}, valueFlags: set("-o", "-t", "--target-release", "-c", "--config-file"), pinned: eqPinned},
	{base: "apt", verbs: []string{"install"}, valueFlags: set("-o", "-t", "--target-release", "-c", "--config-file"), pinned: eqPinned},
	{base: "apk", verbs: []string{"add"}, valueFlags: set("-X", "--repository", "-t", "--virtual", "--root", "-p", "--keys-dir", "--arch"), pinned: eqPinned},
	{base: "dnf", verbs: []string{"install"}, valueFlags: set("--repo", "--enablerepo", "--disablerepo", "--releasever", "--installroot", "--setopt", "-c", "--config"), pinned: rpmPinned},
	{base: "microdnf", verbs: []string{"install"}, valueFlags: set("--enablerepo", "--disablerepo", "--releasever", "--installroot", "--setopt", "--config"), pinned: rpmPinned},
	{base: "yum", verbs: []string{"install"}, valueFlags: set("--enablerepo", "--disablerepo", "--releasever", "--installroot", "--setopt", "-c", "--config"), pinned: rpmPinned},
	{base: "tdnf", verbs: []string{"install"}, valueFlags: set("--enablerepo", "--disablerepo", "--releasever", "--installroot", "-c", "--config"), pinned: rpmPinned},
	{base: "zypper", verbs: []string{"install", "in"}, valueFlags: set("-r", "--repo", "--from", "-t", "--type"), pinned: rpmPinned},
}

func set(items ...string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, s := range items {
		m[s] = true
	}
	return m
}

// Analyze returns the risks of a script, in line order, one hit per kind
// per logical line. dialect is the script's shell (DialectPosix for a
// Dockerfile RUN and a Linux or macOS runner, DialectPowerShell for pwsh).
// truncated reports a script longer than MaxScriptBytes (read only up to
// the cap).
func Analyze(script string, dialect policy.Dialect) (hits []Hit, truncated bool) {
	if len(script) > MaxScriptBytes {
		script, truncated = script[:MaxScriptBytes], true
	}
	for _, ll := range logicalLines(script) {
		cmds := policy.ParseCommand(ll.text, dialect)
		if len(cmds) == 0 {
			continue
		}
		seen := map[Kind]bool{}
		add := func(k Kind, detail string) {
			if !seen[k] {
				seen[k] = true
				hits = append(hits, Hit{Kind: k, Line: ll.start, Detail: detail})
			}
		}
		if ok, _ := policy.RemoteCodePipe(cmds); ok {
			add(RemotePipe, "pipe")
		}
		for i := range cmds {
			if mgr, ok := osUnpinned(&cmds[i]); ok {
				add(OSInstallUnpinned, mgr)
			}
		}
		if LangInstalls != nil {
			if eco, ok := LangInstalls(cmds); ok {
				add(LangInstallUnpinned, eco)
			}
		}
	}
	return hits, truncated
}

// osUnpinned reports an OS install unit that names at least one package
// with no version.
func osUnpinned(c *policy.Command) (string, bool) {
	for _, row := range osInstallTable {
		if c.Base != row.base {
			continue
		}
		args := c.Args()
		verbAt := -1
		for i := 0; i < len(args); i++ {
			a := args[i]
			if strings.HasPrefix(a, "-") {
				if row.valueFlags[a] {
					i++
				}
				continue
			}
			for _, v := range row.verbs {
				if a == v {
					verbAt = i
				}
			}
			break
		}
		if verbAt < 0 {
			return "", false
		}
		for i := verbAt + 1; i < len(args); i++ {
			a := args[i]
			if strings.HasPrefix(a, "-") {
				if row.valueFlags[a] {
					i++
				}
				continue
			}
			if strings.ContainsAny(a, "/$") || strings.HasSuffix(a, ".deb") || strings.HasSuffix(a, ".rpm") || strings.HasSuffix(a, ".apk") {
				continue // a local file or an unexpanded variable: not a registry name
			}
			if !row.pinned(a) {
				return row.base, true
			}
		}
		return "", false
	}
	return "", false
}

// logicalLine is one command line with its continuations joined.
type logicalLine struct {
	start int
	text  string
}

// logicalLines splits a script on newlines, joining a line that ends in a
// backslash (POSIX) or a backtick (PowerShell) with the next.
func logicalLines(script string) []logicalLine {
	var out []logicalLine
	lines := strings.Split(strings.ReplaceAll(script, "\r\n", "\n"), "\n")
	for i := 0; i < len(lines); i++ {
		start := i
		var b strings.Builder
		for {
			l := lines[i]
			t := strings.TrimRight(l, " \t")
			cont := strings.HasSuffix(t, `\`) || strings.HasSuffix(t, "`")
			if cont {
				t = t[:len(t)-1]
			}
			b.WriteString(t)
			if !cont || i+1 >= len(lines) {
				break
			}
			b.WriteByte(' ')
			i++
		}
		if s := strings.TrimSpace(b.String()); s != "" && !strings.HasPrefix(s, "#") {
			out = append(out, logicalLine{start: start, text: s})
		}
	}
	return out
}
