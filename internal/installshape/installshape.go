package installshape

import (
	"path"
	"regexp"
	"strings"
)

// Channel is how the running binary was installed, as far as its path
// shows. It is a reporting value (`GET /api/components` names it) as well as
// the key of the registration table.
type Channel string

const (
	// ChannelNPM is a binary inside node_modules/@superbased/observer-<platform>.
	ChannelNPM Channel = "npm"
	// ChannelPip is a binary inside <site-packages>/observer/_bin.
	ChannelPip Channel = "pip"
	// ChannelOther is every other install (an install.sh or edition archive,
	// a VS Code bundled binary, a local build): its real path is stable.
	ChannelOther Channel = "other"
)

// Input is what Decide needs. Everything that touches the file system is in
// Resolve, injected by the caller.
type Input struct {
	// GOOS is the operating system the registration is for.
	GOOS string
	// Binary is the running binary's absolute path with symlinks resolved.
	Binary string
	// PathCandidates are the `observer` launchers found on PATH, in PATH
	// order, as PATH names them (not resolved).
	PathCandidates []string
	// Resolve returns the path a candidate resolves to (symlinks followed,
	// absolute) and whether it exists as a regular file. nil means nothing
	// exists, so every install keeps its real path.
	Resolve func(p string) (resolved string, ok bool)
}

// Decision is the registered command and why.
type Decision struct {
	// Channel is the install shape the binary path shows.
	Channel Channel
	// Command is what a hook or MCP entry invokes.
	Command string
	// Rule names the table row that decided.
	Rule string
	// Reason is one operator-readable sentence.
	Reason string
}

// shape is a matched install shape: the launcher target a qualifying PATH
// candidate must resolve to, and the launcher paths to try when none on PATH
// does (each must also resolve to target).
type shape struct {
	channel   Channel
	target    string
	fallbacks []string
}

// rule is one row of the registration table, walked top-down: the first row
// whose match returns true decides. Rows that keep the real path return a
// shape with an empty target.
type rule struct {
	name   string
	reason string
	match  func(goos, bin string) (shape, bool)
}

// rules is THE install shape -> registered command table.
var rules = []rule{
	{
		name:   "npm-windows",
		reason: "npm on Windows: the launcher is a .cmd script, which an MCP client cannot spawn without a shell, so the real path stays",
		match: func(goos, bin string) (shape, bool) {
			if goos != "windows" {
				return shape{}, false
			}
			if _, ok := npmShim(bin); ok {
				return shape{channel: ChannelNPM}, true
			}
			return shape{}, false
		},
	},
	{
		name:   "npm",
		reason: "npm install: the npm bin launcher survives `npm install -g` upgrades, the package tree does not",
		match: func(_ string, bin string) (shape, bool) {
			s, ok := npmShim(bin)
			return s, ok
		},
	},
	{
		name:   "pip",
		reason: "pip install: the console script survives upgrades, the bundled _bin path is replaced by them",
		match:  pipScript,
	},
	{
		name:   "other",
		reason: "not inside a package manager's tree: the real path is stable",
		match: func(string, string) (shape, bool) {
			return shape{channel: ChannelOther}, true
		},
	},
}

// Decide returns the command a hook or MCP entry should invoke for in.Binary.
func Decide(in Input) Decision {
	bin := slash(in.Binary)
	for _, r := range rules {
		s, ok := r.match(in.GOOS, bin)
		if !ok {
			continue
		}
		d := Decision{Channel: s.channel, Command: in.Binary, Rule: r.name, Reason: r.reason}
		if s.target == "" {
			return d
		}
		if c, ok := pickLauncher(in, s); ok {
			d.Command = c
			return d
		}
		d.Rule = r.name + "-no-launcher"
		d.Reason = "no " + string(s.channel) + " launcher resolving to this install was found, so the real path stays"
		return d
	}
	return Decision{Channel: ChannelOther, Command: in.Binary, Rule: "other"}
}

// pickLauncher returns the first PATH candidate, then the first fallback,
// that resolves to s.target.
func pickLauncher(in Input, s shape) (string, bool) {
	if in.Resolve == nil {
		return "", false
	}
	want := comparable(in.GOOS, s.target)
	for _, c := range in.PathCandidates {
		if r, ok := in.Resolve(c); ok && comparable(in.GOOS, r) == want {
			return c, true
		}
	}
	for _, f := range s.fallbacks {
		native := f
		if in.GOOS == "windows" {
			native = strings.ReplaceAll(f, "/", `\`)
		}
		if r, ok := in.Resolve(native); ok && comparable(in.GOOS, r) == want {
			return native, true
		}
	}
	return "", false
}

// npmPlatformSeg matches the platform package segment of an npm install.
var npmPlatformSeg = regexp.MustCompile(`/node_modules/@superbased/observer-[a-z0-9]+-[a-z0-9]+/bin/observer(\.exe)?$`)

// npmShim matches a binary inside an npm platform package and returns the
// @superbased/observer shim it belongs to (target) plus the bin launchers
// npm writes for it (fallbacks). Both the hoisted layout
// (<nm>/@superbased/observer-<p>/bin/observer) and the nested one
// (<nm>/@superbased/observer/node_modules/@superbased/observer-<p>/...) map
// to <nm>/@superbased/observer/bin/observer.js.
func npmShim(bin string) (shape, bool) {
	loc := npmPlatformSeg.FindStringIndex(bin)
	if loc == nil {
		return shape{}, false
	}
	nm := bin[:loc[0]] + "/node_modules" // the node_modules holding the platform package
	const nested = "/node_modules/@superbased/observer/node_modules"
	if strings.HasSuffix(nm, nested) {
		nm = strings.TrimSuffix(nm, "/@superbased/observer/node_modules")
	}
	s := shape{channel: ChannelNPM, target: nm + "/@superbased/observer/bin/observer.js"}
	if prefix, ok := strings.CutSuffix(nm, "/lib/node_modules"); ok {
		s.fallbacks = append(s.fallbacks, prefix+"/bin/observer") // npm -g on POSIX
	}
	s.fallbacks = append(s.fallbacks, nm+"/.bin/observer") // a local install
	return s, true
}

// pipBinSeg matches the bundled binary of the superbased-observer wheel.
var pipBinSeg = regexp.MustCompile(`(?i)/lib/(python[0-9.]+/)?(site|dist)-packages/observer/_bin/observer(\.exe)?$`)

// pipScript matches a binary inside a wheel install and returns its console
// script: <base>/bin/observer, or <base>/Scripts/observer.exe on Windows.
func pipScript(goos, bin string) (shape, bool) {
	loc := pipBinSeg.FindStringIndex(bin)
	if loc == nil {
		return shape{}, false
	}
	base := bin[:loc[0]]
	script := base + "/bin/observer"
	if goos == "windows" {
		script = base + "/Scripts/observer.exe"
	}
	return shape{channel: ChannelPip, target: script, fallbacks: []string{script}}, true
}

// slash normalizes a path to forward slashes.
func slash(p string) string { return strings.ReplaceAll(p, `\`, "/") }

// comparable normalizes a path for equality: forward slashes, cleaned, and
// case-folded on Windows.
func comparable(goos, p string) string {
	c := path.Clean(slash(p))
	if goos == "windows" {
		c = strings.ToLower(c)
	}
	return c
}

// Rules returns the table's row names in order, for the table test and the
// docs.
func Rules() []string {
	out := make([]string, 0, len(rules))
	for _, r := range rules {
		out = append(out, r.name)
	}
	return out
}

// PathNameLiveCheck names the live check the bare command form waits on
// (surface-gap DEC-12): a GUI-launched host on a managed Mac (VS Code, Claude
// Desktop started from the Dock) must still resolve the bare name on its own
// PATH. Until it passes, callers apply PathName only on an explicit opt-in.
const PathNameLiveCheck = "the FU-24 GUI-host PATH check (a GUI-launched VS Code or Claude Desktop on a managed Mac resolves the bare observer)"

// PathName returns d with the bare command name "observer" when the name a
// shell would run (the first PATH candidate that exists) resolves to the
// same file d.Command does, and reports whether it did (surface-gap FU-24).
// An org-managed fleet uses it for the MCP entry, so one managed allowlist
// entry (Claude Code allowedMcpServers serverCommand ["observer", "serve"])
// matches every node whatever its install path. Windows keeps the path: a
// child process there is not always started through a PATH search that
// adds .exe, and nothing on that side is live-verified.
func PathName(in Input, d Decision) (Decision, bool) {
	if in.GOOS == "windows" || in.Resolve == nil {
		return d, false
	}
	target, ok := in.Resolve(d.Command)
	if !ok {
		return d, false
	}
	for _, c := range in.PathCandidates {
		r, ok := in.Resolve(c)
		if !ok {
			continue
		}
		if comparable(in.GOOS, r) != comparable(in.GOOS, target) {
			return d, false
		}
		d.Command = "observer"
		d.Rule += "+path-name"
		d.Reason = "org-managed node: the bare observer on PATH runs this install, so every node registers the same command"
		return d, true
	}
	return d, false
}
