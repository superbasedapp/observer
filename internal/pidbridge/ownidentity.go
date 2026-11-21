package pidbridge

import (
	"path"
	"strings"
)

// interpreterSyntax is how one interpreter's command line names the program
// it runs: the flags that consume the next argument, the flags after which
// no script follows (inline code), the flag that names a module instead of
// a script, and the subcommands that precede the script. Table-driven so a
// new interpreter is one row (CLAUDE.md "Module Boundaries" rule 5).
type interpreterSyntax struct {
	valueFlags  map[string]bool
	stopFlags   map[string]bool
	moduleFlag  string
	subcommands map[string]bool
}

func set(xs ...string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}

var (
	nodeSyntax = interpreterSyntax{
		valueFlags: set("-r", "--require", "--import", "--loader", "--experimental-loader", "-C", "--conditions", "--title", "--env-file"),
		stopFlags:  set("-e", "--eval", "-p", "--print", "-i", "--interactive"),
	}
	pythonSyntax = interpreterSyntax{
		valueFlags: set("-W", "-X", "--check-hash-based-pycs"),
		stopFlags:  set("-c"),
		moduleFlag: "-m",
	}
	runnerSyntax = interpreterSyntax{
		valueFlags:  set("-r", "--require", "--preload", "--config", "-c", "--cwd", "--env-file", "--import-map", "-L", "--log-level"),
		stopFlags:   set("-e", "--eval", "-p", "--print"),
		subcommands: set("run"),
	}
	rubySyntax = interpreterSyntax{
		valueFlags: set("-r", "-I", "-C", "-E"),
		stopFlags:  set("-e"),
	}
)

// interpreters maps an interpreter's program basename to its syntax.
// Under one of these the identity is the program it runs (a script, a
// module or an npm package), not the interpreter.
var interpreters = map[string]interpreterSyntax{
	"node": nodeSyntax, "nodejs": nodeSyntax,
	"bun": runnerSyntax, "deno": runnerSyntax,
	"python": pythonSyntax, "python3": pythonSyntax, "pypy3": pythonSyntax,
	"ruby": rubySyntax,
}

func interpreterFor(name string) (interpreterSyntax, bool) {
	if s, ok := interpreters[name]; ok {
		return s, true
	}
	if strings.HasPrefix(name, "python3.") {
		return pythonSyntax, true
	}
	return interpreterSyntax{}, false
}

// processIdentity is what a process says it is, read from /proc: its comm
// (the kernel's 15-byte name, which a Node CLI's process.title sets), the
// target of its exe link and its argv.
type processIdentity struct {
	comm string
	exe  string
	argv []string
}

func baseName(s string) string { return path.Base(strings.ReplaceAll(s, "\\", "/")) }

func normName(s string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".exe")
}

// stripEnv drops a leading `env` and everything env consumes before the
// program it starts: its options (with -S / --split-string splitting its
// argument into words), its -u / -C operands and NAME=value assignments. A
// `#!/usr/bin/env -S node --flag` shebang arrives as
// [env, "-S node --flag", script].
func stripEnv(argv []string) []string {
	if len(argv) == 0 || normName(baseName(argv[0])) != "env" {
		return argv
	}
	rest := argv[1:]
	for len(rest) > 0 {
		a := rest[0]
		switch {
		case a == "--":
			return rest[1:]
		case a == "-S" || a == "--split-string":
			if len(rest) < 2 {
				return nil
			}
			return append(strings.Fields(rest[1]), rest[2:]...)
		case strings.HasPrefix(a, "-S"):
			return append(strings.Fields(strings.TrimPrefix(a, "-S")), rest[1:]...)
		case strings.HasPrefix(a, "--split-string="):
			return append(strings.Fields(strings.TrimPrefix(a, "--split-string=")), rest[1:]...)
		case a == "-u" || a == "--unset" || a == "-C" || a == "--chdir":
			if len(rest) < 2 {
				return nil
			}
			rest = rest[2:]
		case strings.HasPrefix(a, "-"):
			rest = rest[1:]
		case strings.Contains(a, "="):
			rest = rest[1:]
		default:
			return rest
		}
	}
	return nil
}

// programUnder returns the program an interpreter command line runs: the
// script path, or ("", module) for a module run, or ("", "") when the line
// runs inline code or nothing. Leading interpreter flags are skipped
// (`node --max-old-space-size=N cli.js`, the gemini-cli and qwen-code
// relaunch), flags that consume a value skip it too, and a subcommand such
// as `bun run` is stepped over.
func programUnder(syn interpreterSyntax, args []string) (script, module string) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			if i+1 < len(args) {
				return args[i+1], ""
			}
			return "", ""
		case syn.stopFlags[a]:
			return "", ""
		case syn.moduleFlag != "" && a == syn.moduleFlag:
			if i+1 < len(args) {
				return "", args[i+1]
			}
			return "", ""
		case syn.moduleFlag != "" && strings.HasPrefix(a, syn.moduleFlag) && len(a) > len(syn.moduleFlag):
			return "", strings.TrimPrefix(a, syn.moduleFlag)
		case syn.valueFlags[a]:
			i++
		case strings.HasPrefix(a, "-"):
			// A flag with no separate value (--flag or --flag=value).
		case syn.subcommands[a]:
		default:
			return a, ""
		}
	}
	return "", ""
}

// npmPackageName returns the npm package a script path lives in: the
// (scope-stripped) name right after the path's LAST node_modules segment,
// or "" when the path is not inside node_modules. A global install
// (.../lib/node_modules/@qwen-code/qwen-code/cli.js) names its package
// there, whatever the entry script is called; a folder the developer named
// after a tool is not node_modules and never counts.
func npmPackageName(script string) string {
	segs := strings.Split(strings.ReplaceAll(script, "\\", "/"), "/")
	last := -1
	for i, s := range segs {
		if s == "node_modules" {
			last = i
		}
	}
	if last < 0 || last+1 >= len(segs)-1 {
		return ""
	}
	pkg := segs[last+1]
	if strings.HasPrefix(pkg, "@") && last+2 < len(segs)-1 {
		pkg = segs[last+2]
	}
	return pkg
}

// executableNames returns the process's executable identities, lowercased,
// with ".exe" and (for a script) its extension stripped: the comm, the exe
// basename, argv[0]'s basename, and, when argv[0] (after an `env` prefix)
// is an interpreter, the program it runs: the script's basename, the npm
// package the script lives in, or the module of a `-m` run (its top-level
// name, with _ also read as -). Never a substring of an argument: a script
// whose PATH or arguments merely mention a tool is not that tool (sdk-1f L4).
func (p processIdentity) executableNames() []string {
	var out []string
	add := func(s string) {
		if s = normName(s); s != "" {
			out = append(out, s)
		}
	}
	add(p.comm)
	if p.exe != "" {
		add(baseName(strings.TrimSuffix(p.exe, " (deleted)")))
	}
	if len(p.argv) == 0 || p.argv[0] == "" {
		return out
	}
	add(baseName(p.argv[0]))
	argv := stripEnv(p.argv)
	if len(argv) == 0 {
		return out
	}
	prog := normName(baseName(argv[0]))
	add(prog)
	syn, ok := interpreterFor(prog)
	if !ok {
		return out
	}
	script, module := programUnder(syn, argv[1:])
	if script != "" {
		name := baseName(script)
		add(strings.TrimSuffix(name, path.Ext(name)))
		add(npmPackageName(script))
	}
	if module != "" {
		top := strings.SplitN(module, ".", 2)[0]
		add(top)
		add(strings.ReplaceAll(top, "_", "-"))
	}
	return out
}

// isOwnProcess reports whether the process is one of names (case
// insensitive, ".exe" ignored): an exact match of an executable identity,
// never a substring.
func (p processIdentity) isOwnProcess(names []string) bool {
	if len(names) == 0 {
		return false
	}
	want := map[string]bool{}
	for _, n := range names {
		if n = normName(n); n != "" {
			want[n] = true
		}
	}
	for _, id := range p.executableNames() {
		if want[id] {
			return true
		}
	}
	return false
}
