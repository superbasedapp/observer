package seccustom

import (
	"fmt"
	"strings"
)

// PathElem is what the caller read (with Lstat, never following a link)
// about one element of an executable's path, from the file itself up to
// the root.
type PathElem struct {
	Path    string
	Exists  bool
	Symlink bool
	Dir     bool
	Regular bool
	// Perm is the permission bits (0o777); Sticky the sticky bit.
	Perm   uint32
	Sticky bool
}

// ExecCheck is the verdict on one executable path.
type ExecCheck struct {
	OK bool
	// Reason is one plain sentence when OK is false.
	Reason string
	// Note is set when a check could not be made on this OS (the Windows
	// ACL check is a D3 design item: mode bits mean nothing there).
	Note string
}

// execRule is one row of the executable check table, applied to each path
// element top-down (the file first, then each parent).
type execRule struct {
	// unix limits the row to hosts with POSIX mode bits.
	unix bool
	when func(e PathElem, isFile bool) bool
	says func(e PathElem) string
}

// execRules is the JSP-12 executable table: refused when any element of the
// path is a symlink, when the file is not a regular executable, when the
// file or a parent is writable by group or others, or when it sits under a
// shared sticky directory such as /tmp.
var execRules = []execRule{
	{false, func(e PathElem, _ bool) bool { return !e.Exists }, func(e PathElem) string { return e.Path + " does not exist" }},
	{false, func(e PathElem, _ bool) bool { return e.Symlink }, func(e PathElem) string { return e.Path + " is a symlink" }},
	{false, func(e PathElem, isFile bool) bool { return isFile && !e.Regular }, func(e PathElem) string { return e.Path + " is not a regular file" }},
	{true, func(e PathElem, isFile bool) bool { return isFile && e.Perm&0o111 == 0 }, func(e PathElem) string { return e.Path + " is not executable" }},
	{true, func(e PathElem, _ bool) bool { return e.Sticky }, func(e PathElem) string { return e.Path + " is a shared sticky directory" }},
	{true, func(e PathElem, _ bool) bool { return e.Perm&0o022 != 0 }, func(e PathElem) string { return e.Path + " is writable by group or others" }},
	{false, func(e PathElem, isFile bool) bool { return !isFile && !e.Dir }, func(e PathElem) string { return e.Path + " is not a directory" }},
}

// CheckExecutable walks the rule table over the path's elements (the file
// first). On Windows the mode-bit rows do not apply and the verdict carries
// a note: the ACL check that replaces them is a recorded D3 design item.
func CheckExecutable(goos string, elems []PathElem) ExecCheck {
	if len(elems) == 0 {
		return ExecCheck{Reason: "no path to check"}
	}
	windows := goos == "windows"
	for i, e := range elems {
		for _, r := range execRules {
			if r.unix && windows {
				continue
			}
			if r.when(e, i == 0) {
				return ExecCheck{Reason: fmt.Sprintf("the executable is refused: %s", r.says(e))}
			}
		}
	}
	out := ExecCheck{OK: true}
	if windows {
		out.Note = "Windows ACLs were not checked (mode bits do not apply; the ACL check is a design item)"
	}
	return out
}

// PinScope says how much of a driver its digests pin.
type PinScope string

// The PinScope values.
const (
	// PinFull: the executable (and its declared companions) is all that
	// runs.
	PinFull PinScope = "full"
	// PinPartial: the executable is a launcher (a "#!" script) and the
	// digests do not cover what it loads (a Python package tree).
	PinPartial PinScope = "partial"
)

// PinScopeFor is the pin label: partial for an interpreted template, and
// for any executable that starts with "#!".
func PinScopeFor(t *Template, shebang bool) PinScope {
	if shebang || (t != nil && t.Interpreted) {
		return PinPartial
	}
	return PinFull
}

// hasShebang reports whether b starts with "#!".
func hasShebang(b []byte) bool { return len(b) >= 2 && b[0] == '#' && b[1] == '!' }

// shebangWords splits a "#!" line into its whitespace-separated words, nil
// when head does not start with "#!".
func shebangWords(head []byte) []string {
	if len(head) < 2 || head[0] != '#' || head[1] != '!' {
		return nil
	}
	line := head[2:]
	for i, c := range line {
		if c == '\n' || c == '\r' {
			line = line[:i]
			break
		}
	}
	return strings.FieldsFunc(string(line), func(r rune) bool { return r == ' ' || r == '\t' })
}

// Shebang returns the interpreter path a "#!" line names (its first word),
// "" when head does not start with one or names a relative path.
func Shebang(head []byte) string {
	w := shebangWords(head)
	if len(w) == 0 || w[0][0] != '/' {
		return ""
	}
	return w[0]
}

// Interpreter is the verdict on a "#!" executable's interpreter.
type Interpreter struct {
	// Named is the interpreter the "#!" line names, Resolved the same path
	// with its symlinks resolved; both "" for an executable with no "#!".
	Named    string
	Resolved string
	// Applet is the program the interpreter runs as, compared the way the
	// env check compares it (lower case, ".exe" dropped): the interpreter's
	// own name, or for a multi-call launcher (busybox, toybox, coreutils)
	// called by its own name, the applet its first argument names ("" when
	// it names none).
	Applet string
	// Script is true when the interpreter itself starts with "#!": it
	// would run a second interpreter that no digest covers.
	Script bool
	// Reason is one plain sentence when the interpreter is refused.
	Reason string
}

// baseName is the last element of p, split on either separator (the "#!"
// path is POSIX, a resolved path may be Windows).
func baseName(p string) string {
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		return p[i+1:]
	}
	return p
}

// appletName is p's base name the way a program compares it on every host:
// lower case (a case-insensitive file system finds "ENV" as "env") with a
// trailing ".exe" dropped (env.exe on Windows).
func appletName(p string) string {
	return strings.TrimSuffix(strings.ToLower(baseName(p)), ".exe")
}

// multiCallLaunchers are the one-binary toolboxes that run the applet their
// argv[0] names, or, called by their own name, the applet their first
// argument names (a symlink /usr/bin/env -> /bin/busybox runs env).
var multiCallLaunchers = map[string]bool{"busybox": true, "toybox": true, "coreutils": true}

// isMultiCallLauncher reports whether name (an appletName) runs as a
// multi-call launcher under its own name. BusyBox runs as itself for any
// argv[0] that starts with "busybox" (the static downloads are named
// busybox-x86_64, busybox-w32 ships busybox64.exe), so for it the name is
// a prefix; toybox and coreutils are matched exactly.
func isMultiCallLauncher(name string) bool {
	return multiCallLaunchers[name] || strings.HasPrefix(name, "busybox")
}

// coreutilsProgFlags are GNU coreutils' own ways of naming the applet as an
// option instead of as the first argument.
var coreutilsProgFlags = []string{"--coreutils-prog-shebang=", "--coreutils-prog="}

// appletOf is the program an interpreter runs as. The kernel passes the
// "#!" path itself as argv[0], so a link named env to busybox runs env; a
// launcher named by its own name runs the applet its first argument names
// ("" when it names none, which the table refuses).
func appletOf(named string, args []string) string {
	a := appletName(named)
	if !isMultiCallLauncher(a) {
		return a
	}
	if len(args) == 0 {
		return ""
	}
	first := args[0]
	for _, f := range coreutilsProgFlags {
		if strings.HasPrefix(first, f) {
			first = first[len(f):]
			break
		}
	}
	return appletName(first)
}

// isEnv reports whether p names an env launcher, at any path (/usr/bin/env,
// /bin/env, /usr/local/bin/env, ENV, env.exe, a symlink to one, ...).
func isEnv(p string) bool { return p != "" && appletName(p) == "env" }

// runsEnv reports whether the interpreter ends up running env: by its named
// path, its resolved path, or the applet a multi-call launcher runs.
func runsEnv(in Interpreter) bool {
	return isEnv(in.Named) || isEnv(in.Resolved) || in.Applet == "env"
}

// isLauncherWithNoApplet reports a multi-call launcher, by its named or
// resolved path, that runs no applet anyone can name: called by its own
// name with no first argument it would treat the script's own path as the
// applet, which no digest or check covers.
func isLauncherWithNoApplet(in Interpreter) bool {
	if in.Named == "" || in.Applet != "" {
		return false
	}
	return isMultiCallLauncher(appletName(in.Named)) || isMultiCallLauncher(appletName(in.Resolved))
}

// interpreterRule is one row of the interpreter table, walked top-down;
// the first row that matches refuses.
type interpreterRule struct {
	when func(in Interpreter, companions []Companion) bool
	says string
}

// interpreterRules: a "#!" executable runs its interpreter, which the
// executable's digest does not cover, so the interpreter must be absolute,
// found without a PATH lookup, and one of the manifest's declared
// companions (whose digest the runner re-checks before every run).
var interpreterRules = []interpreterRule{
	{
		func(in Interpreter, _ []Companion) bool { return in.Named == "" },
		"the executable starts with \"#!\" but names no absolute interpreter",
	},
	{
		func(in Interpreter, _ []Companion) bool { return runsEnv(in) },
		"the executable finds its interpreter through env and a PATH lookup, which a driver never gets; pick a launcher that names its interpreter",
	},
	{
		func(in Interpreter, _ []Companion) bool { return isLauncherWithNoApplet(in) },
		"the executable's interpreter is a multi-call launcher (busybox, toybox or coreutils) that names no applet; name the real interpreter instead",
	},
	{
		func(in Interpreter, _ []Companion) bool { return in.Script },
		"the executable's interpreter is itself a \"#!\" script, so it would run a second interpreter that no digest covers; name the real interpreter instead",
	},
	{func(in Interpreter, cs []Companion) bool {
		for _, c := range cs {
			if c.Path == in.Resolved || c.Path == in.Named {
				return false
			}
		}
		return true
	}, "the executable's interpreter is not one of its declared, digest-pinned companions; declare it as a companion so its digest is checked before every run"},
}

// CheckInterpreter checks the interpreter of the executable whose first
// bytes are head. resolve returns a path with its symlinks resolved and
// readHead the first bytes of a file (the caller's I/O; a nil readHead
// reads nothing). An executable with no "#!" has nothing to check. An
// interpreter that is itself a "#!" script is refused, not followed: one
// level is all the digest pin covers.
func CheckInterpreter(head []byte, resolve func(string) string, readHead func(string) []byte, companions []Companion) Interpreter {
	if !hasShebang(head) {
		return Interpreter{}
	}
	in := Interpreter{Named: Shebang(head)}
	if in.Named != "" {
		in.Resolved = resolve(in.Named)
		in.Applet = appletOf(in.Named, shebangWords(head)[1:])
		if readHead != nil {
			in.Script = hasShebang(readHead(in.Resolved))
		}
	}
	for _, r := range interpreterRules {
		if r.when(in, companions) {
			in.Reason = r.says
			return in
		}
	}
	return in
}
