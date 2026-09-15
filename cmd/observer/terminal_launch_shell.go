package main

import (
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// terminal_launch_shell.go resolves the argv of a PLAIN SHELL terminal session
// (termsession.SpecShell). It is deliberately platform-NEUTRAL — the OS is a
// parameter, and PATH lookup / env / stat are injected — so the whole ladder is
// a data table with one test case per row, exercisable from any host.
//
// The Windows ladder exists because the POSIX one is meaningless there: the old
// code fell through to "/bin/sh", which CreateProcess resolves as C:\bin\sh
// (ERROR_FILE_NOT_FOUND) on any daemon whose $SHELL is unset — i.e. every
// daemon not started from Git Bash, whose MSYS layer rewrites $SHELL to a real
// Windows bash.exe path (DI-08).

// shellRule is ONE row of an ordered shell-resolution ladder, walked top-down;
// the first row that resolves wins. Exactly one source field is set per row:
//
//	env      — an environment variable naming the program. When requireLookPath
//	           is set the value is honoured only if it resolves to a real
//	           program (Windows: a POSIX $SHELL like /bin/bash must NOT win);
//	           otherwise it is taken verbatim (the historical POSIX behaviour).
//	name     — a program name resolved through PATH (and %PATHEXT% on Windows).
//	path     — an absolute path, accepted when stat() says it exists.
//	fallback — an unconditional last resort. When rootEnv is set and non-empty
//	           in the environment, the path is rebuilt as <root>\<rootRel>
//	           instead (so a non-C: Windows install is still correct).
//
// args are fixed arguments appended after the resolved program.
type shellRule struct {
	env             string
	requireLookPath bool
	name            string
	path            string
	fallback        string
	rootEnv         string
	rootRel         string
	args            []string
}

// windowsShellLadder is the Windows shell ladder. The ordering mirrors what
// editors do on Windows (VS Code / Windows Terminal default to PowerShell, and
// prefer PowerShell 7+ when installed), with cmd.exe as the always-present
// floor. %COMSPEC% is used as an ABSOLUTE path and a bare "cmd" is never
// resolved, so a `cmd.cmd` earlier on PATH cannot shadow the shell (DI-15).
var windowsShellLadder = []shellRule{
	{env: "SHELL", requireLookPath: true},
	{name: "pwsh.exe", args: []string{"-NoLogo"}},
	{name: "powershell.exe", args: []string{"-NoLogo"}},
	{env: "COMSPEC", requireLookPath: true},
	{name: "cmd.exe"},
	{fallback: `C:\Windows\System32\cmd.exe`, rootEnv: "SystemRoot", rootRel: `System32\cmd.exe`},
}

// posixShellLadder is the historical POSIX ladder, unchanged: the daemon's own
// $SHELL verbatim (never client-supplied), then /bin/bash, then /bin/sh.
var posixShellLadder = []shellRule{
	{env: "SHELL"},
	{path: "/bin/bash"},
	{fallback: "/bin/sh"},
}

// resolveShellArgv builds the server-derived argv for a SpecShell session on
// THIS host. argv[0] is a program the spawner resolves via PATH like every
// other termsession spawn; nothing here comes from a client.
func resolveShellArgv() []string {
	return resolveShellArgvFor(runtime.GOOS, exec.LookPath, os.Getenv, os.Stat)
}

// resolveShellArgvFor is the injectable form: the OS is a parameter and PATH
// lookup / environment / stat are supplied, so every row of both ladders is
// unit-testable from any host. It always returns a non-empty argv — the last
// row of each ladder is unconditional.
func resolveShellArgvFor(
	goos string,
	lookPath func(string) (string, error),
	getenv func(string) string,
	stat func(string) (os.FileInfo, error),
) []string {
	ladder := posixShellLadder
	if goos == "windows" {
		ladder = windowsShellLadder
	}
	for _, r := range ladder {
		if argv, ok := r.resolve(lookPath, getenv, stat); ok {
			return argv
		}
	}
	// Unreachable while each ladder ends in a fallback row; kept as an honest
	// floor rather than a panic in library code.
	return []string{"/bin/sh"}
}

// resolve applies one ladder row, returning its argv and whether it matched.
func (r shellRule) resolve(
	lookPath func(string) (string, error),
	getenv func(string) string,
	stat func(string) (os.FileInfo, error),
) ([]string, bool) {
	switch {
	case r.env != "":
		v := getenv(r.env)
		if v == "" {
			return nil, false
		}
		if !r.requireLookPath {
			return r.argv(v), true
		}
		p, err := lookPath(v)
		if err != nil {
			return nil, false
		}
		return r.argv(p), true
	case r.name != "":
		p, err := lookPath(r.name)
		if err != nil {
			return nil, false
		}
		return r.argv(p), true
	case r.path != "":
		if _, err := stat(r.path); err != nil {
			return nil, false
		}
		return r.argv(r.path), true
	case r.fallback != "":
		p := r.fallback
		if r.rootEnv != "" && r.rootRel != "" {
			if root := strings.TrimRight(getenv(r.rootEnv), `\/`); root != "" {
				p = root + `\` + r.rootRel
			}
		}
		return r.argv(p), true
	}
	return nil, false
}

// argv assembles [program] + the row's fixed arguments as a fresh slice.
func (r shellRule) argv(program string) []string {
	out := make([]string, 0, 1+len(r.args))
	out = append(out, program)
	return append(out, r.args...)
}
