package main

import (
	"errors"
	"io/fs"
	"os"
	"strings"
	"testing"
)

// --- injected I/O for the shell-ladder table -------------------------------

// mapGetenv reads from a fixed map (a nil map is an empty environment).
func mapGetenv(env map[string]string) func(string) string {
	return func(k string) string { return env[k] }
}

// lookPathIn resolves only the named programs, mapping each to an absolute
// path the way a real PATH hit would.
func lookPathIn(found map[string]string) func(string) (string, error) {
	return func(name string) (string, error) {
		if p, ok := found[name]; ok {
			return p, nil
		}
		return "", errors.New("executable file not found in %PATH%")
	}
}

// failLookPath resolves nothing.
func failLookPath(string) (string, error) {
	return "", errors.New("executable file not found in %PATH%")
}

// missingStat reports every path as absent.
func missingStat(string) (os.FileInfo, error) { return nil, fs.ErrNotExist }

// statOnly reports exactly the named paths as present.
func statOnly(present ...string) func(string) (os.FileInfo, error) {
	set := make(map[string]bool, len(present))
	for _, p := range present {
		set[p] = true
	}
	return func(p string) (os.FileInfo, error) {
		if set[p] {
			return fakeFileInfo{}, nil
		}
		return nil, fs.ErrNotExist
	}
}

type fakeFileInfo struct{ os.FileInfo }

// --- the table -------------------------------------------------------------

// TestResolveShellArgvFor walks BOTH per-OS shell ladders row by row. The
// Windows rows are the DI-08 fix: the old resolver fell through to "/bin/sh",
// which CreateProcess resolves as C:\bin\sh and fails, on any daemon whose
// $SHELL is unset — i.e. every daemon not started from Git Bash.
func TestResolveShellArgvFor(t *testing.T) {
	tests := []struct {
		name    string
		goos    string
		env     map[string]string
		found   map[string]string
		present []string
		want    []string
	}{
		{
			name:  "windows: pwsh wins when installed",
			goos:  "windows",
			env:   map[string]string{"COMSPEC": `C:\Windows\System32\cmd.exe`},
			found: map[string]string{"pwsh.exe": `C:\Program Files\PowerShell\7\pwsh.exe`, "powershell.exe": `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`},
			want:  []string{`C:\Program Files\PowerShell\7\pwsh.exe`, "-NoLogo"},
		},
		{
			name:  "windows: falls back to Windows PowerShell",
			goos:  "windows",
			env:   map[string]string{"COMSPEC": `C:\Windows\System32\cmd.exe`},
			found: map[string]string{"powershell.exe": `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`},
			want:  []string{`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, "-NoLogo"},
		},
		{
			name:  "windows: a real $SHELL (MSYS-rewritten bash) beats PowerShell",
			goos:  "windows",
			env:   map[string]string{"SHELL": `C:\Program Files\Git\bin\bash.exe`},
			found: map[string]string{`C:\Program Files\Git\bin\bash.exe`: `C:\Program Files\Git\bin\bash.exe`, "pwsh.exe": `C:\pwsh.exe`},
			want:  []string{`C:\Program Files\Git\bin\bash.exe`},
		},
		{
			name:  "windows: a POSIX $SHELL that resolves to nothing is ignored",
			goos:  "windows",
			env:   map[string]string{"SHELL": "/bin/bash", "COMSPEC": `C:\Windows\System32\cmd.exe`},
			found: map[string]string{"powershell.exe": `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`},
			want:  []string{`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, "-NoLogo"},
		},
		{
			name:  "windows: absolute %COMSPEC% when no PowerShell exists",
			goos:  "windows",
			env:   map[string]string{"COMSPEC": `D:\Windows\System32\cmd.exe`},
			found: map[string]string{`D:\Windows\System32\cmd.exe`: `D:\Windows\System32\cmd.exe`},
			want:  []string{`D:\Windows\System32\cmd.exe`},
		},
		{
			name:  "windows: cmd.exe on PATH when %COMSPEC% is unset",
			goos:  "windows",
			found: map[string]string{"cmd.exe": `C:\Windows\System32\cmd.exe`},
			want:  []string{`C:\Windows\System32\cmd.exe`},
		},
		{
			name: "windows: last resort is built from %SystemRoot%",
			goos: "windows",
			env:  map[string]string{"SystemRoot": `D:\Windows`},
			want: []string{`D:\Windows\System32\cmd.exe`},
		},
		{
			name: "windows: last resort literal when %SystemRoot% is unset",
			goos: "windows",
			want: []string{`C:\Windows\System32\cmd.exe`},
		},
		{
			name: "unix: $SHELL verbatim, never PATH-verified",
			goos: "linux",
			env:  map[string]string{"SHELL": "/usr/bin/fish"},
			want: []string{"/usr/bin/fish"},
		},
		{
			name:    "unix: /bin/bash when $SHELL is unset",
			goos:    "linux",
			present: []string{"/bin/bash"},
			want:    []string{"/bin/bash"},
		},
		{
			name: "unix: /bin/sh floor",
			goos: "darwin",
			want: []string{"/bin/sh"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := resolveShellArgvFor(tc.goos, lookPathIn(tc.found), mapGetenv(tc.env), statOnly(tc.present...))
			if !equalArgs(got, tc.want) {
				t.Fatalf("resolveShellArgvFor(%s) = %v, want %v", tc.goos, got, tc.want)
			}
		})
	}
}

// TestResolveShellArgvNeverEmpty pins the floor: whatever the host looks like,
// a plain-shell launch always gets a program (an empty argv would reach the
// spawner as ErrInvalidSpec and read as a mystery 500).
func TestResolveShellArgvNeverEmpty(t *testing.T) {
	for _, goos := range []string{"windows", "linux", "darwin", "plan9"} {
		got := resolveShellArgvFor(goos, failLookPath, mapGetenv(nil), missingStat)
		if len(got) == 0 || got[0] == "" {
			t.Fatalf("resolveShellArgvFor(%s) = %v, want a non-empty program", goos, got)
		}
	}
	if got := resolveShellArgv(); len(got) == 0 || got[0] == "" {
		t.Fatalf("resolveShellArgv() = %v on this host, want a non-empty program", got)
	}
}

// TestDedupEnvWindows pins the Windows environment-block hardening: keys are
// case-insensitive there, so `Path=` from os.Environ() and `PATH=` from a
// caller's ExtraEnv must collapse to the LAST one (making launchChildEnv's
// documented last-wins layering true), the per-drive `=C:=…` entries must keep
// their own keys, and a block with no SYSTEMROOT gets one.
func TestDedupEnvWindows(t *testing.T) {
	tests := []struct {
		name   string
		env    []string
		getenv map[string]string
		want   []string
	}{
		{
			name:   "case-insensitive duplicate keeps the last value at its own position",
			env:    []string{"Path=C:\\a", "HOME=C:\\u", "PATH=C:\\b"},
			getenv: map[string]string{"SYSTEMROOT": `C:\Windows`},
			want:   []string{"HOME=C:\\u", "PATH=C:\\b", `SYSTEMROOT=C:\Windows`},
		},
		{
			name:   "per-drive entries dedup per drive, not against each other",
			env:    []string{"=C:=C:\\one", "=D:=D:\\two", "=C:=C:\\three", "SystemRoot=C:\\Windows"},
			getenv: map[string]string{"SYSTEMROOT": `C:\Windows`},
			want:   []string{"=D:=D:\\two", "=C:=C:\\three", "SystemRoot=C:\\Windows"},
		},
		{
			name:   "SYSTEMROOT backstop added when absent",
			env:    []string{"PATH=C:\\a"},
			getenv: map[string]string{"SYSTEMROOT": `D:\Windows`},
			want:   []string{"PATH=C:\\a", `SYSTEMROOT=D:\Windows`},
		},
		{
			name:   "existing SystemRoot is respected whatever its case",
			env:    []string{"systemroot=E:\\Win", "PATH=C:\\a"},
			getenv: map[string]string{"SYSTEMROOT": `D:\Windows`},
			want:   []string{"systemroot=E:\\Win", "PATH=C:\\a"},
		},
		{
			name:   "no backstop invented when the daemon has none",
			env:    []string{"PATH=C:\\a"},
			getenv: nil,
			want:   []string{"PATH=C:\\a"},
		},
		{
			name:   "entries with no '=' survive, NUL-bearing entries are dropped",
			env:    []string{"BARE", "OK=1", "BAD=x\x00y"},
			getenv: nil,
			want:   []string{"BARE", "OK=1"},
		},
		{
			name:   "empty input stays empty apart from the backstop",
			env:    nil,
			getenv: map[string]string{"SYSTEMROOT": `C:\Windows`},
			want:   []string{`SYSTEMROOT=C:\Windows`},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := dedupEnvWindowsFor(tc.env, mapGetenv(tc.getenv))
			if !equalArgs(got, tc.want) {
				t.Fatalf("dedupEnvWindowsFor(%q) = %q, want %q", tc.env, got, tc.want)
			}
		})
	}
}

// TestDedupEnvWindowsIsIdempotent pins that a second pass changes nothing —
// the helper is applied at two call sites (launchChildEnv, setupChildEnv) and
// a nested layering must not shuffle a block that is already clean.
func TestDedupEnvWindowsIsIdempotent(t *testing.T) {
	getenv := mapGetenv(map[string]string{"SYSTEMROOT": `C:\Windows`})
	once := dedupEnvWindowsFor([]string{"Path=C:\\a", "PATH=C:\\b", "TERM=xterm"}, getenv)
	twice := dedupEnvWindowsFor(once, getenv)
	if !equalArgs(once, twice) {
		t.Fatalf("second pass changed the block: %q → %q", once, twice)
	}
}

// TestLaunchChildEnvKeepsOneKeyPerNameOnWindows pins the hardening AT THE CALL
// SITE on a Windows host: whatever the daemon's own environment looks like, the
// block a terminal child receives must never carry two entries whose keys
// differ only by case.
func TestLaunchChildEnvKeepsOneKeyPerNameOnWindows(t *testing.T) {
	if os.Getenv("OS") == "" && os.PathSeparator != '\\' {
		t.Skip("call-site dedup is Windows-only by design")
	}
	env := setupChildEnv()
	seen := map[string]string{}
	for _, kv := range env {
		i := strings.IndexByte(kv, '=')
		if i <= 0 {
			continue
		}
		k := strings.ToLower(kv[:i])
		if prev, dup := seen[k]; dup {
			t.Fatalf("duplicate key %q in the child env: %q and %q", k, prev, kv)
		}
		seen[k] = kv
	}
}
