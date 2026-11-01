// Package winshell answers one question without doing any I/O of its own:
// does a shell executable a Windows host spawns BY NAME resolve on the
// Windows PATH this process can see?
//
// It exists for hosts whose Windows hook runner is `Command::new("sh")`
// (VT Code, integration.HookSpec.WindowsHookShell): Git for Windows puts
// only `Git\cmd` on PATH by default, which has no sh.exe, so such a host
// launched outside Git Bash cannot spawn any hook and silently fails open.
//
// The PATH value and the file-exists probe are injected, so the package is
// pure (CLAUDE.md Module Boundaries #1; imports_test.go pins it). The answer
// is three-valued: Found, NotFound, and Unknown when no Windows PATH entry is
// visible at all (a WSL daemon with interop appendWindowsPath=false, or a
// service environment) — Unknown never warns, so there is no false alarm.
//
// The PATH examined is this process's view, not the one the host inherits
// at its own launch (a Git Bash terminal adds Git\bin itself), which is why
// callers only ever WARN on NotFound and never block.
package winshell
