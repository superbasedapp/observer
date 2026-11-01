// Package winshim renders a copyable shell command in the form that runs on
// the host's own shell.
//
// On Windows, npm installs `npm`, `npx` (and every global package's bin) as
// three sibling shims: a `.cmd` batch file, a `.ps1` PowerShell script and an
// extensionless POSIX script. PowerShell resolves a bare `npx` to `npx.ps1`
// first, and Windows PowerShell's default execution policy refuses to run it
// ("running scripts is disabled on this system"). The `.cmd` form runs in both
// PowerShell and Command Prompt under any policy, so a command Observer prints
// for a Windows operator to type names it.
//
// StdioLaunch applies the same shim table to a stdio MCP server entry that
// an AI client starts itself. There the right Windows form depends on how
// that client spawns a process, which the caller passes in as a Launch value
// read off the client's registry row (internal/integration), not on the
// shell a person types into.
//
// The package is pure (strings only): callers pass the target GOOS in, so a
// test can exercise the Windows form on Linux. It branches on the operating
// system, the command's first word and a Launch value, never on an AI tool.
package winshim
