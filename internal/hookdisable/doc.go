// Package hookdisable detects the vendor-side switches that silence every
// hook a vendor runs, Observer's included (hook-parity T-046).
//
// A single `"disableAllHooks": true` in ~/.claude/settings.json silences
// Observer on Claude Code AND on every host that replays Claude Code's hook
// settings (cursor-agent, Grok Build, Copilot CLI, VS Code Copilot, Devin
// CLI, DeepSeek Harness). Nothing in Observer's own files changes, so
// neither the hook integrity check nor the registrar notices. This package
// is the one table of such switches; `observer doctor` reports a finding
// and the daemon persists a guard event (which reaches the org on the
// normal guard_events push) when a switch turns on.
//
// The table covers three scopes: the developer's home (user), the
// administrator's system file (managed), and project directories (T-910:
// <project>/.claude/settings.local.json and its siblings, which an agent
// can write and a cloned repository can ship). Project rows are read for
// the projects Observer knows about, at most MaxProjectRoots of them per
// scan. The guard's R-162 rule reads the same table to refuse an agent
// write that turns a switch on.
//
// Since the 2026-10-25 surface-gap pass the table also has env-scope rows
// (a variable that drops the vendor's config files, Options.Getenv),
// list-membership rows (Observer's plugin named in a disabled list) and a
// deny-list row (DimCode's hooks-disabled.json, read for the hashes of
// Observer's own entries only). Managed-scope rows name an agentconfig
// FileRow; the caller resolves it (internal/diag.HookSwitchInputs), so the
// path has one owner. A settings file is decoded only for the one top-level
// member a row names, so provider keys beside it are never parsed.
//
// Pure: the file read, the environment, the managed paths and the
// own-command recogniser are injected, so the package touches no
// filesystem, database or network itself (pinned by TestImportsArePure).
package hookdisable
