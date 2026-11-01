# You're set

You've got SuperBased wired into VS Code end-to-end:

- ✅ Binary verified via `SuperBased: Doctor`
- ✅ Daemon mode chosen
- ✅ Dashboard accessible inside the editor
- ✅ Proxy env vars routable to your AI CLIs
- ✅ Instruction files updatable from learnings with one click

### Where to go next

- **Full user guide** — `docs/vscode-extension-user-guide.md` in
  the [repository](https://github.com/superbasedapp/observer)
  walks through daily workflows for each AI tool (Claude Code,
  Cursor, Codex, Cline, Copilot).
- **Reference docs** — `docs/vscode-extension.md` has the command
  table, settings table, and the binary-resolution precedence.
- **Dashboard Help drawer** — every chart and column has a
  one-liner; click the `?` in the dashboard's top bar.
- **Issues** — file at
  [github.com/superbasedapp/observer/issues](https://github.com/superbasedapp/observer/issues).

### Common follow-ups

- `SuperBased: Refresh All Trees` — force-refresh the four sidebar
  views (Today / Sessions / Discovery / Costs) without waiting for
  the next poll.
- `SuperBased: Stop Daemon` — only available in `managed`/`auto`
  modes; SIGTERMs the extension-managed daemon with a 5 s grace
  before SIGKILL.

### Local-first

Your session content stays on your machine unless you consent to
sending it. Today the extension itself makes no outbound network calls
except a first-install binary download from GitHub Releases when no
`observer` is found locally.
