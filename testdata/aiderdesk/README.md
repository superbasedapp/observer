# testdata/aiderdesk: fixture placeholder

This directory holds no fixtures yet. `internal/adapter/aiderdesk` is an
UNREGISTERED skeleton (surface-gap FU-147, lane w8-writers): its parser
refuses to guess, and its test inputs are SYNTHETIC.

The layout comes from a static read of the `@aiderdesk/aiderdesk` 0.89.0
npm bundle (`out/runner.js`, 2026-10-28) and the AiderDesk docs; nothing
was observed on a live install. See `internal/adapter/aiderdesk/doc.go`.

## What the LCR-60 run should capture

AiderDesk 0.88+ on Windows, one aider-mode task and one agent-mode task in
a scratch project (one tool call each), then:

1. List names only (never open a value): `%APPDATA%\aider-desk`,
   `%USERPROFILE%\.aider-desk`, `<project>\.aider-desk` and
   `<project>\.aider-desk\tasks\<task id>\`.
2. Copy `<project>\.aider-desk\tasks\<task id>\context.json` for both
   tasks, as `context-aider-mode.json` and `context-agent-mode.json` here,
   after anonymizing: replace every prompt, response and tool output text
   with a same-length placeholder, the project path with `C:\w\proj`, and
   any token or key-shaped string with `REDACTED`. Keep every field name,
   the `usageReport` numbers and the `timestamp` values.
3. Whether `<project>\.aider.chat.history.md` was written by the aider-mode
   task (the aider adapter would then capture it too: say which to keep).
4. With an OpenAI-compatible provider whose base URL is the Observer proxy,
   send one message: did an `api_turns` row land, and which settings file
   changed (name only).

## Never copy

The app's own settings store under `%APPDATA%\aider-desk` (provider API
keys), `mcp-oauth.json`, `aider-desk.db`, `memory.db`, a task's
`settings.json`.
