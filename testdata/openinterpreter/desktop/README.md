# Open Interpreter **Desktop** fixture

Captured 2026-09-03 from a live Windows 11 install of the **Interpreter
desktop app** (Electron, `C:\Program Files\Interpreter\Interpreter.exe`,
`cli_version` `0.0.10`). Distinct from `../sessions/`, which holds the
2026-07-29 **CLI** capture from `~/.openinterpreter/` on WSL.

**Headline finding**: the desktop app runs the same Rust binary the CLI
does, but against its **own embedded Codex home** —
`%APPDATA%\interpreter\codex-home\` — not `~/.openinterpreter`. The
grounding box had no `~/.openinterpreter` at all, so before the roots
widening the adapter captured nothing from the desktop app (0
`open-interpreter` rows in the live DB) despite four completed
sessions on disk.

The directory layout under this fixture deliberately mirrors the live
one from `codex-home` down, so a test can point the adapter's explicit
`watchRoot` at the day directory and exercise the real path shape.

## Contents

| File | Source | Notes |
|---|---|---|
| `codex-home/sessions/2026/09/03/rollout-2026-09-03T16-57-59-01a0aaaa-bbbb-7ccc-8ddd-eeeeeeeeeeee.jsonl` | `%APPDATA%\interpreter\codex-home\sessions\2026\09\03\` | The only one of the four live rollouts that carries billable tokens. 89 lines. **Anonymized** — see below. |

## What the fixture exercises

- `session_meta` `{"originator":"codex_ui","cli_version":"0.0.10","source":"vscode","model_provider":"openrouter"}`
  — the desktop discriminator. `source:"vscode"` is an
  inherited-codebase leftover (the app is a standalone Electron
  desktop app), which is why the adapter's surface vocabulary is
  originator-first: this session stamps `desktop` / `open-interpreter`.
- **No `model` in `session_meta`** — only `model_provider`. The model
  (`nvidia/nemotron-3-super-120b-a12b:free`) comes from
  `turn_context.model`.
- `base_instructions` is an **object** (`{"text": …}`), not a bare
  string as in the older CLI capture. The parser ignores the field.
- **28 `token_count` lines → 14 distinct `last_token_usage` tuples.**
  Codex re-emits each one; the shared parser's total-based dedup
  collapses them. Netting: `input − cached_input`, `output −
  reasoning_output`.
- 13 `response_item/function_call` rows of which 11 pair with an
  `event_msg/exec_command_end`; the other two are malformed-argument
  failures that produce a `function_call_output` carrying a parse
  error and no exec end. Parsed as 11 + 2 action rows.

## Anonymization

Derived from the live file by `scratchpad/anon.py` at capture time.
Everything else is byte-for-byte the vendor's own output.

| Replaced | With |
|---|---|
| the operator's Windows username and the two throwaway workspace path segments | `dev`, `work`, `demo` — so `cwd` reads `C:\Users\dev\work\demo` |
| the real session uuid | `01a0aaaa-bbbb-7ccc-8ddd-eeeeeeeeeeee` (also the filename) |
| the real turn uuid | `01a0aaaa-cccc-7ddd-8eee-ffffffffffff` |
| every `call-<uuid>` | `call-0000NNNN-0000-4000-8000-000000000000`, in first-seen order |
| `session_meta.base_instructions.text` (~14 KB) | a two-line stub |
| `turn_context.developer_instructions` and the `role:"developer"` message body (~40 KB) | a one-line stub |

Token counts, model ids, tool names, commands, exit codes and command
outputs are **unmodified** — the fixture's assertions are about real
numbers. Scanned clean for `sk-`/`Bearer`/`api_key`/email patterns
before and after; zero hits.

## NOT copied (deliberately)

- `codex-home/config.toml` and its `config.<ISO-ts>.toml` per-launch
  snapshots — **plaintext provider API keys**
  (`profiles = [{ apiKey = "sk-or-v1-…", baseURL = "…" }, …]`).
  Confirmed present 2026-09-03; never read by the adapter.
- `%APPDATA%\interpreter\config.json` — the Electron app config. Read
  once during grounding only to confirm it carries **no
  store-relocation key** (its `lastWorkspace` / `recentFolders[]` are
  *workspace* pointers). It also carries `userName`, so it is PII and
  is never read by the adapter or persisted here.
- `codex-home/state_5.sqlite` (session index) and `logs_2.sqlite`
  (+ `-wal`/`-shm`, Rust `tracing` debug log) — assessed, not wired.
  Same verdict as the CLI copies; see
  `docs/openinterpreter-adapter.md`.
- The other three live rollouts of the day: two died on provider
  errors before any usage (`token_count` with `info: null` only) and
  one is an Ollama-provider session whose single usage record is all
  zeros. They add no parser coverage the kept file lacks.
- `runtime/`, `logs/`, `Cache/`, `Local Storage/`, `skills/`,
  `memories/`, `tmp/` — Electron/vendor plumbing.
