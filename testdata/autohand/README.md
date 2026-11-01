# testdata/autohand

Anonymized real Autohand Code CLI (autohand-cli 0.9.8) session directories,
captured 2026-10-21 for `internal/adapter/autohand`. Layout mirrors
`~/.autohand/sessions/<uuid>-<epoch-ms>/{conversation.jsonl,metadata.json}`.

| Fixture | Source | Notes |
|---|---|---|
| `windows/sessions/aaaaaaaa-...-1792553743146` | Windows 11 session, model `minimax/minimax-m3.1-flash:free` (OpenRouter route) | `tokenUsageStatus: actual`, 198106 prompt / 108832 cache read / 2420 completion, ANSI-colored file-tool results, Windows console control strings in `shell` output, `projectPath` `C:\Users\user\proj` |
| `windows/sessions/cccccccc-...-1792552793812` | Windows session, model `fantail`, cut off mid-turn | 10 tool calls but 9 results (last call unanswered), no `usage` block |
| `linux/sessions/bbbbbbbb-...-1792552680220` | WSL session, model `fantail` | `tokenUsageStatus: unavailable` (lower-bound totals), a non-zero `run_command` exit, the same prompt typed four times, `chatcmpl-tool-*` and `call_function_*` call-id styles, `projectPath` `/home/user/proj` |
| `windows/sessions/ffffffff-...-1792584719058` | Windows hook-probe session (2026-10-21 live), `read_file`/`shell`/`write_file {path, contents}` | relative paths, full read-edit-verify cycle, transcript-reader + account fixture |
| `windows/sessions/eeeeeeee-...-1792552897123` | Windows `fantail` session ended by the Autohand AI quota error | pairs with `windows/error.log` (api_error row + in-session `cli.version`) |
| `linux/sessions/dddddddd-...-1792669417085` | WSL live E2E 2026-10-22 (MiniMax over OpenRouter), a `shell` call blocked by Observer's own pre-tool hook | the tool result is the hook's bare reason (`user rule U-901: ...`, no `$ ` command header), `tokenUsageStatus: actual` |
| `linux/sessions/99999999-...-1792667111552` | WSL 2026-10-22, a session the vendor never saved a message for | `metadata.json` only: `status: active`, `messageCount: 0`, auto `title`, no `usage`, no `conversation.jsonl` |
| `windows/error.log` | the live quota record, anonymized (host block replaced, stack shortened) | |
| `windows/.account-skills/snapshot.json` | account snapshot, `accountId` replaced, token hash omitted | |

Anonymization: usernames, home paths and the scratch directory names the
sessions listed were replaced (`user`, `proj`, `src`/`docs`/`assets`/`tests`),
session ids were replaced with fixed fake UUIDs (the epoch-ms suffix is kept),
tool/prose content longer than 500 bytes is truncated. No `config.json`,
`traces/**`, hook, auth or history file is present; fixtures contain only the
two session files. Forked, imported and synced-copy sessions are built
synthetically inside the tests (no live example exists).
