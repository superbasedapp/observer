# Stakpak test fixtures

`fixture.sql` is an anonymized SQL dump of the local store
(`~/.stakpak/data/local.db`) from two real `stakpak` 0.3.88 sessions captured
2026-10-21 on the same machine: one on Windows 11 (8 checkpoints) and one on
WSL Ubuntu (the first 8 of its 26 checkpoints). No `.db` binary is tracked (the
tree-wide `*.db` gitignore is deliberate); `internal/adapter/stakpak`'s
`TestMain` builds the database from this file at test time.

Both sessions ran the same kind of task (create / run / edit / delete a
hello-world Python file), so together they pin:

- the `sessions` + `checkpoints` schema (migrations 1 and 2), a linear
  `parent_id` chain, `state` JSON holding the whole cumulative OpenAI-chat
  message list per checkpoint;
- `stakpak__<name>` tool names (create, view, str_replace, remove,
  run_command), string-encoded `arguments`;
- `usage{prompt_tokens, completion_tokens, total_tokens}` on the step's last
  assistant message only;
- the `<local_context>` block appended to the first prompt;
- the result sentinels `TOOL_CALL_CANCELLED` (Windows) and `COMMAND_FAILED`
  (WSL), a user prompt queued mid-run, and a raw `C:\...` cwd beside a POSIX one.

Shapes the live runs did not produce (sub-agent spawn and wait, a per-message
`model`, `usage.prompt_tokens_details`, array-shaped content with an image
part, forked checkpoints, history shrinkage) are built as literal checkpoint
states inside `parse_test.go`; they are named in the vendor binary's struct
definitions, not observed live.

## Anonymization applied

- Ids: every session and checkpoint UUID is replaced by a synthetic
  `00000000-0000-4000-8000-<n>` (session A = ...0001, checkpoints 0002-0009;
  session B = ...0010, checkpoints 0011-0018). Provider tool-call ids
  (`call_function_...`) are kept as emitted.
- Paths: `C:\Users\<operator>` -> `C:\Users\user`, `/home/<operator>` ->
  `/home/user`, working directories -> `...\project` / `/home/user/project`.
- The `<local_context>` block (machine name, date, directory tree) is replaced
  by a minimal block with `Machine Name: host` and `[tree omitted]`; directory
  names that appeared in `ls` output are renamed (`.dir-a`, `dir-c`, ...).
- Machine names, owner/group names and numeric owner ids are neutralized.
- Any string longer than 420 characters is truncated with `...[truncated]`.
- `config.toml` (holds the profile `api_key`), `auth.toml`, `cache/models.json`
  and the project-local `.stakpak/session/**` backups are never read or copied.

Grep proof run on `fixture.sql` before commit: zero hits for the operator's
username, personal name and e-mail, original machine names, numeric owner
ids, `sk-`, `Bearer`, `api_key`, `.env` and unrelated tool directory names; the
only `@` characters are unified-diff hunk headers (`@@ -1 +1 @@`).
