# Antigravity fixtures

Anonymized reference dumps for `internal/adapter/antigravity`, all derived
2026-09-03 from live runs on the operator's Windows box (each with the
operator's standard 5-turn prompt kit: summarise / create+run / edit+run /
delete / verify). Anonymized: prompt text reworded, workspace paths →
`c:\Users\dev\work\stepin*`, conversation uuids replaced, timestamps →
January 2026. The STRUCTURE of every file is verbatim.

| dir | client | live tree | what it grounds |
|---|---|---|---|
| `desktop/` | **Antigravity IDE (standalone build)**, signed in | `~/.gemini/antigravity/` | `brain/<uuid>/…/transcript.jsonl` ONLY — this build wrote the encrypted `conversations/<uuid>.pb` + the transcript and **no `.db`** |
| `desktop-vscode/` | **VS Code extension `Google.google-antigravity`** (bundles its own `~/.gemini/bin/agy.exe`) | `~/.gemini/antigravity/` (the DESKTOP tree — no VS Code globalStorage dir was created) | transcript + a sibling `conversations/<uuid>.db` (plaintext SQLite, `trajectory_meta.source = 1`) |
| `cli/` | **`agy` CLI** (v1.1.x) | `~/.gemini/antigravity-cli/` | transcript + `conversations/<uuid>.db` (`trajectory_meta.source = 17`) |

## Transcript layout (all three)

```
<tree>/brain/<uuid>/.system_generated/logs/transcript.jsonl
```

One JSON object per line, keys `step_index` / `source` / `type` / `status` /
`created_at` / `content` / `tool_calls` / `thinking`. Differences between
the clients, all verbatim in the fixtures:

- **Standalone IDE (`desktop/`)**: typed result steps `LIST_DIRECTORY`,
  `VIEW_FILE`, `RUN_COMMAND`, `CODE_ACTION` (+ `CONVERSATION_HISTORY`
  system marker); command results say `The command completed successfully.`;
  result-header timestamps are UTC (`…Z`); `step_index` is not contiguous
  (4 absent in the live file). Steps 21–22 (`find_by_name` → `GENERIC`)
  were spliced in from the extension run's shape.
- **agy-backed clients (`desktop-vscode/`, `cli/`)**: EVERY result step is
  `type: GENERIC`; command results say `The command exited with code N.`;
  result-header timestamps carry the local offset (`+05:30`); no
  `CONVERSATION_HISTORY` line; `step_index` contiguous 0–19.
- Tool names observed: `list_dir`, `view_file`, `run_command`,
  `write_to_file`, `replace_file_content`, `find_by_name`
  (`find_by_name` args `Excludes` / `Pattern` / `SearchDirectory` grounded
  from the extension run). `run_command` from the agy clients adds
  `IsDaemon`.
- The model is named ONLY in the `<USER_SETTINGS_CHANGE>` block of the
  first `USER_INPUT` (`Gemini 3.6 Flash (High)` / `Gemini 3.8 Flash (High)`
  — vendor display names, not API ids).

## The agy `.db` (`desktop-vscode/`, `cli/`) — schema grounded, blobs test-built

The two live `.db` copies contain the operator's real prompts/paths inside
protobuf blobs and are NOT checked in; the tests build a `.db` from the
grounded schema below (`agydb_test.go::buildAgyDB`) with synthetic blobs
encoded through the same `protowire` field map the reader decodes.

Identical schema in both trees (verified 2026-09-03):

```
battle_mode_infos       (idx integer, data blob)
executor_metadata       (idx integer, data blob)                         -- 1 row, ~5 KB
gen_metadata            (idx integer, data blob, size integer)           -- 1 row per generation
parent_references       (idx integer, data blob)
steps                   (idx, step_type integer, status integer, has_subtrajectory,
                         metadata, error_details, permissions, task_details,
                         render_info, step_payload blob, step_format integer)
trajectory_meta         (trajectory_id text, cascade_id text, trajectory_type integer, source integer)
trajectory_metadata_blob(id text default "main", data blob)              -- field 18 = project id
```

Live values:

- `trajectory_meta`: `trajectory_type = 4` in both; **`source = 1`** for the
  VS Code extension run, **`source = 17`** for the `agy` CLI run;
  `cascade_id` = the conversation uuid (the file's basename). A `.db` whose
  `trajectory_meta` row is not there yet stamps no surface (the tests cover
  both the mapped values, an unmapped value, and the missing row).
- `gen_metadata` usage submessage (`1.17.2.X`, all 20 generations): `1` is
  CONSTANT per conversation (1071 / 1318), `2 + 5` = the growing prompt (`5`
  absent on cache-miss generations), `3 = 9 + 10`, `6 = 24` constant, `7`/`8`/
  `11` bytes — the Anthropic-style uncached / cache-write / cache-read split,
  not Gemini's own `usage_metadata` numbering.
- `steps.step_type`: `14` (USER_INPUT), then alternating `15`
  (PLANNER_RESPONSE) / `132` (GENERIC result); `status = 3` throughout;
  `step_format = 0`. 20 rows, mirroring the 20 transcript lines.
- `gen_metadata`: 10 rows (one per PLANNER_RESPONSE); each blob decodes
  through `decodeGenMetadata` to a real model id + usage —
  VS Code run `gemini-3.6-flash`, e.g. `in=1071 out=55 cacheCreation=16556
  cacheRead=0 reasoning=228`; CLI run `gemini-3.8-flash`, e.g. `in=1318
  out=51 cacheCreation=13781 reasoning=181`. **Desktop-tree tokens are
  therefore REAL whenever an agy backend wrote the conversation**; only the
  standalone IDE build (no `.db`) has none.
- `trajectory_metadata_blob` field 18: the VS Code run resolved to a
  project id whose `~/.gemini/config/projects/<id>.json` carries the
  workspace at `projectResources.resources[0].folderUri` (NOT under
  `gitFolder` as the CLI's own projects do); the CLI run resolved to
  `default-cli-project` (no workspace → the transcript's `Cwd` is the root).

## What the live tree ALSO contained, deliberately NOT fixtured and NOT matched

`transcript_full.jsonl` (same line count, slightly different bytes),
`chunks/transcript/00000000.jsonl` + `chunks/transcript_full/…` (rotation
copies), `steps/<n>/output.txt`, `.user_uploaded/`, `scratch/`,
`conversations/<uuid>.pb` (encrypted; 173 KB), `annotations/<uuid>.pbtxt`
(`last_user_view_time` only), `antigravity_state.pbtxt`
(`last_selected_agent_model: MODEL_PLACEHOLDER_M71` — an opaque enum, not a
model; `installation_uuid` — never persisted), `agyhub_summaries_proto.pb`,
the `.db-wal` / `.db-shm` sidecars.
