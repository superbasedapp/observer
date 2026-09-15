# openclaw fixtures

## OpenClaw 2.0 — one checked-in live fixture

`agentdb/openclaw-agent.sqlite` is a REAL OpenClaw 2.0 per-agent store,
captured 2026-09-03 from a live install (`npm openclaw@2026.8.2`,
`schema_meta.schema_version = 19`) running the standard five-turn prompt
kit against a local Ollama provider, then anonymized:

- assistant/user text replaced with Lorem ipsum;
- the OS username replaced with the literal `<u>`, the workspace renamed
  `oc-probe/proj`, uuids and timestamps regenerated;
- the sqlite-vec (`*_vec*`) and FTS (`*_fts*`) mirror tables dropped so
  the file opens under `modernc.org/sqlite` with no extension loaded;
- **`transcript_events.event_json` keeps the real message/usage SHAPE** —
  this is the point of the fixture.

`TestParseAgentDB_LiveFixture2026_8_2` parses it and asserts the model
(`qwen2.5:1.5b-instruct` off `session_windows`), one session, per-call
usage summed over the nine assistant turns (36855/1102/0/0 — Ollama does
not cache, so input is gross-per-call and cache tokens are zero), zero
warnings, and a no-op re-parse from the watermark.

### What the live capture settled (previously schema-only assumptions)

Before this capture the 2.0 schema was grounded only on vendor source
(`src/state/openclaw-agent-schema.sql`, PR #78595). The live store
resolved the two residuals the source could not:

1. **`transcript_events.seq` is 0-based** (the `session` event is seq 0;
   messages begin at seq 4). Every message event carries an explicit
   `id` (uuid), so the id-based `SourceEventID` — and therefore the
   `openclaw doctor --fix` dedup contract — is unaffected by the base.
   `TestParseAgentDB_ZeroBasedSeqMatchesLegacyJSONL` pins this.
2. **`created_at` (and the `entry_json` timestamps) are milliseconds**
   (13-digit epoch). The reader's epoch helper accepts both s and ms.

3. **Message `content` is dual-shaped**: user turns store `content` as a
   bare JSON string, assistant turns as an array of typed blocks. The
   `messageContentList` unmarshaler (adapter.go) accepts both — a string
   decodes to a single text block. Before this fix a live store warned
   on every user turn (`cannot unmarshal string into []messageContent`).
   `TestMessageContentListUnmarshal` pins both branches.

## Pre-2.0 fixtures are constructed in-test

- Pre-2.0 (`runs.sqlite`, `sessions.json`, `<id>.jsonl`,
  `<id>.trajectory.jsonl`) — `internal/adapter/openclaw/adapter_test.go`
  (`setupTaskRunsDB`, `writeWPFixture`, and per-test inline JSONL).
- A synthetic 2.0 twin — `buildAgentFixture` / `writeAgentDB` in
  `agentdb_test.go` — writes the SAME transcript entries to BOTH layouts
  so `TestParseAgentDB_MatchesLegacyJSONL` can prove the dedup contract
  (byte-identical `SourceFile` / `SourceEventID`s / tokens across the
  2.0 SQLite store and its pre-2.0 `<sessionId>.jsonl` twin).

Live pre-2.0 grounding lives in the package `doc.go` (the 2026-07-31
capture: five message-log usage records vs one trajectory
`model.completed`, byte-identical on the overlapping call).
