-- Qoder Work store fixture — ANONYMIZED.
--
-- Source of truth: `%APPDATA%\com.qoder.app.stable\main.sqlite` on a live
-- Windows install (Qoder Work 2026-09-03). The DDL below is copied
-- verbatim from that database's sqlite_master for the THREE tables this
-- adapter reads; every other table (including the encrypted
-- byok_model_credentials / mcp_oauth_credentials and the account tables)
-- is deliberately absent, so a fixture can never carry a credential and a
-- test can never accidentally exercise a query against one.
--
-- Row VALUES are synthetic and mirror the live shapes:
--   * sess-with-twin      — has a qodercli transcript twin → stamp only.
--   * sess-no-twin        — twin-less (the live 64648372 shape: an
--                           aborted run whose transcript never landed) →
--                           the conversation fallback emits it.
--   * sess-fresh          — inside the freshness window → stamp +
--                           RetrySuggested, never claimed.
--
-- `updated_at` / `created_at` are Unix MILLISECONDS (live: 1788431104170).
-- The fixture builder rewrites them relative to the test clock; the
-- literals here are the base the builder offsets from.
--
-- Rendered into a temp main.sqlite by buildWorkDB in work_test.go — the
-- fixture is checked in as SQL, not as a binary, so it stays diffable and
-- provably free of anything but what is written here.

CREATE TABLE chat_sessions (
        session_id TEXT PRIMARY KEY,
        origin_session_id TEXT,
        session_kind TEXT NOT NULL DEFAULT 'standard' CHECK (session_kind IN (
          'standard', 'sideChat', 'automationExecution'
        )),
        owner_session_id TEXT,
        conversation_mode TEXT NOT NULL DEFAULT 'normal' CHECK (conversation_mode IN ('normal', 'voice')),
        product_mode TEXT NOT NULL DEFAULT 'coding' CHECK (product_mode IN ('coding', 'general')),
        title TEXT NOT NULL,
        cwd TEXT NOT NULL,
        execution_kind TEXT,
        workspace_id TEXT,
        git_branch TEXT,
        model TEXT,
        permission_mode TEXT,
        extra_json TEXT NOT NULL DEFAULT '{}',
        created_at TIMESTAMP NOT NULL,
        updated_at TIMESTAMP NOT NULL,
        archived INTEGER NOT NULL DEFAULT 0,
        deleted_at TIMESTAMP
      );

CREATE TABLE chat_session_messages (
        session_id TEXT NOT NULL,
        message_id TEXT NOT NULL,
        turn_id TEXT,
        sequence INTEGER NOT NULL,
        payload_json TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'completed',
        feedback TEXT,
        source TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        PRIMARY KEY (session_id, message_id),
        FOREIGN KEY (session_id) REFERENCES chat_sessions(session_id) ON DELETE CASCADE
      );

-- Read by NOTHING in this adapter. Present in the fixture so the
-- "tokens are never emitted from the Work store" test can assert against
-- the real shape: tokenCountsAvailable:false with every count zero, i.e.
-- a context-window occupancy gauge, not usage.
CREATE TABLE chat_session_context_usage (
        session_id TEXT PRIMARY KEY,
        snapshot_json TEXT NOT NULL,
        updated_at INTEGER NOT NULL,
        FOREIGN KEY (session_id) REFERENCES chat_sessions(session_id) ON DELETE CASCADE
      );

-- `model` values are the two live shapes; NEITHER is a model name.
INSERT INTO chat_sessions
  (session_id, session_kind, title, cwd, execution_kind, git_branch, model, permission_mode, created_at, updated_at)
VALUES
  ('sess-with-twin', 'standard', 'Create and delete Hello World file', 'C:\Users\dev\proj', 'local', 'main',
   'byok:00000000-0000-4000-8000-0000000000c0', 'acceptEdits', 1788431760953, 1788431833331),
  ('sess-no-twin', 'standard', 'Please give me a one-paragraph summary', 'C:\Users\dev\scratch', 'local', NULL,
   'byok:00000000-0000-4000-8000-0000000000c0', 'acceptEdits', 1788431739858, 1788431748817),
  ('sess-fresh', 'standard', 'Python hello world project summary', 'C:\Users\dev\proj', 'local', 'main',
   'auto', 'bypassPermissions', 1788431854711, 1788431890612);

-- An IMPORT of a Qoder IDE ("quest") task — live shape: extra_json names
-- the source product, execution_kind is NULL (Work never executed it),
-- every message is source='cli-import'. The IDE original lives at
-- projects/<slug>/transcript/<task>.session.execution.jsonl and the
-- import is a second flat <uuid>.jsonl; the adapter must emit NO hosted
-- stamp and NO fallback rows for it.
INSERT INTO chat_sessions
  (session_id, session_kind, title, cwd, execution_kind, git_branch, model, permission_mode, extra_json, created_at, updated_at)
VALUES
  ('sess-import', 'standard', 'Python hello world management', 'c:/Users/dev/proj', NULL, '',
   'auto', 'bypassPermissions', '{"importedFrom":"quest"}', 1788431103620, 1788431244744);

INSERT INTO chat_session_messages
  (session_id, message_id, turn_id, sequence, payload_json, status, source, created_at, updated_at)
VALUES
  -- Twinned session: the qodercli transcript owns these rows; only the
  -- hosted surface stamp comes from here.
  ('sess-with-twin', '00000000-0000-4000-8000-0000000000a1', '00000000-0000-4000-8000-0000000000a1', 1,
   '{"id":"00000000-0000-4000-8000-0000000000a1","role":"user","turnId":"00000000-0000-4000-8000-0000000000a1","text":"Create a hello world file and run it.","timestamp":"2026-09-03T10:36:00.900Z","tools":[],"attachments":[],"runtimeInputState":"not-delivered"}',
   'completed', 'host-projection', 1788431760953, 1788431764606),
  ('sess-with-twin', 'assistant:00000000-0000-4000-8000-0000000000a1', '00000000-0000-4000-8000-0000000000a1', 2,
   '{"id":"assistant:00000000-0000-4000-8000-0000000000a1","role":"assistant","turnId":"00000000-0000-4000-8000-0000000000a1","requestSetId":"00000000-0000-4000-8000-0000000000a1","text":"Done.","timestamp":"2026-09-03T10:36:04.605Z","durationMs":1200,"parts":[],"tools":[{"id":"call_twinnedtoolcall000000","name":"Bash","input":{"command":"ls","description":"List files","dir_path":"/"},"status":"completed","parentToolUseId":null,"startedAt":"2026-09-03T10:36:18.915Z","response":"README.md","completedAt":"2026-09-03T10:36:26.145Z","durationMs":7230}]}',
   'completed', 'sdk-projection', 1788431764605, 1788431832360),

  -- Twin-less session: an aborted run. Live shape — one user message
  -- projected by the host, then two hook-activity system rows and
  -- nothing else; the CLI created its project dir but never wrote a
  -- transcript.
  ('sess-no-twin', '00000000-0000-4000-8000-0000000000b1', '00000000-0000-4000-8000-0000000000b1', 1,
   '{"id":"00000000-0000-4000-8000-0000000000b1","role":"user","turnId":"00000000-0000-4000-8000-0000000000b1","text":"Summarize the project in one paragraph.","timestamp":"2026-09-03T10:35:45.243Z","tools":[],"attachments":[],"runtimeInputState":"not-delivered"}',
   'completed', 'host-projection', 1788431739859, 1788431748817),
  ('sess-no-twin', 'hook-activity:00000000-0000-4000-8000-0000000000b2', '00000000-0000-4000-8000-0000000000b1', 2,
   '{"id":"hook-activity:00000000-0000-4000-8000-0000000000b2","role":"system","turnId":"00000000-0000-4000-8000-0000000000b1","text":"","timestamp":"2026-09-03T10:35:49.256Z","tools":[],"durationMs":0,"parts":[{"id":"hook:00000000-0000-4000-8000-0000000000b2","type":"hook","hook":{"id":"00000000-0000-4000-8000-0000000000b2","event":"SessionStart","status":"succeeded","startedAt":"2026-09-03T10:35:49.256Z","exitCode":0,"completedAt":"2026-09-03T10:35:49.713Z"}}],"subtype":"hook_activity"}',
   'completed', 'sdk-projection', 1788431749256, 1788431749714),

  -- Imported IDE task: adopted wholesale, never hosted by Work.
  ('sess-import', '00000000-0000-4000-8000-0000000000e1', '00000000-0000-4000-8000-0000000000e1', 1,
   '{"id":"00000000-0000-4000-8000-0000000000e1","role":"user","turnId":"00000000-0000-4000-8000-0000000000e1","text":"Create a hello world file.","timestamp":"2026-09-03T10:25:04.170Z","tools":[],"attachments":[]}',
   'completed', 'cli-import', 1788431103620, 1788431244744),
  ('sess-import', 'assistant:00000000-0000-4000-8000-0000000000e1', '00000000-0000-4000-8000-0000000000e1', 2,
   '{"id":"assistant:00000000-0000-4000-8000-0000000000e1","role":"assistant","turnId":"00000000-0000-4000-8000-0000000000e1","text":"Done.","timestamp":"2026-09-03T10:25:40.000Z","tools":[{"id":"toolu_migrated_call_000001","name":"Write","input":{"file_path":"hello_world.py"},"status":"completed"}]}',
   'completed', 'cli-import', 1788431103621, 1788431244744),

  -- Fresh session: the builder rewrites these two timestamps to "now".
  -- Also the failed-assistant shape (empty text + failureReason).
  ('sess-fresh', '00000000-0000-4000-8000-0000000000d1', '00000000-0000-4000-8000-0000000000d1', 1,
   '{"id":"00000000-0000-4000-8000-0000000000d1","role":"user","turnId":"00000000-0000-4000-8000-0000000000d1","text":"Summarize the project.","timestamp":"2026-09-03T10:38:08.537Z","tools":[],"attachments":[],"runtimeInputState":"not-delivered"}',
   'completed', 'sdk-projection', 1788431888537, 1788431890611),
  ('sess-fresh', 'assistant:00000000-0000-4000-8000-0000000000d1', '00000000-0000-4000-8000-0000000000d1', 2,
   '{"id":"assistant:00000000-0000-4000-8000-0000000000d1","role":"assistant","turnId":"00000000-0000-4000-8000-0000000000d1","requestSetId":"00000000-0000-4000-8000-0000000000d1","text":"","timestamp":"2026-09-03T10:38:08.537Z","durationMs":2076,"parts":[],"tools":[],"failureReason":"BYOK_PROVIDER_REQUEST_FAILED"}',
   'failed', 'sdk-projection', 1788431888537, 1788431890613);

INSERT INTO chat_session_context_usage (session_id, snapshot_json, updated_at)
VALUES
  ('sess-with-twin',
   '{"totalTokens":0,"maxTokens":0,"rawMaxTokens":0,"tokenCountsAvailable":false,"percentage":0.119,"model":"byok:00000000-0000-4000-8000-0000000000c0","categories":[{"name":"system_prompt","type":"system_prompt","percentage":0.031,"tokens":0}]}',
   1788431832991);
