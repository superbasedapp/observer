-- Anonymized Freebuff Desktop fixture (derived from a live
-- 2026-09-03 capture). See testdata/freebuff/README.md for the
-- derivation rules and what was withheld. Text .sql rather than a
-- .db because the repo tracks no SQLite binaries.

CREATE TABLE projects (
    id             TEXT PRIMARY KEY,
    root_path      TEXT NOT NULL,
    default_branch TEXT NOT NULL DEFAULT 'main',
    created_at     INTEGER NOT NULL
  );
CREATE TABLE threads (
    id                    TEXT PRIMARY KEY,
    project_id            TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    project_path          TEXT NOT NULL,
    title                 TEXT NOT NULL DEFAULT 'New thread',
    status                TEXT NOT NULL DEFAULT 'open',
    harness_id            TEXT,
    model                 TEXT,
    reasoning_effort      TEXT,
    agent_mode            TEXT NOT NULL DEFAULT 'build',
    execution_mode        TEXT NOT NULL DEFAULT 'local',
    branch                TEXT,
    worktree_path         TEXT,
    turn_state            TEXT NOT NULL DEFAULT 'idle',
    last_turn_outcome     TEXT,
    harness_state         TEXT,
    fork_source_thread_id TEXT,
    created_at            INTEGER NOT NULL,
    updated_at            INTEGER NOT NULL
  );
CREATE TABLE messages (
    seq              INTEGER PRIMARY KEY AUTOINCREMENT,
    thread_id        TEXT NOT NULL REFERENCES threads(id) ON DELETE CASCADE,
    request_id       TEXT,
    input_id         TEXT,
    role             TEXT NOT NULL,
    parts_json       TEXT NOT NULL DEFAULT '[]',
    attachments_json TEXT NOT NULL DEFAULT '[]',
    metrics_json     TEXT NOT NULL DEFAULT '{}',
    ts               INTEGER NOT NULL
  );
CREATE INDEX idx_messages_thread ON messages(thread_id, seq);
CREATE TABLE queue_items (
    id        TEXT PRIMARY KEY,
    thread_id TEXT NOT NULL,
    kind      TEXT NOT NULL DEFAULT 'prompt',
    prompt    TEXT NOT NULL,
    state     TEXT NOT NULL,
    source    TEXT NOT NULL,
    position  REAL NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
  );
CREATE TABLE freebuff_storage_metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);

INSERT INTO projects (id, root_path, default_branch, created_at) VALUES ('/home/dev/code/demo-project', '/home/dev/code/demo-project', 'main', 1788430020848);

INSERT INTO threads (id, project_id, project_path, title, status, harness_id, model, reasoning_effort, agent_mode, execution_mode, branch, worktree_path, turn_state, last_turn_outcome, harness_state, fork_source_thread_id, created_at, updated_at) VALUES ('00000000-1111-2222-3333-444444444444', '/home/dev/code/demo-project', '/home/dev/code/demo-project', 'Hello World Python Project Summary', 'open', 'codebuff', 'deepseek/deepseek-v4-flash', NULL, 'build', 'local', NULL, NULL, 'idle', 'completed', '{"sessionState":{"note":"HARNESS-STATE-SENTINEL-must-never-be-ingested"}}', NULL, 1788430027684, 1788430059891);

INSERT INTO messages (seq, thread_id, request_id, input_id, role, parts_json, attachments_json, metrics_json, ts) VALUES (1, '00000000-1111-2222-3333-444444444444', NULL, 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee', 'user', '[{"kind":"text","text":"Please give me a one-paragraph summary of the current project.\n\nCreate a Hello World Python file and execute it.\nModify the Hello World Python file to read \"Hello Universe\" and then execute it.\nI would like you to delete the Hello World file that you created and then\ncheck the directory to verify if the file was indeed deleted."}]', '[]', '{}', 1788430036080);
INSERT INTO messages (seq, thread_id, request_id, input_id, role, parts_json, attachments_json, metrics_json, ts) VALUES (2, '00000000-1111-2222-3333-444444444444', NULL, NULL, 'assistant', '[{"collapse":"preview","id":"p1-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee","kind":"reasoning","open":false,"text":"The user asked for a summary, then a hello-world file, an edit, a delete and a verify. Explore the directory first."},{"ad":{"adText":"placeholder","cta":"See plans","placementId":"Desktop-Inline-Chat","provider":"first_party","surface":"cli_chat","title":"Need more?","url":"https://example.invalid/plans"},"id":"p2-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee","kind":"ad"},{"kind":"text","text":"\n\n"},{"id":"Zry9lE42ers","input":{"path":"."},"kind":"tool","toolName":"list_directory"},{"id":"Zry9lyvA3tY","input":{"command":"git log --oneline -5 \u0026\u0026 git status","process_type":"SYNC","timeout_seconds":30},"kind":"tool","output":"stdout:\nd7f56ff init\nOn branch main\nnothing added to commit but untracked files present\n","status":"success","toolName":"run_terminal_command"},{"collapse":"preview","id":"p3-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee","kind":"reasoning","open":false,"text":"Read the README to understand the project."},{"kind":"text","text":"\n\n"},{"id":"ZrzEAwcSRhA","input":{"paths":["README.md"]},"kind":"tool","toolName":"read_files"},{"ad":{"adText":"placeholder","cta":"See plans","placementId":"Desktop-Inline-Chat","provider":"first_party","surface":"cli_chat","title":"Need more?","url":"https://example.invalid/plans"},"id":"p4-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee","kind":"ad"},{"collapse":"preview","id":"p5-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee","kind":"reasoning","open":false,"text":"A minimal scratch project. Check the two config files briefly."},{"kind":"text","text":"\n\n"},{"id":"ZrzOGGloxXU","input":{"paths":[".freebuff/project-id",".kiro/settings/cli.json"]},"kind":"tool","toolName":"read_files"},{"collapse":"preview","id":"p6-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee","kind":"reasoning","open":false,"text":"Now write the summary, then create, run, edit, run, delete and verify."},{"kind":"text","text":"**Project summary:** a minimal scratch workspace holding a README and two tool-config directories, with no application code yet.\n\nNow I''ll create the Hello World Python file and execute it:\n\n"},{"id":"Zrzcqy5NgOI","input":{"content":"print(\"Hello World\")","instructions":"Create a Hello World Python file","path":"hello_world.py"},"kind":"tool","toolName":"write_file"},{"kind":"text","text":"\n\n\n"},{"ad":{"adText":"placeholder","cta":"See plans","placementId":"Desktop-Inline-Chat","provider":"first_party","surface":"cli_chat","title":"Need more?","url":"https://example.invalid/plans"},"id":"p7-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee","kind":"ad"},{"id":"Zrzj6zIYDH4","input":{"command":"python hello_world.py","process_type":"SYNC","timeout_seconds":30},"kind":"tool","output":"stdout:\nHello World\r\n","status":"success","toolName":"run_terminal_command"},{"collapse":"preview","id":"p8-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee","kind":"reasoning","open":false,"text":"It printed Hello World. Now modify it to Hello Universe and run again."},{"kind":"text","text":"Created and executed — it printed `Hello World`. Now modifying it to read \"Hello Universe\":\n\n"},{"id":"ZrzpqPht12A","input":{"path":"hello_world.py","replacements":[{"allowMultiple":false,"newString":"print(\"Hello Universe\")","oldString":"print(\"Hello World\")"}]},"kind":"tool","toolName":"str_replace"},{"kind":"text","text":"\n\n\n"},{"id":"ZrzupD64sV0","input":{"command":"python hello_world.py","process_type":"SYNC","timeout_seconds":30},"kind":"tool","output":"stdout:\nHello Universe\r\n","status":"success","toolName":"run_terminal_command"},{"kind":"text","text":"Executed — it printed `Hello Universe`. Now deleting the file and verifying:\n\n"},{"id":"Zrz1CLTaqyI","input":{"command":"rm hello_world.py \u0026\u0026 ls -la","process_type":"SYNC","timeout_seconds":30},"kind":"tool","output":"stdout:\ntotal 13\ndrwxr-xr-x 1 dev dev  0 Sep  3 15:37 .\ndrwxr-xr-x 1 dev dev  0 Sep  3 14:41 ..\n-rw-r--r-- 1 dev dev 45 Sep  3 13:33 README.md\n","status":"success","toolName":"run_terminal_command"},{"collapse":"preview","id":"p9-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee","kind":"reasoning","open":false,"text":"The file is deleted and the listing confirms it. Suggest follow-ups."},{"kind":"text","text":"All done. The directory listing confirms `hello_world.py` is gone.\n\n"},{"id":"Zr0ISN0ISTU","input":{"prompts":[{"label":"Scaffold a real Python project","prompt":"Set up this scratch repo as a proper Python project."},{"label":"Add a .gitignore","prompt":"Create a .gitignore for Python and IDE tooling."}]},"kind":"tool","toolName":"suggest_prompts"},{"files":[{"adds":1,"binary":false,"dels":0,"lockfile":false,"patch":"Index: hello_world.py\n===================================================================\n--- hello_world.py\tbefore\n+++ hello_world.py\tafter\n@@ -0,0 +1,1 @@\n+print(\"Hello Universe\")\n","path":"hello_world.py","status":"added","tooLarge":false}],"id":"p10-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee","kind":"changes"}]', '[]', '{"compactions":[],"context":{"compactionThresholdTokens":400000,"usedTokens":13343,"windowTokens":1048576},"costUsd":0,"usage":{"cachedInputTokens":94208,"inputTokens":108245,"outputTokens":1622,"totalTokens":109867}}', 1788430059891);

INSERT INTO queue_items (id, thread_id, kind, prompt, state, source, position, created_at, updated_at) VALUES ('aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee', '00000000-1111-2222-3333-444444444444', 'prompt', 'queued prompt text (never read by the adapter)', 'done', 'user', 1, 1788430036080, 1788430036080);

INSERT INTO freebuff_storage_metadata (key, value) VALUES ('default_model_migration', 'deepseek-v4-flash-2026-09-02');

