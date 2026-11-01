package devin

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testhome"

	_ "modernc.org/sqlite"
)

// fixtureDB is built ONCE per test binary by TestMain. Repo convention:
// SQLite fixtures are synthesized in-test (no .db binary is tracked —
// the tree-wide *.db gitignore is deliberate); fixtureSQL below is the
// anonymized dump of the live-capture-derived fixture (3 sessions: a
// dead-regeneration branch, a foreign-Windows cwd, a malformed node).
var fixtureDB string

func TestMain(m *testing.M) {
	// Pin the profile roots to a process temp home (surface-gap FU-102):
	// the foreign-mount mirror tests stage a copy under os.UserCacheDir(),
	// which was the developer's real ~/.cache/superbased-observer.
	_, cleanupHome, err := testhome.PinProcess()
	if err != nil {
		panic(err)
	}
	dir, err := os.MkdirTemp("", "devin-fixture")
	if err != nil {
		panic(err)
	}
	fixtureDB = filepath.Join(dir, "sessions.db")
	db, err := sql.Open("sqlite", fixtureDB)
	if err != nil {
		panic(err)
	}
	if _, err := db.Exec(fixtureSQL); err != nil {
		panic(err)
	}
	if err := db.Close(); err != nil {
		panic(err)
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	cleanupHome()
	os.Exit(code)
}

const fixtureSQL = `
CREATE TABLE sessions (
  id TEXT PRIMARY KEY, working_directory TEXT NOT NULL, backend_type TEXT NOT NULL,
  model TEXT NOT NULL, agent_mode TEXT NOT NULL, created_at INTEGER NOT NULL,
  last_activity_at INTEGER NOT NULL, title TEXT, main_chain_id INTEGER,
  shell_last_seen_index INTEGER DEFAULT 0, cogs_json TEXT, workspace_dirs TEXT,
  hidden INTEGER NOT NULL DEFAULT 0, metadata TEXT);
INSERT INTO sessions VALUES('cobalt-fruit','/home/user/project','Windsurf','swe-1-6-slow','normal',1783551869,1783551899,'create file',6,0,NULL,'',0,NULL);
INSERT INTO sessions VALUES('bird-brick','C:\Users\dev\project','Windsurf','swe-1-6-slow','normal',1783551869,1783551879,'hi',1,0,NULL,'',0,NULL);
INSERT INTO sessions VALUES('malformed-test','/home/user/project','Windsurf','swe-1-6-slow','normal',1783551869,1783551874,'broken',1,0,NULL,'',0,NULL);
CREATE TABLE message_nodes (
  row_id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT NOT NULL,
  node_id INTEGER NOT NULL, parent_node_id INTEGER, chat_message TEXT NOT NULL,
  created_at INTEGER NOT NULL, metadata TEXT, UNIQUE(session_id, node_id));
INSERT INTO message_nodes VALUES(1,'cobalt-fruit',0,NULL,'{"message_id": "sys-0", "role": "system", "content": "You are Devin, an interactive command line agent.", "metadata": {"is_system_prefix": true}}',1783551869,NULL);
INSERT INTO message_nodes VALUES(2,'cobalt-fruit',1,0,'{"message_id": "u-1", "role": "user", "content": "Create a file hello.txt containing hi and run ls", "metadata": {"num_tokens": null, "is_user_input": true, "request_id": null, "metrics": null, "finish_reason": null, "created_at": "2026-07-08T23:04:29.978263073Z", "from_event_id": "evt-u-1", "telemetry": {"source": "user", "operation": "unknown"}}}',1783551870,NULL);
INSERT INTO message_nodes VALUES(3,'cobalt-fruit',2,1,'{"message_id": "a-dead", "role": "assistant", "content": "draft answer", "tool_calls": [{"id": "call_dead", "name": "write", "arguments": {"file_path": "/home/user/project/x.txt", "content": "dead"}, "index": 0, "kind": "function"}], "thinking": {"thinking": "dead thinking"}, "metadata": {"num_tokens": 999, "is_user_input": null, "request_id": "req-a-dead", "metrics": {"ttft_ms": 50, "total_time_ms": 550, "input_tokens": 999, "output_tokens": 999, "cache_read_tokens": null, "cache_creation_tokens": null, "tpot_ms": 4.0, "tokens_per_sec": 200.0}, "finish_reason": "stop", "started_generation_at": "2026-07-09T00:15:42.915172190Z", "created_at": "2026-07-09T00:15:43.432219680Z", "generation_model": "swe-1-6-slow", "telemetry": {"source": "assistant", "operation": "inference"}}}',1783551871,NULL);
INSERT INTO message_nodes VALUES(4,'cobalt-fruit',3,1,'{"message_id": "a-live1", "role": "assistant", "content": "I''ll create the file and run ls.", "tool_calls": [{"id": "call_write1", "name": "write", "arguments": {"file_path": "/home/user/project/hello.txt", "content": "hi"}, "index": 0, "kind": "function"}, {"id": "call_exec1", "name": "exec", "arguments": {"command": "ls"}, "index": 1, "kind": "function"}], "thinking": {"thinking": "Let me write then list."}, "metadata": {"num_tokens": 20, "is_user_input": null, "request_id": "req-a-live1", "metrics": {"ttft_ms": 1678, "total_time_ms": 2178, "input_tokens": 120, "output_tokens": 20, "cache_read_tokens": null, "cache_creation_tokens": null, "tpot_ms": 4.0, "tokens_per_sec": 200.0}, "finish_reason": "tool_calls", "started_generation_at": "2026-07-09T00:15:42.915172190Z", "created_at": "2026-07-09T00:15:43.432219680Z", "generation_model": "swe-1-6-slow", "telemetry": {"source": "assistant", "operation": "inference"}}}',1783551872,NULL);
INSERT INTO message_nodes VALUES(5,'cobalt-fruit',4,3,'{"message_id": "t-4", "role": "tool", "content": "File written to hello.txt", "tool_call_id": "call_write1", "metadata": {"num_tokens": null, "metrics": null, "finish_reason": null, "extensions": {"chisel/tool_result_meta": {"success": true, "kind": "edit"}}, "created_at": "2026-07-09T00:15:43.462420572Z", "telemetry": {"source": "tool_result", "operation": "write"}}}',1783551873,NULL);
INSERT INTO message_nodes VALUES(6,'cobalt-fruit',5,4,'{"message_id": "t-5", "role": "tool", "content": "hello.txt\nREADME.md", "tool_call_id": "call_exec1", "metadata": {"num_tokens": null, "metrics": null, "finish_reason": null, "extensions": {"chisel/tool_result_meta": {"success": true, "kind": "exec"}}, "created_at": "2026-07-09T00:15:43.462420572Z", "telemetry": {"source": "tool_result", "operation": "exec"}}}',1783551874,NULL);
INSERT INTO message_nodes VALUES(7,'cobalt-fruit',6,5,'{"message_id": "a-final", "role": "assistant", "content": "Done. Created hello.txt and ran ls.", "metadata": {"num_tokens": 15, "is_user_input": null, "request_id": "req-a-final", "metrics": {"ttft_ms": 904, "total_time_ms": 1404, "input_tokens": 200, "output_tokens": 15, "cache_read_tokens": null, "cache_creation_tokens": null, "tpot_ms": 4.0, "tokens_per_sec": 200.0}, "finish_reason": "stop", "started_generation_at": "2026-07-09T00:15:42.915172190Z", "created_at": "2026-07-09T00:15:43.432219680Z", "generation_model": "swe-1-6-slow", "telemetry": {"source": "assistant", "operation": "inference"}}}',1783551875,NULL);
INSERT INTO message_nodes VALUES(8,'bird-brick',0,NULL,'{"message_id": "u2-0", "role": "user", "content": "hi", "metadata": {"num_tokens": null, "is_user_input": true, "request_id": null, "metrics": null, "finish_reason": null, "created_at": "2026-07-08T23:04:29.978263073Z", "from_event_id": "evt-u2-0", "telemetry": {"source": "user", "operation": "unknown"}}}',1783551869,NULL);
INSERT INTO message_nodes VALUES(9,'bird-brick',1,0,'{"message_id": "a2-1", "role": "assistant", "content": "Hi! How can I help?", "metadata": {"num_tokens": 8, "is_user_input": null, "request_id": "req-a2-1", "metrics": {"ttft_ms": 300, "total_time_ms": 800, "input_tokens": 50, "output_tokens": 8, "cache_read_tokens": null, "cache_creation_tokens": null, "tpot_ms": 4.0, "tokens_per_sec": 200.0}, "finish_reason": "stop", "started_generation_at": "2026-07-09T00:15:42.915172190Z", "created_at": "2026-07-09T00:15:43.432219680Z", "generation_model": "swe-1-6-slow", "telemetry": {"source": "assistant", "operation": "inference"}}}',1783551870,NULL);
INSERT INTO message_nodes VALUES(10,'malformed-test',0,NULL,'{"message_id": "u3-0", "role": "user", "content": "hello", "metadata": {"num_tokens": null, "is_user_input": true, "request_id": null, "metrics": null, "finish_reason": null, "created_at": "2026-07-08T23:04:29.978263073Z", "from_event_id": "evt-u3-0", "telemetry": {"source": "user", "operation": "unknown"}}}',1783551869,NULL);
INSERT INTO message_nodes VALUES(11,'malformed-test',1,0,'{ this is not valid json',1783551870,NULL);
CREATE TABLE prompt_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT, content TEXT NOT NULL,
  timestamp INTEGER NOT NULL, session_id TEXT NOT NULL, is_shell INTEGER NOT NULL DEFAULT 0);
`
