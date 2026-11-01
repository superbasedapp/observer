-- testdata/dimcode/fixture-synthetic.sql
--
-- SYNTHETIC fixture for the DimCode adapter, built against schema.sql. Every
-- id, path and prompt is invented; NONE of it is copied from a real capture.
-- The SHAPES (part types, tool names, metadata keys, usage keys, relation
-- types) come from the two live captures (fixture-wsl.sql / fixture-win.sql)
-- and from the vendor's own code (dimcode 0.5.21): the sub-agent / branch
-- session_relations rows, the `agent` tool, the exec exitCode result and the
-- cost quality "exact" have no live row yet.
--
-- Covers what the live captures could not:
--   * a parallel read + grep tool_use pair (grep result is_error)
--   * an `agent` create call and a `glob` / unknown-MCP call with NO result
--     (pending outcome)
--   * an exec whose result status is "success" but structuredContent.exitCode
--     is 1 (the adapter must still report failure) with wallTimeMs
--   * session_states.settings.reasoningEffort
--   * cacheWriteTokens, cost quality "exact"
--   * a sub-agent child session (relationType subagent) and a branch fork
--   * a ledger row mirroring a run whose usage_run_stats row is absent

INSERT INTO sessions VALUES('sess_1000000000000_synthparent01','/home/user/synthetic','Synthetic parent','active',NULL,NULL,NULL,'2026-10-22T10:00:00.000Z','2026-10-22T10:00:00.000Z',5);
INSERT INTO session_states VALUES('sess_1000000000000_synthparent01','openrouter','anthropic/claude-sonnet-4.5','start','{"promptLocale":"en","reasoningEffort":"high"}','{}','agent',2);
INSERT INTO sessions VALUES('sess_1000000000001_synthchild001','/home/user/synthetic','Find TODOs','active',NULL,NULL,NULL,'2026-10-22T10:00:09.000Z','2026-10-22T10:00:09.000Z',2);
INSERT INTO session_states VALUES('sess_1000000000001_synthchild001','openrouter','anthropic/claude-haiku-4.5','start','{"promptLocale":"en"}','{}','agent',1);
INSERT INTO sessions VALUES('sess_1000000000002_synthfork0001','/home/user/synthetic','Synthetic parent (fork #1)','active',NULL,NULL,NULL,'2026-10-22T10:05:00.000Z','2026-10-22T10:05:00.000Z',1);
INSERT INTO session_states VALUES('sess_1000000000002_synthfork0001','openrouter','anthropic/claude-sonnet-4.5','start','{"promptLocale":"en"}','{}','agent',1);

INSERT INTO session_relations VALUES('rel_1','sess_1000000000000_synthparent01','sess_1000000000001_synthchild001','subagent','{"parentRunId":"run_s1","parentToolCallId":"call_agent1","subagentType":"explorer"}','2026-10-22T10:00:09.000Z');
INSERT INTO session_relations VALUES('rel_2','sess_1000000000000_synthparent01','sess_1000000000002_synthfork0001','branch',NULL,'2026-10-22T10:05:00.000Z');
INSERT INTO session_relations VALUES('rel_3','sess_1000000000000_synthparent01','sess_1000000000009_unknownrel01','fancy',NULL,'2026-10-22T10:05:01.000Z');

-- Parent session, run_s1.
INSERT INTO messages VALUES('msg_user_s1','sess_1000000000000_synthparent01','user','[{"type":"text","text":"Search the code and spawn a helper."}]',NULL,NULL,'{"runId":"run_s1"}','0001-0000','2026-10-22T10:00:00.000Z','2026-10-22T10:00:30.000Z');
INSERT INTO messages VALUES('msg_a1','sess_1000000000000_synthparent01','assistant','[{"type":"thinking","thinking":"Plan: read a.go and grep for TODO.","startTime":"2026-10-22T10:00:01.000Z","endTime":"2026-10-22T10:00:02.000Z"},{"type":"text","text":"Looking.","startTime":"2026-10-22T10:00:02.100Z","endTime":"2026-10-22T10:00:02.200Z"},{"type":"tool_use","id":"call_read1","name":"read","input":{"path":"/home/user/synthetic/a.go"},"startTime":"2026-10-22T10:00:03.000Z"},{"type":"tool_use","id":"call_grep1","name":"grep","input":{"pattern":"TODO"},"startTime":"2026-10-22T10:00:03.001Z"}]',NULL,'{"runId":"run_s1","toolCalls":[{"id":"call_read1","name":"read","status":"completed"},{"id":"call_grep1","name":"grep","status":"completed"}]}','{"runId":"run_s1"}','0001-0001','2026-10-22T10:00:03.100Z','2026-10-22T10:00:03.200Z');
INSERT INTO messages VALUES('msg_tr_read','sess_1000000000000_synthparent01','tool_result','[{"type":"tool_result","tool_use_id":"call_read1","content":"package a","is_error":false}]',NULL,'{"runId":"run_s1","toolCallId":"call_read1","toolName":"read","status":"success"}',NULL,'0001-0002','2026-10-22T10:00:03.500Z','2026-10-22T10:00:03.500Z');
INSERT INTO messages VALUES('msg_tr_grep','sess_1000000000000_synthparent01','tool_result','[{"type":"tool_result","tool_use_id":"call_grep1","content":"grep: bad pattern","is_error":true}]',NULL,'{"runId":"run_s1","toolCallId":"call_grep1","toolName":"grep","status":"error"}',NULL,'0001-0003','2026-10-22T10:00:03.600Z','2026-10-22T10:00:03.600Z');
INSERT INTO messages VALUES('msg_a2','sess_1000000000000_synthparent01','assistant','[{"type":"tool_use","id":"call_agent1","name":"agent","input":{"action":"create","prompt":"Find the TODOs","taskTitle":"Find TODOs","agentName":"explorer"},"startTime":"2026-10-22T10:00:08.000Z"},{"type":"tool_use","id":"call_exec1","name":"exec","input":{"command":"go test ./...","cwd":"/home/user/synthetic"},"startTime":"2026-10-22T10:00:08.100Z"}]',NULL,'{"runId":"run_s1"}','{"runId":"run_s1"}','0001-0004','2026-10-22T10:00:08.200Z','2026-10-22T10:00:08.300Z');
INSERT INTO messages VALUES('msg_tr_exec','sess_1000000000000_synthparent01','tool_result','[{"type":"tool_result","tool_use_id":"call_exec1","content":"FAIL\n","structuredContent":{"type":"finished","status":"completed","command":"go test ./...","exitCode":1,"wallTimeMs":2500},"is_error":false}]',NULL,'{"runId":"run_s1","toolCallId":"call_exec1","toolName":"exec","status":"success"}',NULL,'0001-0005','2026-10-22T10:00:11.000Z','2026-10-22T10:00:11.000Z');
INSERT INTO messages VALUES('msg_a3','sess_1000000000000_synthparent01','assistant','[{"type":"tool_use","id":"call_glob1","name":"glob","input":{"pattern":"**/*.go"},"startTime":"2026-10-22T10:00:20.000Z"},{"type":"tool_use","id":"call_mcp1","name":"some_mcp_tool","input":{"q":"x"},"startTime":"2026-10-22T10:00:20.001Z"}]',NULL,'{"runId":"run_s1"}','{"runId":"run_s1"}','0001-0006','2026-10-22T10:00:20.100Z','2026-10-22T10:00:20.200Z');
INSERT INTO messages VALUES('msg_a4','sess_1000000000000_synthparent01','assistant','[{"type":"text","text":"Done: the build fails, one TODO found.","startTime":"2026-10-22T10:00:29.000Z","endTime":"2026-10-22T10:00:30.000Z"}]',NULL,NULL,'{"runId":"run_s1"}','0001-0007','2026-10-22T10:00:29.500Z','2026-10-22T10:00:30.000Z');

-- Child (sub-agent) session, run_c1.
INSERT INTO messages VALUES('msg_user_c1','sess_1000000000001_synthchild001','user','[{"type":"text","text":"Find the TODOs"}]',NULL,NULL,'{"runId":"run_c1"}','0002-0000','2026-10-22T10:00:09.100Z','2026-10-22T10:00:12.000Z');
INSERT INTO messages VALUES('msg_ac1','sess_1000000000001_synthchild001','assistant','[{"type":"text","text":"One TODO in a.go.","startTime":"2026-10-22T10:00:11.000Z","endTime":"2026-10-22T10:00:12.000Z"}]',NULL,NULL,'{"runId":"run_c1"}','0002-0001','2026-10-22T10:00:11.500Z','2026-10-22T10:00:12.000Z');

-- Fork session (history repeated under new ids).
INSERT INTO messages VALUES('msg_user_f1','sess_1000000000002_synthfork0001','user','[{"type":"text","text":"Search the code and spawn a helper."}]',NULL,NULL,'{"runId":"run_s1"}','0003-0000','2026-10-22T10:05:00.100Z','2026-10-22T10:05:00.100Z');

INSERT INTO usage_run_stats VALUES('run_s1','sess_1000000000000_synthparent01','openrouter','anthropic/claude-sonnet-4.5','completed','2026-10-22T10:00:00.100Z','2026-10-22T10:00:30.000Z',29900,20000,500,20500,12000,3000,'{"inputCostUsd":0.01,"outputCostUsd":0.0023,"cacheReadCostUsd":0,"cacheWriteCostUsd":0,"totalCostUsd":0.0123,"quality":"exact"}','{"providerId":"openrouter","modelId":"anthropic/claude-sonnet-4.5","currency":"USD","source":"catalog"}','2026-10-22T10:00:30.100Z','2026-10-22T10:00:30.100Z');
INSERT INTO usage_run_stats VALUES('run_c1','sess_1000000000001_synthchild001','openrouter','anthropic/claude-haiku-4.5','completed','2026-10-22T10:00:09.200Z','2026-10-22T10:00:12.000Z',2800,1000,50,1050,NULL,NULL,'{"inputCostUsd":0,"outputCostUsd":0,"cacheReadCostUsd":0,"cacheWriteCostUsd":0,"totalCostUsd":0,"quality":"missing_price"}','{"providerId":"openrouter","modelId":"anthropic/claude-haiku-4.5","currency":"USD","source":"unknown"}','2026-10-22T10:00:12.100Z','2026-10-22T10:00:12.100Z');

INSERT INTO usage_ledger VALUES('usage_run_s1','sess_1000000000000_synthparent01','run_s1','openrouter','anthropic/claude-sonnet-4.5','{"promptTokens":20000,"completionTokens":500,"totalTokens":20500,"cacheReadTokens":12000,"cacheWriteTokens":3000,"lastCall":{"promptTokens":5000,"completionTokens":100,"totalTokens":5100,"cacheReadTokens":4000}}',NULL,'2026-10-22T10:00:30.050Z');
INSERT INTO usage_ledger VALUES('plugin_ledger_synth0001','sess_1000000000000_synthparent01','run_s1','openrouter','anthropic/claude-sonnet-4.5','{"promptTokens":100,"completionTokens":20,"totalTokens":120,"cacheReadTokens":0}',NULL,'2026-10-22T10:00:05.000Z');
INSERT INTO usage_ledger VALUES('usage_run_c1','sess_1000000000001_synthchild001','run_c1','openrouter','anthropic/claude-haiku-4.5','{"promptTokens":1000,"completionTokens":50,"totalTokens":1050}',NULL,'2026-10-22T10:00:12.050Z');
-- Mirror of a run whose usage_run_stats row is absent: stands in under run:<id>.
INSERT INTO usage_ledger VALUES('usage_run_orph','sess_1000000000002_synthfork0001','run_orph','openrouter','anthropic/claude-sonnet-4.5','{"promptTokens":500,"completionTokens":10,"totalTokens":510,"cacheReadTokens":100}',NULL,'2026-10-22T10:05:30.000Z');
