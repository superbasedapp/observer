-- Synthetic IBM Bob Shell bob.db rows against schema.sql. Hand-written:
-- the SHAPES (tasks.env keys, message data keys, toolCalls / toolUsage
-- envelopes, _meta fields, epoch-ms timestamps, the whole-turn shared
-- messages.created_at, the empty launch placeholder task) are copied from
-- the two live 2026-10-21 captures (WSL + Windows, bobshell 2.0.6), but
-- every id, path, prompt and output is invented. See README.md.

-- 1. The placeholder task Bob creates on every launch (no messages).
INSERT INTO tasks (id, project_id, parent_id, title, status, first_message, directory, env, costs, created_at, updated_at, task_type)
VALUES ('f0000000000000000000000000000001', 'file:/home/user/proj', NULL, '', 'active', NULL, '',
 '{"id":"f0000000000000000000000000000001","workspace":"/home/user/proj","scheme":"file","language":"en","staticEnvInfo":{"primaryWorkspace":"/home/user/proj","systemInfo":{"platform":"linux","release":"6.6.0-microsoft-standard-WSL2","arch":"x64","shell":"/bin/bash"}}}',
 '{"cost":0,"contextTokens":0}', 1792554440549, 1792554440549, 'normal');

-- 2. A root task (WSL-shaped) exercising every result outcome.
INSERT INTO tasks (id, project_id, parent_id, title, status, first_message, directory, env, costs, created_at, updated_at, task_type)
VALUES ('a1b2c3d4e5f60718293a4b5c6d7e8f90', 'file:/home/user/proj', NULL, 'Create hello.py, run it, then delete it.', 'active', 'Create hello.py, run it, then delete it.', '',
 '{"id":"a1b2c3d4e5f60718293a4b5c6d7e8f90","workspace":"/home/user/proj","scheme":"file","language":"en","staticEnvInfo":{"primaryWorkspace":"/home/user/proj","systemInfo":{"platform":"linux","release":"6.6.0-microsoft-standard-WSL2","arch":"x64","shell":"/bin/bash"}},"model":{"id":"premium-ide","family":"","provider":"","version":"","contextWindow":270000,"maxOutputTokens":64000,"supportsImages":true},"modeId":"agent","task":[{"description":"Create hello.py","state":"done"}]}',
 '{"cost":0.13,"contextTokens":11780}', 1792554444156, 1792554514226, 'normal');

INSERT INTO messages (id, task_id, role, data, created_at) VALUES
('10000000000000000000000000000001', 'a1b2c3d4e5f60718293a4b5c6d7e8f90', 'system',
 '{"role":"system","content":"<role_definition>\nYou are Bob.\n</role_definition>","id":"10000000000000000000000000000001","_meta":{}}', 1792554514225),
('10000000000000000000000000000002', 'a1b2c3d4e5f60718293a4b5c6d7e8f90', 'user',
 '{"role":"user","content":"Create hello.py, run it, then delete it.","envContext":"<environment_details>\n<current_mode>\nAgent\n</current_mode>\n</environment_details>\n","availableTools":["read_file","write_file","execute_command","update_todo_list","spawn_subagent"],"_meta":{"mode":{"id":"agent","name":"Agent"},"timestamp":1792554488090},"id":"10000000000000000000000000000002"}', 1792554514225),
('10000000000000000000000000000003', 'a1b2c3d4e5f60718293a4b5c6d7e8f90', 'assistant',
 '{"role":"assistant","content":"","id":"10000000000000000000000000000003","_meta":{"timestamp":1792554489498,"spend":{"cost":0.020918,"contextTokens":10459}},"toolCalls":[{"id":"tooluse_todo1","name":"update_todo_list","arguments":{"todos":"\n[-] Create hello.py\n[ ] Delete it\n"}}]}', 1792554514225),
('10000000000000000000000000000004', 'a1b2c3d4e5f60718293a4b5c6d7e8f90', 'tool',
 '{"role":"tool","content":"To do list updated: 2 items total.","toolUsage":{"signature":{"id":"tooluse_todo1","name":"update_todo_list","arguments":{"todos":"\n[-] Create hello.py\n[ ] Delete it\n"},"isError":false},"permission":"todo","isOutsideWorkspace":false},"_meta":{"todos":[{"description":"Create hello.py","state":"inprogress"},{"description":"Delete it","state":"pending"}],"durationMs":3755,"timestamp":1792554494020,"processes":[]},"id":"10000000000000000000000000000004"}', 1792554514225),
('10000000000000000000000000000005', 'a1b2c3d4e5f60718293a4b5c6d7e8f90', 'assistant',
 '{"role":"assistant","content":"","id":"10000000000000000000000000000005","_meta":{"timestamp":1792554495197,"spend":{"cost":0.021228,"contextTokens":10614}},"toolCalls":[{"id":"tooluse_write1","name":"write_file","arguments":{"path":"/home/user/proj/hello.py","content":"print(\"hi\")\n","line_count":1}}]}', 1792554514225),
('10000000000000000000000000000006', 'a1b2c3d4e5f60718293a4b5c6d7e8f90', 'tool',
 '{"role":"tool","content":"Created file: hello.py","toolUsage":{"signature":{"id":"tooluse_write1","name":"write_file","arguments":{"path":"/home/user/proj/hello.py","content":"print(\"hi\")\n","line_count":1},"isError":false},"permission":"edit","isOutsideWorkspace":false},"_meta":{"durationMs":1175,"timestamp":1792554496962,"processes":[]},"id":"10000000000000000000000000000006"}', 1792554514225),
('10000000000000000000000000000007', 'a1b2c3d4e5f60718293a4b5c6d7e8f90', 'assistant',
 '{"role":"assistant","content":"","id":"10000000000000000000000000000007","_meta":{"timestamp":1792554498136,"spend":{"cost":0.021472,"contextTokens":10736}},"toolCalls":[{"id":"tooluse_cmd1","name":"execute_command","arguments":{"command":"python3 hello.py","cwd":"/home/user/proj"}}]}', 1792554514225),
('10000000000000000000000000000008', 'a1b2c3d4e5f60718293a4b5c6d7e8f90', 'tool',
 '{"role":"tool","content":"NameError: name is not defined","toolUsage":{"signature":{"id":"tooluse_cmd1","name":"execute_command","arguments":{"command":"python3 hello.py","cwd":"/home/user/proj"},"isError":false},"permission":"execute","commandUse":{"unverifiable":false,"commands":["python3 hello.py"],"requiresSecurityApproval":false},"isOutsideWorkspace":false},"_meta":{"cwd":".","exitCode":1,"durationMs":3312,"timestamp":1792554501791,"processes":[]},"id":"10000000000000000000000000000008"}', 1792554514225),
('10000000000000000000000000000009', 'a1b2c3d4e5f60718293a4b5c6d7e8f90', 'assistant',
 '{"role":"assistant","content":"","id":"10000000000000000000000000000009","_meta":{"timestamp":1792554504710,"spend":{"cost":0.02203,"contextTokens":11015}},"toolCalls":[{"id":"tooluse_edit1","name":"search_and_replace","arguments":{"path":"/home/user/proj/hello.py","search":"print(\"hi\")","replace":"print(\"hello\")"}}]}', 1792554514226),
('10000000000000000000000000000010', 'a1b2c3d4e5f60718293a4b5c6d7e8f90', 'tool',
 '{"role":"tool","content":"No match found for the search text.","toolUsage":{"signature":{"id":"tooluse_edit1","name":"search_and_replace","arguments":{"path":"/home/user/proj/hello.py","search":"print(\"hi\")","replace":"print(\"hello\")"},"isError":true},"permission":"edit","isOutsideWorkspace":false},"_meta":{"durationMs":26,"timestamp":1792554504951,"processes":[]},"id":"10000000000000000000000000000010"}', 1792554514226),
('10000000000000000000000000000011', 'a1b2c3d4e5f60718293a4b5c6d7e8f90', 'assistant',
 '{"role":"assistant","content":"Spawning a helper.","id":"10000000000000000000000000000011","_meta":{"timestamp":1792554506019,"spend":{"cost":0.022466,"contextTokens":11233}},"toolCalls":[{"id":"tooluse_sub1","name":"spawn_subagent","arguments":{"description":"Inspect the project","name":"general"}},{"id":"tooluse_mcp1","name":"mcp__docs__lookup","arguments":{"q":"hello"}}]}', 1792554514226),
('10000000000000000000000000000012', 'a1b2c3d4e5f60718293a4b5c6d7e8f90', 'tool',
 '{"role":"tool","content":"The project has a README.","toolUsage":{"signature":{"id":"tooluse_sub1","name":"spawn_subagent","arguments":{"description":"Inspect the project","name":"general"},"isError":false},"permission":"subagent","isOutsideWorkspace":false},"_meta":{"subagentId":"c0ffee00c0ffee00c0ffee00c0ffee01","durationMs":4000,"timestamp":1792554510019},"id":"10000000000000000000000000000012"}', 1792554514226),
('10000000000000000000000000000013', 'a1b2c3d4e5f60718293a4b5c6d7e8f90', 'tool',
 '{"role":"tool","content":"lookup result","toolUsage":{"signature":{"id":"tooluse_mcp1","name":"mcp__docs__lookup","arguments":{"q":"hello"},"isError":false},"permission":"mcp","isOutsideWorkspace":false},"_meta":{"durationMs":12,"timestamp":1792554510031},"id":"10000000000000000000000000000013"}', 1792554514226),
('10000000000000000000000000000014', 'a1b2c3d4e5f60718293a4b5c6d7e8f90', 'assistant',
 '{"role":"assistant","content":"All done.","id":"10000000000000000000000000000014","_meta":{"timestamp":1792554513294,"spend":{"cost":0.02356,"contextTokens":11780}},"stop":true}', 1792554514226),
('10000000000000000000000000000015', 'a1b2c3d4e5f60718293a4b5c6d7e8f90', 'assistant',
 '{"role":"assistant","content":"Stopped: the task was cancelled.","id":"10000000000000000000000000000015","_meta":{"notAi":true,"timestamp":1792554513999},"stop":true}', 1792554514226);

-- 3. A subagent child task spawned by task 2 (task_type subagent).
INSERT INTO tasks (id, project_id, parent_id, title, status, first_message, directory, env, costs, created_at, updated_at, task_type)
VALUES ('c0ffee00c0ffee00c0ffee00c0ffee01', 'file:/home/user/proj', 'a1b2c3d4e5f60718293a4b5c6d7e8f90', 'Inspect the project', 'completed', 'Inspect the project', '',
 '{"id":"c0ffee00c0ffee00c0ffee00c0ffee01","workspace":"/home/user/proj","scheme":"file","language":"en","model":{"id":"premium-ide","contextWindow":270000},"modeId":"agent"}',
 '{"cost":0.01,"contextTokens":5000}', 1792554506500, 1792554510000, 'subagent');

INSERT INTO messages (id, task_id, role, data, created_at) VALUES
('20000000000000000000000000000001', 'c0ffee00c0ffee00c0ffee00c0ffee01', 'user',
 '{"role":"user","content":"Inspect the project","_meta":{"timestamp":1792554507000},"id":"20000000000000000000000000000001"}', 1792554510000),
('20000000000000000000000000000002', 'c0ffee00c0ffee00c0ffee00c0ffee01', 'assistant',
 '{"role":"assistant","content":"","id":"20000000000000000000000000000002","_meta":{"timestamp":1792554507500,"spend":{"cost":0.005,"contextTokens":2500}},"toolCalls":[{"id":"tooluse_read1","name":"read_file","arguments":{"path":"/home/user/proj/README.md"}}]}', 1792554510000),
('20000000000000000000000000000003', 'c0ffee00c0ffee00c0ffee00c0ffee01', 'tool',
 '{"role":"tool","content":"# proj","toolUsage":{"signature":{"id":"tooluse_read1","name":"read_file","arguments":{"path":"/home/user/proj/README.md"},"isError":false},"permission":"read","isOutsideWorkspace":false},"_meta":{"durationMs":5,"timestamp":1792554507600},"id":"20000000000000000000000000000003"}', 1792554510000),
('20000000000000000000000000000004', 'c0ffee00c0ffee00c0ffee00c0ffee01', 'assistant',
 '{"role":"assistant","content":"The project has a README.","id":"20000000000000000000000000000004","_meta":{"timestamp":1792554509000,"spend":{"cost":0.005,"contextTokens":2500}},"stop":true}', 1792554510000);

-- 4. A Windows-shaped task: raw C:\ workspace, env.model as a bare string,
--    a hidden replay user message, and array-form user content.
INSERT INTO tasks (id, project_id, parent_id, title, status, first_message, directory, env, costs, created_at, updated_at, task_type)
VALUES ('b7e1d2c3a4f5061728394a5b6c7d8e9f', 'file:C:\Users\user\proj', NULL, 'List the files', 'active', 'List the files', '',
 '{"id":"b7e1d2c3a4f5061728394a5b6c7d8e9f","workspace":"C:\\Users\\user\\proj","scheme":"file","language":"en","staticEnvInfo":{"primaryWorkspace":"C:\\Users\\user\\proj","systemInfo":{"platform":"win32","release":"10.0.26200","arch":"x64","shell":"powershell.exe"}},"model":"premium-ide","modeId":"agent"}',
 '{"cost":0.02,"contextTokens":10000}', 1792554599000, 1792554602000, 'normal');

INSERT INTO messages (id, task_id, role, data, created_at) VALUES
('30000000000000000000000000000001', 'b7e1d2c3a4f5061728394a5b6c7d8e9f', 'user',
 '{"role":"user","content":"replayed after compaction","_meta":{"hide":true,"timestamp":1792554599500},"id":"30000000000000000000000000000001"}', 1792554602000),
('30000000000000000000000000000002', 'b7e1d2c3a4f5061728394a5b6c7d8e9f', 'user',
 '{"role":"user","content":[{"type":"text","text":"List the files"},{"type":"image","image":"<omitted>"}],"_meta":{"timestamp":1792554600000},"id":"30000000000000000000000000000002"}', 1792554602000),
('30000000000000000000000000000003', 'b7e1d2c3a4f5061728394a5b6c7d8e9f', 'assistant',
 '{"role":"assistant","content":"Listing.","id":"30000000000000000000000000000003","_meta":{"timestamp":1792554601000,"spend":{"cost":0.02,"contextTokens":10000}},"toolCalls":[{"id":"tooluse_ls1","name":"list_files","arguments":{"path":"C:\\Users\\user\\proj","recursive":false}}]}', 1792554602000),
('30000000000000000000000000000004', 'b7e1d2c3a4f5061728394a5b6c7d8e9f', 'tool',
 '{"role":"tool","content":"a.txt","toolUsage":{"signature":{"id":"tooluse_ls1","name":"list_files","arguments":{"path":"C:\\Users\\user\\proj","recursive":false},"isError":false},"permission":"read","isOutsideWorkspace":false},"_meta":{"durationMs":3,"timestamp":1792554601200},"id":"30000000000000000000000000000004"}', 1792554602000);
