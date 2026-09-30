# cursor-agent debug-log fixtures

Anonymized excerpts of real `cursor-agent` debug logs
(`/tmp/cursor-agent-logs-<uid>/session-*.log`, one file per process), captured
read-only from demo node-1 on 2026-09-27. Only the record kinds the adapter reads
are kept (turn start/outcome, request create, retry diagnostics, hook-executed
analytics, conversation init/dispose); every UUID was remapped, the home dir
renamed to `/home/dev`, and MCP / sandbox / statsig noise dropped. No prompt
text, account data or tokens are present.

| file | shape |
| --- | --- |
| `session-2026-09-27T11-12-48-669Z-141379-1.log` | cursor-agent 2026.09.18, INTERACTIVE, one "hi" prompt, model `default` (Auto). The turn hit `LostConnection` on 3 attempts (initial + 2 resumes); the user ran `/quit` while Cursor was still retrying. No `agent_cli.turn.outcome`, no `stop`, no `afterAgentResponse` - so no usage exists anywhere locally. |
| `session-2026-09-21T19-53-18-627Z-55322-1.log` | cursor-agent 2026.09.18, HEADLESS (`-p`) resume turn that finished: `agent_cli.turn.outcome` carries net input + both cache buckets; no stop / afterAgentResponse hook ever runs in headless mode. |
