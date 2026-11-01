// Package deepagents implements a SQLite adapter for LangChain's Deep Agents
// Code CLI ("dcode", PyPI deepagents-code) session store at
// ~/.deepagents/.state/sessions.db.
//
// # Store shape
//
// dcode runs a local LangGraph server whose checkpointer is a SQLite file
// (langgraph-checkpoint-sqlite): a `checkpoints` table (one row per graph
// step, a UUIDv6 checkpoint_id, a JSON `metadata` BLOB, a msgpack
// `checkpoint` BLOB) and a `writes` table (one row per channel write, value a
// msgpack BLOB). dcode adds its own tables beside them
// (dcode_thread_workspaces carries the thread's cwd and project root;
// dcode_thread_names the title). The layout is identical on Linux, macOS and
// Windows (live-grounded 2026-10-21, deepagents-code 0.1.87).
//
// A thread (== a dcode session; the thread_id is the UUIDv7 `dcode -r <id>`
// accepts, used verbatim as the session id) is rebuilt by replaying the
// `messages` channel writes in (checkpoint_id, task_id, idx) order and folding
// them by message id, exactly as LangGraph's add_messages reducer — and the
// vendor's own thread-inspector skill — do. The `messages` channel is a delta
// channel: the live conversation is NOT stored inline in the checkpoint
// blobs, so the writes are the source of truth. Each write is a msgpack list
// of pydantic-v2 extensions (ext code 5) of langchain_core message classes;
// msgpack.go decodes them without importing or executing anything.
//
// # Tokens
//
// Every AIMessage carries usage_metadata in LangChain's normalized shape:
// input_tokens is the SUM of all input classes (cache reads and writes
// included) and output_tokens the sum of all output classes (reasoning
// included), with the classes in input_token_details / output_token_details.
// The adapter nets both at the boundary: input = input − cache_read −
// cache_creation, output = output − reasoning, reasoning carried separately
// (billed once at the output rate). The OpenRouter-reported dollar cost
// (response_metadata.cost) rides along as EstimatedCostUSD. Per-call cache
// tokens feed the Tier-2 cachetrack engine.
//
// # Sub-agents
//
// The `task` tool runs a sub-agent as a nested graph under checkpoint_ns
// `tools:<task id>`. Its messages are replayed like the root's and emitted
// on the PARENT session flagged IsSidechain with ActionMetadata.AgentID =
// the task id; the child's forked copy of the parent conversation (same
// message ids) is dropped, so nothing is counted twice. A subagent_stop
// bracket closes the run once the parent holds the `task` result.
//
// # Other channels read
//
// `_last_model_request_at` (request start, same task as the AI message) to
// the step's end checkpoint gives native GenMs. `__interrupt__` /
// `__resume__` human-in-the-loop pairs become permission_request /
// permission_denied rows (dcode's hook-protocol interrupts on the same
// channels are skipped). dcode_thread_workspaces.workspace_config_json
// `interactive` gives the cli surface host (dcode / dcode-headless).
//
// # Cursor and files never read
//
// The incremental cursor is the clock embedded in the newest checkpoint id
// in any namespace (declared CursorWatermark). The adapter never reads
// `.state/auth.json`, `.state/chatgpt-auth.json` (a ChatGPT OAuth token
// cache), `config.toml`, any `mcp.json`, the `_session_cost_transfers`
// channel (a sub-agent's usage restated for the parent's cost) or the
// multi-megabyte `_quickjs_snapshot_payload` channel writes. The only file
// read besides sessions.db is `.state/update_state.json` (`seen_version`, the
// install-level tool-version fallback).
//
// # Session handoff
//
// transcript.go implements ReadTranscript / ReadTranscriptFull from the same
// root-namespace replay. See docs/deepagents-adapter.md.
package deepagents
