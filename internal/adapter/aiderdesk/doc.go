// Package aiderdesk is the UNREGISTERED skeleton adapter for AiderDesk
// (hotovo/aider-desk), the desktop app that drives aider and its own agent
// mode (surface-gap FU-147, S-5, live check LCR-60). It follows the
// skeleton convention of docs/new-adapter-checklist.md section 2.2: the
// store's location and field names are grounded from vendor source, but no
// byte of a real store has been read, so ParseSessionFile refuses to guess
// (an empty result with one warning naming testdata/aiderdesk/README.md).
//
// # Layout (grounded from the @aiderdesk/aiderdesk 0.89.0 npm bundle,
// out/runner.js, read 2026-10-28; nothing observed on a live install)
//
//	AIDER_DESK_DIR       env, else ".aider-desk"                      [SOURCE]
//	AIDER_DESK_HOME_DIR  env, else <os home>/AIDER_DESK_DIR           [SOURCE]
//	<home>/mcp-servers.json   global MCP servers {mcpServers: {...}}  [SOURCE + docs]
//	<project>/.aider-desk/mcp-servers.json  project MCP servers       [SOURCE + docs]
//	<project>/.aider-desk/tasks/<task id>/context.json                [SOURCE]
//	    {version, contextMessages: [...], contextFiles: [...]},
//	    rewritten whole and atomically on every save (ContextManager.save)
//	<project>/.aider-desk/tasks/<task id>/settings.json   task data    [SOURCE]
//	    (name, mainModel, provider, model, aiderTotalCost, agentTotalCost,
//	    worktree; UNVERIFIED whether it can carry a credential)
//	<project>/.aider-desk/tasks/<task id>/context.pre-compaction.NNN.json
//	    snapshots before a compaction                                  [SOURCE]
//	<Electron userData>/aider-desk.db  unfinished-run state            [SOURCE]
//
// A contextMessages entry (UNVERIFIED beyond the field names): id (uuid),
// role (user / assistant / tool), content (a string, or AI SDK parts:
// text, reasoning, tool-call {toolCallId, toolName, input}, tool-result
// {toolCallId, toolName, output: {type, value}}), timestamp (Unix ms),
// promptContext, and usageReport {model, sentTokens, receivedTokens,
// cacheWriteTokens, cacheReadTokens, messageCost}. Whether sentTokens is
// gross or net of cache reads is not grounded (the compaction code adds
// cacheReadTokens on top of it, which suggests net).
//
// # Off limits (never read)
//
//	the app's own settings store under its Electron userData (provider API
//	keys), mcp-oauth.json, aider-desk.db, memory.db, a task's settings.json
//	until it is grounded credential-free.
//
// # Why it is not registered (lane w8-writers stop)
//
// Registration (defaults slot, EnabledAdapters, models.Tool*, registry
// row, components catalogue) also needs the tooltax rows for AiderDesk's
// tool names, which regenerates the taxonomy backfill migration, and a
// grounded process basename for internal/procmodel; the lane may change
// neither a migration nor guess a basename, so the wiring waits on LCR-60
// and that decision.
package aiderdesk
