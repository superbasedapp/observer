# JetBrains AI Assistant task-history fixture (`aia-task-history/`)

Anonymized from the operator's live IntelliJ IDEA 2026.2 run
(2026-09-03, Windows, four ACP agents driven through AI Assistant with
the five-turn prompt kit). This directory plays the role of the JetBrains
**vendor config root** (`%APPDATA%\JetBrains` / `~/Library/Application
Support/JetBrains` / `~/.config/JetBrains`): it holds one product config
directory, `IntelliJIdea2026.2/`, whose `aia-task-history/` is the store.

## What the live store holds

Per task `<task-uuid>.{agentsession,events,usage,lastid}`:

| File | Content | Read by Observer? |
|---|---|---|
| `.agentsession` | ONE line `acp.registry.<agent>:<agent's own session id>` | **Yes** — the only file the surface enricher reads |
| `.events` | line 1 `AUI_EVENTS_V1`, then one base64(JSON) UI render event per line (`ChatSessionUserPromptEvent`, `ChatSessionMessageBlockEvent` wrapping `ToolBlockUpdatedEvent` / `MarkdownBlockUpdatedEvent` / `TerminalBlockUpdatedEvent` / `FileChangesBlockUpdatedEvent` / `ViewFilesBlockUpdatedEvent` / `McpBlockUpdatedEvent` / `AgentThoughtBlockUpdatedEvent` / `ResultBlockUpdatedEvent`). Carries prompt text, tool titles/commands/diffs and terminal output. **No tokens, no model, no cost** — grounded across all 7 live tasks. | No — every agent's own store already has the conversation; parsing this would double-count it |
| `.usage` | `{"used":N,"size":M}` — context-WINDOW occupancy vs the agent's window size | No — not tokens; no session field exists for window occupancy (documented gap) |
| `.lastid` | the last event id | No |

A task whose agent never started a session (authentication / terms-of-
service pending) has `.events` + `.lastid` but **no** `.agentsession`;
three of the seven live tasks were of that kind and are represented by
`t-noagent.*` here.

## Mapping grounded on the live run

| `acp.registry.<agent>` | Owning tool | Session id in the token | Identity? |
|---|---|---|---|
| `junie` | `junie` | `session-YYMMDD-HHMMSS-xxxx` | = `sessions.id` verbatim |
| `claude-acp` | `claude-code` | transcript uuid | = `sessions.id` verbatim |
| `codex-acp` | `codex` | rollout thread uuid (v7) | = `sessions.id` verbatim |
| `github-copilot` | `copilot-cli` | session-state dir uuid | = `sessions.id` verbatim |

## Anonymization

Task uuids → `t-<agent>`; every session id → a fixture-shaped id of the
same form; the `.usage` numbers are kept (not identifying). No `.events`
file from the live run is included (they embed the workspace path and
the operator's prompt text); `t-noagent.events` is a two-line synthetic
stand-in that carries only the header and one authentication block.
