# Claude Code cloud transcripts (anonymized fixtures)

Two small transcripts in the ordinary Claude Code JSONL format, one per
`entrypoint` value a Claude Code cloud session was observed to write
(cloud-agents lane CA-B4; grounding in
`docs/plans/cloud-agents/grounding/claude-code-cloud-2026-10-31.md`
section 2):

| File | `entrypoint` | Source |
|---|---|---|
| `remote_desktop.jsonl` | `remote_desktop` | recorded from the lane CA-B4 session's own transcript (Claude Code 2.1.316, a cloud session started from the Claude Desktop app), then anonymized |
| `remote.jsonl` | `remote` | the same anonymized lines re-labelled `remote`, the value lane CA-A2 observed as `CLAUDE_CODE_ENTRYPOINT` in an MCP-started cloud session; `clientPlatform` is dropped because that session was not a desktop client |

## How they were anonymized

`anonymize.py` (here, run with `python3 -I anonymize.py <transcript>
<entrypoint> <out>`) is an allow-list: it builds each output line from
scratch and copies only structure from the real transcript.

Kept from the real transcript: the line types and the order used (user
prompt, assistant `tool_use`, user `tool_result`, `last-prompt`), the
envelope key names, `entrypoint`, `version`, `userType`, `clientPlatform`,
the assistant `model`, `stop_reason` and the token NUMBERS of `usage`
(`input_tokens`, `cache_creation_input_tokens`, `cache_read_input_tokens`,
`output_tokens`, `service_tier`).

Replaced: every id (`sessionId`, `uuid`, `parentUuid`, `promptId`,
`leafUuid` become deterministic UUIDv5 values; `requestId`, `message.id` and
the tool-use id become `*_fixture<entrypoint>`), `cwd`
(`/home/user/example-repo`), `gitBranch` (`claude/example-branch`), the
timestamps, the prompt text, the tool input (`git status`) and the tool
output.

Dropped: everything else, including thinking blocks, attachments,
`serverClassifierRequest` / `serverClassifierContext`, `wireIngestContext`,
`wireToolInputs`, `toolUseResult`, `permissionDecision`, `sandboxed`,
`effort` fields and the `usage` sub-objects other than the numbers above.

The transcript never carries the `cse_...` cloud session id
(`CLAUDE_CODE_REMOTE_SESSION_ID` lives only in the process and hook
environment), and no environment value was copied. The output was checked
for the account e-mail, the organization and repository names, `cse_`,
`session_` URLs and `/root` paths; none occur.
