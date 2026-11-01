# secp4 hook payloads

PreToolUse payloads in the shapes Claude Code and Codex send to a command
hook, used by `cmd/observer` `TestPT39OtherRepoCommitEndToEnd` (lane SEC-P4,
PT-39). They are reconstructed from the hosts' documented payload fields
(Claude Code hooks reference; Codex hooks with `tool_name` and
`tool_input.command`), not captured from a live session: the live run is
owed (PT-39 live checks). `{{CWD}}`, `{{COMMAND}}` and `{{HOME}}` are filled
in by the test. The Codex payload carries a Windows working directory, so
the hook adds the PowerShell second reading (`Set-Location`).
