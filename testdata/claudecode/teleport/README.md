# Claude Code teleport transcript fixture (synthetic)

`teleport.jsonl` reproduces the SHAPE of the local transcript `claude
--teleport` writes when a Claude Code cloud session is pulled into a local
terminal, as live-grounded on 2026-10-31 (CLI 2.1.306,
`docs/plans/cloud-agents/grounding/probe-teleport-2026-10-31.md`). Every
value is synthetic: ids, paths, prompts, answers and token counts were
written by hand; nothing was copied from a real session.

Shape kept from the probe:

- one NEW local session id on every line, every line `entrypoint: "cli"`
  with the local `cwd` and branch;
- copied cloud assistant lines carry `"remoteSourced": true`, an original
  `message.id` and `usage`, cloud-era timestamps and no `requestId`;
- an `attachment` of type `remote_session_change` whose `url` is the cloud
  session's `https://claude.ai/code/session_...`;
- the local continuation after it has no `remoteSourced` and carries a
  `requestId`.

Not grounded, so not asserted by the tests: whether copied cloud USER lines
also carry `remoteSourced` (the probe saw it on assistant lines). Line 1 is a
copied user prompt without the flag; line 3, a copied tool result, carries
it.

Used by `internal/adapter/claudecode/teleport_test.go`.
