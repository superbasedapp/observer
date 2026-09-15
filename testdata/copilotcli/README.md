# testdata/copilotcli — GitHub Copilot CLI fixtures

Live-capture fixtures for `internal/adapter/copilotcli`. Every other
Copilot CLI test builds its JSONL inline in `adapter_test.go`; the
directories here exist for shapes that are only worth pinning against a
real vendor capture.

## `jetbrains/1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d/`

**Captured**: 2026-09-03 from `~/.copilot/session-state/` on the
operator's Windows 11 box. **Producer**: GitHub Copilot CLI **1.0.79**,
driven as the `github-copilot` ACP agent by **IntelliJ IDEA 2026.2 AI
Assistant** (not from a terminal). **Prompt**: the five-turn step-in kit
(summarise the project / create + run `hello_world.py` / edit to "Hello
Universe" + run / delete / verify).

**Why it exists**: it is the only grounded capture of a
`workspace.yaml` whose `client_name` is `JetBrains.IntelliJ IDEA` — the
single discriminator `internal/adapter/copilotcli/surface.go` resolves
into a `models.SessionSurface{Surface: ide, SurfaceHost: jetbrains-idea}`
stamp. Nothing else in the session record distinguishes an IDE-driven
run from a terminal one: `session.start.data.producer` is
`"copilot-agent"` and `copilotVersion` is just the CLI build on both.

| File | Content |
|------|---------|
| `events.jsonl` | The first 30 events of the live stream, trimmed + anonymised (see below) — 2 full assistant turns |
| `workspace.yaml` | The session's own workspace file, anonymised, `client_name` kept verbatim |

**What the fixture yields** (`TestJetBrainsFixtureParse`):

- 1 `SessionSurface` — `ide` / `jetbrains-idea`, `Hosted=false` (an
  ordinary self-report; the JetBrains `aia-task-history` enricher emits
  the separate `Hosted=true` stamp for the same session).
- 2 `TokenEvent`s (the 2 `assistant.message` rows' `outputTokens`),
  model `gpt-5.6-luna`.
- `ProjectRoot` `C:\Users\dev\projects\demo` — `workspace.yaml`'s
  `git_root`, which wins over the in-stream `session.start.context.cwd`.
- 2 `user_prompt`, 3 `permission_request` and the tool rows for the
  turn's `glob` / `rg` / `powershell` calls.

**Trimming** (documented so the counts above are reproducible):

- Only source lines `0-2`, `4-29` and `78` are kept. Line 3 is the
  33 KB system prompt (vendor boilerplate, no shape the parser needs);
  lines 30-77 are three more turns of the same shapes.
- `reasoningOpaque` / `encryptedContent` / `apiCallId` values are
  replaced with `"<redacted-opaque-blob>"` — provider-encrypted blobs
  (the first two multi-KB, `apiCallId` a ~100-byte base64 token of the
  same class) that the adapter never decodes.
- The deferred-tool reminder in the second `user.message` is truncated
  to its first 400 characters.

**Anonymisation**: the operator's Windows account name, the real
workspace path (rewritten to `C:\Users\dev\projects\demo\…`, in both
backslash and forward-slash spellings), the real session UUID and the
git head commit are all replaced. No credential or config file
was read to produce this fixture — `~/.copilot/config`, the token
store and `session.db` are all off-limits and untouched.

## Not captured yet

- **A VS Code-hosted session's `client_name`.** The value is
  UNGROUNDED: no VS Code-hosted Copilot CLI session exists on the
  grounding box, so `surface.go` deliberately carries no VS Code row.
  The one session-state directory holding a `vscode.metadata.json`
  sidecar on the live box (`946bfb36…`, Copilot CLI 1.0.60) turned out
  to be an ordinary **terminal** run — its `client_name` is
  `github/cli` — so that sidecar is NOT a VS Code marker and must not
  be read as one.
- **A `client_name`-less session.** Older Copilot CLI builds wrote none
  at all; that absence means "old build", not "terminal", and gets no
  stamp.
