# testdata/kirocrew — live capture, anonymized

**Grounded 2026-09-03** against a live signed-in Kiro Crew **desktop** run
on Windows (Google sign-in; 5-turn prompt kit on a scratch workspace).
This closes step-in **P6** of
`docs/plans/uncaptured-surfaces-login-schedule-2026-09-03.md` §2 — the
placeholder recipe this file used to carry has been executed and is
replaced by the findings below.

Adapter: `internal/adapter/kirocrew` (registered).
Operator reference: [`docs/kiro-crew-adapter.md`](../../docs/kiro-crew-adapter.md).

---

## The three findings that changed the design

**1. The vendor-documented store path does not exist.** Both
`github.com/kirodotdev/kirocrew`'s README and
`kiro.dev/docs/crew/installation/` list a `~/.kiro/crew/conversations/`
directory. The whole Crew root was listed on the live host: there is **no
`conversations/` at any depth**. The transcripts are
`~/.kiro/crew/sessions/<thread>_<slot>.jsonl` — observed shaped
`sessions/dashboard_chat-2-<epoch>.jsonl`, with a `<name>.jsonl.lock`
sibling (the real slot id is withheld; the fixture below carries a
synthetic one). The pre-grounding skeleton watched the documented path and
would have captured nothing.

**2. The double-count risk is REAL, and the answer is "both".** Crew
drives kiro-cli. Diffing `~/.kiro/sessions/cli/` around the run showed
**three** sessions carrying `session_state.agent_name == "kirocrew"`
(against **one** Crew transcript), and the Crew transcript and its driven
kiro-cli session use **byte-identical `tooluse_*` call ids**. So kiro-cli
is the canonical owner of the conversation and Crew is a surface stamp on
it — *and* Crew still needs its own adapter for chats with no twin. See
`docs/kiro-crew-adapter.md` §Ownership for the full rule.

**3. There is no `kirocrew` CLI on this host.** The desktop app is the
only surface: it installs to `C:\Program Files\KiroCrew\KiroCrew.exe`
(`%LOCALAPPDATA%\kirocrew-desktop-updater` holds only the updater's
`installer.exe`; `%APPDATA%\kirocrew-desktop` is Electron userData). The
schedule's `kirocrew setup` / `kirocrew chat` steps were therefore not
runnable, and **the incognito no-persistence check was not performed** —
that remains unverified.

---

## Files

| Path | What it is |
|---|---|
| `crew/sessions/dashboard_chat-2-1700000002.jsonl` | the Crew chat transcript: 24 lines — the `_type:metadata` header, 1 `user`, 5 `assistant`, 17 `tool` (9 unique `tool_call_id`s, most appearing as a call/completion pair) |
| `crew/session_map.json` | the Gateway's chat-slot → driven-kiro-cli-session index. Resolves this chat to its twin, so the adapter emits nothing for it |
| `crew-no-twin/` | the SAME transcript with a `session_map.json` that is present but does not resolve this slot — exercises the emit branch |
| `kiro-cli/sess0001-….json` + `.jsonl` | the kiro-cli session Crew drove for that chat (`session_state.agent_name: "kirocrew"`). Consumed by BOTH `internal/adapter/kirocrew/dedupe_test.go` and `internal/adapter/kirocli/flat_live_test.go` |
| `kiro-cli/sess0003-….json` | a PLAIN terminal session (`agent_name: "kiro_default"`) — the surface-stamp contrast case. State only; its `.jsonl` is not needed |

The kiro-cli halves live here rather than under `testdata/kirocli/`
deliberately: they are one half of the kiro-crew pair, and their value is
the cross-store correspondence.

## Anonymization applied

Per the repo convention:

- home dir → `<u>`; the workspace path renamed to `demo-workspace`.
- every session id, message id, `mid` and `tool_call_id` replaced with a
  stable synthetic value, **kept consistent across every file** — the
  shared `tooluse_*` ids between the two stores are the whole point of
  the fixture and are pinned by
  `TestToolCallIdsAreSharedAcrossBothStores`.
- the kiro-cli stream's first `Prompt` (the ~73 KB Crew agent system
  prompt) replaced with a one-line placeholder.
- `thinking` blocks' `redactedContent` byte arrays emptied.
- the Crew transcript's `meta.pastes[].content` (a verbatim echo of the
  user's own message, which the adapter never reads) replaced with a
  placeholder; the `meta.file_changes[].path` entries scrubbed.
- `folder_id` / `tab_id` / `tags` replaced with synthetic hex, and the
  chat-SLOT id in the filename replaced too (it is a live chat-tab
  identifier — same precedent as `14bed3721`, which withheld the real
  kiro-cli session id and bucket hash from the docs).
- the kiro-cli `.json` state trimmed to the fields the adapter reads plus
  `agent_name` (the surface discriminator the fixture exists to pin) —
  the agent's own embedded config and system prompt are not committed.

ISO timestamps are the real ones (no PII) so relative ordering is
exact. The two embedded Unix `meta.timestamp` epochs in the kiro-cli
half WERE shifted by a constant (into the same `1700000xxx` family the
synthetic slot id uses), which preserves the 77 s gap between them — the
gap that matches the transcript's own `turn_stats.elapsed_ms` of 77343.

**No secrets were encountered.** The transcripts carry tool inputs and
outputs from a hello-world exercise only. `.env`, `config.json`,
`memory.db`, `audit.log`, `security_events.jsonl` and `workspace/**` were
never opened.

## Regenerating

The fixtures were produced from the raw capture by a one-off anonymizer.
To re-derive from a fresh capture, copy only
`~/.kiro/crew/sessions/*.jsonl` + `~/.kiro/crew/session_map.json` and the
matching `~/.kiro/sessions/cli/<sid>.{json,jsonl}` pair, then apply the
rules above. Do **not** widen the copy without an explicit decision — the
off-limits table in `docs/kiro-crew-adapter.md` is the contract.
