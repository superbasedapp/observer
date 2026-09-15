# testdata/grokbot — Grok Bot (desktop) fixtures

- **Captured**: 2026-08-28, from a live Grok Bot **0.28.0** install on Windows
  11 (`%APPDATA%\Grok Bot\sand-client-persistence\`), read from WSL2 over
  `/mnt/c`, read-only. Schema cross-checked against the shipped
  `app.asar` (`dist/electron-main/main.cjs`, `dist/node-agent-coordinator/
  main.cjs`, `dist/renderer/assets/index-*.js`).
- **Operator**: santosh@marmut.app.
- **Anonymisation**: the fixtures are **SYNTHESIZED, not redacted copies.**
  No captured message text, account id, agent uuid, request id, or timestamp
  appears in any file here. The live capture was a real working conversation
  (marketing drafts naming third-party individuals and URLs) and none of it is
  reproduced. What IS carried over verbatim is *structure only*: field names,
  entry-kind spellings, the id scheme, schema versions, and the filename
  encoding.
  - Account id → `auth0%7Cuser_00000000000000000000000000`
  - Agent (session) uuid → `11111111-2222-3333-4444-555555555555`
  - All other uuids → `00000000-0000-4000-8000-0000000000NN`
  - Timestamps → a fixed `1780000000000` base, +1s per entry
  - Message bodies → invented one-liners

## File inventory

| File | Purpose | Use in tests |
|---|---|---|
| `onqw4zbo…fyytcmjrgeytcmjn…gu2q.blob` | Transcript replica for one conversation. Decodes to `sand.client.slice.account.<acct>.transcript.replicas.<agent>`. 15 entries covering **every** entry kind the app's validator accepts. | `adapter_test.go` — the whole `ParseSessionFile` surface: action mapping, roles, turn tracking, scrubbing, cursor semantics, in-flight stop. |
| `onqw4zbo…fzzg643umvzc43dbon2c24tpon2gk4q.blob` | Roster slice (`roster.last-roster`) for the same account. **Not parsed by the adapter** — kept so the deliberately-not-ingested shape is documented and so `IsSessionFile` can be asserted to reject it. | `adapter_test.go::TestIsSessionFile`, `blobname_test.go::TestTranscriptAgentIDRejectsRosterSlice`. |

Both filenames are produced by the app's own codec (RFC 4648 base32 over the
**lowercase** alphabet `abcdefghijklmnopqrstuvwxyz234567`, unpadded, `.blob`
suffix), so they are byte-for-byte what Grok Bot would write for those keys.

## What the transcript fixture covers

| Entry `kind` | Fixture ids | Coverage value |
|---|---|---|
| `send-message` (type `text`) | `tbs0`, `t0s0` | The agent's outbound message — **including the bootstrap `tbs<n>` greeting that precedes any user turn**. Pins the inverted naming (see gotcha 1). |
| `send-message` + `boxInstruction` | `t0s1` | The remote sandbox handing control back to the human. |
| `send-message` (non-`text` type) | `t0s2` (`secret-request`) | Type-only recording; pins that the payload is **never** dereferenced. |
| `message` role `user` | `t0u`, `t1u` | User prompts. `t1u` carries planted secrets to exercise scrubbing. |
| `message` role `assistant` | `t1s0` | The assistant-role variant of `message` (distinct from `send-message`). |
| `message` `isStreaming: true` | `t1s3` (last) | **In-flight**: must not be ingested and must hold the cursor. |
| `tool-call` | `t0s3`, `t0s4` | Settled vs `status:"failed"`. Only `name`/`status`/`summary` exist. |
| `event` | `event-…005` | `automation-changed`; also pins that a non-`t<N>…` id inherits the running turn. |
| `notice` | `t0s5` | System notice. |
| `user-attachment` | `t0s6` | Carries a `/home/box/...` path — pins that a REMOTE path never becomes a ProjectRoot. |
| `feedback` | `t1s1` | Known kind, skipped **silently** (no warning flood). |
| `voice-call` | `t1s2` | Same. |

**Notably absent — and absent on purpose:** there is no token, model, cost, or
cwd field anywhere, because none exists in the real store either. Grok Bot
executes the agent in a remote sandbox and the desktop is a thin replicated
client. A fixture containing usage numbers would be fiction, and
`adapter_test.go` asserts `len(TokenEvents) == 0` and `Model == ""` precisely
so a future change cannot quietly invent them.

Also absent: a **group conversation** (`isGroup`, `memberIds`, `fromAgent`).
Those fields exist in the app's schema but were not observed live, so the
adapter's `fromAgent`/`fromUser` handling follows the app's own role function
and is **untested against real data**.

## Reproducing the dumps

The store is plaintext JSON — no decryption step, no SQLite client:

```bash
# List slices on a live Windows install, decoding each filename.
cd "/mnt/c/Users/<you>/AppData/Roaming/Grok Bot/sand-client-persistence"
for f in *.blob; do
  python3 - "$f" <<'EOF'
import base64, sys
n = sys.argv[1][:-5].upper()
n += "=" * ((8 - len(n) % 8) % 8)
print(base64.b32decode(n).decode())
EOF
done
```

Do **not** copy a live blob into this directory. Regenerate the fixtures
instead — read a live blob to confirm the *shape*, then hand-write the
synthesized equivalent and re-encode the filename:

```bash
python3 -c '
import base64
k = "sand.client.slice.account.<acct>.transcript.replicas.<agent>"
print(base64.b32encode(k.encode()).decode().lower().rstrip("=") + ".blob")'
```

## Notes for the implementing session

1. **`send-message` is the AGENT, not the user.** It reads like "a message the
   user sent" and is the opposite. The user's turns are `kind:"message"` with
   `role:"user"`. Getting this backwards inverts every transcript. Grounded in
   the app's own role function, not inferred.
2. **The cursor is an ENTRY COUNT, not a byte offset.** The blob is one JSON
   document rewritten in place on every change, so a byte offset is
   meaningless (the freebuff precedent).
3. **Stop at the first in-flight entry.** A streaming `message` holds a
   truncated prefix, and the store's action upsert cannot rewrite a target on
   conflict — persisting it would be permanent. The parser leaves the cursor
   pointing at it and sets `RetrySuggested`.
4. **Never resolve `/home/box/sand-data/...`.** It appears in the roster's
   `path` and in attachment paths, looks exactly like a local project root,
   and is a path inside the REMOTE VM.
5. **Entry ids are natively deterministic** (`tbs<n>` / `t<N>u` / `t<N>s<M>` /
   `event-<uuid>`), so `SourceEventID` needs no synthesis or content hashing.
6. **A key longer than 240 encoded chars is refused storage by the app**, not
   hashed. So a decode failure always means "not our file", never "a file we
   should have understood".
7. **The default scrubber does not catch `sk-ant-api03-…`.** Its API-key regex
   is `(?:sk|pk|ak)[_-][A-Za-z0-9_]{16,}`, whose character class excludes `-`,
   so an Anthropic-style key with internal hyphens stops matching after
   `sk-ant`. This fixture therefore plants `sk-…`/`ghp_…` forms the scrubber
   **does** catch, so `TestScrubsSecrets` proves the scrubber runs on this path
   rather than accidentally passing. The regex gap is pre-existing and
   repo-wide (`internal/scrub`), not specific to this adapter.
