# Prime Agent adapter fixtures

Fixtures for `internal/adapter/primeagent/`. Prime Agent (Prime Intellect)
writes one append-only JSONL transcript per session at
`~/.prime/agent/sessions/<session-uuid>.jsonl`. The authoritative schema
is the vendor's own `docs/session-format.md`, shipped inside the
`prime-agent` npm package; the Phase-0 findings that drove these fixtures
are in `docs/plans/prime-agent-adapter-plan-2026-08-06.md`.

## Inventory

| File | Lines | What it exercises |
|---|---|---|
| `session-flat.jsonl` | 24 | The full entry vocabulary — header, model changes, both `content` shapes, tool call/result pairing (success + failure), shell executions, compaction, RLM child-usage roll-up, a malformed line, and the bookkeeping entries that must be skipped silently. |
| `session-unpaired-tail.jsonl` | 11 | A transcript whose last entry is a tool call with **no** `toolResult` yet — the cross-tick pairing case `adapter.DeferUnpairedTail` defers. Truncated from the first fixture, so the two share a byte-identical prefix. |

Both files use LF line endings. The CRLF case is synthesised in
`crlf_test.go` from `session-flat.jsonl` rather than committed, so the two
forms can never drift apart.

### What `session-flat.jsonl` contains, line by line

| # | Entry | Why it's there |
|---|---|---|
| 1 | `session` header (v3) | `cwd` + `git.branch` are the only statement of project root and branch; the parser re-reads line 0 on every resume. |
| 2–5 | `model_change`, `thinking_level_change`, `service_tier_change`, `session_state` | Only `model_change` is consumed. The other three must be skipped **silently**. |
| 6 | `message` / `user`, **array** `content` | The shape the live capture uses. |
| 7 | `message` / `assistant`, `stopReason:"error"`, all-zero `usage` | A provider failure: must yield an `api_error` action and **no** token row. |
| 8 | `agent_status` | The high-volume bookkeeping entry (3:1 vs messages in the live session) that a "warn on unknown type" default arm would flood the log with. |
| 9 | `model_change` to an **alias** model id | Sets up the `responseModel` resolution below. |
| 10 | `message` / `user`, **bare-string** `content` | The polymorphic-content trap. The vendor types this field `string \| array` and documents the string form; a strict `[]part` type fails the whole envelope and drops the prompt. Also carries a synthetic credential for the scrub test. |
| 11 | `message` / `assistant` with `thinking` + a `toolCall` | Reasoning fan-out, `ContentBytes` from the authored `code` argument, and `responseModel` overriding the alias. |
| 12 | `message` / `toolResult`, `isError:false`, with `details` | Success stamping + `durationMs`. |
| 13 | `message` / `assistant`, text only, `stopReason:"stop"` | `assistant_message` + the token row the child roll-up later upgrades. |
| 14–15 | `message` / `assistant` + `toolResult`, `isError:true` | Failure stamping. |
| 16 | `message` / `bashExecution`, `exitCode:0` | Shell execution; output carries a second synthetic credential. |
| 17 | `message` / `bashExecution`, `cancelled:true`, `exitCode:null` | A cancellation is a failure even with an undefined exit code. |
| 18 | `compaction` | `context_compacted` with `tokensBefore`. |
| 19 | `child_usage_attributed` | The RLM roll-up, keyed to line 13's entry id so the store's MAX-upgrade folds it in rather than double-counting. |
| 20 | `agent_status` | A second one, after the interesting content. |
| 21 | **malformed** (truncated JSON) | The cursor must advance past it with exactly one warning, and the entries after it must still parse. |
| 22–24 | `session_info`, `label`, `custom` | More silently-skipped bookkeeping, placed **after** the malformed line so the "parse continues" claim is real. |

## Anonymisation

These fixtures are **derived from a real session but contain no real
content**: the envelope structure, field names, entry ordering and token
magnitudes were taken from a live capture, and every value that could
identify a person, machine, repository or piece of work was authored
fresh. Nothing was "search-and-replaced" out of a real transcript, so
there is no residue to leak.

### Identity values used

Everything below is invented. These are the *only* identity-bearing
strings in the fixtures, which is what makes the verification commands
meaningful.

| Field | Value in the fixtures |
|---|---|
| Session id (and filename stem) | `019f0000-1111-7222-8333-444444444444` |
| `cwd` / project root | `/home/dev/acme-widgets` |
| `git.repoUrl` | `https://github.com/acme/acme-widgets.git` |
| `git.commit` | `1a2b3c4d5e6f70819293a4b5c6d7e8f901234567` |
| `git.branch` | `main` |
| Entry ids | `a10000NN` plus a handful of 8-hex ids from the vendor's own doc examples |
| Tool call ids | `chatcmpl-tool-aaaa1111`, `chatcmpl-tool-bbbb2222` |
| Response ids | `gen-<epoch>-AAAAAAAAAAAA` / `-BBBBBBBBBBBB` |
| User prompts | Two invented one-liners about listing and summarising a repo |
| Assistant text / thinking | Invented one-liners |
| Tool output | A three-entry directory listing and a `FileNotFoundError` |
| Shell commands | `git status --short`, `sleep 600` |

Model ids, provider names and API-lane names (`openai-responses`,
`openai-completions`) are **not** anonymised: they are public product
identifiers and are load-bearing for the model-resolution tests.

Token counts and the `cost` breakdowns **are** real magnitudes carried
over from the live capture. They identify nothing, and keeping them real
is what makes `TestUsageIsNetNotGross` a genuine arithmetic proof — the
`total == input + output + cacheRead + cacheWrite` identity has to close
on numbers a provider actually produced, not on numbers chosen to make it
close.

### Synthetic credentials

Two credential-shaped strings are embedded so the scrub path is tested on
the two surfaces a secret realistically lands on — a user prompt and shell
output. Both are **fabricated constant runs**, not keys: an `sk-` prefix
followed by 32 identical characters, and a `ghp_` prefix followed by 36
identical characters. Neither the fixture generator nor the test file
writes them as a literal; both rebuild them by concatenation, so no
credential-shaped token appears in any source file.

### Verification

Run from the repository root. Each command asserts a property of the
fixtures as they stand — none of them names a value that was removed.

```bash
# 1. Every absolute path in the fixtures is the invented one. Any other
#    POSIX home path, any Windows drive path, and any UNC path is a leak.
grep -oE '(/home/[A-Za-z0-9._-]+|/Users/[A-Za-z0-9._-]+|[A-Za-z]:\\\\[^"]*|\\\\\\\\wsl[^"]*)' \
  testdata/primeagent/*.jsonl | sort -u
#    expected: only  …:/home/dev

# 2. The only git remote is the invented one.
grep -oE 'https://github\.com/[^"]+' testdata/primeagent/*.jsonl | sort -u
#    expected: only  https://github.com/acme/acme-widgets.git

# 3. The only session uuid is the invented one (36-char 8-4-4-4-12 form).
grep -oE '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' \
  testdata/primeagent/*.jsonl | sort -u
#    expected: only  019f0000-1111-7222-8333-444444444444

# 4. Both synthetic credentials are constant runs — a real key never is.
grep -cE '(sk-A{32}|ghp_B{36})' testdata/primeagent/session-flat.jsonl
#    expected: 2

# 5. The fixtures parse, and the arithmetic + scrub claims hold.
go test -count=1 ./internal/adapter/primeagent/...
```

## Regenerating

The fixtures are hand-authored JSONL and are edited in place; there is no
generator to re-run. If you extend `session-flat.jsonl`, keep
`session-unpaired-tail.jsonl` a byte-identical **prefix** of it (the first
11 lines, stopping before the first `toolResult`) so the deferral test
keeps exercising the same records the main test does:

```bash
head -n 11 testdata/primeagent/session-flat.jsonl \
  > testdata/primeagent/session-unpaired-tail.jsonl
```

Keep the line-by-line table above in sync — several tests assert exact
event counts and would otherwise fail with a count mismatch that says
nothing about what changed.
