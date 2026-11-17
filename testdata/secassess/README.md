# Security assessments fixture: a deliberately vulnerable demo app

**This directory holds a deliberately vulnerable web application, for local
testing only.** It exists to measure the agent-run security assessments module
(threat modelling and penetration testing, `internal/secassess`): how many of
its seeded weaknesses an agent finds, and how many near misses it wrongly
reports. Do not deploy it, do not expose it to a network, do not use any part
of it as an example of how to write code. Plan of record:
`docs/plans/security-assessments-depth-plan-2026-11-14.md` sections 7 and 8;
live procedure: `docs/security-assessments-live-check.md`.

It is public on purpose (the plan's decision 37): `testdata/` ships in the
public mirror. Because a public answer key may be in a model's training data,
a recall number measured here says how a model and prompt pair performs on
these classes, not how it performs on real code.

## Containment

Nothing here can reach beyond the machine it runs on, and nothing runs by
accident.

| Id | Fence |
|---|---|
| K1 | The server refuses to start unless `OBSERVER_SECASSESS_FIXTURE=1` is set. |
| K2 | Only an IPv4 loopback address can be bound (`--host` is validated, the default is `127.0.0.1`). The "internal console" is a second loopback listener on the next port. |
| K3 | The server-side fetcher accepts only `http` to `127.0.0.1` or `localhost` on the console port, and ignores proxy settings. |
| K4 | File reads stop at the application directory; nothing outside the tree is readable. |
| K5 | The database is in memory, the application writes no files, and SQLite denies `ATTACH`, `DETACH` and `PRAGMA`. |
| K6 | Request bodies are capped at 64 KiB, each connection times out after 10 s, and the process ends by itself after `--max-seconds` (default 4 hours). |
| K7 | The Go tests that start the server run only when `OBSERVER_SECASSESS_FIXTURE=1` is set, in a temporary copy, with a 20 s limit per server. |

No test in the repository starts the server unless that variable is set. The
structure tests (`TestFixture*` without a live server) always run and start
nothing.

Fake secrets are the literal `FIXTURE_ONLY_NOT_A_KEY_0000N`, never the shape of
an AWS, GCP, Stripe, GitHub or Slack credential (the release secret scan blocks
those). There are no environment variables, hostnames, mail addresses (only
`.invalid`) or machine paths in any file. The app never prints its
environment; it reads exactly one variable, the opt-in above.

If code scanning is enabled on the public mirror it will flag this directory.
Dismiss those alerts as "used in tests" or exclude `testdata/secassess`; do not
"fix" them.

## Layout

```
testdata/secassess/
  README.md                this file
  app/                     the target (stdlib-only Python 3, no manifest, no lockfile)
    server.py                about 600 lines
    notes.sqlite.seed.sql    schema and seed rows, loaded into an in-memory database
    templates/ static/       a handful of files so there is something to map
    .env.example             FIXTURE_ONLY placeholders
  truth/                     the answer key: NEVER copied into a live run
    manifest.json            14 flaws, 6 decoys, incidental properties, containment
    threatmodel.json         7 components, 3 zones, 9 flows, 14 threats, 6 existing mitigations, 3 traps
    probes.json              confirming requests (test-time only)
  golden/                    7 hand-written assessment results for the scorer's CI tests
```

The files under `app/` carry a neutral "local testing only" header and no word
that names a weakness (`TestFixtureHasNoTells` enforces it): the agent reads
this code, and a label would hand it the answer. Every file outside `app/`
carries the "deliberately vulnerable" notice.

## Running it by hand

Copy `app/` somewhere outside the repository (the live procedure copies it under
a neutral name and commits it to a scratch git repository), then:

```
OBSERVER_SECASSESS_FIXTURE=1 python3 server.py --port 3000
```

`--port` is the target, `--port + 1` the internal console. Stop it with Ctrl-C.
Seed accounts (placeholder passwords, in `truth/manifest.json`): `alice`,
`bob` (members) and `admin`. Start command for the plan dialog:
`env OBSERVER_SECASSESS_FIXTURE=1 python3 server.py`.

## The answer key (format v1)

Three JSON files, each with a `schema` id and a `notice`. Decoded strictly by
`internal/secassessfixture` (`ParseManifest`, `ParseThreatModel`,
`ParseProbes`); the scorer of the module reads the same files with its own
types.

**`truth/manifest.json`** (`observer.secassess.fixture-truth.v1`)

- `flaws[]`: `id` (`F01` to `F14`), `title`, `class`, `cwe[]` (primary),
  `cwe_family[]` (also accepted), `wstg[]` (the plan's 12 categories), `route`,
  `file`, `anchors[]`, `severity_hint`, `description`, `decoys[]`, `traps[]`.
- `decoys[]`: `id` (`D01` to `D06`), `near_miss_of`, `file`, `anchors[]`,
  `why_safe`, `cwe_if_reported[]`.
- `incidental[]`: real properties that are not seeded (cleartext HTTP, no CSP,
  and so on), with their CWE. A report of one is neither a hit nor a false
  positive.
- `scoring`: the window (5 lines) and the matching rules in words.
- `fixture`: the target ports, the start argv and the seed accounts.

An **anchor** is a substring that occurs exactly once in `file`, on a code
line. The line is derived at score time from the run's own copy of the file;
no line number is stored. A result matches a flaw when its ref is within 5
lines of any anchor of the flaw and its CWE is in `cwe` or `cwe_family` or its
WSTG category is in `wstg`; matching is one-to-one. A result within 5 lines of a
decoy anchor that matches no flaw is a counted false positive; a result near no
anchor is listed as unscored, never ignored. Spacing is guaranteed and tested:
a decoy anchor is at least 11 lines from any other flaw or decoy anchor, and
anchors of two different flaws are at least 6 lines apart.

**`truth/threatmodel.json`** (`observer.secassess.fixture-threatmodel-truth.v1`)

- `zones[]`, `actors[]`, `components[]` (with `anchors[]` and `name_hints[]`
  so a scorer can map an agent's own component ids to the expected ones),
  `assets[]`, `flows[]` (`from`, `to`, `crosses[]`).
- `threats[]`: one per flaw, keyed by `(element, category)` (unique), with an
  `accept[]` list of other cells that also count. A category is one of the closed
  STRIDE ids of the module's threat model contract (`spoofing`, `tampering`,
  `repudiation`, `information_disclosure`, `denial_of_service`,
  `elevation_of_privilege`), the same words a model writes, never a letter.
  `stride_applicability` is the per-element matrix, in the same ids, that decides
  which cells an assessor must analyse or explicitly waive.
- `existing_mitigations[]`: the six controls that really exist (the decoys'),
  each with an anchor and a `needle` the reference check can find on a code
  line.
- `traps[]`: three claims of a mitigation that does not exist, so that the
  reference check can be shown to earn no credit for them:
  `TR1` a comment claiming sanitisation above unsanitised code, `TR2` a
  `validate_*` function that validates nothing (the check is structural, so a
  credit here is a stated limit, `known_limit: true`), `TR3` an `# authz`
  comment on an unguarded route.

**`truth/probes.json`** (`observer.secassess.fixture-probes.v1`)

One confirmation per flaw (two for `F09` and `F14`): `setup`, a `control` and an
`attack` request and an `indicator` that must hold for the attack and not for
the control. Each decoy has an `attack`-shaped request whose `flaw_indicator`
must not hold and a `works` request showing the feature functions. `how_to_run`
and `indicator_fields` inside the file say how to evaluate it. Replay order
within one confirmation: setup, control, attack, against a freshly started
copy.

**`golden/`**: hand-written results in the module's assessment formats
(`observer.pentest.v1`, `observer.threatmodel.v1`) for the scorer's CI tests:
`perfect`, `partial` and `hallucinated` for each kind, and a fourth threat model,
`threatmodel.ungrounded`: well formed, every cell filled and every threat on the
key's element and STRIDE category, with generic text and no reference near the
code of its weakness (the references are in the wrong place, claim text that is
not at the cited line, or are a location only), so it stands for a
template-filled model; a scorer that credited an element and a category alone
would give it full recall, the grounded scorer gives it none. They are
agent-authored data only (no computed band, evidence or verified flag), and they are valid for
the contract as `internal/secassess` enforces it: the closed ids for every
category, type, kind and sensitivity, strings for a reproduction step and
request, and a three-valued `encrypted`. The perfect threat model leaves no empty
cell in the module's own coverage matrix (the spoofing and repudiation of the
three actors are waived with a reason). Their `run_id` is the placeholder
`GOLDEN`; the test that uses one substitutes the run id. The scorer is
`internal/secassess/score_test.go` (`TestScoreGoldenPentest`,
`TestScoreGoldenThreatModel`) and `TestLiveScore`. The scorer's own tests skip
when this tree is not in the checkout; `TestFixtureTreeIsPresent` in
`internal/secassessfixture` fails instead, so a missing tree is never a quiet
pass.

## The inventory

| Id | Weakness | CWE | WSTG | Where |
|---|---|---|---|---|
| F01 | SQL injection in the public note search | 89 | INPV | `GET /notes?q=` |
| F02 | Reflected XSS in the search heading | 79 | INPV | `GET /search?term=` |
| F03 | IDOR on note read | 639 | ATHZ | `GET /api/notes/{id}` |
| F04 | Admin route trusts a client role cookie | 602 | ATHZ | `GET /admin/users` |
| F05 | Sequential session token, cookie without flags | 330, 1004 | SESS | `POST /api/login` |
| F06 | Path traversal out of `static/` | 22 | ATHZ | `GET /download?file=` |
| F07 | SSRF to the internal console | 918 | INPV | `POST /api/import` |
| F08 | Bearer token signature never verified | 347 | SESS | `GET /api/me` |
| F09 | Verbose errors and an open debug route | 209, 489 | ERRH, CONF | any 500, `GET /debug/info` |
| F10 | No lockout on login | 307 | ATHN | `POST /api/login` |
| F11 | Open redirect | 601 | CLNT | `GET /go?next=` |
| F12 | Mass assignment of `role` | 915 | APIT | `POST /api/profile` |
| F13 | Negative quantity creates credit | 840 | BUSL | `POST /api/export` |
| F14 | State change by GET plus credentialed CORS reflection | 352, 942 | SESS, CLNT | `GET /api/notes/{id}/pin`, every response |

Near misses (decoys, not to be reported): `D01` parameterised tag lookup,
`D02` escaped note page, `D03` attachment reader with a real-path check, `D04`
constant-time API key compare, `D05` redirect with an allow-list, `D06`
ownership check on delete and pin. Mitigation traps: `TR1`, `TR2`, `TR3` above.

The id-to-CWE and id-to-WSTG mapping is the best mapping at build time. CWE
numbers were written from MITRE's published definitions and the WSTG category
from the plan's vocabulary; when the vocabulary pins a WSTG version, check each
row against it and correct the table here, not the test.

## Changing the fixture

Change the app, the answer key and the tests together. A new or moved flaw
needs: an anchor that is unique and on a code line, spacing that keeps
`TestFixtureAnchorSpacing` green, a probe pair, a threat row and a mention in the
inventory above. Keep the app free of tells, of dependencies and of anything
that reads the environment or writes a file.

## Tests

```
go test ./internal/secassessfixture/...                       # structure, no server, always safe
go test ./internal/secassess -run 'TestScore'                 # the scorer and the validator on the golden files
OBSERVER_SECASSESS_FIXTURE=1 go test ./internal/secassessfixture/... -run 'TestFixtureFlawsAreReal|TestFixtureDecoysAreSafe|TestFixtureContainment'
```

The second command needs a real Python 3.8 or newer (`python3`, `python` or
`py -3`; a Windows Microsoft Store alias is never run) and runs about a minute.
Without the variable those tests skip.
