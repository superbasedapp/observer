# Guard policy authoring — matcher reference

How to write `guard-policy.toml` rules (guard spec §4.4). Two file
locations, both optional:

| Layer | Default path | Config key |
|---|---|---|
| user | `~/.observer/guard-policy.toml` | `[guard.rules] user_policy` |
| project | `<git root>/.observer/guard-policy.toml` | `[guard.rules] project_policy` |

A third layer — the distributed bundle — uses the same format but
arrives signed and merges as a strictness floor (§14.2); you don't
author it locally.

Parsing is **strict**: unknown keys, unknown matcher fields, invalid
regexes, duplicate ids and rules that could never fire are all
load-time errors. `observer guard lint` runs the exact same parser —
a file that lints clean is a file that loads. Regexes are Go RE2:
linear-time, no catastrophic-backtracking class to worry about.

## `[[rule]]` — define a new rule

```toml
[[rule]]
id         = "U-001"            # required; must NOT collide with a built-in ID
category   = "boundary"         # required: destructive|boundary|secrets|exfil|
                                #           posture|mcp|taint|budget|anomaly
severity   = "high"             # optional; default "warn" (info|warn|high|critical)
decision   = "deny"             # required: allow|flag|ask|deny
enforce    = true               # optional: rule blocks even in observe mode (§4.1)
applies_to = ["file_access"]    # optional; usually inferred from the matchers
match.path_outside_project = true
match.path_not = ["~/.config/shared-lint/**"]
```

Decision semantics by mode: in **observe** the effective decision is
`min(decision, flag)` — deny/ask-class rules record but don't block —
unless the rule sets `enforce = true`, which makes the engine use the
declared decision regardless of mode.

## Matcher vocabulary (all fields under `match.`)

Multiple matchers in one rule **AND** together; their detail strings
join into the verdict reason. Matchers come in two scopes, and a rule
may use only one scope (the parser rejects mixing — split into two
rules):

**Command-scoped** — evaluated per parsed command, after the
shellparse unwrap (`bash -c`, wrappers, interpreter one-liners):

| Matcher | Type | Semantics |
|---|---|---|
| `command_regex` | string | RE2 over the raw command text |
| `command_base` | string | exact base-command match, case-insensitive (`"git"`, `"terraform"`) |
| `arg_contains` | string | substring match over any argument (argv[1:]) |

Command-scoped rules imply `applies_to = ["shell_exec"]`.

**Event-scoped** — evaluated once per event:

| Matcher | Type | Semantics | Implies applies_to |
|---|---|---|---|
| `path_glob` | []string | gitignore-style globs over the event path (`~` expands) | file_access, config_change |
| `path_not` | []string | exemption globs — compiles into a per-rule safe pattern checked FIRST | (none; modifies the rule) |
| `path_outside_project` | bool | path resolves outside the session's project root | file_access, config_change |
| `path_sensitive` | bool | the built-in sensitive-path set (SSH keys, cloud creds, …) | file_access, config_change |
| `url_domain` | string | URL host equals the domain or is a subdomain of it | tool_call, api_request |
| `mcp_server` | string | MCP server name parsed from the call target | mcp_call |
| `mcp_tool` | string | MCP tool-name suffix match | mcp_call |
| `event_kind` | []string | the event's kind is in the list | the listed kinds |
| `sink` | string | one of `shell_exec` \| `git_push` \| `out_of_project_write` \| `mcp_call` (§4.5 sinks) | the sink's kinds |
| `taint_source` | string | session carries an active taint mark from this source | **none — pure condition** |
| `session_cost_usd_gt` | float | guard-stamped session spend strictly exceeds the value | **none — pure condition** |
| `repeat_count_gt` | int | consecutive-identical-action run length strictly exceeds the value | **none — pure condition** |

`applies_to` rules: an explicit `applies_to` list always wins;
otherwise the matchers' implied kinds union. A rule built ONLY from
pure conditions (`taint_source`, `session_cost_usd_gt`,
`repeat_count_gt`) implies no kind and must set `applies_to` (or
`event_kind`) explicitly — the parser errors otherwise.

Valid `applies_to` / `event_kind` values: `tool_call`, `file_access`,
`shell_exec`, `mcp_call`, `api_request`, `api_response`,
`config_change`, `session_meta`.

Valid `taint_source` values (§4.5): `web_fetch`, `mcp_unpinned`,
`external_file`, `attachment`, `secrets_read`.

Stamping caveats for the pure conditions: cost/repeat values are
stamped by the daemon (watcher/proxy paths) — hook-path events are
never stamped (a per-tool-call DB read would blow the §6.4 latency
budget), so cost/repeat rules act on the daemon surfaces. Unlike the
built-in A-610 (which fires once per episode on the crossing edge),
`repeat_count_gt` re-matches every event while over the threshold —
your rule owns its own volume.

## `[[override]]` — tune a built-in

Built-in IDs can't be redefined (the parser rejects the collision);
tune them instead:

```toml
[[override]]
rule     = "R-110"     # git force-push
decision = "deny"      # escalate flag → deny
enforce  = true        # and block it even in observe mode
```

`decision` is optional (omit to keep the catalog decision and only
set `enforce`). The full catalog with IDs is
[`guard-rules.md`](guard-rules.md) or `observer guard rules`.

### `overridable` — let the developer grant themselves an exception

On an ORG bundle an override row may also carry `overridable`:

```toml
[[override]]
rule        = "R-171"   # upload of file contents to a remote destination
decision    = "deny"
enforce     = true
overridable = true      # the developer may grant a scoped, reported exception
```

`overridable` defaults to **false**: silence means the rule is hard
and a local approval for it is inert. Setting it true does not weaken
the rule - the deny still fires. It changes what the developer can do
about it: on a tool that can prompt, the deny reaches them as an ask;
where it cannot, the refusal names the `observer guard approve`
command. Every exercised override is reported to the org.

**Read that again for a rule whose decision is `deny`.** This is the
only shape where the flag does anything, and it is what the flag is
for: a `deny` marked `overridable` no longer denies outright on an
ask-capable channel - the node emits it as an **ask**, and the
developer can grant themselves a scoped, time-boxed, reported
approval past it. `overridable` on an `ask`, a `flag` or an `allow`
is inert. Publishing a bundle that grants latitude over a deny is
therefore legal and intended, and the publish emits a **warning**
(never a refusal) naming each such rule, which is also recorded in
the publish audit row. If you did not mean to hand that rule back to
developers, drop the key - do not drop the escalation.

`overridable` is an `[[override]]` key and nowhere else. Written
inside a `[[rule]]` table it is refused at publish with a message
saying exactly that. (It used to be silently stripped, which signed a
body the agent's own parser then rejected - leaving that node with no
org policy at all.)

Composition across bundles is **false-wins**. If the org-wide bundle
grants latitude on a rule and a team bundle mentions the same rule
without granting it, the developer gets the hard deny - a grant is
latitude, and latitude composes by intersection. A bundle that says
nothing at all about a rule does not withdraw another bundle's grant.

## Layering rules (§4.6 — one-way strictness)

- **User** rules apply as written (your machine, your call) — except
  below an org floor, where a relaxing entry is dropped with a load
  issue.
- **Project** rules may only ESCALATE: a project override that
  weakens a built-in or user verdict is dropped with a load issue
  (the agent can edit project files — and an agent session editing
  the project guard file is itself rule R-161).
- **Org** bundles are the floor: escalate-only against everything
  below; the server's publish path lints with the same checks so a
  relaxing bundle is refused before it's ever signed.

Inspect the merged result with `observer guard rules --effective`;
load problems surface in `observer guard status` as `LOAD ISSUE`
lines and via `observer guard lint`.

## Targeting a bundle at a team

A published bundle carries an optional audience. With no audience it
is **org-wide** - what every bundle published before targeting existed
is, and what the Guard tab publishes unless you add a team.

A team-scoped bundle is **never delivered on its own**. Each
developer's node receives its own effective bundle: the org-wide
bundle merged with every team bundle that developer belongs to, folded
by STRICTEST-WINS per rule (decision escalates, `enforce` true-wins,
`overridable` false-wins). Team membership is resolved on the server
from the enrolled identity - a node never names its team on the wire,
so it can never pick a laxer team's policy.

Three consequences worth knowing before you publish:

- **The version you see is not the component's.** Every node is
  served `MAX(published bundle version) + the org's roster counter`,
  whatever composed it. That is deliberate: a node refuses a bundle
  whose version went backwards, and a version derived from "the
  components that happened to apply" would go backwards the moment a
  developer left a team. A sum, not a maximum, so that publishing a
  bundle and editing a roster each move it on their own.
- **Changing a developer's TEAMS converges their node by itself.**
  Adding a member to a team, removing one, or deleting a team moves
  the roster counter, so the developer's next poll carries a higher
  version and their new composition is applied. One exception, stated
  honestly: a roster edit pushed by an **IdP through SCIM** does not
  move the counter (it does not go through the dashboard's team
  writer). Publish any new bundle version - re-publishing the
  org-wide floor is enough - to converge those, or move the roster
  from the dashboard.
- **Team targeting needs the server's signing key.** An org-wide
  bundle is served exactly as it was stored, signature and all. A
  composed bundle can only be signed at delivery, so the serving
  process needs `[policy].signing_key_path` configured **and loaded**
  - if you generated the key from the dashboard, restart the server
  before publishing a team bundle. Publishing one on a server that
  cannot sign is refused, naming that key. Should a server somehow
  lose the key with team bundles already stored, developers on no
  team keep receiving the org-wide floor and only the targeted teams
  see a `409`.

Use the Guard tab's **Effective for a developer** preview to see
exactly which authored bundles compose one developer's bundle and what
the merged TOML says. It runs the delivery path's own resolver, so it
cannot drift from what the node receives.

## Cookbook — worked recipes

Each recipe is a complete user-policy fragment plus the command that
proves it does what you meant. All of them lint with `observer guard
lint` and dry-run with `observer guard test` — verify before you rely.
(The dashboard's Security → Policy layers editor runs the same lint as
its save gate.)

**1. Ask before infrastructure-destroying commands — even in observe
mode.** The `enforce = true` makes this one rule block/ask while the
global mode stays observe: the per-rule ramp from
[`guard-enforce-runbook.md`](guard-enforce-runbook.md).

```toml
[[rule]]
id       = "U-100"
category = "destructive"
decision = "ask"
enforce  = true
match.command_regex = '(?i)\bterraform\s+(apply|destroy)\b'
```

Verify: `observer guard test "terraform apply -auto-approve"` — both
columns should read `ask`.

**2. Deny writes outside the project, with an exemption.** `path_not`
compiles into a safe pattern checked FIRST, so the exempted path never
even reaches the matcher.

```toml
[[rule]]
id        = "U-101"
category  = "boundary"
severity  = "high"
decision  = "deny"
match.path_outside_project = true
match.path_not = ["~/.config/shared-lint/**"]
```

Verify: `observer guard test --file ~/somewhere/else.txt` (hits) vs
`--file ~/.config/shared-lint/rc.json` (exempt).

**3. Taint chain: after an untrusted web fetch, ask before any git
push.** Source→sink rules express "data from X must not reach Y this
session" — the prompt-injection blast-radius limiter.

```toml
[[rule]]
id        = "U-102"
category  = "taint"
severity  = "high"
decision  = "ask"
match.taint_source = "web_fetch"
match.sink         = "git_push"
```

Verify: needs a tainted session, so use history — `observer guard
rescan --since 24h` after a browsing-heavy session, then check the
timeline for U-102 rows.

**4. Flag everything once a session has burned more than $20.** Pure
conditions imply no event kind, so `applies_to` is required. Cost
stamps ride the daemon surfaces (watcher/proxy) — hook-path events
aren't stamped (§6.4 latency budget).

```toml
[[rule]]
id         = "U-103"
category   = "budget"
decision   = "flag"
applies_to = ["shell_exec", "api_request"]
match.session_cost_usd_gt = 20.0
```

Verify: `observer guard simulate --since 720h` and look for U-103 in
the by-rule breakdown — your own history says whether $20 is a
tripwire or a Tuesday. (The Security page's Budget guardrails card
computes the p95s for exactly this sizing question.)

**5. Block calls to an MCP server you haven't vetted.**

```toml
[[rule]]
id       = "U-104"
category = "mcp"
severity = "critical"
decision = "deny"
match.mcp_server = "sketchy-server"
```

Verify: `observer guard test --event '{"kind":"mcp_call","target":
"sketchy-server/do_thing"}'`.

**6. Escalate a built-in and pre-enforce it (the ramp override).**
Built-in IDs can't be redefined — tune them. This is the
observe→enforce ramp in one stanza: R-110 (git force-push) starts
actually blocking while everything else keeps observing.

```toml
[[override]]
rule     = "R-110"
decision = "deny"
enforce  = true
```

Verify: `observer guard test "git push --force origin main"` — the
current-mode column flips to `deny` despite observe mode.

**7. Replace a noisy built-in with an exemption-aware version.**
Overrides tune decisions, not matchers — there is no
`[[override]] match.*`. When a built-in keeps firing on one
legitimate path, the pattern is disable-and-replace: turn the ID off
in *config.toml* and ship your own version with the exemption in the
*policy file*. Two files, deliberately — disabling is a config
posture, matching is policy.

```toml
# config.toml
[guard.rules]
disable = ["R-152"]   # the built-in you're replacing
```

```toml
# ~/.observer/guard-policy.toml — same intent, with your exemption.
[[rule]]
id        = "U-105"
category  = "boundary"
severity  = "critical"
decision  = "deny"
match.path_sensitive = true
match.path_not = ["~/.aws/cli/cache/**"]
```

Verify: `observer guard simulate --since 168h` before and after — the
replaced rule's count collapses while U-105 picks up only the genuine
hits. Strictest-first reminder: a scoped approval beats this entire
recipe when the noise is one project or one session; save
disable-and-replace for permanent, path-shaped noise.

## Validating and shipping a policy

```
observer guard lint                       # user + this repo's project file
observer guard lint path/to/policy.toml   # explicit files (linted as user layer)
observer guard test "rm -rf ./build"      # would THIS hit?
observer guard simulate --since 168h      # what would last week have flagged?
```

Lint exits 1 on any problem, so it composes into pre-commit hooks.
Common rejects: a duplicate `id`, an `id` colliding with a built-in
(use `[[override]]`), unknown `match.*` keys, mixing command-scoped
and event-scoped matchers in one rule, a rule with no matchers, and a
pure-condition rule without `applies_to`.

CEL-expression rules are parsed-but-rejected behind the
`[guard.rules] cel` v2 gate (operator decision Q1) — matchers v1 is
the supported surface.
