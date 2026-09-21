# Guard enforce-migration runbook

How to take the guard from observe (the install default) to enforce
without surprising yourself or your agents. The path is:

> **simulate → review → per-rule ramp → enable → monitor → rollback**

Every step has a dashboard surface and a CLI command; both write
through the same seams, so use whichever you live in. Companion docs:
[`guard.md`](guard.md) (concepts + config reference),
[`guard-policy-authoring.md`](guard-policy-authoring.md) (rule and
override syntax), [`guard-rules.md`](guard-rules.md) (the built-in
catalog).

## What enforce actually changes (read first)

- **Mode is a global switch, blocking is per-channel.** In observe,
  deny/ask-class rules still evaluate and record — the action just
  proceeds. In enforce, they block **only on channels that can
  block**: Claude Code / Cursor hooks (pre-execution) and the proxy
  (egress/budget). Watcher-only adapters keep flagging post-hoc —
  that asymmetry is structural (F2), and the Security page's
  Enforcement coverage table is the honest census for your install.
- **Ask degrades, never silently allows** (F5): on clients without a
  native ask, an `ask` verdict becomes deny-with-reason in enforce
  and a flag in observe.
- **Blocked actions return machine-readable reasons** written for the
  agent — one sentence on what was blocked, one on what to do
  instead. Agents self-correct on good reasons; the block is a
  redirect, not a dead end.
- **Approvals are the relief valve**: a scoped, expiring grant
  downgrades a matching block to a flag, lives in the audit story,
  and takes effect immediately (DB write, no restart).

## Step 1 — Simulate

Replay your real captured history against today's policy under the
enforce projection. This is the question only a tool that already has
your history can answer: *what would last week have blocked?*

- **Dashboard**: Security → **Enforce readiness** → Run the readiness
  check (7d or 30d window).
- **CLI**: `observer guard simulate --since 168h --enforce`

Both run a fresh engine over the actions table — a dry run; nothing
persists, the live guard is untouched. Two reading aids:

- The replay judges against the **on-disk** policy, not the running
  daemon's bound copy — a policy edit you saved but haven't restarted
  for is exactly what gets simulated.
- The replay does **not** consult the approvals register. Active
  grants downgrade matching blocks in live enforce, so the simulated
  `would_block` is an upper bound.
- The replay caps at 50,000 actions per pass. If the cap is hit, the
  window's oldest actions weren't replayed — narrow the window for
  full coverage.

## Step 2 — Review

Read the would-block list rule by rule and sort each into one of two
buckets:

1. **Intended** — "yes, I want that blocked." Leave it alone; this is
   what you're enabling enforce for.
2. **Noise** — a rule firing on your legitimate workflow. Tune it
   before enforce, or your agents hit walls on day one and you'll be
   tempted to turn the whole thing off again.

A concentration signal worth trusting: when one rule carries half or
more of the would-blocks (on real installs an ask-class rule like
R-151 often does), tune that one rule first — it usually collapses
the review to a handful of genuine cases.

Tuning options, **strictest first** (same ladder as the
[`guard.md`](guard.md) FAQ):

| Option | Scope | How |
|---|---|---|
| Scoped approval | one session / one project / global, expiring | dashboard Approvals card ("approve…" on any verdict or readiness row), or `observer guard approve R-xxx --session\|--project\|--global --ttl 168h` |
| Override the decision | the rule, everywhere | `[[override]] rule = "R-xxx"` + `decision = "flag"` in `~/.observer/guard-policy.toml` |
| Exempt paths | the rule, specific paths | author your own stricter replacement with `match.path_not` exemptions ([`guard-policy-authoring.md`](guard-policy-authoring.md)) |
| Disable the ID | everywhere, unconditionally | `[guard.rules] disable = ["R-xxx"]` — last resort; invisible in the audit story |

After each change: `observer guard lint` (a file that lints clean is
a file that loads), then **re-simulate**. The loop is cheap; iterate
until the would-block list reads as intended blocks only.

## Step 3 — Per-rule enforce ramp (optional but recommended)

You don't have to flip the whole engine at once. A rule can carry
`enforce = true` and block **even while the global mode stays
observe** — "enforce critical, observe the rest" is a config posture,
not a separate mode:

```toml
# ~/.observer/guard-policy.toml — block the catastrophic class now,
# keep observing everything else.
[[override]]
rule    = "R-101"   # rm -rf class
enforce = true

[[override]]
rule    = "R-110"   # git force-push
enforce = true
decision = "deny"   # optional: also escalate the decision
```

Run this posture for a few days. Watch the timeline for those rules'
verdicts arriving with the enforced mark (`✓` on the decision pill) —
each one is a real block your workflow survived. When the ramp feels
boring, you're ready for the full flip.

Policy edits bind at daemon restart (the dashboard's restart banner
is honest about this); hook processes read config per invocation and
follow immediately.

### On an enrolled node: org-granted overrides

If your machine carries an org policy bundle, the enforce ramp is not
entirely yours to run: the bundle is a strictness FLOOR you cannot
lower, and the exception register now answers to it.

- A rule the organization marked `overridable = true` still blocks,
  but presents as a native **ask** where the client supports one
  (Claude Code, Cursor) and names the exact grant command everywhere
  else. `observer guard approve <rule> --session <id>` works as
  documented, and the grant is reported to the organization.
- A locked rule is **org-locked**: `observer guard approve` refuses
  with `locked by org policy: <rule>`, and any grant you created
  BEFORE enrolment is ignored at evaluation time (the audit reason
  records `[org_locked: ...]` so the refusal is visible, not silent).
  Ask your admin to mark the rule overridable.
- **How many rules are locked depends on your node's tenancy**, not on
  the bundle alone:
  - a **managed** node (Enterprise-Managed Tenancy) is org-authoritative,
    so *every* rule the bundle did not mark `overridable` is locked,
    including built-ins the bundle never mentions;
  - an **individual** node treats the bundle as a floor: it locks the
    rules the bundle NAMES (an `[[override]]` target or a rule the
    bundle defines) and leaves every other rule's local approvals
    working exactly as before enrolment.
- Check which is which with `observer guard rules --effective` and the
  Security page's **Organization guardrails** card.
- **A block with no session id cannot be overridden from the CLI.**
  Approvals are scoped to a session, or to the project root resolved
  from that session; a proxy-routed client that sends no
  `prompt_cache_key` / `Session-Id` (and that the pidbridge did not
  recognise) gives the daemon nothing to scope a grant to. The deny
  text says so rather than printing an uncallable command - use the
  dashboard Security page, or re-run through a session-identified
  client.

On a node with no org bundle none of this applies and the ramp above
is unchanged.

## Step 4 — Enable enforce

- **Dashboard**: Security → **Mode** card → Enforce. The consent step
  re-runs the 7-day simulate and shows the evidence before you
  confirm; the save goes through the one config seam and raises the
  restart banner.
- **CLI**: `observer guard enable --enforce` (a surgical
  `[guard]` edit — your comments and other sections are untouched),
  then restart the daemon (`observer start`).

Right before flipping, simulate once more — policy and history have
both moved since step 1.

## Step 5 — Monitor

The first 24–48 hours are the proving window:

- **Timeline**: Security → Verdict timeline, decision filter on
  `deny` / `ask`. Enforced verdicts carry the `✓` mark; `degraded
  from` pills show where a channel couldn't express the verdict.
- **Agent behavior**: a healthy block shows the agent reading the
  reason and taking the suggested path. An agent retry-looping
  against the same deny means the reason isn't actionable — tune the
  rule or grant a scoped approval.
- **Relief valve**: approvals take effect immediately (no restart).
  Grant narrow (session scope, short TTL) and let the grant expire
  rather than granting global.
- **Alerts**: `[guard.alerts]` desktop notifications fire at
  `min_severity` (default high) — enforce doesn't change what alerts,
  only what blocks.
- **Audit**: `observer guard verify-audit` confirms the chain over
  the new enforced rows; `observer guard report --period 7d` is the
  evidence pack if someone asks what changed.

## Step 6 — Rollback

Enforce is one config key, and demoting is the same consent flow in
reverse:

- **Dashboard**: Security → Mode card → Observe (restart to bind).
- **CLI**: `observer guard enable` (without `--enforce` it writes
  `mode = "observe"`), then restart.

Nothing is lost on rollback: verdicts keep recording in observe, the
audit chain continues, and your tuned overrides/approvals stay in
place — flipping back later starts from where you left off, not from
scratch. For a partial retreat, remove a single `enforce = true`
override or grant an approval instead of demoting the whole engine.

## Failure-honesty footnotes

- Hooks see **declared** commands, not side effects (F1) — a script
  can do anything; the watcher catches results post-hoc.
- A guard internal error fails **open** by default (allow + a
  recorded `guard_error` event); `[guard] strict = true` inverts to
  fail-closed.
- The agent can edit its own client's hook config (we flag it
  critically and re-register on `observer start`, but the files
  belong to the client) — enforce raises the stakes of that tamper
  surface, not its existence.
