---
name: planea-e2e
description: Run the AI Apps (Plane A) live end-to-end playbook - real chatbots under examples/ai-apps (Python, TypeScript, Go, Java) on OpenAI gpt-5-nano and Anthropic claude-haiku-5-5, against a throwaway superbased machine and org, checked by verify.py - and report the result. The dry run is proven; the live path is not yet proven (no live run has happened). Use when asked to run the AI Apps / Plane A live e2e, the chatbot e2e, or the planea-e2e playbook, or after the user accepts the offer to run it following a significant change to the SDKs, OTLP ingest, the gateway, pricing or cost, admission, app budgets, discovery/sign-in or evals.
---

# AI Apps live e2e

The playbook is `docs/planea-e2e-playbook.md`; read it first. The runner is
`scripts/planea-e2e/run.sh`. The live path has not had its first run yet
(lane E2): say so when you report a live result, and treat its numbers as
the first measurement. The Go and Java examples (sdk-direct) were added by
lane E3 and have only run as dry-run canaries.

## Rules

- Run only in a cloud session or a throwaway Linux or macOS box, never on a
  developer's own machine with a live superbased. The runner refuses on its
  own (a real `~/.observer/observer.db`, or a superbased answering on
  `127.0.0.1:8081` or `:8820`; always on Windows or with a symlinked
  `node_modules`). Do not pass `--allow-live-host` unless the user tells you
  to, and never point the runner at `~/.observer`, `:8081`, `:8820` or `:4318`.
- Keys come from `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` in the environment
  only. Never print, echo, `env`-dump, write or paste a key, not even its
  first characters. Check presence with `[ -n "${OPENAI_API_KEY:-}" ]`.
- How keys reach a cloud session: as secrets of the cloud environment the
  session runs in (the user adds them in the environment's settings), in an
  environment whose network allows `api.openai.com` and `api.anthropic.com`.
  Never ask the user to paste a key in chat; if a key is missing, say which
  one and stop at the dry run.
- Only the cheap models (the examples pin them, and the runner sets
  `CHATBOT_MODEL` itself): OpenAI `gpt-5-nano`; Anthropic `claude-haiku-5-5`
  at `output_config.effort: "low"`. Do not edit an example to use another
  model.
- The run reports; it does not fix. Do not change SDK or product code because
  of a FAIL. Record it (see "Report back").
- If a provider host is blocked (the default cloud environment blocks
  `api.openai.com`), say so plainly and run the dry run; do not claim a live
  pass that did not happen.

## Steps

1. Preflight: `go version`, `python3 --version` (3.10-3.13 available, `uv`
   preferred), `node --version` (22.18 or newer: the TypeScript examples run
   `node chatbot.ts`), `java -version` and `mvn -v` (a JDK 17 or newer, with
   `javac`, for the Java example), and for `online`/`both` PostgreSQL 16
   (`initdb`, `pg_ctl`, `psql`). Missing pieces, on Debian/Ubuntu (a cloud
   session runs as root): `apt-get install -y postgresql-16` (binaries land in
   `/usr/lib/postgresql/16/bin`, which the runner finds),
   `apt-get install -y openjdk-17-jdk-headless maven`, and
   `curl -LsSf https://astral.sh/uv/install.sh | sh` for `uv`. A selection
   that leaves a language out does not need its tools (`--langs python,typescript`
   skips Go's example and Java). Check which keys are set (presence only).
2. Run in the background or with a long timeout: a dry run takes about 3
   minutes warm and 8 cold, a full live run 25-35 minutes, and a foreground
   shell call is capped at 10 minutes. Start it in the background and wait
   for its exit instead of polling.
3. Dry run first, always. It contacts no provider (not even a model-list
   check), with or without keys:

   ```bash
   scripts/planea-e2e/run.sh --dry-run --destination all
   ```

   Exit 0 means the machine, the org, sign-in, every example's environment
   and verify.py all work.
4. Ask before the live run, and state the cap in the question, for example:
   "The dry run passed. Run the live e2e on both providers, all
   destinations? It spends real money: estimated under $0.05, capped at
   `--max-spend` $0.50 (an estimate from reported usage, not a provider-side
   limit)." Run it only on a yes. Scope it to what the change touched (the
   user may name the scope):

   ```bash
   scripts/planea-e2e/run.sh --destination all
   ```

   or `--frameworks openai,langgraph --providers openai --destination local`.
5. Read `scripts/planea-e2e/out/<timestamp>/report.md` (and `report.json`;
   logs are beside them).

Exit status: 0 every case that ran passed; 1 a case failed; 2 setup failed
or the runner refused this host (read `report.md` "Setup error" when there
is one, then `logs/` beside it: `machine-daemon.log`, `org-serve.log`,
`postgres.log`, `install/`; a refusal prints `REFUSED:` lines and writes no
report); 4 nothing ran (every case skipped, usually missing keys).

## Report back

Give the user, in a few lines: the mode (dry run or live), the tree's sha,
pass / fail / skip counts, the approximate spend and the amount charged
against the cap from the report, every SKIP with its reason, and every FAIL
with its first failing check, marked "known (L-03 ...)" when the report
names a known finding for that example and new otherwise. Link the report
path. For a new FAIL, reproduce the single case with `--keep` (the kept
work directory is redacted in place), find the cause in code if you can,
and write it up as the 2026-11-20 reviews do (id, severity, seen live,
cause, fix, owner) in the status or review file the user names, or offer to.
