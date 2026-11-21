#!/usr/bin/env python3
"""Dry-run canary for one Python example: no provider call, ever.

Runs in the example's own virtualenv, with the same superbased settings the
real chatbot would get (destination, machine and org addresses), and checks
the parts that do not need a model:

  * the SDK starts and resolves the expected destination;
  * ``sb.instrument(<the example's targets>)`` answers ``instrumented`` for
    every target (the framework and its instrumentor are installed);
  * one synthetic trace (a root AGENT span and one manual LLM span with fixed
    usage) is exported, so verify.py can prove ingest, identity, tokens and
    cost on the machine and/or the org exactly as for a live run.

Writes a run record in the chatbot's run.json shape. Exit 0 when the SDK set
up cleanly; verify.py decides the rest. Provider keys are stripped from the
environment by the runner before this starts.

  python canary.py --targets openai --service e2e-canary --model gpt-5-nano \
      --provider openai --out run.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time

INPUT, OUTPUT, CACHED = 1000, 100, 0


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--targets", default="", help="comma list passed to sb.instrument()")
    p.add_argument("--service", required=True)
    p.add_argument("--model", required=True)
    p.add_argument("--provider", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--admit-probe", default="", help="also call sb.admit(<text>) and record the verdict")
    a = p.parse_args()

    # The examples on Claude turn the Anthropic SDK's own spans off; the
    # canary makes no Anthropic call, but keep the same environment.
    os.environ.setdefault("ANTHROPIC_OPEN_TELEMETRY", "false")
    os.environ.setdefault("CREWAI_DISABLE_TELEMETRY", "true")
    os.environ.setdefault("CREWAI_TRACING_ENABLED", "false")

    import superbased_sdk as sb

    run_id = os.environ.get("RUN_ID", str(int(time.time())))
    sb.init(service_name=a.service, release="planea-e2e-canary")
    targets = [t for t in a.targets.split(",") if t]
    status = sb.instrument(targets) if targets else {}
    status = {k: str(v) for k, v in (status or {}).items()}
    print("instrument:", status, file=sys.stderr)

    user, session, tenant = "user-ada", f"canary-{run_id}", "acme"
    trace_ids = []
    with sb.propagate_attributes(user=user, session_id=session, tenant=tenant):
        with sb.span("canary-turn", kind=sb.AGENT):
            trace_ids.append(sb.get_current_trace_id())
            with sb.llm_span("canary-chat", model=a.model, provider=a.provider) as s:
                sb.set_usage(s, input_tokens=INPUT, output_tokens=OUTPUT, cache_read_tokens=CACHED,
                             response_model=a.model, response="canary")
    verdicts = []
    if a.admit_probe:
        v = sb.admit(a.admit_probe)
        verdicts.append({"probe": a.admit_probe, "decision": v.decision, "allowed": v.allowed, "mode": v.mode,
                         "degraded": v.degraded})
    sb.flush()
    diag = sb.diagnostics()
    record = {
        "service": a.service, "run_id": run_id, "user": user, "session": session, "tenant": tenant,
        "trace_ids": trace_ids, "calls": [{"kind": "canary", "input": INPUT, "output": OUTPUT, "cached": CACHED}],
        "instrument": status, "verdicts": verdicts,
        "diagnostics": {k: diag.get(k) for k in ("destination", "destination_source", "destinations", "signed_in",
                                                  "credential_source", "failed_exports", "dropped_spans", "warnings")},
    }
    with open(a.out, "w") as f:
        json.dump(record, f, indent=2, default=str)
    sb.shutdown()
    bad = {k: v for k, v in status.items() if v not in ("instrumented", "already")}
    if bad:
        print(f"canary: not instrumented: {bad}", file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
