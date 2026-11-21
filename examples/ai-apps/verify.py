#!/usr/bin/env python3
"""Check that an example chatbot's run arrived, with the right spans, tokens and cost.

Standard library only. Reads the run record the chatbot wrote (run.json: its
trace ids, its identity and the token counts the provider reported) and asks where
the spans should have landed:

  --target machine  this machine's local API, GET <node>/api/obs/trace/<id>
                    (default node http://127.0.0.1:8081, or SUPERBASED_NODE_URL)
  --target org      the organization's gateway, GET <org>/v1/sdk/traces/<id>/cost
                    with SUPERBASED_API_KEY (scope sdk:read). This route returns
                    each LLM span's model and cost, not tokens or identity.

Exit status 0 when every check passes, 1 otherwise. Never prints a key.

  python verify.py run.json --target machine --llm-spans 6
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request

FAILS: list[str] = []


def check(ok: bool, what: str) -> None:
    print(("PASS " if ok else "FAIL ") + what)
    if not ok:
        FAILS.append(what)


def get(url: str, key: str = "") -> tuple[int, dict]:
    req = urllib.request.Request(url)
    if key:
        req.add_header("Authorization", "Bearer " + key)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(req, timeout=10) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, {}
    except (urllib.error.URLError, OSError):
        return 0, {}


def wait_for(fetch, want_spans: int, deadline: float):
    """Poll until the trace is there with at least want_spans spans (ingest is async)."""
    code, body = 0, {}
    while time.time() < deadline:
        code, body = fetch()
        if code == 200 and len(body.get("spans") or []) >= max(want_spans, 1):
            return code, body
        time.sleep(1)
    return code, body


def machine(run: dict, args) -> None:
    node = (args.node or os.environ.get("SUPERBASED_NODE_URL") or "http://127.0.0.1:8081").rstrip("/")
    llm_in = llm_out = llm_n = 0
    llm_cost = 0.0
    for tid in run["trace_ids"]:
        code, body = wait_for(lambda: get(f"{node}/api/obs/trace/{tid}"), 1, time.time() + args.wait)
        check(code == 200, f"machine has trace {tid}")
        if code != 200:
            continue
        t, spans = body.get("trace", {}), body.get("spans", [])
        ids = {s["span_id"] for s in spans}
        check(len(ids) == len(spans), f"{tid}: no duplicate span ids ({len(spans)} spans)")
        orphans = [s["name"] for s in spans if s.get("parent_span_id") and s["parent_span_id"] not in ids]
        check(not orphans, f"{tid}: every parent link resolves inside the trace {orphans or ''}")
        roots = [s for s in spans if not s.get("parent_span_id")]
        check(len(roots) == 1, f"{tid}: one root span (got {len(roots)})")
        for field in ("user", "session", "tenant"):
            want = run.get(field)
            if want:
                got = t.get({"user": "end_user", "session": "session_id"}.get(field, field))
                check(got == want, f"{tid}: trace {field} = {want!r} (got {got!r})")
        check(t.get("service") == run["service"], f"{tid}: service = {run['service']!r} (got {t.get('service')!r})")
        t_in = t_out = 0
        for s in spans:
            if s.get("kind") != "llm" or (args.ignore_span and re.search(args.ignore_span, s.get("name", ""))):
                continue
            t_in += s.get("input_tokens") or 0
            t_out += s.get("output_tokens") or 0
            llm_n += 1
            llm_in += s.get("input_tokens") or 0
            llm_out += s.get("output_tokens") or 0
            llm_cost += s.get("cost_usd") or 0.0
            check(str(s.get("model", "")).startswith(args.model), f"{tid}/{s['name']}: model {s.get('model')!r}")
            check(bool(s.get("cost_source")), f"{tid}/{s['name']}: cost_source {s.get('cost_source')!r}, cost_usd {s.get('cost_usd')}")
            check((s.get("input_tokens") or 0) > 0 and (s.get("output_tokens") or 0) > 0,
                  f"{tid}/{s['name']}: tokens in={s.get('input_tokens')} out={s.get('output_tokens')}")
        # The trace total must be its model calls, counted once (no span above
        # them may add the same tokens again).
        check((t.get("input_tokens"), t.get("output_tokens")) == (t_in, t_out),
              f"{tid}: trace tokens {t.get('input_tokens')}/{t.get('output_tokens')} equal its LLM spans {t_in}/{t_out}")
    report(run, args, llm_n, llm_in, llm_out, llm_cost)


def org(run: dict, args) -> None:
    base = (args.org_url or os.environ.get("SUPERBASED_ORG_URL") or "").rstrip("/")
    key = os.environ.get("SUPERBASED_API_KEY", "")
    if not base or not key:
        check(False, "SUPERBASED_ORG_URL and SUPERBASED_API_KEY are set (the key needs scope sdk:read)")
        return
    llm_n = 0
    llm_cost = 0.0
    for tid in run["trace_ids"]:
        code, body = wait_for(lambda: get(f"{base}/v1/sdk/traces/{tid}/cost", key), 1, time.time() + args.wait)
        check(code == 200, f"org has trace {tid} (HTTP {code})")
        for s in body.get("spans", []):
            llm_n += 1
            llm_cost += s.get("cost_usd") or 0.0
            check(str(s.get("model", "")).startswith(args.model), f"{tid}/{s['span_id']}: model {s.get('model')!r}")
            check(bool(s.get("cost_source")), f"{tid}/{s['span_id']}: cost_source {s.get('cost_source')!r}, cost_usd {s.get('cost_usd')}")
            if args.cost_source:
                check(s.get("cost_source") == args.cost_source, f"{tid}/{s['span_id']}: cost_source is {args.cost_source}")
    if args.llm_spans is not None:
        check(llm_n == args.llm_spans, f"priced LLM spans: {llm_n} (want {args.llm_spans})")
    check_price(run, args, llm_cost)


def report(run: dict, args, n: int, tin: int, tout: int, cost: float = 0.0) -> None:
    calls = [c for c in run.get("calls", []) if "input" in c]
    if args.llm_spans is not None:
        check(n == args.llm_spans, f"LLM spans: {n} (want {args.llm_spans})")
    if calls:
        want_in, want_out = sum(c["input"] for c in calls), sum(c["output"] for c in calls)
        check((tin, tout) == (want_in, want_out),
              f"LLM tokens in/out {tin}/{tout} equal what the provider reported {want_in}/{want_out}")
    check_price(run, args, cost)


def check_price(run: dict, args, cost: float) -> None:
    calls = [c for c in run.get("calls", []) if "input" in c]
    if args.price and calls:
        # Expected cost from the provider's own usage and the given $/MTok
        # rates. calls[].input is the whole (gross) prompt; the cache read
        # (cached) and cache write (cache_write) parts are priced at their own
        # rates and the rest at the input rate.
        rin, rout, rread, rwrite = (float(x) for x in args.price.split(","))
        want = 0.0
        for c in calls:
            read, write = c.get("cached", 0), c.get("cache_write", 0)
            want += ((c["input"] - read - write) * rin + c["output"] * rout + read * rread + write * rwrite) / 1e6
        check(abs(cost - want) <= max(1e-9, want * 0.001),
              f"LLM cost ${cost:.8f} equals the provider usage at the given rates ${want:.8f}")


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("run", help="the run record the chatbot wrote (run.json)")
    p.add_argument("--target", choices=("machine", "org"), default="machine")
    p.add_argument("--node", help="this machine's dashboard API (default SUPERBASED_NODE_URL, else http://127.0.0.1:8081)")
    p.add_argument("--org-url", help="the organization's gateway (default SUPERBASED_ORG_URL)")
    p.add_argument("--llm-spans", type=int, help="the exact number of LLM spans expected")
    p.add_argument("--model", default="gpt-5-nano")
    p.add_argument("--price", help="IN,OUT,CACHE_READ,CACHE_WRITE in $ per million tokens: check the LLM cost equals the provider usage at these rates")
    p.add_argument("--cost-source", help="require this cost_source on every priced span (org target)")
    p.add_argument("--ignore-span", help="a regex of LLM span names to leave out (an instrumentor's spans that make no model call)")
    p.add_argument("--wait", type=float, default=30, help="seconds to wait for ingest")
    args = p.parse_args()
    with open(args.run) as f:
        run = json.load(f)
    (machine if args.target == "machine" else org)(run, args)
    print(f"\n{len(FAILS)} check(s) failed" if FAILS else "\nall checks passed")
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
