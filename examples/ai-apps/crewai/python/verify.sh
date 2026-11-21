#!/usr/bin/env bash
# Check, through the machine's local API, that a chatbot.py run arrived whole:
# crew, agent and tool spans with the right parents, the model calls as LLM
# spans with model, tokens and a request id each, end user and session set,
# and a cost above zero. Exits non-zero on the first missing piece.
#
#   ./verify.sh <session id printed by chatbot.py>
#
# Optional: EXPECT_INPUT_TOKENS / EXPECT_OUTPUT_TOKENS (the "crewai usage"
# line chatbot.py prints) make the token totals an exact match. API defaults
# to http://127.0.0.1:8081 (OBSERVER_API overrides it).
set -euo pipefail

SESSION="${1:-${CHATBOT_SESSION_ID:-}}"
API="${OBSERVER_API:-http://127.0.0.1:8081}"
if [ -z "$SESSION" ]; then
  echo "usage: $0 <session id>" >&2
  exit 2
fi

traces="$(curl -fsS "$API/api/obs/traces?days=1")" || { echo "FAIL: cannot reach $API/api/obs/traces" >&2; exit 1; }
trace_id="$(printf '%s' "$traces" | python3 -c '
import json, sys
s = sys.argv[1]
ts = [t for t in json.load(sys.stdin).get("traces") or [] if t.get("session_id") == s and t.get("status") == "ok"]
print(ts[0]["trace_id"] if ts else "")
' "$SESSION")"
if [ -z "$trace_id" ]; then
  echo "FAIL: no ok trace for session $SESSION (is app observability on and did the run finish?)" >&2
  exit 1
fi

curl -fsS "$API/api/obs/trace/$trace_id" | python3 -c '
import json, os, sys

d = json.load(sys.stdin)
t, spans = d["trace"], d["spans"]
by_id = {s["span_id"]: s for s in spans}
fails = []

def check(ok, msg):
    print(("ok   " if ok else "FAIL ") + msg)
    if not ok:
        fails.append(msg)

def parent(s):
    return by_id.get(s["parent_span_id"])

crew = [s for s in spans if not s["parent_span_id"] and s["name"].startswith("Crew_") and s["name"].endswith(".kickoff")]
check(len(crew) == 1, "one root crew span (Crew_<id>.kickoff)")
agents = [s for s in spans if s["kind"] == "agent"]
check(bool(agents) and all(parent(a) in crew for a in agents), "agent/task span(s) under the crew span: %d" % len(agents))
tools = [s for s in spans if s["kind"] == "tool"]
check(all(parent(x) in agents for x in tools), "tool span(s) under the agent span: %d" % len(tools))

# The model calls. CrewAI also calls OpenAI token counting before calls; the
# OpenAI instrumentor records those as LLM spans with no model or usage
# (InputTokenCountResponse), which superbased stores as chain steps.
calls = [s for s in spans if s["kind"] == "llm" and s["model"]]
check(len(calls) >= 1, "LLM spans with a model: %d" % len(calls))
for c in calls:
    check(c["model"].startswith("gpt-5-nano"), "%s model %s" % (c["span_id"], c["model"]))
    check(parent(c) in agents, "%s parent is the agent span" % c["span_id"])
    check((c["input_tokens"] or 0) > 0 and (c["output_tokens"] or 0) > 0,
          "%s tokens in=%s out=%s" % (c["span_id"], c["input_tokens"], c["output_tokens"]))
# The provider response id (chatcmpl-...) identifies the call; request_id holds
# only an explicit or AI-gateway id.
ids = [c.get("request_id") or c.get("provider_response_id") for c in calls]
check(all(ids) and len(set(ids)) == len(ids), "one LLM span per model call (distinct request ids)")

check(bool(t.get("end_user")), "end user: %s" % t.get("end_user"))
check(t.get("session_id") == sys.argv[1], "session: %s" % t.get("session_id"))
for k, env in (("input_tokens", "EXPECT_INPUT_TOKENS"), ("output_tokens", "EXPECT_OUTPUT_TOKENS")):
    want = os.environ.get(env)
    if want:
        check(t[k] == int(want), "trace %s %s == %s" % (k, t[k], want))
    else:
        check(t[k] > 0, "trace %s %s" % (k, t[k]))
cost = t.get("cost_usd") or 0
label = (d.get("cost_provenance") or {}).get("label")
check(cost > 0, "trace cost_usd %.8f (%s)%s" % (cost, label,
      "" if cost > 0 else ": the machine has no non-zero price for this model, see README"))

print("trace", t["trace_id"], "spans", t["span_count"])
sys.exit(1 if fails else 0)
' "$SESSION"
