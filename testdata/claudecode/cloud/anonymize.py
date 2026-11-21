"""Anonymize a Claude Code cloud transcript into a small adapter fixture.

Structure (line types, key names, entrypoint, version, userType,
clientPlatform, model, usage NUMBERS, stop_reason) is kept from the real
transcript. Every id, path, branch, prompt, thought, tool input, tool output
and every free-form vendor field is REPLACED or DROPPED (allow-list, so an
unknown key never survives).
Usage: python3 -I anonymize.py <transcript.jsonl> <entrypoint> <out.jsonl>
"""
import json, sys, uuid

src, entrypoint, out = sys.argv[1], sys.argv[2], sys.argv[3]
lines = [json.loads(l) for l in open(src)]
NS = uuid.UUID("00000000-0000-5000-8000-000000000000")
SESSION = str(uuid.uuid5(NS, "fixture-session-" + entrypoint))
ids = {}
def fake(kind, real):
    if real is None:
        return None
    k = (kind, real)
    if k not in ids:
        ids[k] = str(uuid.uuid5(NS, "%s-%s-%d" % (entrypoint, kind, len(ids))))
    return ids[k]

CWD = "/home/user/example-repo"
BRANCH = "claude/example-branch"
TS = ["2026-10-31T08:49:%02d.000Z" % s for s in range(10, 60, 3)]
ts_i = [0]
def ts():
    v = TS[ts_i[0]]; ts_i[0] += 1; return v

def envelope(d):
    o = {"type": d["type"], "sessionId": SESSION}
    if "parentUuid" in d:
        o["parentUuid"] = fake("uuid", d["parentUuid"])
        o["isSidechain"] = False
        o["uuid"] = fake("uuid", d["uuid"])
        o["userType"] = d["userType"]
        o["entrypoint"] = entrypoint
        o["cwd"] = CWD
        o["version"] = d["version"]
        o["gitBranch"] = BRANCH
        o["timestamp"] = ts()
    return o

USAGE_KEEP = ["input_tokens", "cache_creation_input_tokens", "cache_read_input_tokens", "output_tokens", "service_tier"]
def usage(u):
    return {k: u[k] for k in USAGE_KEEP if k in u}

def pick(pred):
    for d in lines:
        if pred(d):
            return d
    raise SystemExit("no line matched")

def blocks(d):
    c = (d.get("message") or {}).get("content")
    return c if isinstance(c, list) else []

prompt = pick(lambda d: d["type"] == "user" and isinstance((d.get("message") or {}).get("content"), str))
tooluse = pick(lambda d: d["type"] == "assistant" and any(b.get("type") == "tool_use" and b.get("name") == "Bash" for b in blocks(d)))
tu_id = next(b["id"] for b in blocks(tooluse) if b.get("type") == "tool_use")
result = pick(lambda d: d["type"] == "user" and any(b.get("type") == "tool_result" and b.get("tool_use_id") == tu_id for b in blocks(d)))
lastp = pick(lambda d: d["type"] == "last-prompt")

out_lines = []
o = envelope(prompt)
o["promptId"] = fake("prompt", prompt.get("promptId"))
# clientPlatform is kept only for the entrypoint the source was recorded
# with; a re-labelled variant ("remote" from a remote_desktop source) drops
# it rather than claim a client it never had.
if "clientPlatform" in prompt and prompt.get("entrypoint") == entrypoint:
    o["clientPlatform"] = prompt["clientPlatform"]
o["message"] = {"role": "user", "content": "Show me the working tree status."}
out_lines.append(o)

o = envelope(tooluse)
o["parentUuid"] = out_lines[-1]["uuid"]
m = tooluse["message"]
o["requestId"] = "req_fixture" + entrypoint.replace("_", "")
FAKE_TU = "toolu_fixture" + entrypoint.replace("_", "")
o["message"] = {
    "model": m["model"], "id": "msg_fixture" + entrypoint.replace("_", ""), "type": "message", "role": "assistant",
    "content": [{"type": "tool_use", "id": FAKE_TU, "name": "Bash",
                 "input": {"command": "git status", "description": "Show working tree status"}}],
    "stop_reason": m.get("stop_reason"), "stop_sequence": None, "usage": usage(m["usage"]),
}
out_lines.append(o)

o = envelope(result)
o["parentUuid"] = out_lines[-1]["uuid"]
o["promptId"] = out_lines[0]["promptId"]
o["message"] = {"role": "user", "content": [{"type": "tool_result", "tool_use_id": FAKE_TU,
                "content": "On branch claude/example-branch\nnothing to commit, working tree clean", "is_error": False}]}
out_lines.append(o)

o = envelope(lastp)
o["lastPrompt"] = "Show me the working tree status."
o["leafUuid"] = out_lines[-1]["uuid"]
out_lines.append(o)

with open(out, "w") as f:
    for l in out_lines:
        f.write(json.dumps(l, separators=(",", ":")) + "\n")
