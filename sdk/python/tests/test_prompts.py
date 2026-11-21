"""W3-3: get_prompt() to contracts/prompts.md: the shared compile cases, the
recorded fetch response, the ETag cache with stale-while-revalidate, the
fallback and the span stamp."""

import json
import os
import threading
import time
import urllib.parse

import pytest
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

import superbased_sdk as sb
from superbased_sdk import _prompts

CONTRACT = os.path.join(os.path.dirname(__file__), "..", "..", "contract")


def load(name):
    path = os.path.join(CONTRACT, name)
    if not os.path.exists(path):
        pytest.skip("sdk/contract is not present (an sdist)")
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def cases():
    path = os.path.join(CONTRACT, "prompt-compile-cases.json")
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        return json.load(f)["cases"]


@pytest.mark.parametrize("case", cases(), ids=lambda c: c["name"])
def test_shared_compile_cases(case):
    p = _prompts.Prompt("p", 1, case["type"], case["prompt"])
    text = json.dumps(case["prompt"]) if case["type"] == "chat" else case["prompt"]
    if case["type"] == "chat":
        assert sorted({n for m in case["prompt"] for n in _prompts.placeholders(m["content"])}) == case["variables"]
    else:
        assert _prompts.placeholders(text) == case["variables"]
    if "missing" in case:
        with pytest.raises(sb.PromptCompileError) as e:
            p.compile(case["values"])
        assert e.value.missing == case["missing"]
    else:
        assert p.compile(case["values"]) == case["want"]


def test_compile_accepts_kwargs_numbers_and_never_mutates():
    p = _prompts.Prompt("p", 1, "chat", [{"role": "user", "content": "{{n}} items, ok={{ok}}"}])
    assert p.compile(n=3, ok=True) == [{"role": "user", "content": "3 items, ok=true"}]
    assert p.prompt[0]["content"] == "{{n}} items, ok={{ok}}"


@pytest.fixture
def registry(stub):
    """The stub as the machine's prompt registry, serving the recorded org
    response (same body and ETag by contract section 7)."""
    rec = load("prompt-fetch-response.json")
    etag = rec["headers"]["Etag"]
    state = {"etag": etag, "body": rec["body"], "status": 200, "hits": 0}

    def serve(req):
        state["hits"] += 1
        if state["status"] != 200:
            return state["status"], {"error": state.get("error", "unavailable"), "message": "m", "api_version": "v1"}, {}
        inm = req["headers"].get("If-None-Match", "")
        if inm == state["etag"]:
            return 304, b"", {"ETag": state["etag"]}
        return 200, state["body"], {"ETag": state["etag"], "Cache-Control": "private, no-cache"}

    stub.route("GET", "/api/obs/sdk/prompts/support-reply", serve)
    mem = InMemorySpanExporter()
    sb.init(exporter=mem, node_url=stub.url)
    state["mem"], state["stub"] = mem, stub
    return state


def test_fetch_parses_the_recorded_response(registry):
    p = sb.get_prompt("support-reply")
    assert (p.name, p.version, p.type, p.label, p.source) == ("support-reply", 3, "text", "production", "local")
    assert p.variables == ["customer", "topic"] and p.config["temperature"] == 0.2
    assert p.digest.startswith("sha256:") and p.labels == ["production"]
    assert p.compile(customer="Ada", topic="billing") == "Hello Ada, thanks for writing about billing."
    assert registry["stub"].requests[0]["path"] == "/api/obs/sdk/prompts/support-reply?label=production"


def test_cache_then_stale_while_revalidate_with_etag(registry):
    sb.get_prompt("support-reply", cache_ttl=60)
    sb.get_prompt("support-reply", cache_ttl=60)
    assert registry["hits"] == 1  # fresh: served from cache
    p = sb.get_prompt("support-reply", cache_ttl=0)  # stale: served at once, revalidated behind
    assert p.version == 3
    deadline = time.time() + 2
    while registry["hits"] < 2 and time.time() < deadline:
        time.sleep(0.01)
    reval = registry["stub"].requests[-1]
    assert reval["headers"]["If-None-Match"] == registry["etag"]


def test_revalidation_picks_up_a_new_version(registry):
    sb.get_prompt("support-reply")
    registry["body"] = dict(registry["body"], version=4, prompt="v4 {{customer}}")
    registry["etag"] = '"new"'
    sb.get_prompt("support-reply", cache_ttl=0)
    deadline = time.time() + 2
    while time.time() < deadline and sb.get_prompt("support-reply").version != 4:
        time.sleep(0.01)
    assert sb.get_prompt("support-reply").version == 4


def test_revalidation_failure_keeps_serving_and_404_drops(registry):
    sb.get_prompt("support-reply")
    registry["status"] = 503
    assert sb.get_prompt("support-reply", cache_ttl=0).version == 3
    time.sleep(0.2)
    assert sb.get_prompt("support-reply", cache_ttl=0).version == 3  # still cached
    time.sleep(0.2)
    registry["status"], registry["error"] = 404, "prompt_not_found"
    sb.get_prompt("support-reply", cache_ttl=0)
    deadline = time.time() + 2
    key = None
    while time.time() < deadline:
        key = [k for k in _prompts.CACHE._entries if k[1] == "support-reply"]
        if not key:
            break
        time.sleep(0.01)
    assert not key
    with pytest.raises(sb.PromptNotFound):
        sb.get_prompt("support-reply")


def test_fallback_and_errors(stub, dead_url):
    stub.route("GET", "/api/obs/sdk/prompts/missing", status=404, body={"error": "label_not_set", "message": "m", "api_version": "v1"})
    stub.route("GET", "/api/obs/sdk/prompts/oldnode", status=404, body=b"404 page not found\n")
    sb.init(exporter=InMemorySpanExporter(), node_url=stub.url)
    with pytest.raises(sb.PromptNotFound):
        sb.get_prompt("missing")
    with pytest.raises(sb.PromptNotFound, match="no prompt registry"):
        sb.get_prompt("oldnode")
    fb = sb.get_prompt("missing", fallback="Hi {{who}}")
    assert fb.is_fallback and fb.version == 0 and fb.compile(who="x") == "Hi x" and fb.attributes() == {}
    assert sb.get_prompt("missing", fallback=[{"role": "user", "content": "q"}]).messages == [{"role": "user", "content": "q"}]
    sb.init(exporter=InMemorySpanExporter(), node_url=dead_url, api_timeout=0.3)
    with pytest.raises(sb.PromptFetchError):
        sb.get_prompt("x")
    with pytest.raises(ValueError):
        sb.get_prompt("x", label="staging", version=2)
    with pytest.raises(ValueError):
        sb.get_prompt("bad/name")
    with pytest.raises(ValueError):
        sb.get_prompt("x", label="canary")


def test_span_stamp_inside_span_on_compile_and_llm_span(registry):
    mem = registry["mem"]
    with sb.span("handler"):
        p = sb.get_prompt("support-reply")
    with sb.span("compiled"):
        p.compile(customer="a", topic="b")
    with sb.llm_span("chat", prompt=p):
        pass
    v = sb.get_prompt("support-reply", version=3)
    with sb.llm_span("byversion", prompt=v):
        pass
    assert sb.flush(5)
    got = {s.name: s.attributes for s in mem.get_finished_spans()}
    for name in ("handler", "compiled", "chat"):
        a = got[name]
        assert a["sbo.prompt.name"] == "support-reply" and a["sbo.prompt.version"] == 3 and a["sbo.prompt.label"] == "production"
    assert "input.value" not in got["chat"]  # the template is not request content
    assert got["byversion"]["sbo.prompt.version"] == 3 and "sbo.prompt.label" not in got["byversion"]


def test_online_destination_uses_the_gateway(stub2):
    rec = load("prompt-fetch-response.json")
    stub2.route("GET", "/v1/sdk/prompts/support-reply", status=200, body=rec["body"], headers={"ETag": rec["headers"]["Etag"]})
    sb.init(destination="online", org_url=stub2.url, api_key="ik.k", exporter=InMemorySpanExporter())
    p = sb.get_prompt("support-reply", label="staging")
    assert p.source == "online" and p.label == "staging"
    r = stub2.requests[-1]
    assert r["path"] == "/v1/sdk/prompts/support-reply?label=staging" and r["headers"]["Authorization"] == "Bearer ik.k"


def test_both_falls_back_to_the_machine(stub, stub2):
    rec = load("prompt-fetch-response.json")
    stub2.route("GET", "/v1/sdk/prompts/support-reply", status=501, body={"error": "not_implemented", "message": "W3-3", "api_version": "1"})
    stub.route("GET", "/api/obs/sdk/prompts/support-reply", status=200, body=rec["body"], headers={"ETag": "x"})
    sb.init(destination="both", org_url=stub2.url, api_key="ik.k", node_url=stub.url, exporter={"local": InMemorySpanExporter(), "online": InMemorySpanExporter()})
    assert sb.get_prompt("support-reply").source == "local"


def test_async_get_prompt(registry):
    import asyncio

    async def go():
        with sb.span("a"):
            return await sb.async_get_prompt("support-reply")

    assert asyncio.run(go()).version == 3


# --- prompts.md v2: staged rollout on the fetch (W5-3, lane C8; C5 SDK side) ----------

ROLLOUT_CASES = os.path.join(CONTRACT, "prompt-rollout-cases.json")
ROLLOUT_FETCH = os.path.join(CONTRACT, "prompt-fetch-rollout-response.json")


def _load_contract(path):
    if not os.path.exists(path):
        pytest.skip("sdk/contract is not present (an sdist)")
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def test_rollout_cases_bucket_like_the_cohort_engine():
    cases = _load_contract(ROLLOUT_CASES)["cases"]
    assert len(cases) >= 25
    for c in cases:
        assert _prompts.cohort_hash(c["id"]) == c["hash"], c
        assert c["subject"] == f"{c['key']}:{c['hash']}"
        b = _prompts.rollout_bucket(c["salt"], c["subject"])
        assert b == c["bucket"], c
        assert (b < c["percent"]) is c["candidate"], c


@pytest.fixture
def rollout(stub):
    """The org registry from C8's recording: each leg answers its own key."""
    legs = {leg["name"]: leg for leg in _load_contract(ROLLOUT_FETCH)["legs"]}
    state = {"legs": legs, "drop_rollout": False}

    def answer(req):
        q = dict(urllib.parse.parse_qsl(req["path"].split("?", 1)[1]))
        if q.get("label") != "production":
            return 404, {"error": "label_not_set"}, {}
        h = q.get("user_hash") or q.get("session_hash")
        leg = legs["unkeyed"] if not h else (legs["candidate"] if h == legs["candidate"]["query"].split("user_hash=")[1] else legs["base"])
        body = dict(leg["body"])
        if state["drop_rollout"]:
            body.pop("rollout", None)
        etag = leg["headers"]["Etag"]
        if req["headers"].get("If-None-Match") == etag and not state["drop_rollout"]:
            return 304, b"", {"ETag": etag}
        return 200, body, {"ETag": etag + ("x" if state["drop_rollout"] else "")}

    stub.route("GET", "/v1/sdk/prompts/support-reply", answer)
    sb.init(exporter=InMemorySpanExporter(), destination="online", org_url=stub.url, api_key="k", discover=False)
    return stub, state


def _queries(stub):
    return [dict(urllib.parse.parse_qsl(r["path"].split("?", 1)[1])) for r in stub.requests]


def test_rollout_sends_only_the_hash_and_caches_one_copy_per_side(rollout, mem):
    stub, _ = rollout
    with sb.propagate_attributes(user="Ünïcode user"):
        p = sb.get_prompt("support-reply")
    assert (p.version, p.cohort) == (4, "candidate") and p.rollout.percent == 20
    q = _queries(stub)[-1]
    assert q["user_hash"] == _prompts.cohort_hash("Ünïcode user") and "Ünïcode" not in stub.requests[-1]["path"]
    # alice buckets base with the cached salt: one fetch fills the base side ...
    with sb.propagate_attributes(user="alice@example.com"):
        assert sb.get_prompt("support-reply").version == 3
    n = len(stub.requests)
    # ... and is then served from it, like every other base-side user
    with sb.propagate_attributes(user="alice@example.com"):
        assert sb.get_prompt("support-reply").cohort == "base"
    assert len(stub.requests) == n
    # an unkeyed call is its own side (always the base)
    assert sb.get_prompt("support-reply").cohort == "unkeyed"
    assert "user_hash" not in _queries(stub)[-1] and "session_hash" not in _queries(stub)[-1]
    sides = sorted(k[3] for k in _prompts.CACHE._entries if k[1] == "support-reply")
    assert sides == ["base", "candidate", "unkeyed"]


def test_rollout_session_fallback_explicit_args_and_version_fetch(rollout):
    stub, _ = rollout
    with sb.propagate_attributes(session_id="sess-1"):
        sb.get_prompt("support-reply")
    assert _queries(stub)[-1]["session_hash"] == _prompts.cohort_hash("sess-1")
    _prompts.CACHE.clear()
    with sb.propagate_attributes(user="u1", session_id="sess-1"):
        sb.get_prompt("support-reply", user="Ünïcode user")  # the argument wins; user beats session
    q = _queries(stub)[-1]
    assert q["user_hash"] == _prompts.cohort_hash("Ünïcode user") and "session_hash" not in q
    assert _prompts.cohort_of("version:3", user="u1").subject == ""  # a version fetch names its version


def test_rollout_stamps_the_served_version_and_cohort(rollout, mem):
    sb.init(exporter=mem, destination="online", org_url=rollout[0].url, api_key="k", discover=False)
    with sb.span("handler") as sp:
        with sb.propagate_attributes(user="Ünïcode user"):
            sb.get_prompt("support-reply")
    assert sb.flush(5)
    attrs = mem.get_finished_spans()[0].attributes
    assert attrs["sbo.prompt.version"] == 4 and attrs["sbo.prompt.cohort"] == "candidate"
    assert attrs["sbo.prompt.label"] == "production"


def test_rollout_change_drops_the_other_sides(rollout):
    stub, state = rollout
    with sb.propagate_attributes(user="Ünïcode user"):
        sb.get_prompt("support-reply")
    with sb.propagate_attributes(user="alice@example.com"):
        sb.get_prompt("support-reply")
    assert len([k for k in _prompts.CACHE._entries if k[1] == "support-reply"]) == 2
    state["drop_rollout"] = True  # the rollout ended: every key is served one answer
    with sb.propagate_attributes(user="alice@example.com"):
        sb.get_prompt("support-reply", cache_ttl=0)  # stale: revalidates in the background
    deadline = time.time() + 2
    while time.time() < deadline:
        sides = sorted(k[3] for k in _prompts.CACHE._entries if k[1] == "support-reply")
        if sides == ["all"]:
            break
        time.sleep(0.01)
    assert sides == ["all"]
    # the revalidation re-sent the key that filled the entry
    assert _queries(stub)[-1]["user_hash"] == _prompts.cohort_hash("alice@example.com")
    with sb.propagate_attributes(user="Ünïcode user"):
        p = sb.get_prompt("support-reply")
    assert p.cohort == "" and p.version == 3


def test_v1_answer_is_side_all(stub):
    """A v1 server ignores the key and never sends a rollout."""
    body = _load_contract(os.path.join(CONTRACT, "prompt-fetch-response.json"))["body"]
    stub.route("GET", "/v1/sdk/prompts/support-reply", lambda req: (200, body, {"ETag": '"v1"'}))
    sb.init(exporter=InMemorySpanExporter(), destination="online", org_url=stub.url, api_key="k", discover=False)
    with sb.propagate_attributes(user="a"):
        p = sb.get_prompt("support-reply")
    assert p.rollout is None and p.cohort == "" and "sbo.prompt.cohort" not in p.attributes()
    assert [k[3] for k in _prompts.CACHE._entries] == ["all"]
