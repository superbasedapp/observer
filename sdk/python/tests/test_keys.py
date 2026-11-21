"""The SDK writes only keys from sdk/contract/sdk-attribute-keys.json, and
_keys.py matches that file (go test ./tests/sdkcontract pins the file to the
Go vocabulary)."""

import json
import os

import pytest

import superbased_sdk as sb
from superbased_sdk import _keys as K

CONTRACT = os.path.join(os.path.dirname(__file__), "..", "..", "contract", "sdk-attribute-keys.json")


@pytest.fixture(scope="module")
def contract():
    if not os.path.exists(CONTRACT):
        pytest.skip("sdk/contract is not present (an sdist)")
    with open(CONTRACT, encoding="utf-8") as f:
        return json.load(f)


def allowed(contract):
    keys = set(contract["vocabulary"]) | set(contract["sdk_owned"]) | set(contract.get("pending_vocabulary", []))
    prefixes = tuple(contract["vocabulary_prefixes"]) + tuple(contract.get("sdk_owned_prefixes", []))
    return keys, prefixes


def test_keys_module_matches_contract(contract):
    assert set(K.CONTENT_KEYS) == set(contract["content_keys"])
    assert tuple(K.CONTENT_PREFIXES) == tuple(contract["content_prefixes"])
    assert tuple(K.CONTENT_PREFIX_EXEMPT_SUFFIXES) == tuple(contract["content_prefix_exempt_suffixes"])
    assert tuple(K.EXTRA_CONTENT_PREFIXES) == tuple(contract["extra_content_prefixes"])
    assert contract["limits"] == {
        "max_value_len": K.MAX_VALUE_LEN,
        "max_tags": K.MAX_TAGS,
        "max_tag_len": K.MAX_TAG_LEN,
        "max_metadata_keys": K.MAX_METADATA_KEYS,
        "max_metadata_key_len": K.MAX_METADATA_KEY_LEN,
        "max_metadata_value_len": K.MAX_METADATA_VALUE_LEN,
    }
    keys, prefixes = allowed(contract)
    for name, value in vars(K).items():
        if name.isupper() and isinstance(value, str):
            assert value in keys or value in prefixes, f"_keys.{name} = {value!r} is not in the contract"
    for value in K.REQUEST_PARAMS.values():
        assert value in keys


def test_every_emitted_key_is_in_the_contract(contract, mem, stub):
    stub.reply({"allowed": True, "decision": "allow", "verdict_id": "v1"})
    sb.init(exporter=mem, tenant="t", user="u", session_id="s", release="r", environment="e", tags=["x"], metadata={"m": "1"})
    with sb.propagate_attributes(user="u2", session_id="s2", tenant="t2", tags=["y"], metadata={"k": "v"}, release="r2", environment="e2"):
        with sb.agent_span("agent", agent_id="a1"):
            with sb.llm_span("llm", model="m", provider="p", prompt=[{"role": "user", "content": "hi"}], system="s") as s:
                sb.admit("hi", endpoint=stub.url)
                sb.set_usage(
                    s, input_tokens=1, output_tokens=1, total_tokens=2, cache_read_tokens=0, cache_write_tokens=0,
                    reasoning_tokens=0, response_id="r", request_id="q", response_model="m", finish_reasons=["stop"],
                    cost_usd=0.1, response="yo",
                )
                sb.set_request_params(
                    s, max_tokens=1, temperature=0.1, top_p=1.0, top_k=1, stop_sequences=["x"], frequency_penalty=0.0,
                    presence_penalty=0.0, seed=1, stream=False, reasoning_level="low",
                )
            with sb.llm_span("llm2", prompt="text") as s2:
                sb.set_content(s2, response="text")
            with sb.tool_span("tool", call_id="c", arguments={"a": 1}) as t:
                sb.set_tool_result(t, "ok")
            with sb.retriever_span("ret", query="q") as r:
                sb.set_documents(r, ["d"])
            with sb.embedding_span("emb", model="e", provider="p"):
                pass
            with sb.span("chain") as c:
                sb.set_input(c, "i")
                sb.set_output(c, "o")
    assert sb.flush(5)
    keys, prefixes = allowed(contract)
    seen = set()
    for sp in mem.get_finished_spans():
        seen.update(sp.attributes)
        seen.update(sp.resource.attributes)
    # The OTel SDK's own resource keys are not the SDK's to declare.
    foreign = {k for k in seen if k.startswith("telemetry.sdk.") or k == "service.instance.id"}
    unknown = sorted(k for k in seen - foreign if k not in keys and not k.startswith(prefixes))
    assert unknown == [], f"keys the contract does not list: {unknown}"
    # And the sweep really covered the new helpers.
    for key in (K.CACHE_READ_TOKENS, K.TOOL_ARGUMENTS, K.RETRIEVAL_DOCUMENTS, K.AGENT_ID, K.TAGS, K.ADMISSION_VERDICT_ID):
        assert key in seen
