"""``get_prompt()`` (W3-3; contract
docs/plans/plane-a-sdk-buildout/contracts/prompts.md).

Fetches a prompt version from the registry of the destination (the gateway's
``/v1/sdk/prompts/{name}``, the machine's ``/api/obs/sdk/prompts/{name}``),
caches it per (endpoint, name, selector) for ``prompt_cache_ttl`` and then
serves the cached copy while it revalidates in the background with
``If-None-Match`` (stale-while-revalidate). ``Prompt.compile()`` fills the
``{{variable}}`` placeholders by the registry's rules; using a prompt stamps
``sbo.prompt.name`` / ``.version`` / ``.label`` on the span.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Tuple, Type, Union

from . import _control
from . import _keys as K
from ._planrefusal import AllowanceExceededError, PlanRefusalError, PlanRequiredError

LOG = logging.getLogger("superbased_sdk")

LABELS = ("production", "staging")
DEFAULT_LABEL = "production"
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_PLACEHOLDER = re.compile(r"\{\{[ \t]*([A-Za-z_][A-Za-z0-9_]*)[ \t]*\}\}")
# Error codes meaning "this registry has no such prompt" (try the next
# destination, then raise PromptNotFound).
_NOT_FOUND = {"prompt_not_found", "version_not_found", "label_not_set", "not_implemented"}


class PromptError(Exception):
    """Base class of the prompt errors."""


class PromptNotFound(PromptError, LookupError):
    """No registry had the prompt (or the label points at nothing)."""


class PromptFetchError(PromptError, RuntimeError):
    """The registry could not be reached or answered badly, and nothing was cached."""


class PromptPlanRequiredError(PlanRequiredError, PromptFetchError):
    """get_prompt()'s PromptFetchError when the org's plan does not include
    AI Apps (403 ``plan_required``): both a ``PlanRequiredError`` and a
    ``PromptFetchError``."""


class PromptAllowanceExceededError(AllowanceExceededError, PromptFetchError):
    """get_prompt()'s PromptFetchError over the plan's monthly AI Apps
    allowance (429): both an ``AllowanceExceededError`` and a
    ``PromptFetchError``."""


_PLAN_ERRORS: Dict[str, Type[PlanRefusalError]] = {PlanRequiredError.kind: PromptPlanRequiredError, AllowanceExceededError.kind: PromptAllowanceExceededError}


class PromptCompileError(PromptError, KeyError):
    """compile() was missing values. ``missing`` lists the names, sorted."""

    def __init__(self, missing: List[str]) -> None:
        super().__init__("missing prompt variables: " + ", ".join(missing))
        self.missing = list(missing)

    def __str__(self) -> str:
        return "missing prompt variables: " + ", ".join(self.missing)


def placeholders(text: str) -> List[str]:
    """The distinct placeholder names in ``text``, in byte order."""
    return sorted(set(_PLACEHOLDER.findall(text or "")))


def _js_number(x: float) -> str:
    """ECMAScript Number::toString for a finite float (the shortest digits
    that round-trip, then the spec's choice of plain or exponent form), so a
    Python value renders as JSON.stringify renders it."""
    if x == 0:
        return "0"
    sign = "-" if x < 0 else ""
    r = repr(abs(x))
    mant, _, exp = r.partition("e")
    whole, _, frac = mant.partition(".")
    if frac == "0":
        frac = ""
    digits = (whole + frac).lstrip("0")
    point = len(whole) + (int(exp) if exp else 0)  # decimal point position in whole+frac
    lead = len(whole + frac) - len((whole + frac).lstrip("0"))
    n = point - lead  # value = 0.digits * 10**n
    digits = digits.rstrip("0") or "0"
    k = len(digits)
    if k <= n <= 21:
        out = digits + "0" * (n - k)
    elif 0 < n <= 21:
        out = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        out = "0." + "0" * (-n) + digits
    else:
        e = n - 1
        out = digits[0] + ("." + digits[1:] if k > 1 else "") + "e" + ("+" if e >= 0 else "-") + str(abs(e))
    return sign + out


def _js_json(v: Any) -> str:
    """Compact JSON the way JSON.stringify writes it (review R-B19,
    sdk/contract/sdk-behaviour-cases.json ``compile_values``): no spaces,
    numbers in the ECMAScript form (1.0 -> 1, 1e-7), NaN and infinities as
    null, non-ASCII kept, keys in insertion order. Anything else is its
    ``str()`` as a JSON string."""
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        if v != v or v in (float("inf"), float("-inf")):
            return "null"
        return _js_number(v)
    if isinstance(v, str):
        return json.dumps(v, ensure_ascii=False)
    if isinstance(v, Mapping):
        return "{" + ",".join(json.dumps(str(k), ensure_ascii=False) + ":" + _js_json(x) for k, x in v.items()) + "}"
    if isinstance(v, (list, tuple)):
        return "[" + ",".join(_js_json(x) for x in v) + "]"
    return json.dumps(str(v), ensure_ascii=False)


def _as_text(v: Any) -> str:
    """A placeholder value as text: a string as is, anything else as compact
    JSON, the same text the TypeScript SDK's JSON.stringify gives."""
    if isinstance(v, str):
        return v
    return _js_json(v)


def compile_text(text: str, values: Mapping[str, Any]) -> str:
    """One left-to-right pass: a substituted value is never re-scanned."""
    missing = sorted({n for n in _PLACEHOLDER.findall(text) if n not in values})
    if missing:
        raise PromptCompileError(missing)
    return _PLACEHOLDER.sub(lambda m: _as_text(values[m.group(1)]), text)


@dataclass
class PromptRollout:
    """A label's staged rollout as the server reported it (prompts.md v2
    section 9.3): which version this key was served (``cohort``), the split
    and the salt the server bucketed with."""

    base_version: int
    candidate_version: int
    percent: int
    cohort: str  # "candidate", "base" or "unkeyed"
    key: str  # "user", "session" or ""
    salt: str

    def signature(self) -> str:
        return f"{self.candidate_version}|{self.percent}|{self.salt}"


@dataclass
class Prompt:
    """One prompt version as the registry served it."""

    name: str
    version: int
    type: str  # "text" or "chat"
    prompt: Union[str, List[Dict[str, str]]]
    config: Dict[str, Any] = field(default_factory=dict)
    labels: List[str] = field(default_factory=list)
    label: str = ""  # the label it was resolved by; "" for a version fetch
    resolved_by: str = ""
    variables: List[str] = field(default_factory=list)
    digest: str = ""
    commit_message: str = ""
    created_at: str = ""
    is_fallback: bool = False
    source: str = ""  # "online" / "local" / "fallback"
    rollout: Optional[PromptRollout] = None  # prompts.md v2: the label's staged rollout, if any

    @property
    def cohort(self) -> str:
        """Which rollout side served this copy (``candidate``, ``base`` or
        ``unkeyed``); "" when the label has no rollout."""
        return self.rollout.cohort if self.rollout is not None else ""

    @property
    def text(self) -> str:
        """The body of a text prompt ("" for chat)."""
        return self.prompt if isinstance(self.prompt, str) else ""

    @property
    def messages(self) -> List[Dict[str, str]]:
        """The messages of a chat prompt (copies; [] for text)."""
        return [dict(m) for m in self.prompt] if isinstance(self.prompt, list) else []

    def compile(self, values: Optional[Mapping[str, Any]] = None, /, **kw: Any) -> Union[str, List[Dict[str, str]]]:
        """Fill every ``{{name}}`` placeholder. Raises PromptCompileError
        naming every missing name (sorted); extra names are ignored. A chat
        prompt compiles each message's content and returns a new list. Stamps
        the current span with this prompt's name and version."""
        vals: Dict[str, Any] = dict(values or {})
        vals.update(kw)
        if isinstance(self.prompt, list):
            missing = sorted({n for m in self.prompt for n in _PLACEHOLDER.findall(m.get("content", "")) if n not in vals})
            if missing:
                raise PromptCompileError(missing)
            out: Union[str, List[Dict[str, str]]] = [
                {**m, "content": compile_text(m.get("content", ""), vals)} for m in self.prompt
            ]
        else:
            out = compile_text(self.prompt, vals)
        self.stamp()
        return out

    def attributes(self) -> Dict[str, Any]:
        """The span attributes this prompt stamps ({} for a fallback)."""
        if self.is_fallback:
            return {}
        out: Dict[str, Any] = {K.PROMPT_NAME: self.name, K.PROMPT_VERSION: int(self.version)}
        if self.label:
            out[K.PROMPT_LABEL] = self.label
        if self.rollout is not None:
            out[K.PROMPT_COHORT] = self.rollout.cohort
        return out

    def stamp(self, span: Any = None) -> None:
        """Stamp ``span`` (default: the current span) with this prompt."""
        from opentelemetry import trace

        sp = span if span is not None else trace.get_current_span()
        try:
            if sp.is_recording():
                for k, v in self.attributes().items():
                    sp.set_attribute(k, v)
        except Exception:  # noqa: BLE001
            pass


def _parse(body: Any, side: str, label: str) -> Prompt:
    if not isinstance(body, dict):
        raise PromptFetchError("the registry answered without a JSON object")
    name, version, typ, prompt = body.get("name"), body.get("version"), body.get("type"), body.get("prompt")
    ok = isinstance(name, str) and isinstance(version, int) and not isinstance(version, bool)
    ok = ok and (
        (typ == "text" and isinstance(prompt, str))
        or (typ == "chat" and isinstance(prompt, list) and all(isinstance(m, dict) for m in prompt))
    )
    if not ok:
        raise PromptFetchError("the registry answered with a malformed prompt")
    cfg = body.get("config")
    text = json.dumps(prompt) if isinstance(prompt, list) else str(prompt)
    raw_vars = body.get("variables")
    variables: List[Any] = raw_vars if isinstance(raw_vars, list) else placeholders(text)
    body_prompt: Union[str, List[Dict[str, str]]] = prompt  # type: ignore[assignment]  # checked above
    return Prompt(
        name=str(name),
        version=int(version),  # type: ignore[arg-type]  # checked above
        type=str(typ),
        prompt=body_prompt,
        config=cfg if isinstance(cfg, dict) else {},
        labels=[str(x) for x in body.get("labels") or () if isinstance(x, str)],
        label=label,
        resolved_by=str(body.get("resolved_by") or ""),
        variables=[str(v) for v in variables],
        digest=str(body.get("digest") or ""),
        commit_message=str(body.get("commit_message") or ""),
        created_at=str(body.get("created_at") or ""),
        source=side,
        rollout=_parse_rollout(body.get("rollout")),
    )


def _parse_rollout(ro: Any) -> Optional[PromptRollout]:
    """The v2 ``rollout`` object, or None when absent or malformed (then the
    answer is treated as side ``all``, like a v1 server's)."""
    if not isinstance(ro, dict) or not isinstance(ro.get("salt"), str) or ro.get("cohort") not in SIDES_WITH_ROLLOUT:
        return None
    try:
        return PromptRollout(
            base_version=int(ro.get("base_version") or 0),
            candidate_version=int(ro.get("candidate_version") or 0),
            percent=int(ro.get("percent") or 0),
            cohort=str(ro["cohort"]),
            key=str(ro.get("key") or ""),
            salt=str(ro["salt"]),
        )
    except (TypeError, ValueError):
        return None


# --- prompts.md v2: the cohort key and the rollout bucket (section 9.2) ---------

SIDE_ALL = "all"
SIDES_WITH_ROLLOUT = ("candidate", "base", "unkeyed")


def cohort_hash(value: str) -> str:
    """Lowercase hex SHA-256 of ``value``'s UTF-8 bytes: what the SDK sends as
    ``user_hash`` / ``session_hash`` (the raw id never leaves the SDK)."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def rollout_bucket(salt: str, subject: str) -> int:
    """``uint32_be(sha256(salt + "|" + subject)[0:4]) % 100``
    (rolloutcore.HashBucket; pinned by sdk/contract/prompt-rollout-cases.json)."""
    digest = hashlib.sha256((salt + "|" + subject).encode("utf-8")).digest()
    return int.from_bytes(digest[:4], "big") % 100


@dataclass(frozen=True)
class Cohort:
    """The key a label fetch is bucketed by: ``subject`` is ``user:<hash>``,
    ``session:<hash>`` or "" (unkeyed); ``query`` the parameter that carries
    it."""

    subject: str = ""
    query: Tuple[Tuple[str, str], ...] = ()


def cohort_of(selector: str, user: Optional[str] = None, session_id: Optional[str] = None) -> Cohort:
    """The end user (argument, else the current trace's), else the session;
    a version fetch is never keyed (it names its version)."""
    if selector.startswith("version:"):
        return Cohort()
    from ._context import get_current_attributes

    cur = get_current_attributes()
    u = user if user is not None else str(cur.get("user") or "")
    if u:
        h = cohort_hash(u)
        return Cohort("user:" + h, (("user_hash", h),))
    sess = session_id if session_id is not None else str(cur.get("session_id") or "")
    if sess:
        h = cohort_hash(sess)
        return Cohort("session:" + h, (("session_hash", h),))
    return Cohort()


def _side_of(p: Prompt) -> str:
    return p.rollout.cohort if p.rollout is not None else SIDE_ALL


@dataclass
class _Entry:
    prompt: Prompt
    etag: str
    fetched: float
    refreshing: bool = False
    query: Tuple[Tuple[str, str], ...] = ()  # the cohort key that filled it (revalidated with the same)


Group = Tuple[str, str, str]  # (endpoint, name, selector)
Key = Tuple[str, str, str, str]  # (endpoint, name, selector, side)


class PromptCache:
    """The process-wide prompt cache. Thread-safe; at most one background
    revalidation per key at a time."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._entries: Dict[Key, _Entry] = {}
        self._last_log = 0.0

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()

    def get(self, key: Key) -> Optional[_Entry]:
        with self._lock:
            return self._entries.get(key)

    def put(self, key: Key, entry: _Entry) -> None:
        with self._lock:
            self._entries[key] = entry

    def drop(self, key: Key) -> None:
        with self._lock:
            self._entries.pop(key, None)

    def group(self, g: Group) -> Dict[str, _Entry]:
        """The entries of one (endpoint, name, selector), by side."""
        with self._lock:
            return {k[3]: e for k, e in self._entries.items() if k[:3] == g}

    def side_for(self, g: Group, cohort: Cohort) -> str:
        """The side ``cohort`` is served from (section 9.4): bucket with a
        cached rollout's salt and percent, else ``all``."""
        with_rollout = next((e.prompt.rollout for e in self.group(g).values() if e.prompt.rollout is not None), None)
        if with_rollout is None:
            return SIDE_ALL
        if not cohort.subject:
            return "unkeyed"
        return "candidate" if rollout_bucket(with_rollout.salt, cohort.subject) < with_rollout.percent else "base"

    def store(self, g: Group, p: Prompt, etag: str, query: Tuple[Tuple[str, str], ...]) -> None:
        """Keep an answer under the side it names; a changed rollout (another
        percent or candidate, or none) drops the other sides."""
        sig = p.rollout.signature() if p.rollout is not None else ""
        with self._lock:
            for k in [k for k, e in self._entries.items() if k[:3] == g]:
                other = self._entries[k].prompt.rollout
                if (other.signature() if other is not None else "") != sig:
                    del self._entries[k]
            self._entries[g + (_side_of(p),)] = _Entry(p, etag, time.monotonic(), query=query)

    def claim_refresh(self, key: Key) -> bool:
        with self._lock:
            e = self._entries.get(key)
            if e is None or e.refreshing:
                return False
            e.refreshing = True
            return True

    def log_failure(self, msg: str) -> None:
        now = time.time()
        with self._lock:
            if now - self._last_log < 60:
                return
            self._last_log = now
        LOG.warning("superbased_sdk: prompt revalidation failed, serving the cached copy: %s", msg)


CACHE = PromptCache()


def _selector(label: Optional[str], version: Optional[int]) -> Tuple[str, Dict[str, Any], str]:
    """(cache selector, query, label stamped)."""
    if label is not None and version is not None:
        raise ValueError("get_prompt takes label= or version=, not both")
    if version is not None:
        if isinstance(version, bool) or int(version) < 1:
            raise ValueError(f"version must be a positive integer, got {version!r}")
        return f"version:{int(version)}", {"version": int(version)}, ""
    lbl = label or DEFAULT_LABEL
    if lbl not in LABELS:
        raise ValueError(f"label must be one of {', '.join(LABELS)}, got {lbl!r}")
    return f"label:{lbl}", {"label": lbl}, lbl


def _fetch(side: _control.Side, name: str, query: Dict[str, Any], etag: str = "") -> Any:
    headers = {"If-None-Match": etag} if etag else None
    return side.call("GET", "prompt", query=query, headers=headers, name=name)


def _not_found(resp: Any) -> bool:
    return resp.status in (404, 501) and (resp.error_code() in _NOT_FOUND or not resp.error_code())


def _revalidate(key: Key, side: _control.Side, name: str, query: Dict[str, Any], label: str) -> None:
    entry = CACHE.get(key)
    try:
        if entry is None:
            return
        resp = _fetch(side, name, {**query, **dict(entry.query)}, entry.etag)
        if resp.status == 304:
            entry.fetched = time.monotonic()
        elif resp.status == 200:
            p = _parse(resp.body, side.name, label)
            if _side_of(p) != key[3]:
                CACHE.drop(key)  # this key's side changed: it is served its new side
            CACHE.store(key[:3], p, resp.header("etag"), entry.query)
            return
        elif _not_found(resp):
            CACHE.drop(key)
            return
        else:
            CACHE.log_failure(resp.describe())
    except Exception as exc:  # noqa: BLE001
        CACHE.log_failure(f"{type(exc).__name__}: {exc}")
    finally:
        e = CACHE.get(key)
        if e is not None:
            e.refreshing = False


def get_prompt(
    name: str,
    *,
    label: Optional[str] = None,
    version: Optional[int] = None,
    cache_ttl: Optional[float] = None,
    fallback: Union[str, List[Dict[str, str]], None] = None,
    user: Optional[str] = None,
    session_id: Optional[str] = None,
) -> Prompt:
    """Fetch prompt ``name`` by ``label`` (``production``, the default, or
    ``staging``) or by ``version`` (not both: ValueError).

    Served from the registry of the destination chosen at ``init()`` (the
    gateway for ``online``, the machine for ``local``; ``both`` tries the
    gateway, then the machine). Cached for ``cache_ttl`` seconds (default
    ``prompt_cache_ttl``, 60 s); after that the cached copy is returned at
    once and revalidated in the background. When nothing is cached and the
    fetch fails, ``fallback`` (a text body or a message list) is returned as
    an unversioned prompt that stamps nothing; without one this raises
    PromptNotFound or PromptFetchError (when the org's plan refused the
    fetch, a PromptFetchError that is also a PlanRequiredError or an
    AllowanceExceededError, with the ``upgrade_url``). Called inside a span, it stamps the
    span with the prompt's name and version.

    A label under a staged rollout (prompts.md v2) serves each end user the
    candidate or the base: the SDK sends the SHA-256 of ``user`` (default: the
    current trace's end user), else of ``session_id`` (default: the trace's
    session), never the id itself, and caches one copy per side. The served
    side is ``Prompt.cohort`` and the ``sbo.prompt.cohort`` stamp."""
    if not isinstance(name, str) or not _NAME.match(name):
        raise ValueError(f"prompt name {name!r} must match {_NAME.pattern}")
    selector, query, stamped_label = _selector(label, version)
    cohort = cohort_of(selector, user, session_id)
    ttl = cache_ttl
    if ttl is None:
        from . import settings

        s = settings()
        ttl = s.prompt_cache_ttl if s is not None else 60.0
    errors: List[str] = []
    not_found = True
    refused: Optional[PlanRefusalError] = None
    targets = _control.sides()
    if not targets:
        errors.append(_control.unavailable_reason())
        not_found = False  # nothing was asked: a fetch error, not "not found"
    for side in targets:
        group: Group = (f"{side.name}:{side.base}", name, selector)
        key: Key = group + (CACHE.side_for(group, cohort),)
        entry = CACHE.get(key)
        if entry is not None:
            if time.monotonic() - entry.fetched >= max(0.0, ttl) and CACHE.claim_refresh(key):
                threading.Thread(
                    target=_revalidate, args=(key, side, name, query, stamped_label), name="superbased-prompt-refresh", daemon=True
                ).start()
            entry.prompt.stamp()
            return entry.prompt
        try:
            resp = _fetch(side, name, {**query, **dict(cohort.query)})
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{side.name}: {type(exc).__name__}: {exc}")
            not_found = False
            continue
        if resp.status == 200:
            try:
                p = _parse(resp.body, side.name, stamped_label)
            except PromptFetchError as exc:
                errors.append(f"{side.name}: {exc}")
                not_found = False
                continue
            CACHE.store(group, p, resp.header("etag"), cohort.query)
            p.stamp()
            return p
        if _not_found(resp):
            msg = "this server has no prompt registry" if resp.status == 501 or not resp.error_code() else resp.describe()
            errors.append(f"{side.name}: {msg}")
            continue
        not_found = False
        refused = refused or resp.plan_refusal()
        errors.append(f"{side.name}: {resp.describe()}")
    if fallback is not None:
        return _fallback(name, fallback)
    detail = "; ".join(errors) or "no destination"
    if not_found:
        raise PromptNotFound(f"prompt {name!r} ({selector}) not found: {detail}")
    msg = f"prompt {name!r} ({selector}) could not be fetched: {detail}"
    if refused is not None:
        # The org's plan refused it: a PlanRefusalError that is also the
        # PromptFetchError this call raises (existing except clauses hold).
        raise refused.rebased(_PLAN_ERRORS, msg)
    raise PromptFetchError(msg)


def _fallback(name: str, body: Union[str, List[Dict[str, str]]]) -> Prompt:
    if isinstance(body, list):
        text = json.dumps(body)
        return Prompt(name, 0, "chat", [dict(m) for m in body], variables=placeholders(text), is_fallback=True, source="fallback")
    return Prompt(name, 0, "text", str(body), variables=placeholders(str(body)), is_fallback=True, source="fallback")


async def async_get_prompt(name: str, **kw: Any) -> Prompt:
    """``get_prompt()`` without blocking the event loop on a first fetch.
    Stamps the span current HERE."""
    from opentelemetry import trace

    span = trace.get_current_span()
    p = await asyncio.get_running_loop().run_in_executor(None, lambda: get_prompt(name, **kw))
    p.stamp(span)
    return p
