"""The client side of the online device sign-in (plan 3.6,
docs/plans/onboarding-v2-connect-flow.md section 13): create the request
at the cloud, poll it with the device code, redeem the key grant on the
organization's host, and (``--forget``) let a key revoke itself.

Standard library only (``_http``). The wire shapes are
sdk/contract/fixtures/setup/*.json. The decisions are ``plan``'s tables;
this module only moves bytes. No secret (the device code, the redeem
secret, the grant, the key) is ever put in a message or a repr.
"""

from __future__ import annotations

import base64
import hashlib
import os
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Mapping, Optional, Tuple

from .. import _http
from . import plan as P

CLOUD_URL = "https://cloud.superbased.app"
ENV_CLOUD_URL = "SUPERBASED_CLOUD_URL"
CREATE_PATH = "/v1/connect/requests"
POLL_PATH = "/v1/connect/requests/"
REDEEM_PATH = "/api/agent/sdk-credential/grant"
REVOKE_PATH = "/v1/sdk/credential/revoke"
CLIENT = "superbased-sdk-python"
PURPOSE = "sdk_key"

GRANT_LIFE = 600.0  # seconds a key grant can be redeemed after the approval
DEFAULT_INTERVAL = 3.0
DEFAULT_EXPIRES_IN = 900.0

Http = Callable[..., _http.Response]


class Clock:
    """Time and sleep (a seam the tests replace)."""

    def monotonic(self) -> float:
        return time.monotonic()

    def sleep(self, seconds: float) -> None:
        time.sleep(max(0.0, seconds))


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def redeem_pair(random: Callable[[int], bytes] = os.urandom) -> Tuple[str, str]:
    """(redeem_secret, redeem_hash): 32 random bytes as unpadded base64url,
    and base64url-nopad(SHA-256(the secret's ASCII bytes))."""
    secret = _b64(random(32))
    return secret, redeem_hash(secret)


def redeem_hash(secret: str) -> str:
    return _b64(hashlib.sha256(secret.encode("ascii")).digest())


@dataclass(frozen=True)
class Created:
    request_id: str
    user_code: str
    approve_url: str
    verify_url: str
    expires_in: float
    interval: float
    device_code: str = field(repr=False, compare=False)


@dataclass(frozen=True)
class Target:
    org_id: str = ""
    slug: str = ""
    kind: str = ""
    display_name: str = ""
    server_url: str = ""
    ready: bool = False


@dataclass(frozen=True)
class Minted:
    key_id: str
    gateway_url: str
    dashboard_url: str
    expires_at: str
    plan_refusal: Optional[Dict[str, Any]] = None
    key: str = field(default="", repr=False, compare=False)


def _str(v: Any) -> str:
    return v if isinstance(v, str) else ""


def _num(v: Any, default: float) -> float:
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return default
    return float(v) if v > 0 else default


def _code(resp: _http.Response, field_name: str) -> str:
    body = resp.body if isinstance(resp.body, dict) else {}
    return _str(body.get(field_name))


def server_message(resp: _http.Response) -> str:
    """The server's own explanation of an error answer (never a 2xx body)."""
    body = resp.body if isinstance(resp.body, dict) else {}
    for name in ("message", "error"):
        v = _str(body.get(name)).strip()
        if v and " " in v:
            return v
    if resp.status == 0:
        return resp.error or "no answer"
    return f"HTTP {resp.status}" + (f" {_code(resp, 'code') or _code(resp, 'error')}" if (_code(resp, "code") or _code(resp, "error")) else "")


def retry_after(resp: _http.Response, default: float) -> float:
    raw = resp.header("Retry-After").strip()
    try:
        v = float(raw)
    except ValueError:
        return default
    return min(max(v, 0.0), 60.0)


# --- create ---------------------------------------------------------------------------


def create(http: Http, base: str, body: Mapping[str, Any], timeout: float = 15.0) -> Tuple[Optional[Created], P.Step, _http.Response]:
    """POST the request. (created, step, response): created is set when the
    step is CONTINUE."""
    resp = http("POST", _http.join(base, CREATE_PATH), body=dict(body), timeout=timeout)
    st = P.step(P.CREATE_ROWS, P.Answer(status=resp.status, code=_code(resp, "code")))
    if st.action != P.CONTINUE:
        return None, st, resp
    b = resp.body if isinstance(resp.body, dict) else {}
    created = Created(
        request_id=_str(b.get("request_id")),
        user_code=_str(b.get("user_code")),
        approve_url=_str(b.get("approve_url")),
        verify_url=_str(b.get("verify_url")),
        expires_in=_num(b.get("expires_in"), DEFAULT_EXPIRES_IN),
        interval=_num(b.get("interval"), DEFAULT_INTERVAL),
        device_code=_str(b.get("device_code")),
    )
    if not (created.request_id and created.user_code and created.approve_url and created.device_code):
        return None, P.Step(P.STOP, P.EXIT_ENVIRONMENT, "unexpected"), resp
    return created, st, resp


# --- poll -----------------------------------------------------------------------------


@dataclass
class PollResult:
    step: P.Step
    grant: str = field(default="", repr=False)
    target: Target = field(default_factory=Target)
    response: Optional[_http.Response] = field(default=None, repr=False)


def poll_once(http: Http, base: str, created: Created, timeout: float = 15.0) -> PollResult:
    resp = http(
        "GET",
        _http.join(base, POLL_PATH + created.request_id),
        headers={"Authorization": "Bearer " + created.device_code},
        timeout=timeout,
    )
    b = resp.body if isinstance(resp.body, dict) and resp.status == 200 else {}
    raw_target = b.get("target")
    t: Dict[str, Any] = raw_target if isinstance(raw_target, dict) else {}
    target = Target(
        org_id=_str(t.get("org_id")),
        slug=_str(t.get("slug")),
        kind=_str(t.get("kind")),
        display_name=_str(t.get("display_name")),
        server_url=_str(t.get("server_url")).rstrip("/"),
        ready=t.get("ready") is True,
    )
    grant = _str(b.get("key_grant"))
    answer = P.Answer(
        status=resp.status,
        code=_code(resp, "code"),
        state=_str(b.get("status")),
        ready=target.ready and bool(target.server_url),
        grant=bool(grant),
    )
    return PollResult(P.step(P.POLL_ROWS, answer), grant, target, resp)


# --- redeem ---------------------------------------------------------------------------


@dataclass
class RedeemResult:
    step: P.Step
    minted: Optional[Minted] = None
    response: Optional[_http.Response] = field(default=None, repr=False)


def redeem_once(http: Http, server_url: str, grant: str, secret: str, machine_name: str, replaces_key_id: str = "", timeout: float = 20.0) -> RedeemResult:
    resp = http(
        "POST",
        _http.join(server_url, REDEEM_PATH),
        body={"key_grant": grant, "redeem_secret": secret, "machine_name": machine_name, "replaces_key_id": replaces_key_id},
        timeout=timeout,
    )
    b = resp.body if isinstance(resp.body, dict) else {}
    refusal = b.get("plan_refusal") if resp.status == 201 and isinstance(b.get("plan_refusal"), dict) else None
    answer = P.Answer(status=resp.status, code=_code(resp, "error"), plan_refusal=refusal is not None, reason=_code(resp, "reason"))
    st = P.step(P.REDEEM_ROWS, answer)
    minted = None
    if resp.status == 201:
        key = _str(b.get("credential"))
        if not key or "." not in key:
            return RedeemResult(P.Step(P.STOP, P.EXIT_ENVIRONMENT, "unexpected"), None, resp)
        minted = Minted(
            key_id=_str(b.get("key_id")) or key.split(".", 1)[0],
            gateway_url=_str(b.get("gateway_url")).rstrip("/"),
            dashboard_url=_str(b.get("dashboard_url")).rstrip("/"),
            expires_at=_str(b.get("expires_at")),
            plan_refusal=refusal,
            key=key,
        )
    return RedeemResult(st, minted, resp)


# --- revoke ---------------------------------------------------------------------------


def revoke(http: Http, gateway_url: str, key: str, timeout: float = 15.0) -> Tuple[bool, _http.Response]:
    """POST the key's own revoke. (revoked, response)."""
    resp = http("POST", _http.join(gateway_url, REVOKE_PATH), headers={"Authorization": "Bearer " + key}, timeout=timeout)
    ok = resp.status == 200 and isinstance(resp.body, dict) and bool(resp.body.get("revoked"))
    return ok, resp


def cloud_base(env: Mapping[str, str], flag: str = "") -> Tuple[str, str]:
    """(base, problem): ``--cloud-url``, ``SUPERBASED_CLOUD_URL``, else
    cloud.superbased.app. https only (or http to a loopback host, tests)."""
    from .._destination import gateway_problem

    base = (flag or env.get(ENV_CLOUD_URL) or CLOUD_URL).strip().rstrip("/")
    problem = gateway_problem(base)
    return base, problem
