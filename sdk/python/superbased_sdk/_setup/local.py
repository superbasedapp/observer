"""The client side of the local enable (plan 3.7): this computer's
Observer, asked over loopback.

- ``status()``: ``GET /api/apps/status`` (whether AI Apps is on, the one
  consent sentence the machine serves, and the confirm token a caller
  echoes);
- ``enable()``: ``POST /api/apps/enable`` with the confirm token (header and
  double-submit cookie) and ``source: "sdk-setup"`` (the audit row names
  it). The person's y/N on a terminal, or their click on the dashboard's
  Turn on button, is the approval; setup never calls the machine's SDK
  credential routes or its key-minting and key-installing CLI verbs
  (R-165, SDKQS-8).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict

from .. import _http

STATUS_PATH = "/api/apps/status"
ENABLE_PATH = "/api/apps/enable"
ENABLE_PAGE = "/apps?enable=1&from=setup"
CONFIRM_HEADER = "X-Observer-Confirm"
CONFIRM_COOKIE = "sb_remote_confirm"
SOURCE = "sdk-setup"
TIMEOUT = 5.0
ENABLE_TIMEOUT = 30.0
POLL_EVERY = 2.0
POLL_FOR = 300.0  # the dashboard click: up to 5 minutes

Http = Callable[..., _http.Response]


@dataclass(frozen=True)
class AppsStatus:
    answered: bool = False
    on: bool = False
    consent: str = ""
    receiver: str = ""
    token: str = field(default="", repr=False)


def status(http: Http, node_url: str) -> AppsStatus:
    if not _http.is_loopback_url(node_url):
        return AppsStatus()
    resp = http("GET", _http.join(node_url, STATUS_PATH), timeout=TIMEOUT)
    if resp.status != 200 or not isinstance(resp.body, dict):
        return AppsStatus()
    b = resp.body
    c, r = b.get("consent"), b.get("receiver")
    consent: Dict[str, Any] = c if isinstance(c, dict) else {}
    receiver: Dict[str, Any] = r if isinstance(r, dict) else {}
    return AppsStatus(
        answered=True,
        on=b.get("on") is True,
        consent=str(consent.get("sentence") or "").strip(),
        receiver=str(receiver.get("http_addr") or ""),
        token=str(b.get("confirm_token") or ""),
    )


@dataclass(frozen=True)
class EnableResult:
    ok: bool
    message: str = ""
    fix: str = ""
    status: int = 0


def enable(http: Http, node_url: str, token: str) -> EnableResult:
    if not _http.is_loopback_url(node_url):
        return EnableResult(False, "this computer's dashboard address is not a loopback address")
    resp = http(
        "POST",
        _http.join(node_url, ENABLE_PATH),
        body={"source": SOURCE},
        headers={CONFIRM_HEADER: token, "Cookie": f"{CONFIRM_COOKIE}={token}"},
        timeout=ENABLE_TIMEOUT,
    )
    b: Dict[str, Any] = resp.body if isinstance(resp.body, dict) else {}
    if resp.status == 200 and b.get("ok") is True:
        return EnableResult(True, str(b.get("message") or ""), status=200)
    msg = str(b.get("message") or "").strip()
    if not msg:
        raw = resp.raw.decode("utf-8", "replace").strip() if resp.raw else ""
        msg = raw[:300] or resp.describe()
    return EnableResult(False, msg, str(b.get("fix") or ""), resp.status)


def page_url(node_url: str) -> str:
    return node_url.rstrip("/") + ENABLE_PAGE
