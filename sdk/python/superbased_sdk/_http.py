"""A small JSON-over-HTTP client (standard library only) for the SDK's
control calls: destination discovery, scores, prompts, datasets and
experiments. Never raises for a transport or HTTP failure; the caller gets a
``Response`` with ``ok`` False and the reason.
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional

USER_AGENT = "superbased-sdk-python"


@dataclass
class Response:
    """The outcome of one call. ``status`` 0 means no HTTP answer (transport
    failure or timeout, see ``error``)."""

    status: int = 0
    body: Any = None  # decoded JSON, or None
    headers: Dict[str, str] = field(default_factory=dict)  # lower-cased names
    error: str = ""
    raw: bytes = b""

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300

    def header(self, name: str) -> str:
        return self.headers.get(name.lower(), "")

    def error_code(self) -> str:
        """The SDK control API error envelope's ``error`` field, or ""."""
        if isinstance(self.body, dict) and isinstance(self.body.get("error"), str):
            return str(self.body["error"])
        return ""

    def plan_refusal(self) -> Any:
        """The org's plan refusal in this answer (a ``PlanRefusalError``:
        403 ``plan_required`` or a 429 over the plan's allowance), or None."""
        if self.status not in (403, 429):
            return None
        from ._planrefusal import parse_plan_refusal

        return parse_plan_refusal(self.status, self.body if isinstance(self.body, dict) else self.raw, self.headers)

    def describe(self) -> str:
        if self.status == 0:
            return self.error or "no response"
        code = self.error_code()
        msg = self.body.get("message") if isinstance(self.body, dict) else ""
        return f"HTTP {self.status}" + (f" {code}" if code else "") + (f": {msg}" if msg else "")


def is_loopback_url(url: str) -> bool:
    """True when ``url``'s host is 127.0.0.0/8, ::1 or localhost."""
    try:
        host = urllib.parse.urlsplit(url).hostname or ""
    except ValueError:
        return False
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def join(base: str, path: str, query: Optional[Mapping[str, Any]] = None) -> str:
    url = base.rstrip("/") + path
    if query:
        q = {k: str(v) for k, v in query.items() if v is not None and v != ""}
        if q:
            url += "?" + urllib.parse.urlencode(q)
    return url


def request(
    method: str,
    url: str,
    *,
    body: Any = None,
    headers: Optional[Mapping[str, str]] = None,
    timeout: float = 5.0,
) -> Response:
    """One HTTP call with a JSON body (when given) and a JSON answer."""
    hdrs = {"Accept": "application/json", "User-Agent": USER_AGENT}
    data = None
    if body is not None:
        data = json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        hdrs["Content-Type"] = "application/json"
    if headers:
        hdrs.update({str(k): str(v) for k, v in headers.items()})
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    deadline = time.monotonic() + max(0.001, timeout)  # connect, headers and body share it
    try:
        with _opener(is_loopback_url(url)).open(req, timeout=max(0.001, timeout)) as resp:
            return _read(resp, resp.status, deadline)
    except urllib.error.HTTPError as err:
        try:
            return _read(err, err.code, deadline)
        except Exception:  # noqa: BLE001
            return Response(status=err.code, headers={k.lower(): v for k, v in (err.headers or {}).items()})
    except (socket.timeout, TimeoutError) as exc:
        return Response(error=f"timeout after {timeout:g}s ({exc})")
    except (urllib.error.URLError, OSError, http.client.HTTPException, ValueError) as exc:
        return Response(error=f"{type(exc).__name__}: {exc}")


def _read(resp: Any, status: int, deadline: Optional[float] = None) -> Response:
    raw = (read_bounded(resp, deadline, CONTROL_BODY_CAP) if deadline is not None else resp.read(CONTROL_BODY_CAP)) or b""
    headers = {k.lower(): v for k, v in (resp.headers or {}).items()}
    body: Any = None
    if raw:
        try:
            body = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            body = None
    return Response(status=status, body=body, headers=headers, raw=raw)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A credential is never forwarded to a host the caller did not name."""

    def redirect_request(self, *a: Any, **kw: Any) -> None:
        return None


def _opener(loopback: bool) -> Any:
    # A loopback call never goes through an HTTP(S)_PROXY from the
    # environment; a remote call honours it (corporate proxies).
    handlers: list = [_NoRedirect()]
    if loopback:
        handlers.append(urllib.request.ProxyHandler({}))
    return urllib.request.build_opener(*handlers)


# Body caps: the admission verdict is small (the Go SDK reads at most 1 MiB);
# a control answer is bounded at 32 MiB.
ADMIT_BODY_CAP = 1 << 20
CONTROL_BODY_CAP = 32 << 20


def read_bounded(resp: Any, deadline: float, cap: int) -> bytes:
    """Read ``resp``'s body, at most ``cap`` bytes, within ``deadline`` (a
    ``time.monotonic()`` instant). The per-socket timeout only bounds each
    recv, so a server dripping a byte at a time could hold the call past its
    budget; a watchdog shuts the socket at the deadline and the loop checks
    it between chunks. Raises ``TimeoutError`` when the deadline passes."""
    expired = threading.Event()

    def abort() -> None:
        expired.set()
        try:
            sock = resp.fp.raw._sock  # type: ignore[attr-defined]
            sock.shutdown(socket.SHUT_RDWR)
        except Exception:  # noqa: BLE001
            try:
                resp.close()
            except Exception:  # noqa: BLE001
                pass

    timer = threading.Timer(max(0.001, deadline - time.monotonic()), abort)
    timer.daemon = True
    timer.start()
    chunks = []
    total = 0
    try:
        while total < cap:
            if time.monotonic() >= deadline or expired.is_set():
                raise TimeoutError("timed out reading the response body")
            try:
                chunk = resp.read(min(65536, cap - total))
            except (OSError, http.client.HTTPException, ValueError):
                if expired.is_set() or time.monotonic() >= deadline:
                    raise TimeoutError("timed out reading the response body") from None
                raise
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
    finally:
        timer.cancel()
    return b"".join(chunks)
