"""Final-review fixes FR-S02, FR-S04, FR-S07, FR-S09 (Python side)."""

import socket
import threading
import time

import pytest

import superbased_sdk as sb
from superbased_sdk import _destination as D
from superbased_sdk import _http
from superbased_sdk._config import Settings


class _Unserialisable:
    pass


@pytest.mark.parametrize(
    "env,arg,want_allowed",
    [("1", None, False), ("", None, True), ("1", False, True), ("", True, False)],
)
def test_last_resort_handler_honours_fail_closed(monkeypatch, env, arg, want_allowed):
    """FR-S02: an exception inside admit() (a non-JSON ``user=``) still obeys
    fail_closed and SUPERBASED_ADMISSION_FAIL_CLOSED."""
    if env:
        monkeypatch.setenv("SUPERBASED_ADMISSION_FAIL_CLOSED", env)
    v = sb.admit("hi", user=_Unserialisable(), endpoint="http://127.0.0.1:9/x", fail_closed=arg)
    assert v.degraded == sb.BAD_RESPONSE
    assert v.allowed is want_allowed


def _online_headers(env):
    s = Settings.resolve(env, org_url="http://gw.example.com", api_key="ik_1.key")
    p = D.resolve(s, env, explicit_destination="online", explicit_endpoint=None, explicit_api_key="ik_1.key")
    (exp,) = [e for e in p.exporters if e.name == "online"]
    return dict(exp.headers)


@pytest.mark.parametrize("name", ["Authorization", "authorization", "AUTHORIZATION"])
def test_online_credential_replaces_user_authorization_any_case(name):
    """FR-S04: the SDK credential always wins on the gateway exporter."""
    env = {"SUPERBASED_OTLP_HEADERS": f"{name}=Bearer foreign,X-A=b"}
    h = _online_headers(env)
    auth = [k for k in h if k.lower() == "authorization"]
    assert auth == ["Authorization"] and h["Authorization"] == "Bearer ik_1.key"
    assert h["X-A"] == "b"


def test_flush_false_when_every_span_was_rejected(stub):
    """FR-S07: a 401 drops every span; flush() says so, quiet or not."""
    stub.status = 401
    sb.init(endpoint=stub.url + "/v1/traces", shutdown_timeout=2)
    with sb.span("lost"):
        pass
    assert sb.flush() is False
    assert sb.diagnostics()["dropped_spans"] >= 1


def test_flush_true_when_everything_exported(mem):
    sb.init(exporter=mem)
    with sb.span("ok"):
        pass
    assert sb.flush() is True


class _RawServer:
    """A one-shot raw socket server: sends headers then ``body_fn(conn)``."""

    def __init__(self, body_fn, content_length=None):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(4)
        self.url = f"http://127.0.0.1:{self.sock.getsockname()[1]}/check"
        self.body_fn, self.content_length = body_fn, content_length
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        try:
            conn, _ = self.sock.accept()
            conn.recv(65536)
            conn.settimeout(0.2)
            try:  # drain the request body so closing never resets the reply
                conn.recv(65536)
            except OSError:
                pass
            conn.settimeout(None)
            head = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
            if self.content_length is not None:
                head += f"Content-Length: {self.content_length}\r\n"
            conn.sendall((head + "Connection: close\r\n\r\n").encode())
            self.body_fn(conn)
            conn.close()
        except OSError:
            pass


def test_admit_body_read_is_bounded_by_the_deadline():
    """FR-S09: a server dripping the body cannot hold admit() past timeout."""

    def drip(conn):
        conn.sendall(b'{"allowed": ')
        for _ in range(100):
            time.sleep(0.1)
            conn.sendall(b" ")

    srv = _RawServer(drip, content_length=1000)
    t = time.monotonic()
    v = sb.admit("hi", endpoint=srv.url, timeout=0.5)
    assert time.monotonic() - t < 2.0
    assert v.degraded == sb.TIMEOUT and v.allowed is True


def test_admit_body_is_capped():
    """FR-S09: the response body is cut at 1 MiB, as the Go SDK does: a valid
    verdict padded past the cap is truncated into a bad response."""

    def big(conn):
        try:
            conn.sendall(b'{"allowed": true, "pad": "')
            for _ in range(32):
                conn.sendall(b"x" * 65536)
            conn.sendall(b'"}')
        except OSError:
            pass

    srv = _RawServer(big)
    v = sb.admit("hi", endpoint=srv.url, timeout=5)
    assert v.degraded == sb.BAD_RESPONSE


def test_control_call_body_is_bounded_by_the_deadline():
    def drip(conn):
        for _ in range(100):
            time.sleep(0.1)
            conn.sendall(b" ")

    srv = _RawServer(drip, content_length=1000)
    t = time.monotonic()
    r = _http.request("GET", srv.url, timeout=0.5)
    assert time.monotonic() - t < 2.0
    assert r.status == 0 and "timed out" in r.error or "timeout" in r.error
