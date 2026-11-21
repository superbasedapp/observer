"""Shared fixtures: SDK state reset, a clean global TracerProvider slot, an
in-memory exporter and a local HTTP stub for admit()."""

import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import superbased_sdk as sb  # noqa: E402
from opentelemetry import trace  # noqa: E402
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter  # noqa: E402
from opentelemetry.util._once import Once  # noqa: E402

_SDK_ENV = [k for k in os.environ if k.startswith(("SUPERBASED_", "OTEL_", "OBSERVER_CAPTURE"))]


def _reset_global_provider():
    # The OTel API allows set_tracer_provider once per process; tests reset it.
    trace._TRACER_PROVIDER_SET_ONCE = Once()
    trace._TRACER_PROVIDER = None


@pytest.fixture(autouse=True)
def clean(monkeypatch):
    for k in list(os.environ):
        if k.startswith(("SUPERBASED_", "OTEL_", "OBSERVER_CAPTURE", "ANTHROPIC_OPEN_TELEMETRY")):
            monkeypatch.delenv(k, raising=False)
    # Never ask a real machine on :8081 from a unit test; the destination tests
    # turn discovery on against a stub.
    monkeypatch.setenv("SUPERBASED_DISCOVER", "0")
    sb._reset_for_tests()
    _reset_global_provider()
    yield
    sb._reset_for_tests()
    _reset_global_provider()


@pytest.fixture
def mem():
    return InMemorySpanExporter()


class Stub:
    """A tiny HTTP server whose responses are scripted per test: ``reply()``
    sets the default answer; ``route(method, path, ...)`` answers one path
    (query string ignored) with a fixed reply or a callable(request) ->
    (status, body, headers). Every request is recorded (JSON bodies decoded,
    others kept as raw bytes)."""

    def __init__(self):
        self.status = 200
        self.body = b"{}"
        self.headers = {}
        self.delay = 0.0
        self.requests = []
        self.truncate = False
        self.routes = {}
        stub = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _answer(self):
                n = int(self.headers.get("Content-Length", "0") or 0)
                raw = self.rfile.read(n) if n else b""
                try:
                    body = json.loads(raw or b"{}")
                except ValueError:
                    body = None
                req = {"method": self.command, "path": self.path, "headers": dict(self.headers), "body": body, "raw": raw}
                stub.requests.append(req)
                path = self.path.split("?", 1)[0]
                status, out, headers = stub.status, stub.body, stub.headers
                hit = stub.routes.get((self.command, path))
                if hit is not None:
                    status, out, headers = hit(req) if callable(hit) else hit
                    out = out if isinstance(out, bytes) else json.dumps(out).encode()
                if stub.delay:
                    threading.Event().wait(stub.delay)
                self.send_response(status)
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                if stub.truncate:
                    self.send_header("Content-Length", str(len(out) + 50))
                else:
                    self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                try:
                    self.wfile.write(out)
                except OSError:
                    pass

            do_POST = _answer
            do_GET = _answer

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.server.daemon_threads = True
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True).start()

    def reply(self, body, status=200, headers=None):
        self.status = status
        self.body = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.headers = headers or {}

    def route(self, method, path, reply=None, status=200, headers=None, *, body=None):
        """Answer ``method path`` with ``body`` (or a callable ``reply``)."""
        self.routes[(method, path)] = reply if callable(reply) else (status, body if body is not None else reply, headers or {})

    def paths(self, method=None):
        return [r["path"].split("?", 1)[0] for r in self.requests if method is None or r["method"] == method]

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def stub():
    s = Stub()
    yield s
    s.close()


@pytest.fixture
def stub2():
    """A second, independent stub (the org gateway beside the machine)."""
    s = Stub()
    yield s
    s.close()


@pytest.fixture
def dead_url():
    """A URL on a port nothing listens on."""
    import socket

    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return f"http://127.0.0.1:{port}"
