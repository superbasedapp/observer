"""Setup's output: plain lines for people, or (``--json``) one JSON object
per phase for agents, with the people lines on stderr.

Every write passes the secret guard: a value registered with ``Secrets``
(the SDK key, its secret half, the device code, the redeem secret, the key
grant) is replaced before anything is written, so no output, ``--json``
line or log record can carry one (plan 3.5, SDKQS-4). The guard is the
second line of defence: setup never formats a secret in the first place,
and the secrecy test checks that nothing reaches the guard either.
"""

from __future__ import annotations

import json
import logging
import sys
import threading
from typing import Any, List, Optional, TextIO

REDACTED = "[redacted]"


class Secrets:
    """Values that must never be written (longest first when scrubbing)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._values: List[str] = []
        self.hits = 0  # how many times the guard had to act (tests assert 0)

    def add(self, *values: Optional[str]) -> None:
        with self._lock:
            for v in values:
                if v and len(v) >= 8 and v not in self._values:
                    self._values.append(v)
                    # The compound's secret half is a secret of its own.
                    if "." in v:
                        half = v.split(".", 1)[1]
                        if len(half) >= 8 and half not in self._values:
                            self._values.append(half)
            self._values.sort(key=len, reverse=True)

    def scrub(self, text: str) -> str:
        with self._lock:
            values = list(self._values)
        for v in values:
            if v in text:
                text = text.replace(v, REDACTED)
                self.hits += 1
        return text


class Output:
    """Where setup writes. ``json_mode``: stdout carries only JSON lines."""

    def __init__(self, secrets: Secrets, *, json_mode: bool = False, stdout: Optional[TextIO] = None, stderr: Optional[TextIO] = None) -> None:
        self.secrets = secrets
        self.json_mode = json_mode
        self.stdout = stdout if stdout is not None else sys.stdout
        self.stderr = stderr if stderr is not None else sys.stderr
        self.events: List[dict] = []

    def _write(self, stream: TextIO, text: str) -> None:
        try:
            stream.write(self.secrets.scrub(text) + "\n")
            stream.flush()
        except Exception:  # noqa: BLE001 - a closed pipe never breaks setup
            pass

    def say(self, text: str = "") -> None:
        """A line for the person (stdout; stderr under --json)."""
        self._write(self.stderr if self.json_mode else self.stdout, text)

    def warn(self, text: str) -> None:
        self._write(self.stderr, text)

    def event(self, phase: str, **fields: Any) -> None:
        """One JSON object for this phase (written only under --json)."""
        obj = {"phase": phase}
        obj.update({k: v for k, v in fields.items() if v is not None})
        self.events.append(obj)
        if self.json_mode:
            self._write(self.stdout, json.dumps(obj, separators=(",", ":"), ensure_ascii=False, default=str))


class _LogHandler(logging.Handler):
    """The SDK's own log lines during setup (destination warnings and the
    like), written through the guard."""

    def __init__(self, out: Output) -> None:
        super().__init__(logging.WARNING)
        self._out = out

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = record.getMessage()
        except Exception:  # noqa: BLE001
            return
        self._out.warn(msg)


class capture_sdk_logs:
    """Route the ``superbased_sdk`` logger through the guard while setup
    runs (and keep it from reaching the root logger's handlers)."""

    def __init__(self, out: Output) -> None:
        self._handler = _LogHandler(out)
        self._logger = logging.getLogger("superbased_sdk")
        self._propagate = True

    def __enter__(self) -> "capture_sdk_logs":
        self._propagate = self._logger.propagate
        self._logger.addHandler(self._handler)
        self._logger.propagate = False
        return self

    def __exit__(self, *exc: Any) -> None:
        self._logger.removeHandler(self._handler)
        self._logger.propagate = self._propagate
