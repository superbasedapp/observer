"""SDK settings: one options object, each field mapped to an env var.

Resolution for every field: explicit ``init()`` argument, then the
``SUPERBASED_*`` variable, then the standard OpenTelemetry variable (where
one exists), then the default. Pure over an environment mapping, so it is
testable without touching ``os.environ``.

Export goes to a list of ``Destination`` objects (endpoint, headers, timeout
each). Today the list has one entry; choosing local / online / both (W2-7)
adds entries without changing the exporter plumbing.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, fields
from typing import Any, Dict, List, Mapping, Optional, Tuple
from urllib.parse import unquote

DEFAULT_ENDPOINT = "http://127.0.0.1:4318/v1/traces"
DEFAULT_SERVICE_NAME = "custom-app"
DEFAULT_MAX_CONTENT_CHARS = 8000
DEFAULT_EXPORT_TIMEOUT = 5.0  # seconds, per export request
DEFAULT_SHUTDOWN_TIMEOUT = 2.0  # seconds, bound on flush()/shutdown()
TRACES_PATH = "/v1/traces"
DEFAULT_NODE_URL = "http://127.0.0.1:8081"
DEFAULT_API_TIMEOUT = 5.0  # seconds, per control call (scores, prompts, datasets, experiments)
DEFAULT_PROMPT_CACHE_TTL = 60.0  # seconds a fetched prompt is fresh

_FALSE_WORDS = ("0", "false", "no", "off", "")


def env_flag(env: Mapping[str, str], names: Tuple[str, ...], default: bool) -> bool:
    """Parse the first set boolean-ish env var in ``names``; none set gives default."""
    for name in names:
        raw = env.get(name)
        if raw is not None:
            return raw.strip().lower() not in _FALSE_WORDS
    return default


def _env_str(env: Mapping[str, str], *names: str) -> str:
    for name in names:
        val = (env.get(name) or "").strip()
        if val:
            return val
    return ""


def _env_ms(env: Mapping[str, str], *names: str) -> Optional[float]:
    """First parseable millisecond value among ``names``, as seconds."""
    for name in names:
        raw = (env.get(name) or "").strip()
        if raw:
            try:
                return max(0.001, float(raw) / 1000.0)
            except ValueError:
                continue
    return None


def _env_int(env: Mapping[str, str], name: str, default: int) -> int:
    raw = (env.get(name) or "").strip()
    try:
        return int(raw) if raw else default
    except ValueError:
        return default


def parse_kv_list(raw: Optional[str]) -> Dict[str, str]:
    """Parse the OTel ``key1=value1,key2=value2`` list format (percent-decoded),
    as used by ``OTEL_RESOURCE_ATTRIBUTES`` and ``OTEL_EXPORTER_OTLP_HEADERS``.
    Malformed members are skipped."""
    out: Dict[str, str] = {}
    if not raw:
        return out
    for member in raw.split(","):
        if "=" not in member:
            continue
        key, _, value = member.partition("=")
        key = unquote(key.strip())
        if key:
            out[key] = unquote(value.strip())
    return out


def resolve_endpoint(explicit: Optional[str], env: Mapping[str, str]) -> str:
    """Explicit, ``SUPERBASED_OTLP_ENDPOINT`` (full traces URL),
    ``OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`` (full URL, used as is),
    ``OTEL_EXPORTER_OTLP_ENDPOINT`` (base URL; ``/v1/traces`` appended), then
    the local node's loopback receiver."""
    if explicit:
        return explicit
    val = _env_str(env, "SUPERBASED_OTLP_ENDPOINT", "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
    if val:
        return val
    base = _env_str(env, "OTEL_EXPORTER_OTLP_ENDPOINT")
    if base:
        return base.rstrip("/") + TRACES_PATH
    return DEFAULT_ENDPOINT


def resolve_headers(explicit: Optional[Mapping[str, str]], env: Mapping[str, str]) -> Dict[str, str]:
    """``OTEL_EXPORTER_OTLP_HEADERS``, ``OTEL_EXPORTER_OTLP_TRACES_HEADERS``,
    ``SUPERBASED_OTLP_HEADERS`` (later wins), then explicit headers on top."""
    out: Dict[str, str] = {}
    for name in ("OTEL_EXPORTER_OTLP_HEADERS", "OTEL_EXPORTER_OTLP_TRACES_HEADERS", "SUPERBASED_OTLP_HEADERS"):
        out.update(parse_kv_list(env.get(name)))
    if explicit:
        out.update({str(k): str(v) for k, v in explicit.items()})
    return out


def resolve_service_name(explicit: Optional[str], env: Mapping[str, str]) -> str:
    """Explicit, ``SUPERBASED_SERVICE_NAME``, ``OTEL_SERVICE_NAME``,
    ``service.name`` in ``OTEL_RESOURCE_ATTRIBUTES``, then ``custom-app``."""
    if explicit:
        return explicit
    val = _env_str(env, "SUPERBASED_SERVICE_NAME", "OTEL_SERVICE_NAME")
    if val:
        return val
    return parse_kv_list(env.get("OTEL_RESOURCE_ATTRIBUTES")).get("service.name", "").strip() or DEFAULT_SERVICE_NAME


def resolve_export_timeout(explicit: Optional[float], env: Mapping[str, str], default: float) -> float:
    """Seconds: explicit, then ``SUPERBASED_EXPORT_TIMEOUT_MS``,
    ``OTEL_EXPORTER_OTLP_TRACES_TIMEOUT``, ``OTEL_EXPORTER_OTLP_TIMEOUT``
    (all milliseconds, per the OTel spec), then ``default``."""
    if explicit is not None:
        return max(0.001, float(explicit))
    v = _env_ms(env, "SUPERBASED_EXPORT_TIMEOUT_MS", "OTEL_EXPORTER_OTLP_TRACES_TIMEOUT", "OTEL_EXPORTER_OTLP_TIMEOUT")
    return default if v is None else v


def _seconds(explicit: Any, env: Mapping[str, str], name: str, default: float, floor: float = 0.001) -> float:
    if explicit is not None:
        return max(floor, float(explicit))
    v = _env_ms(env, name)
    return default if v is None else max(floor, v)


_SAMPLERS = {
    "always_on": (1.0, False, False),
    "always_off": (0.0, False, False),
    "traceidratio": (None, False, True),
    "parentbased_always_on": (1.0, True, False),
    "parentbased_always_off": (0.0, True, False),
    "parentbased_traceidratio": (None, True, True),
}


def _ratio(raw: Any) -> Optional[float]:
    try:
        v = float(raw)
    except (TypeError, ValueError):
        return None
    return v if 0.0 <= v <= 1.0 else None


def resolve_sampling(explicit: Optional[float], env: Mapping[str, str]) -> Tuple[float, bool]:
    """(rate, parent_based): explicit ``sample_rate``, then
    ``SUPERBASED_SAMPLE_RATE`` (parent-based), then the standard
    ``OTEL_TRACES_SAMPLER`` / ``OTEL_TRACES_SAMPLER_ARG`` pair, else (1.0, True).
    An explicit rate outside 0..1 raises ValueError; a bad env value is ignored."""
    if explicit is not None:
        if isinstance(explicit, bool) or _ratio(explicit) is None:
            raise ValueError(f"sample_rate must be a number in 0..1, got {explicit!r}")
        return float(explicit), True
    v = _ratio(_env_str(env, "SUPERBASED_SAMPLE_RATE") or None)
    if v is not None:
        return v, True
    name = _env_str(env, "OTEL_TRACES_SAMPLER").lower()
    row = _SAMPLERS.get(name)
    if row is not None:
        rate, parent, takes_arg = row
        if takes_arg:
            arg = _ratio(_env_str(env, "OTEL_TRACES_SAMPLER_ARG") or None)
            rate = 1.0 if arg is None else arg
        return float(rate if rate is not None else 1.0), parent
    return 1.0, True


def sampling_env_problem(env: Mapping[str, str]) -> str:
    """Why an environment sampling value was ignored ("" when none was):
    ``SUPERBASED_SAMPLE_RATE`` or ``OTEL_TRACES_SAMPLER_ARG`` that is not a
    number in 0..1 (review E-38). Only consulted when no explicit
    ``sample_rate`` was given; an explicit bad value raises instead."""
    bad: List[str] = []
    raw = _env_str(env, "SUPERBASED_SAMPLE_RATE")
    if raw and _ratio(raw) is None:
        bad.append(f"SUPERBASED_SAMPLE_RATE={raw!r}")
    if not raw or _ratio(raw) is None:
        row = _SAMPLERS.get(_env_str(env, "OTEL_TRACES_SAMPLER").lower())
        arg = _env_str(env, "OTEL_TRACES_SAMPLER_ARG")
        if row is not None and row[2] and arg and _ratio(arg) is None:
            bad.append(f"OTEL_TRACES_SAMPLER_ARG={arg!r}")
    if not bad:
        return ""
    return " and ".join(bad) + " is not a number in 0..1; ignored"


@dataclass(frozen=True)
class Destination:
    """One OTLP/HTTP export target."""

    endpoint: str
    headers: Tuple[Tuple[str, str], ...] = field(default=(), repr=False)  # may carry the credential
    timeout: float = DEFAULT_EXPORT_TIMEOUT
    name: str = "primary"


@dataclass(frozen=True)
class Settings:
    """Every SDK option. ``init(**kwargs)`` takes these names; ``from_env``
    fills unset ones from the environment (see each field's comment)."""

    endpoint: str = DEFAULT_ENDPOINT  # SUPERBASED_OTLP_ENDPOINT > OTEL_EXPORTER_OTLP_TRACES_ENDPOINT > OTEL_EXPORTER_OTLP_ENDPOINT
    headers: Tuple[Tuple[str, str], ...] = field(default=(), repr=False)  # OTEL_EXPORTER_OTLP_HEADERS, ..._TRACES_HEADERS, SUPERBASED_OTLP_HEADERS
    api_key: str = field(default="", repr=False)  # SUPERBASED_API_KEY (sent as Authorization: Bearer)
    service_name: str = DEFAULT_SERVICE_NAME  # SUPERBASED_SERVICE_NAME > OTEL_SERVICE_NAME > OTEL_RESOURCE_ATTRIBUTES
    resource_attributes: Tuple[Tuple[str, str], ...] = ()  # OTEL_RESOURCE_ATTRIBUTES
    tenant: str = ""  # SUPERBASED_TENANT
    user: str = ""  # SUPERBASED_USER
    session_id: str = ""  # SUPERBASED_SESSION_ID
    capture_content: bool = True  # SUPERBASED_CAPTURE_CONTENT (legacy OBSERVER_CAPTURE_CONTENT)
    max_content_chars: int = DEFAULT_MAX_CONTENT_CHARS  # SUPERBASED_MAX_CONTENT_CHARS
    export_timeout: float = DEFAULT_EXPORT_TIMEOUT  # SUPERBASED_EXPORT_TIMEOUT_MS > OTEL_EXPORTER_OTLP_(TRACES_)TIMEOUT (ms)
    shutdown_timeout: float = DEFAULT_SHUTDOWN_TIMEOUT  # SUPERBASED_SHUTDOWN_TIMEOUT_MS
    quiet: bool = True  # SUPERBASED_QUIET
    console: bool = False  # SUPERBASED_CONSOLE
    release: str = ""  # SUPERBASED_RELEASE (resource service.version)
    environment: str = ""  # SUPERBASED_ENVIRONMENT (resource deployment.environment.name)
    tags: Tuple[str, ...] = ()  # SUPERBASED_TAGS (comma list)
    metadata: Tuple[Tuple[str, str], ...] = ()  # SUPERBASED_METADATA (k=v,k2=v2)
    sample_rate: float = 1.0  # SUPERBASED_SAMPLE_RATE > OTEL_TRACES_SAMPLER(+_ARG)
    sample_parent_based: bool = True  # from OTEL_TRACES_SAMPLER (parentbased_* or not)
    destination: str = ""  # SUPERBASED_DESTINATION; "" = the machine's default, else local
    org_url: str = ""  # SUPERBASED_ORG_URL: the org gateway base (OTLP and /v1/sdk/*)
    node_url: str = DEFAULT_NODE_URL  # SUPERBASED_NODE_URL: this machine's dashboard API
    discover: bool = True  # SUPERBASED_DISCOVER: ask the machine for its default
    api_timeout: float = DEFAULT_API_TIMEOUT  # SUPERBASED_API_TIMEOUT_MS: scores, prompts, datasets
    prompt_cache_ttl: float = DEFAULT_PROMPT_CACHE_TTL  # SUPERBASED_PROMPT_CACHE_TTL_MS
    gateway_request_id: bool = True  # SUPERBASED_GATEWAY_REQUEST_ID: stamp the AI gateway's X-SBO-Request-Id on the active span
    extra: Tuple[Tuple[str, Any], ...] = field(default=(), compare=True)  # non-env: exporter / tracer_provider ids

    @classmethod
    def resolve(cls, env: Mapping[str, str], **explicit: Any) -> "Settings":
        """Build settings from explicit arguments (None = unset) over env."""
        unknown = set(explicit) - {f.name for f in fields(cls)}
        if unknown:
            raise TypeError(f"unknown superbased_sdk setting(s): {', '.join(sorted(unknown))}")

        def pick(name: str, from_env: Any) -> Any:
            v = explicit.get(name)
            return from_env if v is None else v

        hdrs = resolve_headers(explicit.get("headers"), env)
        rate, parent_based = resolve_sampling(explicit.get("sample_rate"), env)
        tags_in = explicit.get("tags")
        if tags_in is None:
            tags_in = _env_str(env, "SUPERBASED_TAGS")
        meta_in = explicit.get("metadata")
        if meta_in is None:
            meta_in = parse_kv_list(env.get("SUPERBASED_METADATA"))
        elif not isinstance(meta_in, Mapping):
            raise TypeError("metadata must be a mapping")
        from . import _context

        tags = tuple(_context.normalize_tags(tags_in))
        meta = tuple(sorted(_context.normalize_metadata(meta_in).items()))
        max_chars_env = _env_int(env, "SUPERBASED_MAX_CONTENT_CHARS", DEFAULT_MAX_CONTENT_CHARS)
        shut = explicit.get("shutdown_timeout")
        if shut is None:
            shut = _env_ms(env, "SUPERBASED_SHUTDOWN_TIMEOUT_MS")
        return cls(
            endpoint=resolve_endpoint(explicit.get("endpoint"), env),
            headers=tuple(sorted(hdrs.items())),
            api_key=pick("api_key", _env_str(env, "SUPERBASED_API_KEY")),
            service_name=resolve_service_name(explicit.get("service_name"), env),
            resource_attributes=tuple(sorted(parse_kv_list(env.get("OTEL_RESOURCE_ATTRIBUTES")).items())),
            tenant=pick("tenant", _env_str(env, "SUPERBASED_TENANT")),
            user=pick("user", _env_str(env, "SUPERBASED_USER")),
            session_id=pick("session_id", _env_str(env, "SUPERBASED_SESSION_ID")),
            capture_content=bool(
                pick("capture_content", env_flag(env, ("SUPERBASED_CAPTURE_CONTENT", "OBSERVER_CAPTURE_CONTENT"), True))
            ),
            max_content_chars=int(pick("max_content_chars", max_chars_env)),
            export_timeout=resolve_export_timeout(explicit.get("export_timeout"), env, DEFAULT_EXPORT_TIMEOUT),
            shutdown_timeout=max(0.0, float(DEFAULT_SHUTDOWN_TIMEOUT if shut is None else shut)),
            quiet=bool(pick("quiet", env_flag(env, ("SUPERBASED_QUIET",), True))),
            console=bool(pick("console", env_flag(env, ("SUPERBASED_CONSOLE",), False))),
            release=str(pick("release", _env_str(env, "SUPERBASED_RELEASE"))).strip()[:256],
            environment=str(pick("environment", _env_str(env, "SUPERBASED_ENVIRONMENT"))).strip()[:256],
            tags=tags,
            metadata=meta,
            sample_rate=rate,
            sample_parent_based=parent_based,
            destination=str(pick("destination", _env_str(env, "SUPERBASED_DESTINATION"))).strip().lower(),
            org_url=str(pick("org_url", _env_str(env, "SUPERBASED_ORG_URL"))).strip().rstrip("/"),
            node_url=str(pick("node_url", _env_str(env, "SUPERBASED_NODE_URL") or DEFAULT_NODE_URL)).strip().rstrip("/"),
            discover=bool(pick("discover", env_flag(env, ("SUPERBASED_DISCOVER",), True))),
            api_timeout=_seconds(explicit.get("api_timeout"), env, "SUPERBASED_API_TIMEOUT_MS", DEFAULT_API_TIMEOUT),
            prompt_cache_ttl=_seconds(
                explicit.get("prompt_cache_ttl"), env, "SUPERBASED_PROMPT_CACHE_TTL_MS", DEFAULT_PROMPT_CACHE_TTL, floor=0.0
            ),
            gateway_request_id=bool(pick("gateway_request_id", env_flag(env, ("SUPERBASED_GATEWAY_REQUEST_ID",), True))),
            extra=tuple(explicit.get("extra") or ()),
        )

    def export_headers(self) -> Dict[str, str]:
        out = dict(self.headers)
        if self.api_key and not any(h.lower() == "authorization" for h in out):
            out["Authorization"] = "Bearer " + self.api_key
        return out

    def destinations(self) -> List[Destination]:
        """The single export target of the pre-destination settings (the
        ``endpoint`` chain). ``init()`` exports to the destination plan
        (``_destination.resolve``) instead; this stays for callers of A7."""
        return [Destination(self.endpoint, tuple(sorted(self.export_headers().items())), self.export_timeout)]

    def identity(self, sdk_marker: str) -> Dict[str, Any]:
        """Process-wide identity, written on the resource (or stamped per span
        when the SDK is attached to the host's provider)."""
        from . import _keys as K

        out: Dict[str, Any] = {K.SDK: sdk_marker}
        if self.tenant:
            out[K.TENANT] = self.tenant
        if self.user:
            out[K.USER] = self.user
        if self.session_id:
            out[K.SESSION] = self.session_id
        if self.release:
            out[K.RESOURCE_RELEASE] = self.release
        if self.environment:
            out[K.RESOURCE_ENVIRONMENT] = self.environment
        if self.tags:
            out[K.TAGS] = tuple(self.tags)
        for k, v in self.metadata:
            out[K.METADATA_PREFIX + k] = v
        return out


def environ() -> Mapping[str, str]:
    """The process environment (a seam for tests)."""
    return os.environ
