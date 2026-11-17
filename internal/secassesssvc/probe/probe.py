#!/usr/bin/env python3
"""Logged request helper for an Observer security assessment run.

    python3 probe.py METHOD TARGET [-H 'Name: value'] [-d DATA | -d @file]
        [--role control|attack] [--wstg ID] [--account LABEL] [--note TEXT]
        [--follow] [--timeout SECONDS]

or, in a retest, to send the stored requests of one finding:  python3 probe.py --replay ID

or, from a script in this folder:  from probe import request

Every request to the target goes through here and is appended, one JSON line
each, to probes.jsonl next to this file. Settings come from probe.json. Python
3.8+, standard library only. probes.jsonl is a plain file: a record of what
this helper sent, not proof of anything.
"""
import argparse
import datetime
import http.client
import ipaddress
import json
import os
import re
import ssl
import sys
import time
import urllib.parse

try:
    import fcntl
except ImportError:  # Windows
    fcntl = None
try:
    import msvcrt
except ImportError:  # POSIX
    msvcrt = None

HERE = os.path.dirname(os.path.abspath(__file__))
LOG_NAME = "probes.jsonl"
METHODS = ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")
WSTG = ("INFO", "CONF", "IDNT", "ATHN", "ATHZ", "SESS", "INPV", "ERRH", "CRYP", "BUSL", "CLNT", "APIT")
BANNED_HEADERS = ("host", "connection", "content-length", "transfer-encoding")
REDIRECTS = (301, 302, 303, 307, 308)
MAX_BODY, MAX_HOPS, MAX_LOCKOUT, EXCERPT, MAX_RECORD = 65536, 3, 10, 1024, 24576
LOG_FULL = 12 << 20  # stop here: one more record (at most MAX_RECORD) stays under the 16 MiB Observer reads
LOCK_AT = 1 << 30  # Windows lock byte, far beyond the data so readers are never blocked
REDACTED = "[REDACTED]"
LABEL = re.compile(r"[A-Za-z0-9_.-]{1,40}")
ITEM_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,47}")  # a finding id, as Observer writes it
CONFIG_MAX = 256 << 10  # probe.json is read to here; Observer writes at most 192 KiB (a retest carries stored requests)
MAX_REPLAY_FINDINGS, MAX_REPLAY_STEPS = 8, 8


class ProbeRefused(Exception):
    """A request the helper will not send. The refusal is logged first."""

    def __init__(self, code, message):
        Exception.__init__(self, "%s: %s" % (code, message))
        self.code = code
        self.message = message


# ---- redaction (everything stored; stdout is never redacted) ----------------
# A secret is found by its value (a token's shape) or by the name it travels
# under: a header name, a JSON key, a query or form field. LONG words match
# anywhere in a name; SHORT ones only as a whole part of it (set apart by _ - or .),
# so "key" and "auth" hide `?key=` and `x-auth` but not "keyboard" or "author".
# "code" is a credential as a query or form field (an OAuth `code=`) but an error
# code in a JSON key or a line of text, so only `code=` is hidden. The Go side
# (internal/secassess/headers.go) holds the same header-name pattern; a test in
# the secassesssvc package runs both over one table.
_W = r"[A-Za-z0-9_.-]{0,40}"
_LONG = (r"password|passwd|passphrase|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|auth[_-]?(?:key|code)"
         r"|authorization|session|sessid|signature|credential|csrf|xsrf|jwt")
_SHORT = r"sid|key|auth|pass|pwd|otp"
_KEY = r"(?:%s(?:%s)%s|(?:%s[_.-])?(?:%s)(?:[_.-]%s)?)" % (_W, _LONG, _W, _W, _SHORT, _W)
_CODE = r"(?:%s[_.-])?code(?:[_.-]%s)?" % (_W, _W)
_PATTERNS = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)", re.S), REDACTED),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*"), REDACTED),
    (re.compile(r"\b(Bearer)\s+[A-Za-z0-9._~+/=-]{16,}", re.I), r"\1 " + REDACTED),
    (re.compile(r"AKIA[0-9A-Z]{16}"), REDACTED),
    (re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"), REDACTED),
    (re.compile(r"(?<![A-Za-z0-9])sk-[A-Za-z0-9_-]{20,}"), REDACTED),
    (re.compile(r"xox[abprs]-[A-Za-z0-9-]{10,}"), REDACTED),
    (re.compile(r'("' + _KEY + r'"\s*:\s*")(?:[^"\\]|\\.)+(")', re.I), r"\1" + REDACTED + r"\2"),
    (re.compile(r"(?<![A-Za-z0-9_.-])(" + _KEY + r"[ \t]*[=:][ \t]*)[^\s\"'&;,<>]+", re.I), r"\1" + REDACTED),
    (re.compile(r"(?<![A-Za-z0-9_.-])(" + _CODE + r"=)[^\s\"'&;,<>]+", re.I), r"\1" + REDACTED),
]
# A header whose NAME says it carries a credential is stored as [REDACTED],
# whatever the value looks like. The challenge headers and the CORS flag name
# credentials but carry none.
_CRED_NAME = re.compile(r"auth|token|secret|key|sess|sid|cook|pass|pwd|sign|otp|csrf|xsrf|jwt|cred|bearer|hmac", re.I)
_NOT_CRED = ("www-authenticate", "proxy-authenticate", "access-control-allow-credentials")


def redact_text(text):
    """Replace obvious secrets in text with [REDACTED] (best effort)."""
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def credential_header(name):
    """True when a header's name says its value is a credential."""
    low = name.lower()
    return bool(_CRED_NAME.search(low)) and low not in _NOT_CRED


def redact_header(name, value):
    """The stored form of one header value, at most 256 characters."""
    low = name.lower()
    if not value.strip():
        out = ""
    elif low in ("authorization", "proxy-authorization"):
        scheme, sep, rest = value.strip().partition(" ")
        out = scheme + " " + REDACTED if sep and rest.strip() and re.fullmatch(r"[A-Za-z0-9-]{1,16}", scheme) else REDACTED
    elif low == "cookie":
        out = "; ".join(p.split("=", 1)[0].strip() + "=" + REDACTED if "=" in p else REDACTED
                        for p in value.split(";") if p.strip())
    elif low == "set-cookie":  # keep the attributes (HttpOnly, SameSite, Path, Secure) visible
        first, sep, attrs = value.partition(";")
        out = (first.split("=", 1)[0].strip() + "=" + REDACTED if "=" in first else REDACTED) + sep + redact_text(attrs)
    elif credential_header(name):
        out = REDACTED
    else:
        out = redact_text(value)
    return out[:256]


# ---- configuration and request checks ---------------------------------------
def _origin_parts(text):
    """(scheme, host, port) of a loopback http(s) origin with an explicit port, else None."""
    if not isinstance(text, str):
        return None
    try:
        u = urllib.parse.urlsplit(text)
        host, port = u.hostname, u.port
    except ValueError:
        return None
    if u.scheme not in ("http", "https") or not host or not port or "@" in u.netloc:
        return None
    if text != "%s://%s" % (u.scheme, u.netloc):  # no path, query or fragment
        return None
    canon = _loopback_host(host)
    return (u.scheme, canon, port) if canon else None


def _loopback_host(host):
    """The canonical form of a loopback host: localhost, a 127.x.y.z address or ::1, in any spelling Observer
    accepts for a target ([0:0:0:0:0:0:0:1], [::ffff:127.0.0.1]); None for anything else."""
    host = host.lower()
    if host == "localhost":
        return host
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:  # also a zone id, "127.1" and a decimal number
        return None
    addr = getattr(addr, "ipv4_mapped", None) or addr
    return str(addr) if addr.is_loopback else None


def _load_config():
    try:
        with open(os.path.join(HERE, "probe.json"), "rb") as f:
            raw = f.read(CONFIG_MAX + 1)
        if len(raw) > CONFIG_MAX:
            raise ProbeRefused("bad_config", "probe.json is over %d bytes" % CONFIG_MAX)
        cfg = json.loads(raw.decode("utf-8-sig"))
    except (OSError, ValueError) as exc:
        raise ProbeRefused("bad_config", "cannot read probe.json: %s" % exc)
    if not isinstance(cfg, dict) or cfg.get("schema") != "observer.probe.v1":
        raise ProbeRefused("bad_config", "probe.json: unknown schema")
    if cfg.get("run_id") != os.path.basename(HERE):
        raise ProbeRefused("bad_config", "probe.json: run_id does not match this folder")
    parts = _origin_parts(cfg.get("origin"))
    if parts is None:
        raise ProbeRefused("bad_config", "probe.json: origin must be http(s) on localhost, 127.x.y.z or [::1] with a port")
    for key in ("budget", "pace_rps", "max_bytes"):
        v = cfg.get(key)
        if not isinstance(v, int) or isinstance(v, bool) or v < 1:
            raise ProbeRefused("bad_config", "probe.json: %s must be a positive integer" % key)
    return {"origin": cfg["origin"], "parts": parts, "budget": cfg["budget"],
            "pace_rps": cfg["pace_rps"], "max_bytes": min(cfg["max_bytes"], 1048576),
            "replay": _load_replay(cfg.get("replay"))}


def _load_replay(raw):
    """The stored requests of a retest, by finding id: {id: {"wstg": str, "steps": [(method, path, headers, body)]}}.
    Absent for any run that is not a retest; a malformed one refuses every request, so it is never half-read."""
    if raw is None:
        return {}
    bad = ProbeRefused("bad_config", "probe.json: replay is not a set of at most %d findings with at most %d stored requests each"
                       % (MAX_REPLAY_FINDINGS, MAX_REPLAY_STEPS))
    if not isinstance(raw, dict) or len(raw) > MAX_REPLAY_FINDINGS:
        raise bad
    out = {}
    for fid, entry in raw.items():
        steps = entry.get("steps") if isinstance(entry, dict) else None
        wstg = entry.get("wstg", "") if isinstance(entry, dict) else ""
        if not (ITEM_ID.fullmatch(str(fid)) and isinstance(steps, list) and 1 <= len(steps) <= MAX_REPLAY_STEPS
                and isinstance(wstg, str) and wstg in ("",) + WSTG):
            raise bad
        clean = []
        for s in steps:
            if not isinstance(s, dict) or not isinstance(s.get("method"), str) or not isinstance(s.get("path"), str):
                raise bad
            heads, body = s.get("headers") or [], s.get("body", "")
            if not isinstance(heads, list) or not isinstance(body, str):
                raise bad
            pairs = []
            for h in heads:
                if not isinstance(h, dict) or not isinstance(h.get("name"), str) or not isinstance(h.get("value", ""), str):
                    raise bad
                pairs.append((h["name"], h.get("value", "")))
            clean.append((s["method"], s["path"], pairs, body))
        out[fid] = {"wstg": wstg, "steps": clean}
    return out


def _resolve(target, cfg):
    """The path+query to send for target; refuse anything that is not on the origin."""
    scheme, host, port = cfg["parts"]
    if not isinstance(target, str):
        raise ProbeRefused("bad_path", "target must be a string")
    if re.match(r"[A-Za-z][A-Za-z0-9+.-]*://", target):
        try:
            u = urllib.parse.urlsplit(target)
            same = (u.scheme.lower(), _loopback_host(u.hostname or ""), u.port or (80 if u.scheme == "http" else 443)) == (scheme, host, port)
        except ValueError:
            same = False
        if not same or "@" in u.netloc:
            raise ProbeRefused("off_target", "only %s is allowed" % cfg["origin"])
        target = (u.path or "/") + ("?" + u.query if u.query else "")
    if target.startswith("//"):
        raise ProbeRefused("bad_path", "a path starts with a single /")
    if not re.fullmatch(r"/[\x21-\x7e]{0,2047}", target):
        raise ProbeRefused("bad_path", "a path starts with /, is at most 2048 characters of printable ASCII, no spaces")
    return target


def _pairs(headers):
    pairs = []
    for h in (headers.items() if isinstance(headers, dict) else headers or []):
        if isinstance(h, str):
            name, sep, value = h.partition(":")
            if not sep:
                raise ProbeRefused("bad_header", "expected 'Name: value'")
        else:
            name, value = h
        pairs.append((str(name).strip(), str(value).strip()))
    return pairs


def _check_headers(pairs):
    if len(pairs) > 20:
        raise ProbeRefused("bad_header", "at most 20 headers")
    for name, value in pairs:
        if not re.fullmatch(r"[A-Za-z0-9-]{1,64}", name) or name.lower() in BANNED_HEADERS:
            raise ProbeRefused("bad_header", "header name not allowed: %s" % name[:64])
        if len(value) > 2048 or re.search(r"[\r\n\0]", value):
            raise ProbeRefused("bad_header", "header value too long or has CR, LF or NUL: %s" % name)


def _prepare(cfg, rec, method, target, headers, body):
    """Validate everything that costs nothing; fill the record as far as it is known."""
    if rec["method"] not in METHODS:
        raise ProbeRefused("bad_method", "method must be one of " + " ".join(METHODS))
    path = _resolve(target, cfg)
    rec["path"] = redact_text(path)
    pairs = _pairs(headers)
    rec["req_headers"] = [{"n": n[:64], "v": redact_header(n, v)} for n, v in pairs[:20]]
    _check_headers(pairs)
    if body is None:
        data = b""
    elif isinstance(body, (bytes, bytearray)):
        data = bytes(body)
    else:
        data = str(body).encode("utf-8")
    rec["req_body_bytes"] = len(data)
    rec["req_body_excerpt"] = redact_text(data[:MAX_BODY].decode("utf-8", "replace"))[:EXCERPT]
    if len(data) > MAX_BODY:
        raise ProbeRefused("body_too_large", "a request body is at most %d bytes" % MAX_BODY)
    return path, pairs, data


def _unreserved(match):
    """%41 -> A for a letter, digit or one of . _ ~ - (the characters that never need encoding)."""
    ch = chr(int(match.group(1), 16))
    return ch if re.fullmatch(r"[A-Za-z0-9._~-]", ch) else match.group(0).upper()


def _lock_path(path):
    """The path an attempt counts against. The method, letter case, a trailing /, ;params, ./ and ../
    segments, repeated / and %-encoded letters and digits make no new path. A guard rail, not a barrier:
    it follows what servers commonly treat as one path, and the helper cannot know the server's rules."""
    path = re.sub(r"%([0-9A-Fa-f]{2})", _unreserved, path.split("?", 1)[0])
    parts = []
    for seg in path.split("/"):
        seg = seg.split(";", 1)[0].lower()
        if seg == "..":
            if parts:
                parts.pop()
        elif seg not in ("", "."):
            parts.append(seg)
    return "/" + "/".join(parts)


def _check_limits(cfg, rec, records):
    """Refuse an 11th attempt on one account and path, or a request past the budget. Returns cost so far."""
    if rec["account"]:
        key = _lock_path(rec["path"])
        tries = sum(1 for r in records if r.get("sent") is True and r.get("account") == rec["account"]
                    and _lock_path(str(r.get("path", ""))) == key)
        if tries >= MAX_LOCKOUT:
            raise ProbeRefused("lockout", "%d attempts already sent for account %s on %s" % (tries, rec["account"], key))
    used = sum(r["cost"] if isinstance(r.get("cost"), int) and r["cost"] > 0 else 1 for r in records if r.get("sent") is True)
    if used + 1 > cfg["budget"]:
        raise ProbeRefused("budget", "the request budget of %d is used up" % cfg["budget"])
    return used


# ---- the log ----------------------------------------------------------------
def _now():
    t = datetime.datetime.now(datetime.timezone.utc)
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ" % (t.microsecond // 1000)


def _lock(fd):
    """Exclusive lock for the whole invocation, so ids, pace and budget stay exact."""
    if fcntl is not None:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            return True
        except OSError:
            return False
    if msvcrt is not None:
        give_up = time.monotonic() + 300
        os.lseek(fd, LOCK_AT, os.SEEK_SET)
        while time.monotonic() < give_up:
            try:
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                return True
            except OSError:
                time.sleep(0.02)
    return False  # no locking available: carry on unlocked rather than hang


def _unlock(fd):
    if msvcrt is not None and fcntl is None:
        os.lseek(fd, LOCK_AT, os.SEEK_SET)
        try:
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        except OSError:
            pass


def _prior(fd):
    """(records, line count, prefix, size): one dict per non-empty log line; {} for an unreadable one."""
    os.lseek(fd, 0, os.SEEK_SET)
    chunks = []
    while True:
        part = os.read(fd, 1 << 20)
        if not part:
            break
        chunks.append(part)
    raw = b"".join(chunks)
    records = []
    for line in raw.split(b"\n"):
        if line.strip():
            try:
                rec = json.loads(line.decode("utf-8"))
            except (ValueError, RecursionError):  # a line the agent edited by hand
                rec = {}
            records.append(rec if isinstance(rec, dict) else {})
    return records, len(records), (b"\n" if raw and not raw.endswith(b"\n") else b""), len(raw)


def _newly_hidden(prior, headers, rec, text):
    """Names whose value this record hides and no earlier record of the log did: a response header's
    name (first spelling seen) or "the body". Once per name per log, so the note below is not per request."""
    seen = set()
    for r in prior:
        for h in r.get("resp_headers") or ():
            if isinstance(h, dict) and REDACTED in str(h.get("v", "")):
                seen.add(str(h.get("n", "")).lower())
        if REDACTED in str(r.get("body_excerpt", "")):
            seen.add("the body")
    out = []
    for (name, value), kept in zip(headers[:40], rec["resp_headers"]):
        low = name[:64].lower()
        if REDACTED in kept["v"] and REDACTED not in value and low not in seen:
            seen.add(low)
            out.append(name[:64])
    if REDACTED in rec["body_excerpt"] and REDACTED not in text[:EXCERPT] and "the body" not in seen:
        out.append("the body")
    return out


def _blank(rid, role, wstg, account, note, method, path):
    return {"v": 1, "id": rid, "ts": _now(), "role": role, "wstg": wstg, "account": account,
            "note": redact_text(str(note))[:200], "method": method, "path": path, "req_headers": [],
            "req_body_bytes": 0, "req_body_excerpt": "", "sent": False, "refused": "", "error": "",
            "status": 0, "resp_headers": [], "body_bytes": 0, "body_truncated": False, "body_excerpt": "",
            "ms": 0, "hops": 0, "redirect_to": "", "redirect_blocked": False, "cost": 0}


def _append(fd, rec, prefix):
    """One compact, ASCII-only line, one os.write; shrinks the excerpts if a record grows past MAX_RECORD."""
    line = json.dumps(rec, separators=(",", ":"), ensure_ascii=True)
    while len(line) > MAX_RECORD and (rec["body_excerpt"] or rec["resp_headers"]):
        if rec["body_excerpt"]:
            rec["body_excerpt"] = rec["body_excerpt"][:len(rec["body_excerpt"]) // 2]
        else:
            del rec["resp_headers"][len(rec["resp_headers"]) // 2:]
        line = json.dumps(rec, separators=(",", ":"), ensure_ascii=True)
    os.write(fd, prefix + line.encode("ascii") + b"\n")


# ---- sending ----------------------------------------------------------------
def _fetch(cfg, out, method, path, headers, body, timeout):
    scheme, host, port = cfg["parts"]
    out.update(status=0, reason="", headers=[], data=bytearray(), cut=False)
    if scheme == "https":
        # A loopback dev server usually has a self-signed certificate. The host
        # is pinned to loopback by probe.json, so certificate checks are off.
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
    else:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
    deadline = time.monotonic() + timeout
    try:
        conn.putrequest(method, path, skip_accept_encoding=any(n.lower() == "accept-encoding" for n, _ in headers))
        for name, value in headers:
            conn.putheader(name, value)
        if body or method in ("POST", "PUT", "PATCH"):
            conn.putheader("Content-Length", str(len(body)))
        conn.endheaders(body or None)
        resp = conn.getresponse()
        out["status"], out["reason"], out["headers"] = resp.status, resp.reason, resp.getheaders()
        limit = cfg["max_bytes"]
        while len(out["data"]) <= limit:
            if time.monotonic() > deadline:
                raise TimeoutError("response not complete within %d s" % timeout)
            chunk = resp.read(min(8192, limit + 1 - len(out["data"])))
            if not chunk:
                break
            out["data"] += chunk
        if len(out["data"]) > limit:
            out["cut"] = True
            del out["data"][limit:]
    finally:
        conn.close()


def _send(cfg, out, method, path, headers, body, follow, timeout, room):
    """Send the request and, with follow, same-origin redirects, each hop paced like a request.
    I/O errors land in out."""
    while True:
        try:
            _fetch(cfg, out, method, path, headers, body, timeout)
        except Exception as exc:  # refused, reset, timed out, malformed reply
            out["error"] = ("%s: %s" % (type(exc).__name__, exc))[:200]
            return
        location = next((v for n, v in out["headers"] if n.lower() == "location"), "")
        out["redirect_to"] = location[:300] if out["status"] in REDIRECTS else ""
        if not out["redirect_to"] or not follow:
            return
        try:
            nxt = _resolve(urllib.parse.urljoin(cfg["origin"] + path, location), cfg)
        except (ProbeRefused, ValueError):  # another origin, or not a usable path
            out["blocked"] = True
            return
        if out["hops"] >= MAX_HOPS or out["hops"] + 1 > room:
            return
        if out["status"] == 303 or (out["status"] in (301, 302) and method == "POST"):
            # Simplified browser behaviour: these become a GET without a body.
            method = method if method == "HEAD" else "GET"
            body = b""
            headers = [h for h in headers if h[0].lower() != "content-type"]
        time.sleep(min(1.0 / cfg["pace_rps"], 5.0))
        path, out["hops"], out["redirect_to"] = nxt, out["hops"] + 1, ""


def request(method, target, headers=None, body=None, role="", wstg="", account="", note="", follow=False, timeout=10, _replay=""):
    """Send one logged request to the origin in probe.json.

    Returns {"id", "status", "reason", "headers", "body", "path", "record", "hidden"}; status 0 means
    no HTTP response (the record's error says why); hidden names what the log hides here for the first time. Raises ProbeRefused, after logging it
    (a full log, log_full, cannot be), for a request the helper will not send. headers: dict, (name, value) pairs or 'Name: value' strings.
    """
    if role not in ("", "control", "attack") or wstg not in ("",) + WSTG or (account and not LABEL.fullmatch(account)):
        raise ValueError("role, wstg or account label not allowed")
    timeout = min(30.0, max(1.0, float(timeout)))
    try:
        fd = os.open(os.path.join(HERE, LOG_NAME), os.O_RDWR | os.O_APPEND | os.O_CREAT | getattr(os, "O_BINARY", 0), 0o600)
    except OSError as exc:
        raise ProbeRefused("bad_config", "cannot open %s: %s" % (LOG_NAME, exc))
    locked = _lock(fd)
    try:
        return _logged(fd, method, target, headers, body, role, wstg, account, note, follow, timeout, _replay)
    finally:
        if locked:
            _unlock(fd)
        os.close(fd)


def _logged(fd, method, target, headers, body, role, wstg, account, note, follow, timeout, replay):
    records, count, prefix, size = _prior(fd)
    if size >= LOG_FULL:  # not logged: one more record would pass what Observer reads back
        raise ProbeRefused("log_full", "%s is %d bytes; the helper stops at %d" % (LOG_NAME, size, LOG_FULL))
    rec = _blank("p%d" % (count + 1), role, wstg, account, note, str(method)[:16].upper(), redact_text(str(target))[:300])
    if replay:  # only a request sent by replay() carries the key
        rec["replay"] = replay
    try:
        cfg = _load_config()
        path, pairs, data = _prepare(cfg, rec, method, target, headers, body)
        used = _check_limits(cfg, rec, records)
    except ProbeRefused as exc:
        rec["refused"] = exc.code
        _append(fd, rec, prefix)  # every refusal is logged; log_full above is the one that cannot be
        raise
    try:  # pace: start at least 1/pace_rps after the previous record, never wait over 5 s
        gap = datetime.datetime.strptime(records[-1]["ts"], "%Y-%m-%dT%H:%M:%S.%fZ").replace(
            tzinfo=datetime.timezone.utc).timestamp() + 1.0 / cfg["pace_rps"] - time.time()
        if gap > 0:
            time.sleep(min(gap, 5.0))
    except (IndexError, KeyError, ValueError, TypeError):
        pass
    rec["ts"] = _now()
    started = time.monotonic()
    out = {"error": "", "hops": 0, "redirect_to": "", "blocked": False}
    _send(cfg, out, rec["method"], path, pairs, data, follow, timeout, cfg["budget"] - used - 1)
    text = bytes(out["data"]).decode("utf-8", "replace")
    rec.update(sent=True, error=out["error"], status=out["status"],
               resp_headers=[{"n": n[:64], "v": redact_header(n, v)} for n, v in out["headers"][:40]],
               body_bytes=len(out["data"]), body_truncated=out["cut"], body_excerpt=redact_text(text)[:EXCERPT],
               ms=int((time.monotonic() - started) * 1000), hops=out["hops"],
               redirect_to=redact_text(out["redirect_to"])[:300], redirect_blocked=out["blocked"], cost=1 + out["hops"])
    _append(fd, rec, prefix)
    return {"id": rec["id"], "status": out["status"], "reason": out["reason"], "headers": out["headers"],
            "body": text, "path": path, "record": rec, "hidden": _newly_hidden(records, out["headers"], rec, text)}


def replay(finding, timeout=10, each=None):
    """Send the stored requests of one finding of an earlier run, in order, each through request() and logged
    with "replay": the finding id (probe.json holds them; a retest's launch writes them). A header whose stored
    value was hidden is not sent: its name goes in the record's note, and a step that needs it is for the
    caller's own test account. each(result) is called after every step. A refused step is logged, then raised,
    and ends the replay. Returns the results."""
    entry = _load_config()["replay"].get(finding) if isinstance(finding, str) and ITEM_ID.fullmatch(finding) else None
    if not entry:
        raise ProbeRefused("no_replay", "probe.json holds no stored request for %s" % str(finding)[:48])
    results, last = [], len(entry["steps"])
    for i, (method, path, pairs, body) in enumerate(entry["steps"], 1):
        send = [(n, v) for n, v in pairs if v.strip() and REDACTED not in v]
        gone = [n[:64] for n, v in pairs if not (v.strip() and REDACTED not in v)]
        note = "replay %s step %d of %d" % (finding, i, last)
        if gone:
            note += "; no stored value for %s, not sent" % ", ".join(gone[:4])
        res = request(method, path, send, body, "attack" if i == last else "", entry["wstg"], "", note, False, timeout, finding)
        res["unsent_headers"] = gone
        results.append(res)
        if each is not None:
            each(res)
    return results


# ---- command line -----------------------------------------------------------
def _write(stream, text):
    buf = getattr(stream, "buffer", None)
    if buf is None:
        stream.write(text)
    else:  # UTF-8 whatever the console code page is
        buf.write(text.encode("utf-8", "replace"))
        buf.flush()


def _label(value):
    if not LABEL.fullmatch(value):
        raise argparse.ArgumentTypeError("use 1-40 characters from A-Z a-z 0-9 _ . -")
    return value


def _show(res):
    """Print one result the way the command line shows it; returns the exit code: 0 a response, 1 none."""
    rec = res["record"]
    head = "probe %s %s %s" % (res["id"], rec["method"], res["path"])
    if res["status"] == 0:
        _write(sys.stderr, "%s -> no response (%s)\n" % (head, rec["error"]))
        return 1
    lines = ["%s -> %d %s (%d ms, %d bytes)" % (head, res["status"], res["reason"], rec["ms"], rec["body_bytes"])]
    lines += ["%s: %s" % h for h in res["headers"]]
    text = "\n".join(lines) + "\n\n" + res["body"]
    if rec["body_truncated"]:
        text += ("" if text.endswith("\n") else "\n") + "[body cut at %d bytes]\n" % rec["body_bytes"]
    _write(sys.stdout, text)
    if res["hidden"]:  # one line, once per name: what the log keeps is not what was printed above
        names = res["hidden"]
        shown = ", ".join(names[:4]) + (" and %d more" % (len(names) - 4) if len(names) > 4 else "")
        _write(sys.stderr, "note: the log keeps [REDACTED] in place of a value in %s above; in indicator.when "
                           "name the field and [REDACTED], never the value.\n" % shown)
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="probe.py", description="Send one request to the assessment target and log it to %s." % LOG_NAME,
        epilog="Exit 0: an HTTP response arrived (any status). 1: no response. 2: usage error. 3: refused, nothing sent. "
               "The log keeps [REDACTED] in place of a credential value: in indicator.when name the field and [REDACTED], never the value.")
    ap.add_argument("method", nargs="?", help="GET HEAD POST PUT PATCH DELETE OPTIONS")
    ap.add_argument("target", nargs="?", help="a path and query starting with /, or a URL on the same origin")
    ap.add_argument("-H", "--header", action="append", default=[], metavar="HEADER", help="'Name: value', repeatable, at most 20")
    ap.add_argument("-d", "--data", metavar="DATA", help="request body, or @file to read it from a file (at most 65536 bytes)")
    ap.add_argument("--role", choices=("control", "attack"), default="", help="what this request is for in a finding")
    ap.add_argument("--wstg", choices=WSTG, default="", help="OWASP WSTG category")
    ap.add_argument("--account", type=_label, help="test account label (at most 10 attempts per path)")
    ap.add_argument("--note", default="", help="short note stored with the request")
    ap.add_argument("--follow", action="store_true", help="follow up to 3 same-origin redirects")
    ap.add_argument("--timeout", type=float, default=10.0, help="seconds, 1 to 30")
    ap.add_argument("--replay", metavar="ID", help="retest only: send the stored requests of finding ID in order, "
                                                   "with no method or target; each is logged as a replay of ID")
    args = ap.parse_args(argv)
    if args.replay:
        if args.method or args.target or args.data is not None or args.header:
            ap.error("--replay sends the stored requests: give it no method, target, header or data")
        code = [0]

        def each(res):
            code[0] = max(code[0], _show(res))
            _write(sys.stdout, "\n")  # the next request starts on a line of its own
            for name in res["unsent_headers"]:
                _write(sys.stderr, "note: the stored value of header %s was hidden, so it was not sent\n" % name)
        try:
            replay(args.replay, args.timeout, each)
        except ProbeRefused as exc:
            _write(sys.stderr, "probe refused (%s): %s\n" % (exc.code, exc.message))
            return 3
        return code[0]
    if not args.method or not args.target:
        ap.error("give a method and a target (or --replay ID)")
    body = args.data
    if body is not None and body.startswith("@"):
        try:
            with open(body[1:], "rb") as f:
                body = f.read(MAX_BODY + 1)
        except OSError as exc:
            ap.error("cannot read %s: %s" % (body[1:], exc))
    try:
        res = request(args.method, args.target, args.header, body, args.role, args.wstg, args.account or "",
                      args.note, args.follow, args.timeout)
    except ProbeRefused as exc:
        _write(sys.stderr, "probe refused (%s): %s\n" % (exc.code, exc.message))
        return 3
    return _show(res)


if __name__ == "__main__":
    sys.exit(main())
