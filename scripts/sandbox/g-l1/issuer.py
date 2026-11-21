#!/usr/bin/env python3
"""Throwaway OIDC issuer for live check G-L1 (and G-L2's tokens).

Lane G5, docs/plans/openshell/build/g1-design.md sections 5.2 and 11.6. It
stands in for the org server's issuer (`<external_url>/sandbox-idp`) on the
test VM, with no Observer server code: it mints EdDSA, ES256 and RS256 test
tokens from throwaway keys and serves a static discovery document and JWKS
on 127.0.0.1 only. Run it with `python3 -I`. It needs only the standard
library and the `openssl` command line tool (3.0 or later), so nothing is
installed on the VM.

  issuer.py keys DIR
      make the throwaway keys (kids ed-1, ed-2, es-1, rs-1) in DIR (0700)
  issuer.py serve DIR --state FILE --portfile FILE --log FILE [--port N]
      serve http://127.0.0.1:PORT/sandbox-idp; the state file (JSON, read on
      every request) picks the discovery shape and the JWKS answer:
        {"discovery": "g2" | "minimal" | "extended",
         "jwks": "normal" | "next" | "drop" | "empty" | "404"
                 | "only-ed" | "only-es" | "only-rs"}
      g2 mirrors the org server's own document (lane G2's
      openshellidp.Issuer.Discovery: issuer, jwks_uri, the algorithms of
      the published keys, subject and response types, claims; no
      endpoints); minimal = issuer and jwks_uri only; extended = minimal
      plus authorization and token endpoints.
      normal = ed-1, es-1, rs-1; next = normal plus ed-2 (a rotation);
      drop = ed-2, es-1, rs-1 (ed-1 removed); empty = no keys; only-* = one
      key type alone (ed-1, es-1 or rs-1); 404 = the discovery document and
      the JWKS both answer 404 (a disabled issuer).
      Each request is logged as one line: UTC time, path, status. No token
      or key is ever logged.
  issuer.py mint DIR --kid KID --issuer URL --sub SUB --aud AUD --out FILE
      [--roles JSON] [--roles-path PATH] [--scope S] [--ttl SECONDS]
      [--exp-offset SECONDS]
      write one signed token to FILE (0600); the algorithm follows the kid
      (ed EdDSA, es ES256, rs RS256); --roles-path is the dot path the
      roles array sits at (default "roles"); --exp-offset moves exp (with
      a negative value the token is already expired)
  issuer.py tamper IN OUT
      copy the token file IN to OUT (0600) with one signature byte flipped
      (a forged token the gateway must refuse)
  issuer.py selftest DIR
      mint and verify one token per algorithm with openssl; exit 0 when all
      three verify

Every key is throwaway: the calling script removes DIR when it exits.
"""

import base64
import hashlib
import http.server
import json
import os
import re
import secrets
import socketserver
import subprocess
import sys
import tempfile
import threading
import time

KIDS = ("ed-1", "ed-2", "es-1", "rs-1")
JWKS_SETS = {
    "normal": ("ed-1", "es-1", "rs-1"),
    "next": ("ed-1", "ed-2", "es-1", "rs-1"),
    "drop": ("ed-2", "es-1", "rs-1"),
    "empty": (),
    "only-ed": ("ed-1",),
    "only-es": ("es-1",),
    "only-rs": ("rs-1",),
}
JWKS_STATES = tuple(JWKS_SETS) + ("404",)
# The claims the org server's discovery lists (lane G2, openshellidp).
G2_CLAIMS = ["iss", "aud", "sub", "roles", "scope", "exp", "iat", "nbf", "jti"]
ISSUER_PATH = "/sandbox-idp"
KID_RE = re.compile(r"^(ed|es|rs)-[0-9]$")


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def openssl(*args, data=None):
    """Run openssl with a fixed argv; return stdout bytes or raise."""
    proc = subprocess.run(["openssl", *args], input=data, capture_output=True, check=False)
    if proc.returncode != 0:
        raise RuntimeError("openssl %s failed: %s" % (args[0], proc.stderr.decode("utf-8", "replace")[:300]))
    return proc.stdout


def alg_for(kid):
    return {"ed": "EdDSA", "es": "ES256", "rs": "RS256"}[kid[:2]]


def key_path(d, kid):
    if not KID_RE.match(kid):
        raise ValueError("bad kid %r" % kid)
    return os.path.join(d, kid + ".pem")


def make_keys(d):
    os.makedirs(d, mode=0o700, exist_ok=True)
    os.chmod(d, 0o700)
    old = os.umask(0o077)
    try:
        for kid in KIDS:
            out = key_path(d, kid)
            if kid.startswith("ed"):
                openssl("genpkey", "-algorithm", "ED25519", "-out", out)
            elif kid.startswith("es"):
                openssl("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", out)
            else:
                openssl("genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", out)
            with open(os.path.join(d, kid + ".jwk.json"), "w", encoding="utf-8") as f:
                json.dump(public_jwk(d, kid), f)
    finally:
        os.umask(old)


def public_jwk(d, kid):
    pem = key_path(d, kid)
    der = openssl("pkey", "-in", pem, "-pubout", "-outform", "DER")
    jwk = {"kid": kid, "use": "sig", "alg": alg_for(kid)}
    if kid.startswith("ed"):
        jwk.update(kty="OKP", crv="Ed25519", x=b64url(der[-32:]))
    elif kid.startswith("es"):
        point = der[-65:]
        if point[0] != 4:
            raise RuntimeError("unexpected EC point encoding")
        jwk.update(kty="EC", crv="P-256", x=b64url(point[1:33]), y=b64url(point[33:65]))
    else:
        text = openssl("rsa", "-in", pem, "-noout", "-modulus").decode("ascii").strip()
        modulus = bytes.fromhex(text.split("=", 1)[1])
        info = openssl("rsa", "-in", pem, "-noout", "-text").decode("ascii")
        m = re.search(r"publicExponent: (\d+)", info)
        if not m:
            raise RuntimeError("no RSA public exponent")
        e = int(m.group(1))
        jwk.update(kty="RSA", n=b64url(modulus), e=b64url(e.to_bytes((e.bit_length() + 7) // 8, "big")))
    return jwk


def der_to_raw_ecdsa(sig, size=32):
    """Convert an ASN.1 DER ECDSA signature to the JWS raw r||s form."""
    if sig[0] != 0x30:
        raise RuntimeError("not a DER sequence")
    i = 2 if sig[1] < 0x80 else 2 + (sig[1] & 0x7F)
    out = b""
    for _ in range(2):
        if sig[i] != 0x02:
            raise RuntimeError("not a DER integer")
        n = sig[i + 1]
        v = sig[i + 2 : i + 2 + n].lstrip(b"\x00")
        if len(v) > size:
            raise RuntimeError("integer too long")
        out += v.rjust(size, b"\x00")
        i += 2 + n
    return out


def raw_to_der_ecdsa(raw):
    def integer(v):
        v = v.lstrip(b"\x00") or b"\x00"
        if v[0] & 0x80:
            v = b"\x00" + v
        return b"\x02" + bytes([len(v)]) + v

    body = integer(raw[:32]) + integer(raw[32:])
    return b"\x30" + bytes([len(body)]) + body


def sign(d, kid, message):
    pem = key_path(d, kid)
    with tempfile.TemporaryDirectory(dir=d) as tmp:
        msg = os.path.join(tmp, "m")
        with open(msg, "wb") as f:
            f.write(message)
        if kid.startswith("ed"):
            return openssl("pkeyutl", "-sign", "-inkey", pem, "-rawin", "-in", msg)
        sig = openssl("dgst", "-sha256", "-sign", pem, msg)
        return der_to_raw_ecdsa(sig) if kid.startswith("es") else sig


def verify(d, kid, token):
    head, body, sig = token.split(".")
    message = (head + "." + body).encode("ascii")
    raw = base64.urlsafe_b64decode(sig + "=" * (-len(sig) % 4))
    pem = key_path(d, kid)
    with tempfile.TemporaryDirectory(dir=d) as tmp:
        pub = os.path.join(tmp, "pub.pem")
        msg = os.path.join(tmp, "m")
        sgf = os.path.join(tmp, "s")
        with open(pub, "wb") as f:
            f.write(openssl("pkey", "-in", pem, "-pubout"))
        with open(msg, "wb") as f:
            f.write(message)
        with open(sgf, "wb") as f:
            f.write(raw_to_der_ecdsa(raw) if kid.startswith("es") else raw)
        if kid.startswith("ed"):
            args = ["pkeyutl", "-verify", "-pubin", "-inkey", pub, "-rawin", "-in", msg, "-sigfile", sgf]
        else:
            args = ["dgst", "-sha256", "-verify", pub, "-signature", sgf, msg]
        proc = subprocess.run(["openssl", *args], capture_output=True, check=False)
        return proc.returncode == 0


def set_path(claims, path, value):
    parts = path.split(".")
    cur = claims
    for p in parts[:-1]:
        cur = cur.setdefault(p, {})
    cur[parts[-1]] = value


def mint(d, kid, issuer, sub, aud, roles, roles_path, scope, ttl, exp_offset):
    now = int(time.time())
    header = {"alg": alg_for(kid), "typ": "JWT", "kid": kid}
    claims = {"iss": issuer, "sub": sub, "aud": aud, "iat": now, "exp": now + ttl + exp_offset,
              "jti": secrets.token_hex(8)}
    if roles is not None:
        set_path(claims, roles_path, roles)
    if scope is not None:
        claims["scope"] = scope
    signing_input = b64url(json.dumps(header, separators=(",", ":")).encode()) + "." + \
        b64url(json.dumps(claims, separators=(",", ":")).encode())
    return signing_input + "." + b64url(sign(d, kid, signing_input.encode("ascii")))


def read_state(path):
    try:
        with open(path, encoding="utf-8") as f:
            s = json.load(f)
    except (OSError, ValueError):
        s = {}
    disc = s.get("discovery", "g2")
    jwks = s.get("jwks", "normal")
    if disc not in ("g2", "minimal", "extended"):
        disc = "g2"
    if jwks not in JWKS_STATES:
        jwks = "404"
    return disc, jwks


def serve(d, state, portfile, log, port):
    jwks_cache = {kid: public_jwk(d, kid) for kid in KIDS}
    log_lock = threading.Lock()

    class Handler(http.server.BaseHTTPRequestHandler):
        server_version = "g-l1-issuer"
        sys_version = ""

        def log_message(self, *args):
            return

        def answer(self, code, body):
            data = json.dumps(body).encode() if body is not None else b""
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)
            with log_lock, open(log, "a", encoding="utf-8") as f:
                f.write("%s %s %d\n" % (time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), self.path, code))

        def do_GET(self):
            disc, jwks = read_state(state)
            host = "http://127.0.0.1:%d" % self.server.server_address[1]
            issuer = host + ISSUER_PATH
            if self.path == ISSUER_PATH + "/.well-known/openid-configuration":
                if jwks == "404":
                    return self.answer(404, {"error": "not_found"})
                doc = {"issuer": issuer, "jwks_uri": issuer + "/jwks.json"}
                if disc == "g2":
                    algs = []
                    for kid in JWKS_SETS.get(jwks, ()):
                        if alg_for(kid) not in algs:
                            algs.append(alg_for(kid))
                    doc.update(id_token_signing_alg_values_supported=algs,
                               subject_types_supported=["public"],
                               response_types_supported=["id_token"],
                               claims_supported=G2_CLAIMS)
                if disc == "extended":
                    doc.update(authorization_endpoint=host + "/sandbox/openshell/approve",
                               token_endpoint=issuer + "/token",
                               response_types_supported=["code"],
                               subject_types_supported=["public"],
                               id_token_signing_alg_values_supported=["EdDSA", "ES256", "RS256"])
                return self.answer(200, doc)
            if self.path == ISSUER_PATH + "/jwks.json":
                if jwks == "404":
                    return self.answer(404, {"error": "not_found"})
                return self.answer(200, {"keys": [jwks_cache[k] for k in JWKS_SETS[jwks]]})
            return self.answer(404, {"error": "not_found"})

        def do_POST(self):
            if self.path == ISSUER_PATH + "/token":
                return self.answer(400, {"error": "unsupported_grant_type"})
            return self.answer(404, {"error": "not_found"})

    class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
        daemon_threads = True
        allow_reuse_address = True

    srv = Server(("127.0.0.1", port), Handler)
    with open(portfile, "w", encoding="utf-8") as f:
        f.write(str(srv.server_address[1]))
    srv.serve_forever()


def selftest(d):
    ok = True
    for kid in ("ed-1", "es-1", "rs-1"):
        tok = mint(d, kid, "http://127.0.0.1:1" + ISSUER_PATH, "member:selftest", "openshell:selftest",
                   ["openshell-user"], "roles", "sandbox:read", 60, 0)
        good = verify(d, kid, tok)
        print("%s %s %s" % (kid, alg_for(kid), "verified" if good else "NOT VERIFIED"))
        ok = ok and good
    return 0 if ok else 1


def main(argv):
    if len(argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    verb, d = argv[0], argv[1]
    if verb == "tamper":
        if len(argv) != 3:
            print("usage: issuer.py tamper IN OUT", file=sys.stderr)
            return 2
        with open(d, encoding="ascii") as f:
            head, body, sig = f.read().strip().split(".")
        raw = bytearray(base64.urlsafe_b64decode(sig + "=" * (-len(sig) % 4)))
        raw[len(raw) // 2] ^= 0x01
        fd = os.open(argv[2], os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="ascii") as f:
            f.write("%s.%s.%s\n" % (head, body, b64url(bytes(raw))))
        return 0
    opts = {}
    rest = argv[2:]
    while rest:
        if not rest[0].startswith("--") or len(rest) < 2:
            print("bad argument %r" % rest[0], file=sys.stderr)
            return 2
        opts[rest[0][2:]] = rest[1]
        rest = rest[2:]
    if verb == "keys":
        make_keys(d)
        return 0
    if verb == "serve":
        serve(d, opts["state"], opts["portfile"], opts["log"], int(opts.get("port", "0")))
        return 0
    if verb == "mint":
        roles = json.loads(opts["roles"]) if "roles" in opts else None
        tok = mint(d, opts["kid"], opts["issuer"], opts["sub"], opts["aud"], roles,
                   opts.get("roles-path", "roles"), opts.get("scope"), int(opts.get("ttl", "3600")),
                   int(opts.get("exp-offset", "0")))
        fd = os.open(opts["out"], os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="ascii") as f:
            f.write(tok + "\n")
        # The digest only, so a log line can tell two tokens apart.
        print(hashlib.sha256(tok.encode()).hexdigest()[:12])
        return 0
    if verb == "selftest":
        return selftest(d)

    print("unknown verb %r" % verb, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
