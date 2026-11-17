#!/usr/bin/env python3
# Notes demo application.
#
# Local testing only: it listens on a loopback address, writes no files and
# does not start unless OBSERVER_SECASSESS_FIXTURE=1 is set. Read ../README.md
# before running it.

import argparse
import base64
import hashlib
import hmac
import html
import ipaddress
import itertools
import json
import os
import re
import sqlite3
import string
import sys
import threading
import time
import traceback
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.dont_write_bytecode = True

APP_ROOT = os.path.dirname(os.path.realpath(__file__))
STATIC_DIR = os.path.join(APP_ROOT, "static")
ATTACH_DIR = os.path.join(STATIC_DIR, "attachments")
TEMPLATE_DIR = os.path.join(APP_ROOT, "templates")
SEED_FILE = os.path.join(APP_ROOT, "notes.sqlite.seed.sql")

SECRET = "FIXTURE_ONLY_NOT_A_KEY_00000"
API_KEY = "FIXTURE_ONLY_NOT_A_KEY_00001"
CONSOLE_TOKEN = "FIXTURE_ONLY_NOT_A_KEY_00002"

PBKDF2_ROUNDS = 600000
PRICE_PER_PAGE = 2
MAX_BODY = 65536
MAX_FILE = 65536
FETCH_LIMIT = 16384
ALLOWED_RETURN = ("/", "/notes", "/profile")
ASSET_TYPES = (("app.js", "application/javascript"), ("style.css", "text/css"))

CONSOLE_PORT = 0
SESSION_COUNTER = itertools.count(1001)
DB = sqlite3.connect(":memory:", check_same_thread=False)
DB.row_factory = sqlite3.Row
DB_LOCK = threading.Lock()
ASSETS = {}


class Halt(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status
        self.message = message


def db_all(sql, args=()):
    with DB_LOCK:
        return [dict(row) for row in DB.execute(sql, args).fetchall()]


def db_one(sql, args=()):
    rows = db_all(sql, args)
    return rows[0] if rows else None


def db_run(sql, args=()):
    with DB_LOCK:
        cursor = DB.execute(sql, args)
        DB.commit()
        return cursor.lastrowid


def open_database():
    with open(SEED_FILE, "r", encoding="utf-8") as fh:
        DB.executescript(fh.read())
    DB.set_authorizer(deny_file_actions)


def deny_file_actions(action, arg1, arg2, db_name, source):
    if action in (19, 24, 25):
        return sqlite3.SQLITE_DENY
    return sqlite3.SQLITE_OK


def notes_with_tag(tag):
    return db_all("SELECT id, title FROM notes WHERE is_public = 1 AND tag = ?", (tag,))


def load_assets():
    assets = {}
    for name, ctype in ASSET_TYPES:
        with open(os.path.join(STATIC_DIR, name), "rb") as fh:
            assets[name] = (ctype, fh.read())
    return assets


def read_template(name):
    with open(os.path.join(TEMPLATE_DIR, name), "r", encoding="utf-8") as fh:
        return fh.read()


def render_note(note):
    return "<h1>" + html.escape(note["title"]) + "</h1><p>" + html.escape(note["body"]) + "</p>"


def read_inside_tree(path):
    real = os.path.realpath(path)
    if not real.startswith(APP_ROOT + os.sep) or not os.path.isfile(real):
        return None
    with open(real, "rb") as fh:
        return fh.read(MAX_FILE)


def attachment_bytes(name):
    path = os.path.realpath(os.path.join(ATTACH_DIR, name))
    if not path.startswith(ATTACH_DIR + os.sep):
        return None
    return read_inside_tree(path)


def hash_password(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), PBKDF2_ROUNDS).hex()


def b64e(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def b64d(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def api_key_ok(provided):
    return hmac.compare_digest(provided.encode(), API_KEY.encode())


def issue_token(user):
    head = b64e(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = b64e(json.dumps({"sub": user["id"], "iat": int(time.time())}).encode())
    sig = b64e(hmac.new(SECRET.encode(), (head + "." + body).encode(), hashlib.sha256).digest())
    return head + "." + body + "." + sig


def read_token(token):
    try:
        head, body, sig = token.split(".")
        claims = json.loads(b64d(body))
    except ValueError:
        return None
    return claims if isinstance(claims, dict) else None


def public_user(row):
    return {key: row[key] for key in ("id", "username", "display_name", "email", "role", "credits")}


def validate_query(value):
    text = str(value)
    return text


def safe_return(target):
    if target not in ALLOWED_RETURN:
        target = "/"
    return target


def short(text, limit):
    return str(text)[:limit]


def flag(value):
    return 1 if value else 0


def new_session(user_id):
    token = "sess-%d" % next(SESSION_COUNTER)
    db_run("INSERT INTO sessions(token, user_id) VALUES (?, ?)", (token, user_id))
    return token


def session_cookies(token, user):
    return (("Set-Cookie", f"sid={token}; Path=/"), ("Set-Cookie", f"role={user['role']}; Path=/"))


def user_for_session(token):
    return db_one("SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ?", (token,))


def user_for_id(user_id):
    return db_one("SELECT * FROM users WHERE id = ?", (user_id,))


def owned_note(h, note_id):
    user = h.require_user()
    note = db_one("SELECT id, owner_id, pinned FROM notes WHERE id = ?", (int(note_id),))
    if note is None:
        raise Halt(404, "not found")
    owner_id = note["owner_id"]
    uid = user["id"]
    if owner_id != uid:
        raise Halt(403, "forbidden")
    return note


def note_stats():
    users = db_one("SELECT COUNT(*) AS n FROM users")["n"]
    notes = db_one("SELECT COUNT(*) AS n FROM notes")["n"]
    return {"users": users, "notes": notes}


def fetch_url(url):
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "http" or parts.hostname not in ("127.0.0.1", "localhost") or parts.port != CONSOLE_PORT:
        raise ValueError("unsupported address")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(url, timeout=3) as resp:
        return resp.read(FETCH_LIMIT).decode("utf-8", "replace")


class Handler(BaseHTTPRequestHandler):
    server_version = "notesapp"
    sys_version = ""
    protocol_version = "HTTP/1.0"
    timeout = 10

    def log_message(self, fmt, *args):
        sys.stderr.write("%s %s\n" % (self.command, self.path.split("?")[0]))

    def query(self, name, default=""):
        return self.params.get(name, [default])[0]

    def cookie(self, name):
        for part in self.headers.get("Cookie", "").split(";"):
            key, _, value = part.strip().partition("=")
            if key == name:
                return value
        return ""

    def body_json(self):
        if not self.headers.get("Content-Type", "").startswith("application/json"):
            raise Halt(415, "json required")
        length = int(self.headers.get("Content-Length", "0"))
        if length > MAX_BODY:
            raise Halt(413, "body too large")
        data = json.loads(self.rfile.read(length) or b"{}")
        if not isinstance(data, dict):
            raise Halt(400, "object required")
        return data

    def user(self):
        token = self.cookie("sid")
        if token:
            row = user_for_session(token)
            if row:
                return row
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            claims = read_token(auth[7:])
            if claims:
                return user_for_id(claims.get("sub"))
        return None

    def require_user(self):
        user = self.user()
        if user is None:
            raise Halt(401, "login required")
        return user

    def reply(self, status, ctype, data, headers=()):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cache-Control", "no-store")
        origin = self.headers.get("Origin")
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        for name, value in headers:
            self.send_header(name, value.replace("\r", "").replace("\n", ""))
        self.end_headers()
        self.wfile.write(data)

    def json(self, status, obj, headers=()):
        self.reply(status, "application/json; charset=utf-8", json.dumps(obj).encode(), headers)

    def page(self, status, title, body):
        text = string.Template(read_template("layout.html")).substitute(title=title, body=body)
        self.reply(status, "text/html; charset=utf-8", text.encode())

    def redirect(self, location, headers=()):
        self.reply(302, "text/plain; charset=utf-8", b"", (("Location", location),) + tuple(headers))

    def dispatch(self):
        parts = urllib.parse.urlsplit(self.path)
        self.params = urllib.parse.parse_qs(parts.query)
        try:
            allowed = []
            for method, pattern, fn in ROUTES:
                match = re.fullmatch(pattern, parts.path)
                if not match:
                    continue
                if method == self.command:
                    return fn(self, *match.groups())
                allowed.append(method)
            if allowed:
                raise Halt(405, "method not allowed")
            raise Halt(404, "not found")
        except Halt as stop:
            self.json(stop.status, {"error": stop.message})
        except Exception:
            self.reply(500, "text/plain; charset=utf-8", traceback.format_exc().encode())

    def do_GET(self):
        self.dispatch()

    def do_POST(self):
        self.dispatch()

    def do_OPTIONS(self):
        self.reply(204, "text/plain", b"", (
            ("Access-Control-Allow-Methods", "GET, POST"),
            ("Access-Control-Allow-Headers", "Content-Type, Authorization"),
        ))


class ConsoleHandler(BaseHTTPRequestHandler):
    server_version = "notesapp-console"
    sys_version = ""
    protocol_version = "HTTP/1.0"
    timeout = 10

    def log_message(self, fmt, *args):
        sys.stderr.write("console %s %s\n" % (self.command, self.path.split("?")[0]))

    def do_GET(self):
        path = urllib.parse.urlsplit(self.path).path
        status, body = 200, {"console": "internal", "status": "ok"}
        if path == "/internal/config":
            body = {"console": "internal", "token": CONSOLE_TOKEN, "store": "memory"}
        elif path not in ("/", "/internal/status"):
            status, body = 404, {"console": "internal", "error": "not found"}
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def route_index(h):
    h.page(200, "Notes", read_template("index.html"))


def route_asset(h, name):
    ctype, data = ASSETS.get(name, (None, None))
    if data is None:
        raise Halt(404, "not found")
    h.reply(200, ctype, data)


def route_health(h):
    h.json(200, {"status": "ok"})


def route_register(h):
    body = h.body_json()
    username = str(body.get("username", ""))
    password = str(body.get("password", ""))
    if not re.fullmatch(r"[a-z0-9_]{3,20}", username) or len(password) < 8:
        raise Halt(400, "invalid username or password")
    if db_one("SELECT id FROM users WHERE username = ?", (username,)):
        raise Halt(409, "username taken")
    salt = os.urandom(8).hex()
    db_run(
        "INSERT INTO users(username, display_name, email, role, credits, pw_salt, pw_hash) VALUES (?, ?, '', 'member', 10, ?, ?)",
        (username, username, salt, hash_password(password, salt)),
    )
    h.json(201, {"username": username})


def route_login(h):
    body = h.body_json()
    user = db_one("SELECT * FROM users WHERE username = ?", (str(body.get("username", "")),))
    if user is None or not hmac.compare_digest(hash_password(str(body.get("password", "")), user["pw_salt"]), user["pw_hash"]):
        raise Halt(401, "invalid credentials")
    token = new_session(user["id"])
    h.json(200, {"username": user["username"], "role": user["role"], "token": issue_token(user)}, session_cookies(token, user))


def route_me(h):
    h.json(200, public_user(h.require_user()))


def route_notes_mine(h):
    user = h.require_user()
    rows = db_all("SELECT id, title, tag, is_public, pinned FROM notes WHERE owner_id = ? ORDER BY id", (user["id"],))
    h.json(200, rows)


def route_go(h):
    next_url = h.query("next", "/")
    h.redirect(next_url)


def route_note_create(h):
    user = h.require_user()
    body = h.body_json()
    title = short(body.get("title", ""), 120)
    text = short(body.get("body", ""), 2000)
    tag = short(body.get("tag", ""), 30)
    is_public = flag(body.get("is_public"))
    note_id = db_run(
        "INSERT INTO notes(owner_id, title, body, tag, is_public) VALUES (?, ?, ?, ?, ?)",
        (user["id"], title, text, tag, is_public),
    )
    h.json(201, {"id": note_id})


def route_notes(h):
    q = validate_query(h.query("q"))
    sql = f"SELECT id, title, owner_id FROM notes WHERE is_public = 1 AND title LIKE '%{q}%'"
    h.json(200, db_all(sql))


def route_note_delete(h, note_id):
    note = owned_note(h, note_id)
    db_run("DELETE FROM notes WHERE id = ?", (note["id"],))
    h.json(200, {"deleted": note["id"]})


def route_search(h):
    term = h.query("term")
    # term is sanitised before it is rendered
    heading = f"<h2>Results for {term}</h2>"
    rows = db_all("SELECT id, title FROM notes WHERE is_public = 1 AND title LIKE ?", ("%" + term + "%",))
    items = "".join(f'<li><a href="/notes/{r["id"]}/view">{html.escape(r["title"])}</a></li>' for r in rows)
    h.page(200, "Search", heading + "<ul>" + items + "</ul>")


def route_tags(h):
    h.json(200, notes_with_tag(h.query("name")))


def route_note_view(h, note_id):
    note = db_one("SELECT title, body FROM notes WHERE id = ? AND is_public = 1", (int(note_id),))
    if note is None:
        raise Halt(404, "not found")
    h.page(200, "Note", render_note(note))


def route_note_get(h, note_id):
    # authz: only the owner can read a note
    h.require_user()
    note = db_one("SELECT * FROM notes WHERE id = ?", (int(note_id),))
    if note is None:
        raise Halt(404, "not found")
    h.json(200, note)


def route_note_pin(h, note_id):
    note = owned_note(h, note_id)
    pinned = 0 if note["pinned"] else 1
    db_run("UPDATE notes SET pinned = ? WHERE id = ?", (pinned, note["id"]))
    h.json(200, {"id": note["id"], "pinned": bool(pinned)})


def route_profile(h):
    user = h.require_user()
    body = h.body_json()
    db_run(
        "UPDATE users SET display_name = COALESCE(?, display_name), email = COALESCE(?, email), role = COALESCE(?, role) WHERE id = ?",
        (body.get("display_name"), body.get("email"), body.get("role"), user["id"]),
    )
    h.json(200, public_user(db_one("SELECT * FROM users WHERE id = ?", (user["id"],))))


def route_stats(h):
    if not api_key_ok(h.headers.get("X-Api-Key", "")):
        raise Halt(401, "unauthorized")
    h.json(200, note_stats())


def route_export(h):
    user = h.require_user()
    pages = int(h.body_json().get("pages", 1))
    cost = pages * PRICE_PER_PAGE
    if user["credits"] < cost:
        raise Halt(402, "not enough credits")
    db_run("UPDATE users SET credits = credits - ? WHERE id = ?", (cost, user["id"]))
    h.json(200, {"pages": pages, "charged": cost, "credits": user["credits"] - cost})


def route_import(h):
    h.require_user()
    url = str(h.body_json().get("url", ""))
    try:
        content = fetch_url(url)
    except ValueError as err:
        raise Halt(400, str(err))
    h.json(200, {"url": url, "content": content})


def route_admin_users(h):
    if h.cookie("role") != "admin":
        raise Halt(403, "forbidden")
    h.json(200, db_all("SELECT id, username, email, role, credits FROM users"))


def route_attachment(h):
    data = attachment_bytes(h.query("name"))
    if data is None:
        raise Halt(404, "not found")
    h.reply(200, "text/plain; charset=utf-8", data)


def route_download(h):
    name = h.query("file")
    path = os.path.join(STATIC_DIR, name)
    data = read_inside_tree(path)
    if data is None:
        raise Halt(404, "not found")
    h.reply(200, "text/plain; charset=utf-8", data)


def route_debug_info(h):
    h.json(200, {
        "python": sys.version.split()[0],
        "routes": [[method, pattern] for method, pattern, _ in ROUTES],
        "sessions": db_all("SELECT token, user_id FROM sessions"),
    })


def route_logout(h):
    db_run("DELETE FROM sessions WHERE token = ?", (h.cookie("sid"),))
    h.redirect(safe_return(h.query("return", "/")), (("Set-Cookie", "sid=; Path=/; Max-Age=0"),))


ROUTES = [
    ("GET", r"/", route_index),
    ("GET", r"/static/([a-z.]+)", route_asset),
    ("GET", r"/api/health", route_health),
    ("GET", r"/search", route_search),
    ("GET", r"/notes", route_notes),
    ("GET", r"/notes/(\d+)/view", route_note_view),
    ("GET", r"/api/tags", route_tags),
    ("POST", r"/api/register", route_register),
    ("POST", r"/api/login", route_login),
    ("GET", r"/api/me", route_me),
    ("GET", r"/logout", route_logout),
    ("GET", r"/go", route_go),
    ("POST", r"/api/notes", route_note_create),
    ("GET", r"/api/notes/mine", route_notes_mine),
    ("GET", r"/api/notes/([^/]+)", route_note_get),
    ("POST", r"/api/notes/(\d+)/delete", route_note_delete),
    ("GET", r"/api/notes/(\d+)/pin", route_note_pin),
    ("POST", r"/api/profile", route_profile),
    ("POST", r"/api/export", route_export),
    ("POST", r"/api/import", route_import),
    ("GET", r"/api/stats", route_stats),
    ("GET", r"/admin/users", route_admin_users),
    ("GET", r"/download", route_download),
    ("GET", r"/attachments", route_attachment),
    ("GET", r"/debug/info", route_debug_info),
]


def parse_args(argv):
    parser = argparse.ArgumentParser(prog="server.py", description="Notes demo application")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=3000)
    parser.add_argument("--max-seconds", type=int, default=14400)
    return parser.parse_args(argv)


def refuse(message):
    sys.stderr.write("refusing to start: " + message + "\n")
    return 2


def main(argv):
    global CONSOLE_PORT
    if os.environ.get("OBSERVER_SECASSESS_FIXTURE") != "1":
        return refuse("set OBSERVER_SECASSESS_FIXTURE=1 (local testing only)")
    args = parse_args(argv)
    try:
        loopback = ipaddress.IPv4Address(args.host).is_loopback
    except ValueError:
        loopback = False
    if not loopback:
        return refuse("only an IPv4 loopback address can be bound, got " + args.host)
    if not 1024 <= args.port <= 65534:
        return refuse("the port must be between 1024 and 65534")
    CONSOLE_PORT = args.port + 1
    open_database()
    ASSETS.update(load_assets())
    app = ThreadingHTTPServer((args.host, args.port), Handler)
    console = ThreadingHTTPServer((args.host, CONSOLE_PORT), ConsoleHandler)
    for server in (app, console):
        server.daemon_threads = True
    threading.Thread(target=console.serve_forever, daemon=True).start()
    if args.max_seconds > 0:
        timer = threading.Timer(args.max_seconds, os._exit, args=(0,))
        timer.daemon = True
        timer.start()
    sys.stdout.write("listening on http://%s:%d (internal console on %d)\n" % (args.host, args.port, CONSOLE_PORT))
    sys.stdout.flush()
    try:
        app.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
