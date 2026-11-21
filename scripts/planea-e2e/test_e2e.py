#!/usr/bin/env python3
"""Unit tests for the AI Apps e2e runner's pure parts (no daemon, no network).

  python3 -m unittest scripts/planea-e2e/test_e2e.py
"""

from __future__ import annotations

import dataclasses
import json
import os
import sys
import tempfile
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import e2e  # noqa: E402


class Redact(unittest.TestCase):
    def setUp(self):
        e2e._SECRETS.clear()

    def test_registered_secret_never_survives(self):
        e2e.add_secret("sk-test-THIS-IS-A-FAKE-KEY-0123456789")
        out = e2e.redact("key=sk-test-THIS-IS-A-FAKE-KEY-0123456789 done")
        self.assertNotIn("FAKE-KEY", out)
        self.assertIn("<redacted>", out)

    def test_patterns(self):
        for s in ("sk-proj-" + "a" * 30, "sk-ant-api03-" + "b" * 30, "sbo-vk-" + "c" * 20,
                  "2c9d7583b4e1fb118c9b3a3eaaf34de4." + "d" * 43):
            self.assertNotIn(s, e2e.redact(f"x {s} y"), s)
        self.assertEqual(e2e.redact("Authorization: Bearer abc123"), "Authorization: <redacted>")
        # P-29: a password in a DSN, registered or not.
        self.assertEqual(e2e.redact("dial postgres://admin:hunter2pass@db.example:5432/postgres?sslmode=require"),
                         "dial postgres://admin:<redacted>@db.example:5432/postgres?sslmode=require")
        self.assertEqual(e2e.redact("postgres://e2e@127.0.0.1:5/postgres"), "postgres://e2e@127.0.0.1:5/postgres")
        url = "GET http://127.0.0.1:53173/auth?email=e2e-admin@example.com"
        self.assertEqual(e2e.redact(url), url)  # a port is not a password
        self.assertNotIn("abcdef", e2e.redact("Open http://h/first-run#token=abcdef to create one"))
        self.assertEqual(e2e.redact("x-api-key=abc123 tail"), "x-api-key: <redacted> tail")

    def test_trace_ids_are_kept(self):
        tid = "47f37be0ac59cd944b22ed987dc02627"
        self.assertEqual(e2e.redact(f"PASS machine has trace {tid}"), f"PASS machine has trace {tid}")


class Catalog(unittest.TestCase):
    def test_every_row_has_its_directory_and_verify_args(self):
        for ex in e2e.CATALOG:
            self.assertIn(ex.lang, e2e.LANGS, ex.path)
            lang = e2e.LANGS[ex.lang]
            self.assertTrue(ex.dir.is_dir(), ex.path)
            self.assertTrue((ex.dir / "verify.sh").exists(), ex.path)
            self.assertTrue((ex.dir / lang.entry).exists(), ex.path)
            for f in lang.files:
                self.assertTrue((ex.dir / f).exists(), f"{ex.path}: {f}")
            self.assertIn(ex.provider, e2e.PROVIDERS)
            if ex.lang == "python":
                self.assertIn(ex.framework, e2e.PY_EXTRAS)
            elif ex.lang in ("go", "java"):
                # The Go and Java SDKs have no instrument(): only sdk-direct.
                self.assertEqual((ex.special, ex.targets, ex.ts_modules), ("sdk-direct", (), ()), ex.path)
            else:
                # ESM apps hand instrument() the module(s); the key is the
                # module slot (LangGraph's is "langchain"), as each chatbot.ts does.
                self.assertTrue(ex.ts_modules, ex.path)
                src = (ex.dir / "chatbot.ts").read_text()
                for k, _ in ex.ts_modules:
                    self.assertIn(k, src, ex.path)
            if ex.special != "crewai":
                self.assertTrue(e2e.verify_args_from_sh(ex) is not None, ex.path)

    def test_every_example_directory_is_in_the_catalog(self):
        on_disk = {str(p.parent.relative_to(e2e.EXAMPLES)) for p in e2e.EXAMPLES.glob("*/*/verify.sh")}
        catalogued = {ex.path for ex in e2e.CATALOG}
        self.assertEqual(on_disk, catalogued)

    def test_langs_table(self):
        # Every row is complete; the runner never branches on a language name
        # outside the table (P-31).
        for name, lang in e2e.LANGS.items():
            self.assertTrue(lang.entry and lang.tools, name)
            for fn in (lang.install, lang.script, lang.canary):
                self.assertTrue(callable(fn), name)
        src = (Path(e2e.__file__)).read_text()
        self.assertNotIn('ex.lang == "python"', src)
        self.assertNotIn("ex.lang == 'python'", src)
        self.assertEqual(e2e.LANGS["python"].script(None, "/v/bin/python", "experiment.py"),
                         ["/v/bin/python", "experiment.py"])
        self.assertEqual(e2e.LANGS["typescript"].script(None, "/d", "chatbot.ts"), ["node", "chatbot.ts"])
        self.assertEqual(e2e.LANGS["go"].script(None, "/c/go/x", "experiment/main.go"), ["/c/go/x/experiment"])
        self.assertEqual(e2e.LANGS["java"].script(None, "/a:/b.jar", "src/main/java/example/Experiment.java"),
                         ["java", "-cp", "/a:/b.jar", "example.Experiment"])
        # Every sdk-direct language names its experiment, and the file exists.
        for ex in e2e.CATALOG:
            if ex.special == "sdk-direct":
                exp = e2e.LANGS[ex.lang].experiment
                self.assertTrue(exp and (ex.dir / exp).exists(), ex.path)

    def test_go_and_java_canaries(self):
        spec = {"service": "svc", "model": "gpt-5-nano", "provider": "openai", "out": "/w/run.json",
                "targets": [], "admit_probe": e2e.ADMIT_PROBE}
        go = next(e for e in e2e.CATALOG if e.path == "sdk-direct/go")
        cmd, cwd = e2e.LANGS["go"].canary(go, "/c/go/x", Path("/w"), spec)
        self.assertEqual(cmd[0], "/c/go/x/planea-e2e-canary")
        self.assertEqual(cmd[cmd.index("-admit-probe") + 1], e2e.ADMIT_PROBE)
        self.assertEqual(cwd, Path("/w"))
        java = next(e for e in e2e.CATALOG if e.path == "sdk-direct/java")
        cmd, _ = e2e.LANGS["java"].canary(java, "/a:/b.jar", Path("/w"), spec)
        self.assertEqual(cmd[:4], ["java", "-cp", "/a:/b.jar", str(e2e.HERE / "Canary.java")])
        self.assertEqual(json.loads(cmd[4]), {"service": "svc", "model": "gpt-5-nano", "provider": "openai",
                                              "out": "/w/run.json", "admit_probe": e2e.ADMIT_PROBE})
        # The Go canary stays out of the root module (it imports sdk/go, a
        # separate module): the build tag must be its first line.
        self.assertTrue((e2e.HERE / "canary.go").read_text().startswith("//go:build ignore\n"))
        # Maven writes target/ in sdk/java and the example: a symlink there is refused.
        self.assertIn(java.dir / "target", e2e.LANGS["java"].install_dirs(java))
        self.assertIn(e2e.REPO / "sdk" / "java" / "target", e2e.LANGS["java"].install_dirs(java))

    def test_go_and_java_versions(self):
        for out, ok in (("go1.20.14\n", False), ("go1.21.0\n", True), ("go1.27.3\n", True)):
            with mock.patch.object(e2e, "run", return_value=(0, out)):
                self.assertEqual(e2e.go_version_error() == "", ok, out)
        cases = (('openjdk version "11.0.2" 2019-01-15', False), ('java version "1.8.0_202"', False),
                 ('openjdk version "17.0.9" 2023-10-17', True), ('Picked up X\nopenjdk version "21.0.13.0.3"', True))
        for out, ok in cases:
            with mock.patch.object(e2e, "run", return_value=(0, out)), \
                    mock.patch.object(e2e.shutil, "which", return_value="/usr/bin/javac"):
                self.assertEqual(e2e.java_version_error() == "", ok, out)
        with mock.patch.object(e2e, "run", return_value=(0, 'openjdk version "21"')), \
                mock.patch.object(e2e.shutil, "which", return_value=None):
            self.assertIn("no javac", e2e.java_version_error())

    def test_go_and_java_build_env_is_allowed(self):
        env = e2e.base_env({"PATH": "/bin", "GOMODCACHE": "/m", "JAVA_TOOL_OPTIONS": "-Dx=1", "GOFLAGS": "-tags=x",
                            "MAVEN_ARGS": "-Dfoo"})
        self.assertEqual(env["GOMODCACHE"], "/m")
        self.assertEqual(env["JAVA_TOOL_OPTIONS"], "-Dx=1")
        self.assertNotIn("GOFLAGS", env)
        self.assertNotIn("MAVEN_ARGS", env)

    def test_required_tools_follow_the_selected_langs(self):
        self.assertEqual(e2e.required_tools(["python"], prebuilt_bin=False), ["go", "python3"])
        self.assertEqual(e2e.required_tools(["python"], prebuilt_bin=True), ["python3"])
        self.assertEqual(e2e.required_tools(["typescript"], prebuilt_bin=True), ["node", "npm"])
        self.assertEqual(e2e.required_tools(["go", "java"], prebuilt_bin=False), ["go", "java", "mvn"])
        self.assertEqual(e2e.required_tools(["java"], prebuilt_bin=True), ["java", "mvn"])
        with self.assertRaises(SystemExit):
            e2e.select("all", ["openai"], ["cobol"])

    def test_print_tools(self):
        import contextlib
        import io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = e2e.main(["--print-tools", "--langs", "python", "--bin", "/nowhere"])
        self.assertEqual(rc, 0)
        self.assertEqual(buf.getvalue().split(), ["python3"])

    def test_crewai_honours_the_destination(self):
        # Q4: the example no longer pins destination local, so it runs online.
        ex = next(e for e in e2e.CATALOG if e.path == "crewai/python")
        self.assertFalse(ex.machine_only)
        src = (ex.dir / "chatbot.py").read_text()
        self.assertNotIn('destination="local"', src)

    def test_typescript_examples_need_node_22_18(self):
        # P-35: `node chatbot.ts` strips types by default only from 22.18.
        self.assertEqual(e2e.MIN_NODE, (22, 18))
        for ex in e2e.CATALOG:
            if ex.lang != "typescript":
                continue
            pkg = json.loads((ex.dir / "package.json").read_text())
            self.assertEqual(pkg["engines"]["node"], ">=22.18", ex.path)

    def test_verify_args_follow_verify_sh(self):
        ex = next(e for e in e2e.CATALOG if e.path == "anthropic/python")
        args = e2e.verify_args_from_sh(ex)
        self.assertIn("--price", args)
        self.assertNotIn("$@", args)
        ex = next(e for e in e2e.CATALOG if e.path == "llama-index/python")
        self.assertIn("--ignore-span", e2e.verify_args_from_sh(ex))

    def test_select(self):
        got = e2e.select("openai,langgraph", ["openai"], ["python"])
        self.assertEqual([e.path for e in got], ["openai/python", "langgraph/python"])
        self.assertEqual(len(e2e.select("all", ["openai", "anthropic"], list(e2e.LANGS))), len(e2e.CATALOG))
        got = e2e.select("all", ["openai", "anthropic"], ["go", "java"])
        self.assertEqual([e.path for e in got], ["sdk-direct/go", "sdk-direct/java"])
        with self.assertRaises(SystemExit):
            e2e.select("nope", ["openai"], ["python"])


class Math(unittest.TestCase):
    def test_est_cost_anthropic_cache_write(self):
        # 27 net + 8,298 cache write, 56 out at Haiku 5.5: the 2026-11-20 figure 0.00106795.
        calls = [{"input": 27 + 8298, "output": 56, "cached": 0, "cache_write": 8298}]
        self.assertAlmostEqual(e2e.est_cost(calls, e2e.PROVIDERS["anthropic"]["rates"]), 0.00106795, places=10)

    def test_est_cost_skips_usage_less_calls(self):
        self.assertEqual(e2e.est_cost([{"kind": "chat", "id": "x"}], (1, 1, 1, 1)), 0.0)

    def test_strip_flag(self):
        self.assertEqual(e2e.strip_flag(["--a", "1", "--b", "2"], "--a"), ["--b", "2"])

    def test_parse_checks(self):
        out = "PASS one\nFAIL two\nok   three\nnoise\n"
        got = e2e.parse_checks(out, "machine")
        self.assertEqual([(c["ok"], c["what"]) for c in got], [(True, "one"), (False, "two"), (True, "three")])


class Report(unittest.TestCase):
    def test_nothing_ran_is_not_a_pass(self):
        r = e2e.Result("openai/python", "openai", "openai", "python", "local", "live",
                       reason="OPENAI_API_KEY is not set")
        meta = {"mode": "live", "started": "t", "git": {"sha": "0" * 40, "branch": "b", "dirty": False},
                "destinations": ["local"], "providers": {}, "machine": {"dashboard": "d", "otlp": "o"},
                "org": None, "duration_s": 1}
        with tempfile.TemporaryDirectory() as d:
            e2e.write_report(Path(d), meta, [r])
            md = (Path(d) / "report.md").read_text()
            doc = json.loads((Path(d) / "report.json").read_text())
        self.assertIn("NOTHING RAN", md)
        self.assertIn("OPENAI_API_KEY is not set", md)
        self.assertEqual(doc["totals"]["skip"], 1)


DUMMY_KEY = "sk-proj-DUMMY-NOT-A-REAL-KEY-0123456789abcdef"


class _NoNetwork:
    """Fails the test on any outbound connection attempt."""

    def __init__(self, test):
        self.test = test
        self.calls = []

    def __enter__(self):
        import socket
        self._patches = [
            mock.patch.object(socket.socket, "connect", side_effect=self._boom),
            mock.patch.object(socket, "create_connection", side_effect=self._boom),
            mock.patch("urllib.request.urlopen", side_effect=self._boom),
            mock.patch("urllib.request.OpenerDirector.open", side_effect=self._boom),
        ]
        for p in self._patches:
            p.start()
        return self

    def _boom(self, *a, **kw):
        self.calls.append(a)
        raise AssertionError("an outbound connection was attempted")

    def __exit__(self, *exc):
        for p in self._patches:
            p.stop()
        return False


class Probe(unittest.TestCase):
    def setUp(self):
        e2e._SECRETS.clear()

    def test_dry_run_opens_no_connection_even_with_a_key(self):
        # P-25: the dry run never contacts a provider, key or no key.
        with mock.patch.dict(os.environ, {"OPENAI_API_KEY": DUMMY_KEY, "ANTHROPIC_API_KEY": DUMMY_KEY + "x"}):
            opener = mock.Mock()
            with _NoNetwork(self) as net:
                for name in e2e.PROVIDERS:
                    st = e2e.probe_provider(name, dry_run=True, opener=opener)
                    self.assertTrue(st["key_set"])
                    self.assertIsNone(st["reachable"])
                    self.assertFalse(st["usable"])
                    self.assertEqual(st["reason"], "not used (dry run)")
                    st = e2e.probe_provider(name, dry_run=True)  # the default opener path too
                    self.assertIsNone(st["reachable"])
            self.assertEqual(net.calls, [])
            opener.open.assert_not_called()
            # The key is still registered for redaction.
            self.assertNotIn("DUMMY-NOT-A-REAL", e2e.redact(f"x {DUMMY_KEY} y"))

    def _http_error(self, code, body):
        import io
        return urllib.error.HTTPError("https://x/v1/models", code, "x", {}, io.BytesIO(body.encode()))

    def test_proxy_403_is_blocked_not_refused(self):
        # P-33: a proxy's 403 page is "blocked by this environment".
        opener = mock.Mock()
        opener.open.side_effect = self._http_error(403, "<html>Forbidden by agent proxy</html>")
        with mock.patch.dict(os.environ, {"OPENAI_API_KEY": DUMMY_KEY}):
            st = e2e.probe_provider("openai", dry_run=False, opener=opener)
        self.assertFalse(st["reachable"])
        self.assertFalse(st["usable"])
        self.assertIn("blocked by this environment", st["reason"])
        self.assertNotIn("refused the key", st["reason"])

    def test_provider_403_is_a_refused_key(self):
        opener = mock.Mock()
        opener.open.side_effect = self._http_error(403, '{"error": {"message": "no access", "type": "x"}}')
        with mock.patch.dict(os.environ, {"OPENAI_API_KEY": DUMMY_KEY}):
            st = e2e.probe_provider("openai", dry_run=False, opener=opener)
        self.assertTrue(st["reachable"])
        self.assertIn("refused the key (HTTP 403)", st["reason"])

    def test_probe_opener_does_not_follow_redirects(self):
        # P-37: a redirect would carry the key's header elsewhere.
        import http.server
        import threading
        seen = []

        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                seen.append((self.path, self.headers.get("Authorization")))
                if self.path == "/v1/models":
                    self.send_response(302)
                    self.send_header("Location", "/elsewhere")
                    self.end_headers()
                else:
                    self.send_response(200)
                    self.end_headers()

            def log_message(self, *a):
                pass

        srv = http.server.HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            url = f"http://127.0.0.1:{srv.server_port}/v1/models"
            prov = dict(e2e.PROVIDERS["openai"], probe=url)
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), e2e._NoRedirect())
            with mock.patch.dict(e2e.PROVIDERS, {"openai": prov}), \
                    mock.patch.dict(os.environ, {"OPENAI_API_KEY": DUMMY_KEY}):
                st = e2e.probe_provider("openai", dry_run=False, opener=opener)
        finally:
            srv.shutdown()
        self.assertEqual([p for p, _ in seen], ["/v1/models"])
        self.assertFalse(st["usable"])
        self.assertIn("redirect", st["reason"])
        # The real opener carries the same handler.
        self.assertTrue(any(isinstance(h, e2e._NoRedirect) for h in e2e.probe_opener().handlers))


class ChildEnv(unittest.TestCase):
    def test_allow_list(self):
        # P-27: the child environment is an allow-list.
        parent = {"PATH": "/bin", "HTTPS_PROXY": "http://p:1", "LC_ALL": "C.UTF-8", "SSL_CERT_FILE": "/ca",
                  "UV_CACHE_DIR": "/c", "CHATBOT_MODEL": "gpt-4o", "OPENAI_BASE_URL": "http://evil",
                  "OPENAI_API_KEY": DUMMY_KEY, "SUPERBASED_DESTINATION": "online", "OBSERVER_DB": "/x",
                  "LITELLM_MODEL": "gpt-4o", "PGPASSWORD": "pw", "AWS_SECRET_ACCESS_KEY": "s"}
        env = e2e.base_env(parent)
        for k in ("PATH", "HTTPS_PROXY", "LC_ALL", "SSL_CERT_FILE", "UV_CACHE_DIR"):
            self.assertEqual(env[k], parent[k], k)
        for k in ("CHATBOT_MODEL", "OPENAI_BASE_URL", "OPENAI_API_KEY", "SUPERBASED_DESTINATION", "OBSERVER_DB",
                  "LITELLM_MODEL", "PGPASSWORD", "AWS_SECRET_ACCESS_KEY"):
            self.assertNotIn(k, env, k)
        self.assertIn("127.0.0.1", env["NO_PROXY"])

    def test_case_env_sets_the_model_explicitly(self):
        with tempfile.TemporaryDirectory() as d, \
                mock.patch.dict(os.environ, {"CHATBOT_MODEL": "gpt-4o", "OPENAI_API_KEY": DUMMY_KEY}):
            m = e2e.Machine(Path("/nonexistent/observer"), Path(d))
            for ex in e2e.CATALOG:
                env, _ = e2e.case_env(ex, "local", m, None, Path(d) / "run.json", "1", with_key=False)
                self.assertEqual(env["CHATBOT_MODEL"], e2e.PROVIDERS[ex.provider]["model"], ex.path)
                self.assertNotIn(e2e.PROVIDERS[ex.provider]["key_env"], env, ex.path)
            env, _ = e2e.case_env(e2e.CATALOG[0], "local", m, None, Path(d) / "run.json", "1", with_key=True)
            self.assertEqual(env["OPENAI_API_KEY"], DUMMY_KEY)


class PostgresDSN(unittest.TestCase):
    def setUp(self):
        e2e._SECRETS.clear()

    def test_split(self):
        argv, pw = e2e.split_dsn_password("postgres://admin:s%40cret-pass@db.example:6432/postgres?sslmode=require")
        self.assertEqual(argv, "postgres://admin@db.example:6432/postgres?sslmode=require")
        self.assertEqual(pw, "s@cret-pass")
        self.assertEqual(e2e.split_dsn_password("postgres://e2e@127.0.0.1:5/postgres"),
                         ("postgres://e2e@127.0.0.1:5/postgres", ""))
        self.assertNotIn("s@cret-pass", e2e.redact("x s@cret-pass y"))

    def test_password_never_reaches_argv_or_a_log(self):
        # P-29: psql gets the password through PGPASSWORD; the command log
        # (written by run()) never sees it.
        pw = "Tr0ub4dor-and-3"
        dsn = f"postgres://admin:{pw}@127.0.0.1:1/postgres?sslmode=disable"
        calls = []

        def fake_run(cmd, **kw):
            calls.append((cmd, kw.get("env")))
            return 0, ""

        with tempfile.TemporaryDirectory() as d, mock.patch.object(e2e, "run", side_effect=fake_run), \
                mock.patch.object(e2e.shutil, "which", return_value="/usr/bin/psql"):
            pg = e2e.Postgres(Path(d), dsn)
            pg.start()
            org_dsn = pg.dsn
            pg.stop()
        self.assertEqual(len(calls), 2)  # CREATE DATABASE, DROP DATABASE
        for cmd, env in calls:
            self.assertFalse(any(pw in str(c) for c in cmd), cmd)
            self.assertEqual(env["PGPASSWORD"], pw)
        # The org server gets the full DSN through its environment, not argv.
        self.assertIn(pw, org_dsn)
        self.assertTrue(org_dsn.endswith("/" + pg.dbname + "?sslmode=disable"), org_dsn)

    def test_run_log_is_redacted(self):
        pw = "an0ther-Secret-pw"
        e2e.split_dsn_password(f"postgres://u:{pw}@h/db")
        with tempfile.TemporaryDirectory() as d:
            lp = Path(d) / "x.log"
            e2e.run(["echo", f"postgres://u:{pw}@h/db"], log_path=lp)
            self.assertNotIn(pw, lp.read_text())


class HostGuard(unittest.TestCase):
    def _ts(self):
        return next(e for e in e2e.CATALOG if e.lang == "typescript")

    def test_refusals(self):
        # P-30.
        ex = self._ts()
        no = lambda p: False  # noqa: E731
        self.assertEqual(e2e.host_refusals([ex], False, platform="linux", homes=[], port_open=no), [])
        self.assertEqual(e2e.host_refusals([ex], False, platform="darwin", homes=[], port_open=no), [])
        out = e2e.host_refusals([ex], True, platform="win32", homes=[], port_open=no)
        self.assertTrue(out and "Linux or macOS" in out[0])
        with tempfile.TemporaryDirectory() as h:
            (Path(h) / ".observer").mkdir()
            (Path(h) / ".observer" / "observer.db").write_text("")
            out = e2e.host_refusals([ex], False, platform="linux", homes=[h], port_open=no)
            self.assertTrue(any("observer.db exists" in x for x in out), out)
            self.assertEqual(e2e.host_refusals([ex], True, platform="linux", homes=[h], port_open=no), [])
        live = lambda p: p == 8820  # noqa: E731
        out = e2e.host_refusals([ex], False, platform="linux", homes=[], port_open=live)
        self.assertEqual(len(out), 1)
        self.assertIn("127.0.0.1:8820 answers", out[0])
        self.assertEqual(e2e.host_refusals([ex], True, platform="linux", homes=[], port_open=live), [])

    def test_symlinked_node_modules_is_always_refused(self):
        ex = self._ts()
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "elsewhere"
            target.mkdir()
            link = Path(d) / "node_modules"
            link.symlink_to(target)
            lang = dataclasses.replace(e2e.LANGS["typescript"], install_dirs=lambda e: [link])
            with mock.patch.dict(e2e.LANGS, {"typescript": lang}):
                for allow in (False, True):
                    out = e2e.host_refusals([ex], allow, platform="linux", homes=[], port_open=lambda p: False)
                    self.assertEqual(len(out), 1, out)
                    self.assertIn("is a symlink", out[0])

    def test_reserved_ports(self):
        for p in (8821, 8823, 8081, 8820, 4318):
            self.assertIn(p, e2e.RESERVED_PORTS)
        self.assertTrue(set(e2e.LIVE_HOST_PORTS) <= e2e.RESERVED_PORTS)

    def test_node_version(self):
        for out, ok in (("v22.17.1\n", False), ("v22.18.0\n", True), ("v24.1.0\n", True), ("v20.19.0", False)):
            with mock.patch.object(e2e, "run", return_value=(0, out)):
                self.assertEqual(e2e.node_version_error() == "", ok, out)

    def test_main_refuses_before_touching_anything(self):
        with mock.patch.object(e2e, "host_refusals", return_value=["platform 'win32'"]), \
                mock.patch.object(e2e, "probe_provider") as probe, \
                mock.patch.object(e2e, "build_binaries") as build, \
                mock.patch.object(e2e.tempfile, "mkdtemp") as mk:
            rc = e2e.main(["--dry-run", "--langs", "python"])
        self.assertEqual(rc, 2)
        probe.assert_not_called()
        build.assert_not_called()
        mk.assert_not_called()


def _res(status="pass", calls=1, cost=0.001, path="openai/python", dest="local"):
    r = e2e.Result(path, path.split("/")[0], "openai", "python", dest, "live", status=status)
    if calls:
        r.tokens = {"calls": calls, "input": 10, "output": 5}
        r.est_cost_usd = cost
    return r


class Spend(unittest.TestCase):
    def _run(self, outcomes, max_spend=0.50, mode="live", n=None):
        it = iter(outcomes)

        def runner(ex, dest):
            o = next(it)
            if isinstance(o, Exception):
                raise o
            return o

        exs = [e for e in e2e.CATALOG if e.lang == "python"][: (n or len(outcomes))]
        with mock.patch.object(e2e, "log"):
            return e2e.run_cases(exs, ["local"], mode, max_spend, runner, [])

    def test_no_usage_case_is_charged_worst_case(self):
        # P-28: a live case with no usage record counts, not $0.
        res = self._run([_res(status="fail", calls=0)])
        self.assertEqual(res[0].charged_usd, e2e.WORST_CASE_CASE_USD)
        self.assertTrue(any("worst-case" in n for n in res[0].notes))

    def test_cap_stops_new_cases(self):
        res = self._run([_res(status="fail", calls=0), _res(status="fail", calls=0), _res()], max_spend=0.015, n=3)
        self.assertEqual([r.status for r in res], ["fail", "fail", "skip"])
        self.assertIn("--max-spend", res[2].reason)

    def test_three_consecutive_live_failures_stop_the_run(self):
        outs = [_res(status="fail", cost=0.0001)] * 3 + [_res()] * 2
        res = self._run(outs, n=5)
        self.assertEqual([r.status for r in res], ["fail", "fail", "fail", "skip", "skip"])
        self.assertIn("consecutive live failures", res[3].reason)

    def test_a_pass_resets_the_streak(self):
        f = lambda: _res(status="fail", cost=0.0001)  # noqa: E731
        res = self._run([f(), f(), _res(), f(), f(), _res()], n=6)
        self.assertNotIn("skip", [r.status for r in res])

    def test_dry_run_is_never_stopped_or_charged(self):
        outs = [_res(status="fail", calls=0)] * 4
        res = self._run(outs, max_spend=0.0, mode="dry-run", n=4)
        self.assertEqual([r.status for r in res], ["fail"] * 4)
        self.assertEqual(sum(r.charged_usd for r in res), 0)

    def test_an_exception_is_that_case_fail(self):
        # P-34: one bad case never ends the run.
        res = self._run([ValueError("boom"), _res()], n=2)
        self.assertEqual([r.status for r in res], ["fail", "pass"])
        self.assertIn("ValueError: boom", res[0].reason)
        self.assertEqual(res[0].charged_usd, e2e.WORST_CASE_CASE_USD)

    def test_experiment_is_charged(self):
        r = _res(path="sdk-direct/python", cost=0.002)
        self.assertAlmostEqual(e2e.charge(r, "live"), 0.002 + e2e.EXPERIMENT_USD)
        self.assertEqual(e2e.charge(_res(path="sdk-direct/python", dest="online", cost=0.002), "live"), 0.002)


class RunRecord(unittest.TestCase):
    def test_malformed_and_missing(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "run.json"
            rec, why = e2e.read_run_record(p)
            self.assertIsNone(rec)
            self.assertIn("no run.json", why)
            p.write_text("{not json")
            rec, why = e2e.read_run_record(p)
            self.assertIsNone(rec)
            self.assertIn("not valid JSON", why)
            p.write_text("[1]")
            self.assertIsNone(e2e.read_run_record(p)[0])
            p.write_text('{"trace_ids": []}')
            self.assertEqual(e2e.read_run_record(p), ({"trace_ids": []}, ""))

    def test_stale_run_json_is_removed(self):
        ex = next(e for e in e2e.CATALOG if e.path == "openai/python")
        with tempfile.TemporaryDirectory() as d:
            work = Path(d)
            stale = work / "runs" / "openai_python-local" / "run.json"
            stale.parent.mkdir(parents=True)
            stale.write_text('{"trace_ids": ["old"]}')
            r = e2e.run_case(ex, "local", "live", None, None, work, {},
                             {"openai": {"usable": False, "reason": "OPENAI_API_KEY is not set"}})
            self.assertEqual(r.status, "skip")
            self.assertFalse(stale.exists())

    def test_destination_check(self):
        self.assertIsNone(e2e.destination_check({}, "both"))
        ok = e2e.destination_check({"destination": "both", "destinationSource": "machine"}, "both")
        self.assertTrue(ok["ok"])
        bad = e2e.destination_check({"destination": "local", "destination_source": "default"}, "both")
        self.assertFalse(bad["ok"])
        self.assertIn("'local' (source default), want 'both'", bad["what"])

    def test_export_counters(self):
        self.assertEqual(e2e.export_counters({"failed_exports": 1, "dropped_spans": 2}), (1, 2))
        self.assertEqual(e2e.export_counters({"failedExports": 0, "droppedSpans": 3}), (0, 3))
        self.assertEqual(e2e.export_counters({}), (0, 0))


class Keep(unittest.TestCase):
    def setUp(self):
        e2e._SECRETS.clear()

    def test_redact_in_place(self):
        # P-37: a kept work dir holds no unredacted daemon or org log.
        e2e.add_secret("ingest-cred-secret-value-123")
        with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as outside:
            work = Path(d)
            (work / "logs").mkdir()
            (work / "logs" / "org-serve.log").write_text("token ingest-cred-secret-value-123 and #token=abc\n")
            (work / "runs" / "c" / "canary").mkdir(parents=True)
            (work / "runs" / "c" / "run.json").write_text('{"k": "Authorization: Bearer xyz"}')
            target = Path(outside) / "pkg.js"
            target.write_text("Authorization: Bearer keep-me-outside")
            (work / "runs" / "c" / "canary" / "node_modules").symlink_to(outside)
            (work / "db.bin").write_bytes(b"\xff\x00ingest-cred-secret-value-123")
            n = e2e.redact_in_place(work)
            self.assertEqual(n, 2)
            self.assertNotIn("ingest-cred-secret", (work / "logs" / "org-serve.log").read_text())
            self.assertNotIn("xyz", (work / "runs" / "c" / "run.json").read_text())
            self.assertIn("keep-me-outside", target.read_text())  # never through a symlink


class CrewAIOrg(unittest.TestCase):
    def test_finds_the_session(self):
        org = mock.Mock()
        row = {"group_key": "crewai-1", "trace_count": 1, "error_count": 0, "total_tokens": 1234,
               "total_cost_usd": 0.0003}
        org.api.side_effect = [(200, json.dumps({"groups": []})),
                               (200, json.dumps({"groups": [{"group_key": "other"}, row]}))]
        checks = e2e.crewai_org_checks(org, "crewai-1", 1234, wait_s=5, sleep=lambda s: None)
        self.assertTrue(all(c["ok"] for c in checks), checks)
        self.assertEqual(len(checks), 4)
        bad = e2e.crewai_org_checks(mock.Mock(api=mock.Mock(return_value=(200, json.dumps({"groups": [row]})))),
                                    "crewai-1", 999, wait_s=0, sleep=lambda s: None)
        self.assertFalse(all(c["ok"] for c in bad))

    def test_missing_session_fails(self):
        org = mock.Mock(api=mock.Mock(return_value=(404, "")))
        checks = e2e.crewai_org_checks(org, "crewai-1", None, wait_s=0, sleep=lambda s: None)
        self.assertEqual(len(checks), 1)
        self.assertFalse(checks[0]["ok"])


class DryRunReport(unittest.TestCase):
    def test_provider_row_says_not_contacted(self):
        st = {"model": "gpt-5-nano", "key_env": "OPENAI_API_KEY", "key_set": True, "reachable": None,
              "usable": False, "reason": "not used (dry run)"}
        meta = {"mode": "dry-run", "started": "t", "git": {"sha": "0" * 40, "branch": "b", "dirty": False},
                "destinations": ["local"], "providers": {"openai": st}, "machine": {"dashboard": "d", "otlp": "o"},
                "org": None, "duration_s": 1, "charged_usd": 0, "max_spend": 0.5}
        with tempfile.TemporaryDirectory() as d:
            e2e.write_report(Path(d), meta, [])
            md = (Path(d) / "report.md").read_text()
        self.assertIn("host not contacted: not used (dry run) |", md)


if __name__ == "__main__":
    unittest.main()
