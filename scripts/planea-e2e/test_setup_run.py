#!/usr/bin/env python3
"""Unit tests for setup_run.py (the setup run of docs/planea-e2e-playbook.md).

No network, no daemon, no package install: a fake `setup` (written below)
plays each answer the plan names, and the app run is stubbed.

  python3 -m unittest scripts/planea-e2e/test_setup_run.py
"""

from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import setup_run as sr  # noqa: E402

FAKE_KEY = "0" * 31 + "1" + ".FAKE-sdk-key-secret-for-contract-tests-only"

# A stand-in for setup. FAKE_SETUP_MODE picks the behaviour; the key it
# "receives" is FAKE_KEY. It writes the key file where setup_run expects it.
FAKE_SETUP = textwrap.dedent(f'''
    import json, os, sys
    from pathlib import Path
    sys.path.insert(0, {str(Path(__file__).resolve().parent)!r})
    import setup_run as sr
    mode = os.environ.get("FAKE_SETUP_MODE", "good")
    key = {FAKE_KEY!r}
    path = sr.credential_path(os.environ)
    args = sys.argv[1:]
    def say(obj):
        print(json.dumps(obj), flush=True)
    if "--status" in args:
        say({{"phase": "status", "configured": path.exists(), "file": str(path)}})
        sys.exit(0)
    if "--forget" in args:
        if path.exists():
            path.unlink()
        say({{"phase": "forget", "revoked": True}})
        sys.exit(0)
    say({{"phase": "detect", "language": "python", "libraries": ["openai"]}})
    if not path.exists():
        say({{"phase": "approve", "approve_url": "https://cloud.superbased.app/connect/r1", "user_code": "KTRW-4821"}})
        say({{"phase": "approve", "state": "approved_not_ready"}})
        say({{"phase": "approve", "state": "approved", "dashboard": "u-k7x2", "kind": "personal"}})
        if mode == "declined":
            sys.exit(2)
        if mode != "nofile":
            path.parent.mkdir(parents=True, exist_ok=True)
            os.chmod(path.parent, 0o700)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600 if mode != "loose" else 0o644)
            os.write(fd, (key + "\\n").encode())
            os.close(fd)
            if mode == "loose":
                os.chmod(path, 0o644)
    if mode == "leak":
        print("debug: using " + key)
    if mode == "aigw":
        say({{"phase": "next", "init_line": "import superbased_sdk; superbased_sdk.init()", "also": "try the AI gateway"}})
    elif mode == "field":
        say({{"phase": "next", "init_line": "import superbased_sdk; superbased_sdk.init()", "device_code": "x"}})
    else:
        say({{"phase": "next", "init_line": "import superbased_sdk; superbased_sdk.init()"}})
    say({{"phase": "done", "trace_url": "https://u-k7x2.superbased.app/trajectories?trace=" + "ab" * 16}})
''')


class PureTests(unittest.TestCase):
    def test_parse_phases_skips_text_and_bad_json(self):
        out = 'hello\n{"phase":"detect"}\n{not json\n[1]\n  {"phase":"done","trace_url":"x"}\n'
        self.assertEqual([p["phase"] for p in sr.parse_phases(out)], ["detect", "done"])

    def test_phase_takes_the_last(self):
        ps = [{"phase": "done", "n": 1}, {"phase": "done", "n": 2}]
        self.assertEqual(sr.phase(ps, "done")["n"], 2)
        self.assertIsNone(sr.phase(ps, "approve"))

    def test_secret_fields_nested(self):
        obj = {"phase": "x", "a": {"Device_Code": 1}, "b": [{"key_grant": 2}], "key_id": "ok"}
        self.assertEqual(sorted(sr.secret_fields(obj)), ["a.Device_Code", "b[0].key_grant"])

    def test_key_shape_and_redact(self):
        self.assertTrue(sr.KEY_SHAPE.search("x " + FAKE_KEY + " y"))
        self.assertFalse(sr.KEY_SHAPE.search("key id " + "0" * 32 + " only"))
        self.assertNotIn(FAKE_KEY, sr.redact("a " + FAKE_KEY))

    def test_leak_checks(self):
        rows = sr.leak_checks("t", ["clean"], [{"phase": "done"}])
        self.assertTrue(all(c.ok for c in rows))
        rows = sr.leak_checks("t", [FAKE_KEY, "use the AI gateway"], [{"phase": "x", "redeem_secret": 1}])
        self.assertEqual([c.ok for c in rows], [False, False, False])

    def test_trace_url(self):
        good = "https://u-k7x2.superbased.app/trajectories?trace=" + "ab" * 16
        self.assertTrue(sr.TRACE_URL.match(good))
        for bad in ("http://u-k7x2.superbased.app/trajectories?trace=" + "ab" * 16,
                    "https://evil.example/trajectories?trace=" + "ab" * 16,
                    "https://u-k7x2.superbased.app/trajectories?trace=xyz"):
            self.assertFalse(sr.TRACE_URL.match(bad), bad)

    def test_credential_path_ladder(self):
        self.assertEqual(sr.credential_path({"SUPERBASED_CREDENTIAL_FILE": "/x/f", "HOME": "/h"}), Path("/x/f"))
        self.assertEqual(sr.credential_path({"XDG_CONFIG_HOME": "/c", "HOME": "/h"}, "posix"),
                         Path("/c/superbased/sdk-credential"))
        self.assertEqual(sr.credential_path({"HOME": "/h"}, "posix"), Path("/h/.config/superbased/sdk-credential"))
        self.assertEqual(sr.credential_path({"LOCALAPPDATA": "L"}, "nt"), Path("L") / "superbased" / "sdk-credential")

    def test_show_approval_prints_only_the_address(self):
        with mock.patch("builtins.print") as p:
            sr.show_approval('{"phase":"approve","state":"approved"}')
            self.assertFalse(p.called)
            sr.show_approval('{"phase":"approve","approve_url":"https://cloud.superbased.app/connect/r1","user_code":"A-1"}')
            self.assertIn("https://cloud.superbased.app/connect/r1", p.call_args_list[0].args[0])

    def test_init_line(self):
        self.assertEqual(sr.init_line([{"phase": "next", "init_line": " x() "}]), "x()")
        self.assertEqual(sr.init_line([{"phase": "next_steps", "line": "y()"}]), "y()")
        self.assertEqual(sr.init_line([{"phase": "done"}]), "")

    @unittest.skipIf(os.name == "nt", "unix modes")
    def test_file_checks(self):
        with tempfile.TemporaryDirectory() as d:
            folder = Path(d) / "superbased"
            folder.mkdir(mode=0o700)
            os.chmod(folder, 0o700)
            f = folder / "sdk-credential"
            self.assertFalse(sr.file_checks(f)[0].ok)
            f.write_text("x\n")
            os.chmod(f, 0o600)
            self.assertTrue(all(c.ok for c in sr.file_checks(f)))
            os.chmod(f, 0o640)
            self.assertFalse(all(c.ok for c in sr.file_checks(f)))
            os.chmod(f, 0o600)
            link = folder / "link"
            link.symlink_to(f)
            self.assertFalse(sr.file_checks(link)[1].ok)

    def test_summarize_ignores_warnings(self):
        self.assertEqual(sr.summarize([sr.Check("a", True), sr.Check("b", False, warn=True)]), "PASS")
        self.assertEqual(sr.summarize([sr.Check("a", False)]), "FAIL")

    def test_child_env_drops_callers_superbased_and_ci(self):
        with tempfile.TemporaryDirectory() as d, mock.patch.dict(
                os.environ, {"SUPERBASED_API_KEY": "k", "CI": "1", "OTEL_SERVICE_NAME": "s"}):
            env = sr.child_env(Path(d))
        self.assertNotIn("SUPERBASED_API_KEY", env)
        self.assertNotIn("CI", env)
        self.assertNotIn("OTEL_SERVICE_NAME", env)
        self.assertEqual(env["SUPERBASED_NODE_URL"], "http://127.0.0.1:9")
        self.assertTrue(env["HOME"].startswith(d))

    def test_every_exit_code_has_a_meaning(self):
        self.assertEqual(sorted(sr.EXIT_MEANING), [0, 1, 2, 3, 4, 5])


@unittest.skipIf(os.name == "nt", "the fake setup writes unix modes")
class MainWithFakeSetup(unittest.TestCase):
    def run_main(self, mode, keep=False):
        d = tempfile.mkdtemp()
        fake = Path(d) / "fake_setup.py"
        fake.write_text(FAKE_SETUP)
        out = Path(d) / "out"

        def make_project(root, lang, name):
            p = root / name
            p.mkdir(parents=True)
            (p / "app.py").write_text("print('app')\n")
            return p

        app = (0, "superbased: first trace from this process: https://u-k7x2.superbased.app/x\n", True)
        argv = ["--lang", "python", "--setup-cmd", f"{sys.executable} {fake}", "--out", str(out),
                "--approve-timeout", "30"] + (["--keep-key"] if keep else [])
        with mock.patch.dict(os.environ, {"FAKE_SETUP_MODE": mode}), \
                mock.patch.object(sr, "make_project", make_project), \
                mock.patch.object(sr, "run_app", return_value=app), \
                mock.patch("builtins.print"):
            code = sr.main(argv)
        rep = json.loads((out / "report.json").read_text())
        log = (out / "setup.log").read_text()
        return code, rep, log

    def failed(self, rep):
        return [c["name"] for c in rep["checks"] if not c["ok"] and not c["warn"]]

    def test_good_run_passes(self):
        code, rep, _ = self.run_main("good")
        self.assertEqual(self.failed(rep), [])
        self.assertEqual(code, 0)

    def test_a_printed_key_fails_and_is_redacted(self):
        code, rep, log = self.run_main("leak")
        self.assertEqual(code, 1)
        self.assertIn("all runs: nothing printed is shaped like an SDK key", self.failed(rep))
        self.assertNotIn(FAKE_KEY, log)
        self.assertNotIn(FAKE_KEY, json.dumps(rep))

    def test_naming_the_ai_gateway_fails(self):
        _, rep, _ = self.run_main("aigw")
        self.assertIn("all runs: nothing printed names the AI gateway", self.failed(rep))

    def test_a_secret_field_fails(self):
        _, rep, _ = self.run_main("field")
        self.assertIn("all runs: no --json object carries a secret's field", self.failed(rep))

    def test_a_loose_key_file_fails(self):
        _, rep, _ = self.run_main("loose")
        self.assertIn("the key file is readable by this user alone", self.failed(rep))

    def test_a_declined_approval_fails(self):
        code, rep, _ = self.run_main("declined")
        self.assertEqual(code, 1)
        self.assertIn("setup exits 0 (the trace arrived)", self.failed(rep))
        self.assertIn("the key file exists", self.failed(rep))


if __name__ == "__main__":
    unittest.main()
