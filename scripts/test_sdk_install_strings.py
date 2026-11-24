"""Tests for scripts/sdk-install-strings.py (review E-66, lane C0): the
repository's install strings and the SDK catalog are all in one state, a flip
on a copy turns every row to the released text exactly once, and a new
catalog row needs no other edit.

    python3 -m unittest scripts/test_sdk_install_strings.py
"""

import importlib.util
import json
import os
import shutil
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
_spec = importlib.util.spec_from_file_location("sdk_install_strings", os.path.join(HERE, "sdk-install-strings.py"))
sis = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sis)  # type: ignore[union-attr]


def _copy(dst: str, rel: str) -> None:
    os.makedirs(os.path.dirname(os.path.join(dst, rel)), exist_ok=True)
    shutil.copyfile(os.path.join(ROOT, rel), os.path.join(dst, rel))


def _copy_surfaces(dst: str) -> None:
    for row in sis.ROWS:
        for path in sis._files(ROOT, row.pattern):
            _copy(dst, os.path.relpath(path, ROOT))
    _copy(dst, sis.CATALOG)


def _copy_pre(dst: str) -> None:
    """The surfaces in their pre-release state, whatever state the repository
    is in: copy them, then put every row's pre-release text back and clear the
    catalog's published flags."""
    _copy_surfaces(dst)
    for row in sis.ROWS:
        for path in sis._files(dst, row.pattern):
            text = sis._read(path)
            if row.after in text:
                _write(dst, os.path.relpath(path, dst), text.replace(row.after, row.before))
    doc = _catalog(dst)
    for r in doc["sdks"]:
        r["published"] = False
    sis.write_catalog(dst, doc)


def _catalog(root: str) -> dict:
    with open(os.path.join(root, sis.CATALOG), encoding="utf-8") as f:
        return json.load(f)


def _write(root: str, rel: str, text: str) -> None:
    os.makedirs(os.path.dirname(os.path.join(root, rel)), exist_ok=True)
    with open(os.path.join(root, rel), "w", encoding="utf-8") as f:
        f.write(text)


FIXTURE = os.path.join(ROOT, "shared", "lib", "sdkCatalog.fixture.json")


class InstallStrings(unittest.TestCase):
    def test_the_repository_is_in_one_state(self):
        states = sis.check(ROOT)
        self.assertEqual(len(states), 1, states)
        self.assertIn(next(iter(states)), (sis.PRE, sis.POST))

    def test_flip_rewrites_every_row_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            _copy_pre(tmp)
            self.assertEqual(set(sis.check(tmp)), {sis.PRE})
            written = sis.flip(tmp)
            self.assertTrue(written)
            self.assertEqual(set(sis.check(tmp)), {sis.POST})
            with self.assertRaises(ValueError):
                sis.flip(tmp)
            self.assertEqual(sis.main(["check", "--root", tmp]), 0)

    def test_a_changed_surface_fails_the_check(self):
        with tempfile.TemporaryDirectory() as tmp:
            _copy_pre(tmp)
            path = os.path.join(tmp, "docs", "sdk", "README.md")
            with open(path, encoding="utf-8") as f:
                text = f.read()
            with open(path, "w", encoding="utf-8") as f:
                f.write(text.replace(sis.ROWS[0].before, "Install it somehow."))
            self.assertEqual(sis.main(["check", "--root", tmp]), 1)
            with self.assertRaises(ValueError):
                sis.flip(tmp)



class Catalog(unittest.TestCase):
    def test_the_catalog_has_the_four_sdks_and_java_is_unpublished(self):
        # v1.43.0 publishes Python and TypeScript (PyPI, npm) and tags the Go
        # module; Java (Maven Central) has no publish path yet.
        doc = sis.load_catalog(ROOT)
        self.assertEqual([r["id"] for r in doc["sdks"]], ["python", "typescript", "go", "java"])
        self.assertEqual({r["id"]: r["release"] for r in doc["sdks"]},
                         {"python": "sdk-release", "typescript": "sdk-release", "go": "none", "java": "none"})
        self.assertEqual({r["id"]: r["published"] for r in doc["sdks"]},
                         {"python": True, "typescript": True, "go": True, "java": False})

    def test_java_stays_on_its_checkout_text(self):
        with open(os.path.join(ROOT, "docs", "sdk", "README.md"), encoding="utf-8") as f:
            text = f.read()
        self.assertIn("Java is not on Maven Central", text)
        self.assertIn("mvn -f sdk/java install", text)

    def test_write_catalog_keeps_the_committed_layout(self):
        with tempfile.TemporaryDirectory() as tmp:
            _copy(tmp, sis.CATALOG)
            sis.write_catalog(tmp, sis.load_catalog(tmp))
            with open(os.path.join(ROOT, sis.CATALOG), encoding="utf-8") as a, open(os.path.join(tmp, sis.CATALOG), encoding="utf-8") as b:
                self.assertEqual(a.read(), b.read())

    def test_flip_publishes_only_the_workflow_rows(self):
        with tempfile.TemporaryDirectory() as tmp:
            _copy_pre(tmp)
            sis.flip(tmp)
            got = {r["id"]: r["published"] for r in _catalog(tmp)["sdks"]}
            self.assertEqual(got, {"python": True, "typescript": True, "go": False, "java": False})

    def test_flip_sdk_marks_one_hand_released_row(self):
        with tempfile.TemporaryDirectory() as tmp:
            _copy_pre(tmp)
            self.assertEqual(sis.main(["flip", "--sdk", "go", "--root", tmp]), 0)
            got = {r["id"]: r["published"] for r in _catalog(tmp)["sdks"]}
            self.assertEqual(got, {"python": False, "typescript": False, "go": True, "java": False})
            self.assertEqual(sis.main(["check", "--root", tmp]), 0)
            with open(os.path.join(tmp, "docs", "sdk", "go.md"), encoding="utf-8") as f:
                self.assertIn("go get github.com/superbasedapp/observer/sdk/go", f.read())
            for bad in ("go", "python", "ruby"):
                with self.assertRaises(ValueError, msg=bad):
                    sis.flip_sdk(tmp, bad)
            with self.assertRaises(SystemExit):  # --sdk goes with flip only
                sis.main(["check", "--sdk", "go", "--root", tmp])

    def test_go_text_and_catalog_must_agree(self):
        with tempfile.TemporaryDirectory() as tmp:
            _copy_pre(tmp)
            doc = _catalog(tmp)
            doc["sdks"][2]["published"] = True  # the flag flipped, the text did not
            sis.write_catalog(tmp, doc)
            self.assertEqual(sis.main(["check", "--root", tmp]), 1)
            with self.assertRaises(ValueError):
                sis.flip_sdk(tmp, "go")

    def test_java_can_stay_unpublished_after_the_other_flips(self):
        with tempfile.TemporaryDirectory() as tmp:
            _copy_pre(tmp)
            sis.flip(tmp)
            sis.flip_sdk(tmp, "go")
            self.assertEqual(sis.main(["check", "--root", tmp]), 0)
            self.assertFalse([r for r in _catalog(tmp)["sdks"] if r["id"] == "java"][0]["published"])

    def test_the_workflow_rows_must_agree(self):
        with tempfile.TemporaryDirectory() as tmp:
            _copy_pre(tmp)
            doc = _catalog(tmp)
            doc["sdks"][0]["published"] = True
            sis.write_catalog(tmp, doc)
            self.assertEqual(sis.main(["check", "--root", tmp]), 1)
            with self.assertRaises(ValueError):
                sis.flip(tmp)

    def test_a_malformed_catalog_fails_the_check(self):
        cases = {
            "duplicate id": lambda d: d["sdks"].append(dict(d["sdks"][0])),
            "unknown release": lambda d: d["sdks"][2].update(release="someday"),
            "published not a boolean": lambda d: d["sdks"][3].update(published="no"),
            "two-line install": lambda d: d["sdks"][1].update(install_checkout="a\nb"),
            "empty snippet": lambda d: d["sdks"][0].update(snippet=[]),
            "no rows": lambda d: d.update(sdks=[]),
        }
        for name, spoil in cases.items():
            with self.subTest(name), tempfile.TemporaryDirectory() as tmp:
                _copy_surfaces(tmp)
                doc = _catalog(tmp)
                spoil(doc)
                sis.write_catalog(tmp, doc)
                self.assertEqual(sis.main(["check", "--root", tmp]), 1)

    def test_an_app_that_hard_codes_an_install_line_fails_the_check(self):
        line = sis.load_catalog(ROOT)["sdks"][2]["install_checkout"]
        for rel in ("web/src/lib/x.ts", "web2/src/components/X.tsx", "webcloud/src/pages/Y.tsx"):
            with self.subTest(rel), tempfile.TemporaryDirectory() as tmp:
                _copy_surfaces(tmp)
                _write(tmp, rel, f"export const INSTALL = {json.dumps(line)};\n")
                self.assertEqual(sis.main(["check", "--root", tmp]), 1)
        with tempfile.TemporaryDirectory() as tmp:
            _copy_surfaces(tmp)
            _write(tmp, "web/src/lib/notes.md", line)  # not an app source
            _write(tmp, "web/node_modules/x/index.ts", line)
            self.assertEqual(sis.main(["check", "--root", tmp]), 0)

    def test_the_repository_apps_read_the_catalog(self):
        self.assertEqual(sis.hard_coded_installs(ROOT, sis.load_catalog(ROOT)), [])

    def test_a_new_catalog_row_needs_no_other_edit(self):
        with open(FIXTURE, encoding="utf-8") as f:
            row = json.load(f)["row"]
        with tempfile.TemporaryDirectory() as tmp:
            _copy_pre(tmp)
            doc = _catalog(tmp)
            doc["sdks"].append(row)
            sis.write_catalog(tmp, doc)
            self.assertEqual(sis.main(["check", "--root", tmp]), 0)
            sis.flip_sdk(tmp, row["id"])
            self.assertEqual(sis.main(["check", "--root", tmp]), 0)
            self.assertTrue([r for r in _catalog(tmp)["sdks"] if r["id"] == row["id"]][0]["published"])


if __name__ == "__main__":
    unittest.main()
