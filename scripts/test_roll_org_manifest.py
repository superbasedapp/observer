"""Offline tests for the secret-preserving org ACI rollout input guard."""

import copy
import importlib.util
import os
import pathlib
import subprocess
import tempfile
import unittest
from unittest import mock

import yaml


ROOT = pathlib.Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("roll_manifest", ROOT / "scripts/roll-org-manifest.py")
MANIFEST = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MANIFEST)


def fixture():
    env = [{"name": name, "secureValue": value} for name, value in {
        "OBSERVER_CONTROL_STORE_DSN": "postgresql://app:sentinel@pg.example/org?sslmode=verify-full",
        "OBSERVER_DATA_STORE_DSN": "postgresql://app:sentinel@pg.example/org?sslmode=verify-full",
        "OBSERVER_ORG_SECRET_KEY": "a" * 64,
    }.items()]
    return {"properties": {"containers": [
        {"name": "sidecar", "properties": {"image": "sidecar:untouched", "environmentVariables": []}},
        {"name": "observer-org", "properties": {"image": "test.azurecr.io/observer-org:v46", "environmentVariables": env,
         "volumeMounts": [{"name": "state", "mountPath": "/var/lib/observer-org"}]}}
    ], "volumes": [{"name": "state", "azureFile": {"storageAccountKey": "sentinel-volume-secret"}}]}}


class ManifestTest(unittest.TestCase):
    def setUp(self):
        self.environment = mock.patch.dict(os.environ, {name: "" for name in ["SECRET_KEY_FILE", "GATEWAY_TOKEN_FILE", "CLICKHOUSE_ENV", "CONTROL_DSN_FILE", "DATA_DSN_FILE"]})
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def test_valid_postgres_and_canonical_files(self):
        manifest = fixture()
        _, org = MANIFEST.select_from_manifest(manifest)
        self.assertEqual(MANIFEST.verify(manifest, org), "postgres")
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "dsn"
            path.write_text("mismatched-secret", encoding="utf-8")
            os.environ["CONTROL_DSN_FILE"] = str(path)
            with self.assertRaisesRegex(ValueError, "canonical"):
                MANIFEST.verify(manifest, org)

    def test_postgres_guards(self):
        for bad in ["sqlite:///tmp/server.db", "postgres://pg/db?sslmode=disable", "postgres://pg?sslmode=verify-full", "", "postgres://pg/db?sslmode=verify-full&sslmode=disable"]:
            with self.subTest(bad=bad):
                manifest = fixture()
                _, org = MANIFEST.select_from_manifest(manifest)
                org["environmentVariables"][0]["secureValue"] = bad
                with self.assertRaises(ValueError):
                    MANIFEST.verify(manifest, org)
        for mutation in ["plaintext", "duplicate", "missing-data", "bad-seal"]:
            with self.subTest(mutation=mutation):
                manifest = fixture()
                _, org = MANIFEST.select_from_manifest(manifest)
                env = org["environmentVariables"]
                if mutation == "plaintext":
                    env[0]["value"] = env[0].pop("secureValue")
                elif mutation == "duplicate":
                    env.append(copy.deepcopy(env[0]))
                elif mutation == "missing-data":
                    env.pop(1)
                else:
                    env[2]["secureValue"] = "bad"
                with self.assertRaises(ValueError):
                    MANIFEST.verify(manifest, org)

    def test_legacy_requires_explicit_override(self):
        manifest = fixture()
        _, org = MANIFEST.select_from_manifest(manifest)
        org["environmentVariables"] = org["environmentVariables"][2:]
        with self.assertRaisesRegex(ValueError, "rollback"):
            MANIFEST.verify(manifest, org)
        self.assertEqual(MANIFEST.verify(manifest, org, allow_legacy=True), "legacy")

    def test_retag_preserves_all_other_fields_and_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest = fixture()
            original = copy.deepcopy(manifest)
            _, org = MANIFEST.select_from_manifest(manifest)
            output = pathlib.Path(directory) / "release.yaml"
            MANIFEST.retag(manifest, org, "test.azurecr.io/observer-org:v47", output)
            reread, new_org = MANIFEST.load_manifest(output)
            self.assertEqual(new_org["image"], "test.azurecr.io/observer-org:v47")
            new_org["image"] = "test.azurecr.io/observer-org:v46"
            self.assertEqual(reread, original)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                MANIFEST.retag(manifest, org, "test.azurecr.io/observer-org:v48", output)

    def test_cli_redacts_malformed_input(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "bad.yaml"
            path.write_text("properties: [sentinel-private-credential", encoding="utf-8")
            result = subprocess.run(["/usr/bin/python3", str(ROOT / "scripts/roll-org-manifest.py"), "verify", str(path)], text=True, capture_output=True, check=False)
            self.assertEqual(result.returncode, 1)
            self.assertNotIn("sentinel", result.stdout + result.stderr)

    def test_shell_check_only_is_offline_and_redacted(self):
        with tempfile.TemporaryDirectory() as directory:
            temp = pathlib.Path(directory)
            manifest = fixture()
            _, org = MANIFEST.select_from_manifest(manifest)
            org["environmentVariables"].extend([
                {"name": "GATEWAY_TOKEN", "secureValue": "sentinel-gateway"},
                {"name": "OBSERVER_CLICKHOUSE_URL", "secureValue": "https://sentinel-clickhouse"},
            ])
            path = temp / "input.yaml"
            path.write_text(yaml.safe_dump(manifest), encoding="utf-8")
            env = dict(os.environ)
            for variable, content in {
                "SECRET_KEY_FILE": "a" * 64,
                "GATEWAY_TOKEN_FILE": "sentinel-gateway",
                "CLICKHOUSE_ENV": "OBSERVER_CLICKHOUSE_URL=https://sentinel-clickhouse",
                "CONTROL_DSN_FILE": "postgresql://app:sentinel@pg.example/org?sslmode=verify-full",
                "DATA_DSN_FILE": "postgresql://app:sentinel@pg.example/org?sslmode=verify-full",
            }.items():
                secret = temp / variable
                secret.write_text(content, encoding="utf-8")
                env[variable] = str(secret)
            result = subprocess.run(["bash", str(ROOT / "scripts/roll-org.sh"), "v47", "--check-only", "--base", str(path)], env=env, text=True, capture_output=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("no Azure action", result.stdout)
            self.assertNotIn("sentinel", result.stdout + result.stderr)

    def test_partial_postgres_cannot_use_legacy_override(self):
        manifest = fixture()
        _, org = MANIFEST.select_from_manifest(manifest)
        org["environmentVariables"].pop(1)
        with self.assertRaises(ValueError):
            MANIFEST.verify(manifest, org, allow_legacy=True)

    def test_build_only_never_reads_input_or_recreates(self):
        # Subprocesses are stubbed inside the copied shell, including git and
        # az. No actual git, Docker, or Azure action runs in this test.
        script = (ROOT / "scripts/roll-org.sh").read_text(encoding="utf-8")
        start = script.index("build_image() {")
        end = script.index("\nROLLBACK=false", start)
        script = script[:start] + 'build_image() { echo "STUB_BUILD_ONLY"; }\n' + script[end:]
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "roll.sh"
            path.write_text(script, encoding="utf-8")
            result = subprocess.run(["bash", str(path), "v47", "--build-only"], text=True, capture_output=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("STUB_BUILD_ONLY", result.stdout)
            self.assertIn("no config read", result.stdout)
            self.assertNotIn("recreating", result.stdout)


if __name__ == "__main__":
    unittest.main()
