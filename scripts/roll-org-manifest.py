#!/usr/bin/env python3
"""Validate/retag saved ACI create-inputs without logging their secret values."""

import argparse
import copy
import os
import pathlib
import re
import sys
import urllib.parse

import yaml


def load_manifest(filename):
    with open(filename, encoding="utf-8") as source:
        manifest = yaml.safe_load(source)
    containers = manifest.get("properties", {}).get("containers", [])
    selected = [entry for entry in containers if entry.get("name") == "observer-org"]
    if len(selected) != 1:
        raise ValueError("create-input must contain exactly one observer-org container")
    return manifest, selected[0]["properties"]


def environment(properties):
    result = {}
    for entry in properties.get("environmentVariables", []):
        name = entry.get("name")
        if name in result:
            raise ValueError("duplicate environment variable in create-input")
        result[name] = entry
    return result


def secret_value(env, name):
    entry = env.get(name, {})
    if "value" in entry or not isinstance(entry.get("secureValue"), str) or not entry["secureValue"].strip():
        raise ValueError(name + " must be a nonempty secureValue")
    return entry["secureValue"].strip()


def compare_file(value, filename, label):
    if filename and value != pathlib.Path(filename).read_text(encoding="utf-8").strip():
        raise ValueError(label + " differs from its canonical file")


def verify(manifest, org, allow_legacy=False):
    env = environment(org)
    dsns = ["OBSERVER_CONTROL_STORE_DSN", "OBSERVER_DATA_STORE_DSN"]
    legacy = not any(name in env for name in dsns)
    if legacy and not allow_legacy:
        raise ValueError("PostgreSQL DSNs are required; legacy SQLite rollback needs an explicit backup-qualified override")
    if not legacy:
        for name, file_knob in zip(dsns, ["CONTROL_DSN_FILE", "DATA_DSN_FILE"]):
            value = secret_value(env, name)
            parsed = urllib.parse.urlsplit(value)
            if parsed.scheme not in ("postgres", "postgresql") or not parsed.hostname or not parsed.path.strip("/"):
                raise ValueError(name + " must be a PostgreSQL URL with host and database")
            tls = urllib.parse.parse_qs(parsed.query).get("sslmode", [])
            if tls != ["verify-full"]:
                raise ValueError(name + " must set sslmode=verify-full")
            compare_file(value, os.environ.get(file_knob), name)
    key = secret_value(env, "OBSERVER_ORG_SECRET_KEY")
    if not re.fullmatch(r"[0-9a-fA-F]{64}", key):
        raise ValueError("OBSERVER_ORG_SECRET_KEY must preserve the 64-hex sealing identity")
    compare_file(key, os.environ.get("SECRET_KEY_FILE"), "sealing key")
    # Preserve the existing estate's file-sourced secret hard gates, but only
    # require optional integrations when their canonical file is configured.
    gateway_file = os.environ.get("GATEWAY_TOKEN_FILE")
    if gateway_file:
        gateway_values = []
        for container in manifest["properties"]["containers"]:
            candidate = environment(container["properties"])
            if "GATEWAY_TOKEN" in candidate:
                gateway_values.append(secret_value(candidate, "GATEWAY_TOKEN"))
        if not gateway_values:
            raise ValueError("GATEWAY_TOKEN missing from create-input")
        for value in gateway_values:
            compare_file(value, gateway_file, "gateway token")
    clickhouse_file = os.environ.get("CLICKHOUSE_ENV")
    if clickhouse_file:
        lines = pathlib.Path(clickhouse_file).read_text(encoding="utf-8").splitlines()
        values = [line.split("=", 1)[1] for line in lines if line.startswith("OBSERVER_CLICKHOUSE_URL=")]
        if len(values) != 1 or secret_value(env, "OBSERVER_CLICKHOUSE_URL") != values[0]:
            raise ValueError("ClickHouse URL differs from its canonical env file")
    return "legacy" if legacy else "postgres"


def retag(manifest, org, image, output):
    if not re.fullmatch(r"[a-zA-Z0-9./_-]+/observer-org:[a-zA-Z0-9_][a-zA-Z0-9_.-]*", image):
        raise ValueError("invalid observer-org image reference")
    before = copy.deepcopy(manifest)
    org["image"] = image
    _, original_org = select_from_manifest(before)
    original_org["image"] = image
    if before != manifest:
        raise ValueError("retag unexpectedly changed non-image fields")
    # Exclusive creation prevents a repeated version from overwriting the
    # previous rollback input. Mode is private from the first write.
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as destination:
        yaml.safe_dump(manifest, destination, sort_keys=False)


def select_from_manifest(manifest):
    org = next(entry["properties"] for entry in manifest["properties"]["containers"] if entry["name"] == "observer-org")
    return manifest, org


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["verify", "retag"])
    parser.add_argument("manifest")
    parser.add_argument("--allow-legacy", action="store_true")
    parser.add_argument("--image")
    parser.add_argument("--output")
    args = parser.parse_args()
    try:
        manifest, org = load_manifest(args.manifest)
        if args.action == "verify":
            engine = verify(manifest, org, args.allow_legacy)
            print("create-input verified: " + engine + "; secret values redacted")
        else:
            if not args.image or not args.output:
                raise ValueError("retag requires --image and --output")
            retag(manifest, org, args.image, args.output)
            print("create-input saved privately; only observer-org image changed")
    except (OSError, ValueError, KeyError, TypeError, AttributeError, yaml.YAMLError):
        # YAML parser/URL/file exceptions can embed source lines or credentials.
        print("roll-org manifest validation failed (check structure, canonical secret files, PostgreSQL secureValue URLs with verify-full, and output uniqueness)", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
