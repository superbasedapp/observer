#!/usr/bin/env python3
"""gen_contract.py — emit the golden artifacts for verify-telemetry-contract.

Writes (into contract/golden/):
  contract.json                  machine-readable contract description
                                 (version, vocabularies, event matrix, tiers)
  sample_batch.json.gz           one valid §D3 envelope (gzip JSON)
  sample_batch_invalid.json.gz   schema-violating envelope (unknown event
                                 name) for quarantine-path tests

verify-telemetry-contract (Makefile target) regenerates these into a temp
dir and diffs against the committed copies — any contract drift fails the
gate in this repo, and the observer repo mirrors the same artifacts from its
internal/telemetry contract copy.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import re
import sys
import tempfile
from pathlib import Path

CONTRACT_VERSION = "1.2.0"
ENVELOPE_VERSION = "v1"
SCHEMA_VERSION = "2026-09-14T00:00:00Z"

VOCABS = {
    "tool_name": ["read", "edit", "write", "glob", "grep", "shell",
                  "apply_patch", "browser_click", "browser_navigate",
                  "terminal_write", "planner", "web_search", "read_url",
                  "todo_write", "ask_user", "other"],
    "error_class": ["tool_timeout", "tool_failed", "hook_failed", "proxy_5xx",
                    "proxy_4xx", "adapter_parse", "db_locked", "scrub_reject",
                    "consent_missing", "network_unreachable", "other"],
    "error_surface": ["tool", "hook", "proxy", "adapter", "db", "watcher",
                      "batcher"],
    "model_tier": ["frontier", "standard", "fast", "local"],
    "role": ["user", "assistant", "tool"],
    "adapter": ["claudecode", "codex", "cursor", "cline", "copilot",
                "copilot-cli", "gemini", "antigravity", "hermes", "other"],
    "outcome": ["ok", "user_stop", "error", "cancelled"],
    "consent_tier": ["off", "baseline", "enrichment", "error", "usage", "deep"],
    "model": ["anthropic", "openai", "google", "cursor", "copilot",
              "codex", "antigravity", "cline", "other"],
    "provider": ["anthropic", "openai", "google", "cursor", "copilot",
                 "codex", "antigravity", "cline", "other"],
    "segment": ["user_prompt", "system_nudge", "tool_call", "other"],
}

# Closed field-name allow-list per event (contract 1.2.0): any other key is
# refused, every event — the no-text-fields guarantee by construction.
FIELDS = {
    "app_start": ["arch", "os", "version"],
    "app_stop": ["arch", "os", "version"],
    "session_start": ["adapter"],
    "session_end": ["adapter", "duration_ms", "outcome"],
    "tool_use": ["count", "tool_name"],
    "error": ["error_class", "surface"],
    "token_use": ["cache_read", "model_tier", "role", "tokens_in", "tokens_out"],
    "day_active": [],
    "batch_meta": ["dropped_count", "retry_count"],
    "diag_command": ["argv_trunc", "exit", "tool_name"],
    "prompt_cycle": ["cache_percentage", "end_to_end_duration_ms", "input_size",
                     "model", "output_size", "provider", "segment",
                     "session_span", "turn_id"],
}

# Every free-form string (versions, os/arch, correlation spans) must match this.
IDENT_PATTERN = "^[A-Za-z0-9._+-]{1,64}$"

EVENTS = {
    "app_start": {"classification": "SystemMetaData", "purpose": "PerformanceAndHealth"},
    "app_stop": {"classification": "SystemMetaData", "purpose": "PerformanceAndHealth"},
    "session_start": {"classification": "SystemMetaData", "purpose": "FeatureInsight"},
    "session_end": {"classification": "SystemMetaData", "purpose": "FeatureInsight"},
    "tool_use": {"classification": "SystemMetaData", "purpose": "FeatureInsight"},
    "error": {"classification": "CallstackOrException", "purpose": "PerformanceAndHealth"},
    "token_use": {"classification": "SystemMetaData", "purpose": "BusinessInsight"},
    "day_active": {"classification": "SystemMetaData", "purpose": "FeatureInsight"},
    "batch_meta": {"classification": "SystemMetaData", "purpose": "PerformanceAndHealth"},
    "diag_command": {"classification": "EndUserPseudonymizedInformation", "purpose": "FeatureInsight",
                     "deep_only": True},
    "prompt_cycle": {"classification": "SystemMetaData", "purpose": "BusinessInsight"},
}

TIERS = {
    "off": [],
    "error": ["error", "batch_meta"],
    "usage": ["app_start", "app_stop", "session_start", "session_end",
              "tool_use", "error", "token_use", "day_active", "batch_meta"],
    "baseline": ["app_start", "app_stop", "session_start", "session_end",
                  "tool_use", "error", "token_use", "day_active", "batch_meta",
                  "prompt_cycle"],
    "enrichment": ["app_start", "app_stop", "session_start", "session_end",
                   "tool_use", "error", "token_use", "day_active", "batch_meta",
                   "prompt_cycle"],  # placeholder until enrichment events are defined
    "error": ["error", "batch_meta"],
    "usage": ["app_start", "app_stop", "session_start", "session_end",
              "tool_use", "error", "token_use", "day_active", "batch_meta",
              "prompt_cycle"],  # legacy alias for baseline
    "deep": ["app_start", "app_stop", "session_start", "session_end",
             "tool_use", "error", "token_use", "day_active", "batch_meta",
             "prompt_cycle", "diag_command"],
}


def deep_disclosure_digest() -> str:
    """sha256 of the canonical deep-tier disclosure text, extracted from
    contract/contract.go — single source of truth; regenerating after any
    wording change updates the golden, and both repos' tests pin their Go
    DeepDisclosureDigest() against this value."""
    src = (Path(__file__).resolve().parent.parent / "contract" / "contract.go").read_text()
    m = re.search(r"const DeepDisclosure = `(.*?)`", src, re.S)
    if not m:
        raise SystemExit("DeepDisclosure constant not found in contract/contract.go")
    return hashlib.sha256(m.group(1).encode()).hexdigest()


def sample_valid() -> dict:
    iid = "inst-0123456789ab"
    ev = [
        {"event": "session_start", "event_version": 1, "schema_version": SCHEMA_VERSION,
         "ts": "2026-09-14T09:58:00Z", "install_id": iid, "seq": 100,
         "session_span": "span-demo0000001", "classification": "SystemMetaData",
         "purpose": "FeatureInsight", "fields": {"adapter": "claudecode"}},
        {"event": "tool_use", "event_version": 1, "schema_version": SCHEMA_VERSION,
         "ts": "2026-09-14T09:59:00Z", "install_id": iid, "seq": 101,
         "session_span": "span-demo0000001", "classification": "SystemMetaData",
         "purpose": "FeatureInsight",
         "fields": {"tool_name": "shell", "count": 2}},
        {"event": "error", "event_version": 1, "schema_version": SCHEMA_VERSION,
         "ts": "2026-09-14T09:59:30Z", "install_id": iid, "seq": 102,
         "session_span": "span-demo0000001", "classification": "CallstackOrException",
         "purpose": "PerformanceAndHealth",
         "fields": {"error_class": "tool_timeout", "surface": "tool"}},
        {"event": "session_end", "event_version": 1, "schema_version": SCHEMA_VERSION,
         "ts": "2026-09-14T10:02:00Z", "install_id": iid, "seq": 103,
         "session_span": "span-demo0000001", "classification": "SystemMetaData",
         "purpose": "FeatureInsight",
         "fields": {"adapter": "claudecode", "duration_ms": 240000, "outcome": "ok"}},
        {"event": "prompt_cycle", "event_version": 1, "schema_version": SCHEMA_VERSION,
         "ts": "2026-09-14T10:00:15Z", "install_id": iid, "seq": 104,
         "session_span": "span-demo0000001", "classification": "SystemMetaData",
         "purpose": "BusinessInsight",
         "fields": {"model": "other", "provider": "other",
                    "input_size": 280, "output_size": 120,
                    "cache_percentage": 65, "end_to_end_duration_ms": 1580,
                    "segment": "user_prompt"}},
    ]
    return {"envelope_version": ENVELOPE_VERSION,
            "batch_uuid": "0b5c3d1e-1111-4222-8333-444455556666",
            "install_id": iid, "seq_start": 100, "seq_end": 103,
            "client_version": "1.5.0", "os": "linux", "arch": "amd64",
            "event_count": len(ev), "client_ts": "2026-09-14T10:05:00Z",
            "events": ev}


def sample_invalid() -> dict:
    env = sample_valid()
    env["events"][1]["event"] = "page_viewed"  # not in the taxonomy
    return env


def main() -> int:
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "contract/golden")
    doc = {"contract_version": CONTRACT_VERSION, "envelope_version": ENVELOPE_VERSION,
           "schema_version": SCHEMA_VERSION,
           "max_uncompressed_bytes": 1 << 20, "max_argv_len": 120,
           "deep_disclosure_digest": deep_disclosure_digest(),
           "vocabularies": VOCABS, "events": EVENTS, "tiers": TIERS,
           "fields": FIELDS, "ident_pattern": IDENT_PATTERN,
           "digest": None}
    doc["digest"] = hashlib.sha256(json.dumps(
        {k: v for k, v in doc.items() if k != "digest"}, sort_keys=True).encode()).hexdigest()

    tmp = Path(tempfile.mkdtemp())
    (tmp / "contract.json").write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
    for name, env in (("sample_batch.json.gz", sample_valid()),
                      ("sample_batch_invalid.json.gz", sample_invalid())):
        raw = json.dumps(env, separators=(",", ":")).encode()
        with gzip.GzipFile(filename=str(tmp / name), mode="wb", mtime=0) as fh:
            fh.write(raw)

    out.mkdir(parents=True, exist_ok=True)
    for f in sorted(tmp.iterdir()):
        (out / f.name).write_bytes(f.read_bytes())
        print(f"wrote {out / f.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
