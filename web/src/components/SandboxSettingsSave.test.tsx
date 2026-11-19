// The Save path of Settings > Sandbox isolation (live check D-5): one click
// on Save sends exactly one PUT, and the card reads clean afterwards even
// when the reload after the save hands back the pre-save read (the shared
// query cache joins a GET already in flight). Run under node's test runner
// (scripts/test-components.mjs); the card's state transitions are
// lib/configSave.ts, driven here exactly as the card drives them.

import { test } from "node:test";
import assert from "node:assert/strict";
import { confirmClick } from "@shared/primitives/confirmButtonModel";
import {
  SANDBOX_MASTER_SWITCH_HELP,
  putSandboxConfig,
  sandboxConfigEqual,
  type TerminalSandboxConfig,
} from "@/components/SandboxSettingsCard";
import { ApiError } from "@/lib/api";
import { CONFIG_CONFLICT_MSG, applyLoaded, canStartSave, editDraft, emptySave, isDirty, runSave, saveErrorView } from "@/lib/configSave";

const saved: TerminalSandboxConfig = {
  enabled: true,
  backend: "bwrap",
  home_mode: "tmpfs",
  default_on: false,
  allow_remote_clone: false,
  remote_allowed_hosts: [],
  allow_worktree_source: false,
  workspaces_dir: "",
  workspace_retention_days: 7,
  mask_paths: [],
  extra_ro_binds: [],
  extra_rw_binds: [],
  prep_timeout_seconds: 120,
  backends: ["bwrap"],
  setup: { allow_elevated: false },
};

type Call = { path: string; params: unknown; init: RequestInit | undefined };

// fakeFetch records every request and answers the PUT the way the daemon's
// commitConfigEdit does: the saved block and the new etag.
function fakeFetch(calls: Call[]) {
  return (async (path: string, params?: unknown, init?: RequestInit) => {
    calls.push({ path, params, init });
    const body = JSON.parse(String(init?.body ?? "null")) as TerminalSandboxConfig;
    return { restart_required: true, sandbox: body, config_etag: "etag-2" };
  }) as unknown as Parameters<typeof putSandboxConfig>[3];
}

test("Save once: one PUT, clean on the reply, a stale reload keeps it clean", async () => {
  // The card's first read.
  let s = applyLoaded(emptySave<TerminalSandboxConfig>(), { block: saved, etag: "etag-1" }, sandboxConfigEqual);
  assert.equal(isDirty(s, sandboxConfigEqual), false);

  // Tick "Let a setup step ask for your password".
  s = editDraft(s, (d) => ({ ...d, setup: { allow_elevated: true } }));
  assert.equal(isDirty(s, sandboxConfigEqual), true);

  // The Save button needs no confirm here (nothing expands authority), so
  // the first click fires.
  assert.equal(confirmClick({ requireConfirm: false, armed: false, reasonMissing: false }), "fire");
  assert.deepEqual(canStartSave(s, false, "tok"), { ok: true });

  const calls: Call[] = [];
  const { state, reply } = await runSave(s, (body, baseEtag) => putSandboxConfig(body, baseEtag, "tok", fakeFetch(calls)));
  assert.equal(calls.length, 1, "one click sends exactly one PUT");
  assert.equal(calls[0].init?.method, "PUT");
  assert.deepEqual(calls[0].params, { base_etag: "etag-1" });
  assert.equal(new Headers(calls[0].init?.headers).get("X-Observer-Confirm"), "tok");
  assert.equal(JSON.parse(String(calls[0].init?.body)).setup.allow_elevated, true);
  assert.equal(reply.restart_required, true);
  s = state;
  assert.equal(isDirty(s, sandboxConfigEqual), false, "the save itself clears Unsaved changes");

  // The reload after the save joined a GET already in flight: the pre-save
  // read arrives. It is stale and changes nothing.
  s = applyLoaded(s, { block: saved, etag: "etag-1" }, sandboxConfigEqual);
  assert.equal(isDirty(s, sandboxConfigEqual), false);
  assert.equal(s.draft?.setup?.allow_elevated, true, "the stale read did not undo the saved toggle");

  // The fresh read after it is the baseline.
  s = applyLoaded(s, { block: { ...saved, setup: { allow_elevated: true } }, etag: "etag-2" }, sandboxConfigEqual);
  assert.equal(isDirty(s, sandboxConfigEqual), false);
  assert.equal(s.etag, "etag-2");
});

test("a refetch of the same file keeps the person's edits", () => {
  let s = applyLoaded(emptySave<TerminalSandboxConfig>(), { block: saved, etag: "etag-1" }, sandboxConfigEqual);
  s = editDraft(s, (d) => ({ ...d, setup: { allow_elevated: true } }));
  s = applyLoaded(s, { block: saved, etag: "etag-1" }, sandboxConfigEqual);
  assert.equal(s.draft?.setup?.allow_elevated, true);
  assert.equal(isDirty(s, sandboxConfigEqual), true);
});

test("a click that cannot start a save says why", () => {
  const loaded = applyLoaded(emptySave<TerminalSandboxConfig>(), { block: saved, etag: "etag-1" }, sandboxConfigEqual);
  for (const [state, busy, token] of [
    [emptySave<TerminalSandboxConfig>(), false, "tok"],
    [loaded, true, "tok"],
    [loaded, false, undefined],
  ] as const) {
    const start = canStartSave(state, busy, token);
    assert.equal(start.ok, false);
    if (!start.ok) assert.ok(start.why.length > 0);
  }
});

// D-R4-1: the enable switch's help never promises a restart, since a save of
// it applies live.
test("the master switch help says the save binds on the next launch, not after a restart", () => {
  assert.doesNotMatch(SANDBOX_MASTER_SWITCH_HELP, /after restart/);
  assert.match(SANDBOX_MASTER_SWITCH_HELP, /next launch/);
});

// D5 (live run 2026-11-19): a setup step's Undo on the same page rewrote
// config.toml. The setup panel now tells the card (onSettled), the card
// re-reads, and the fresh read (a new etag) replaces the stale draft, so the
// next Save starts from the file's own etag instead of a 409.
test("a re-read after a setup Undo replaces the stale values and etag", () => {
  let s = applyLoaded(emptySave<TerminalSandboxConfig>(), { block: saved, etag: "etag-1" }, sandboxConfigEqual);
  const undone: TerminalSandboxConfig = { ...saved, enabled: false, backends: [] };
  s = applyLoaded(s, { block: undone, etag: "etag-2" }, sandboxConfigEqual);
  assert.equal(s.etag, "etag-2");
  assert.deepEqual(s.draft, undone);
  assert.equal(isDirty(s, sandboxConfigEqual), false);
});

test("a 409 Save reads in plain words and offers the reload", () => {
  const conflict = saveErrorView(new ApiError(409, "/api/terminal/sandbox/config", '{"error":"config_changed","etag":"etag-2"}'));
  assert.equal(conflict.conflict, true);
  assert.equal(conflict.message, CONFIG_CONFLICT_MSG);
  assert.ok(!conflict.message.includes("api 409"));
  assert.ok(!conflict.message.includes("{"));
  const other = saveErrorView(new Error("network down"));
  assert.deepEqual(other, { message: "network down", conflict: false });
});
