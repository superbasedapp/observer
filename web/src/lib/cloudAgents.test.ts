// Pins the Cloud agents card's pure model (lib/cloudAgents.ts, lane CA-B5):
// every vocabulary value has a glyph, an unknown value is never guessed into a
// known one, a missing figure is never drawn as zero, the connect form's
// required-field rules (pickers for closed lists), the key only in the body,
// and the user picker's options and hints. No em dashes in any copy.
import assert from "node:assert/strict";
import test from "node:test";

import { VOCAB_ICONS } from "../../../shared/lib/vocabIcons.ts";
import {
  COVERAGE,
  ERROR_CLASS,
  GROUNDING,
  SIGNAL_LABEL,
  USER_STATE,
  accountPath,
  checkConnectForm,
  connectBody,
  coverageEntry,
  errorEntry,
  gapText,
  lastPassText,
  needsLabel,
  needsUser,
  paramControl,
  probeText,
  syncText,
  taskCounts,
  userNotes,
  userOptions,
  type CloudAgentAccount,
  type CloudAgentConnector,
  type CloudAgentSync,
  type CloudAgentUsers,
} from "./cloudAgents.ts";

function connector(over: Partial<CloudAgentConnector> = {}): CloudAgentConnector {
  return {
    id: "codex-cloud",
    label: "Codex Cloud",
    provider: "openai",
    tool: "codex",
    kind: "cli",
    command: "codex",
    experimental: true,
    placeholder_project: "[codex-cloud]",
    placeholder_note: "repository not reported",
    signals: [],
    doc_ref: "",
    needs_key: false,
    params: [],
    grounding: "live_verified",
    grounding_label: "Live verified",
    grounding_rank: 0,
    grounding_meaning: "A live run confirmed it.",
    chooses_user: false,
    ...over,
  };
}

const devin = connector({
  id: "devin",
  label: "Devin",
  kind: "api",
  command: undefined,
  needs_key: true,
  key_label: "Devin key",
  params: [{ name: "org_id", label: "Organization id", hint: "org-<32 hex>" }],
  hosts: ["api.devin.ai"],
  chooses_user: true,
  user_label: "Devin user",
});

const qoder = connector({
  id: "qoder-cloud",
  label: "Qoder",
  kind: "api",
  needs_key: true,
  params: [
    {
      name: "region",
      label: "Region",
      hint: "",
      choices: [
        { value: "global", label: "Global" },
        { value: "cn", label: "China" },
      ],
    },
  ],
});

function account(over: Partial<CloudAgentAccount> = {}): CloudAgentAccount {
  return {
    id: 3,
    connector: "codex-cloud",
    label: "Codex Cloud",
    provider: "openai",
    account_id: "user-1",
    coverage: "verified",
    gaps: [],
    activity_gaps: 0,
    open_tasks: 0,
    waiting: 0,
    owed: 0,
    signals: [],
    linked_at: "2026-11-01T00:00:00Z",
    ...over,
  };
}

test("every vocabulary value has a glyph under the vocabulary it renders with", () => {
  const rows: [Record<string, unknown>, Record<string, unknown>][] = [
    [COVERAGE, VOCAB_ICONS.cloudAgentCoverage],
    [ERROR_CLASS, VOCAB_ICONS.cloudAgentError],
    [GROUNDING, VOCAB_ICONS.cloudAgentGrounding],
    [USER_STATE, VOCAB_ICONS.cloudAgentUser],
  ];
  for (const [table, icons] of rows) {
    for (const k of Object.keys(table)) assert.ok(icons[k], `no glyph for ${k}`);
    for (const k of Object.keys(icons)) assert.ok(table[k], `no tone for ${k}`);
  }
});

test("the coverage and error vocabularies match the server's closed sets", () => {
  assert.deepEqual(Object.keys(COVERAGE).sort(), [
    "available_to_configure",
    "delayed_reporting",
    "disconnected",
    "not_established",
    "partial_history",
    "permission_required",
    "verified",
  ]);
  assert.deepEqual(Object.keys(ERROR_CLASS).sort(), [
    "failed",
    "host_not_allowed",
    "invalid",
    "not_installed",
    "not_signed_in",
    "over_cap",
    "permission_denied",
    "rate_limited",
    "server_error",
    "stream_expired",
    "stream_resume_refused",
    "timeout",
    "unreachable",
    "wrong_shape",
  ]);
  assert.deepEqual(Object.keys(SIGNAL_LABEL), ["discovery", "identity", "activity", "tokens", "usage", "billing", "control"]);
});

test("an unknown class or state keeps its raw token, never a known label", () => {
  assert.equal(errorEntry("brand_new").label, "brand_new");
  assert.equal(coverageEntry("brand_new").label, "brand_new");
  assert.equal(coverageEntry("").label, "Unknown");
  assert.equal(errorEntry("not_signed_in").label, "Not signed in");
});

test("a pass that never ran is null, never a time or a zero", () => {
  const fmt = (s: string) => `at ${s}`;
  assert.equal(lastPassText(account(), fmt), null);
  assert.equal(
    lastPassText(account({ last_attempt: "2026-11-02T10:00:00Z", last_success: "2026-11-02T10:00:00Z" }), fmt),
    "Last pass at 2026-11-02T10:00:00Z, succeeded",
  );
  assert.equal(
    lastPassText(account({ last_attempt: "2026-11-02T11:00:00Z", last_success: "2026-11-02T10:00:00Z" }), fmt),
    "Last pass at 2026-11-02T11:00:00Z, failed; last success at 2026-11-02T10:00:00Z",
  );
  assert.equal(lastPassText(account({ last_attempt: "2026-11-02T11:00:00Z" }), fmt), "Last pass at 2026-11-02T11:00:00Z, no success yet");
});

test("task counts and gaps are omitted when there are none", () => {
  assert.equal(taskCounts(account()), null);
  assert.equal(taskCounts(account({ open_tasks: 2, owed: 1 })), "2 running, 1 finished with a read still owed");
  assert.equal(gapText(account()), null);
  assert.equal(gapText(account({ gaps: null })), null);
  assert.equal(
    gapText(
      account({
        gaps: [
          { from: "a", to: "b" },
          { from: "a", to: "b", scope: "run x/y" },
          { from: "a", to: "b", scope: "run x/z" },
        ],
      }),
    ),
    "1 discovery gap, 2 run streams could not be resumed",
  );
});

test("a closed parameter list is a picker; an open one is a field", () => {
  assert.equal(paramControl(qoder.params![0]), "select");
  assert.equal(paramControl(devin.params![0]), "text");
});

test("the connect form names the missing field in plain words", () => {
  assert.deepEqual(checkConnectForm(undefined, "", {}), { ok: false, reason: "Choose a connector." });
  assert.deepEqual(checkConnectForm(connector(), "", {}), { ok: true });
  assert.deepEqual(checkConnectForm(devin, "", { org_id: "org-1" }), { ok: false, reason: "Paste the API key." });
  assert.deepEqual(checkConnectForm(devin, "a b", { org_id: "org-1" }), {
    ok: false,
    reason: "The key cannot contain spaces or line breaks.",
  });
  assert.deepEqual(checkConnectForm(devin, "cog_x", {}), { ok: false, reason: "Enter the organization id." });
  assert.deepEqual(checkConnectForm(qoder, "k", {}), { ok: false, reason: "Choose the region." });
  assert.deepEqual(checkConnectForm(qoder, "k", { region: "mars" }), { ok: false, reason: "Choose the region from the list." });
  assert.deepEqual(checkConnectForm(qoder, "k", { region: "cn" }), { ok: true });
});

test("the key rides in the body only for a connector that needs one", () => {
  assert.deepEqual(connectBody(connector(), "leftover", {}), { connector: "codex-cloud" });
  assert.deepEqual(connectBody(devin, "  cog_abc \n", { org_id: " org-1 ", extra: "x" }), {
    connector: "devin",
    key: "cog_abc",
    params: { org_id: "org-1" },
  });
  assert.equal(accountPath(7, "users"), "/api/cloud-agents/accounts/7/users");
});

test("what a connector needs is said from the catalog, not its id", () => {
  assert.equal(needsLabel(connector()), "your signed-in codex CLI");
  assert.equal(needsLabel(devin), "an API key, organization id and choosing your Devin user");
  // Any connector declaring member users gets the picker (OpenHands, Warp ...).
  const other = connector({ id: "openhands-cloud", needs_key: true, chooses_user: true, user_label: "OpenHands user" });
  assert.equal(needsUser(account({ connector: "openhands-cloud", user_state: "vendor_user_not_chosen" }), other), true);
  assert.equal(needsUser(account({ user_state: "vendor_user_chosen" }), other), false);
  assert.equal(needsUser(account({ user_state: "vendor_user_not_chosen" }), connector()), false);
});

test("probe and pass sentences carry the error class", () => {
  assert.equal(probeText({ connector: "x", ok: true, coverage: "verified", display: "me@x.dev" }), "It works: reached me@x.dev.");
  assert.match(probeText({ connector: "x", ok: false, coverage: "disconnected", error_class: "not_signed_in" }), /^Check failed: Not signed in\./);
  const base: CloudAgentSync = {
    account: 1,
    connector: "x",
    pages: 1,
    tasks: 3,
    sessions_touched: 2,
    actions_inserted: 0,
    partial: false,
    coverage: "verified",
    open_tasks: 0,
    waiting: 0,
    owed: 0,
  };
  assert.equal(syncText(base), "Pass done: 3 sessions seen, 2 updated.");
  assert.match(syncText({ ...base, error_class: "rate_limited" }), /^Pass failed: Rate limited\./);
  assert.equal(syncText({ ...base, user_state: "vendor_user_not_chosen" }), "Nothing pulled: choose your user first.");
});

test("the user picker lists candidates and keeps the current choice", () => {
  const u: CloudAgentUsers = {
    account: 3,
    connector: "devin",
    user_label: "Devin user",
    chosen: "user-old",
    candidates: [
      { user_id: "user-a", username: "alice", sessions: 4 },
      { user_id: "user-b", sessions: 1 },
    ],
    more: true,
    service_user_sessions: 2,
    no_user_sessions: 0,
    message_reads: 1,
  };
  assert.deepEqual(userOptions(u), [
    { value: "user-old", label: "user-old (current choice, not on the first page)" },
    { value: "user-a", label: "alice (4 sessions on the first page)" },
    { value: "user-b", label: "user-b (1 session on the first page)" },
  ]);
  const notes = userNotes(u);
  assert.equal(notes.length, 2);
  assert.match(notes[0], /first page/);
  assert.match(notes[1], /2 listed sessions were started by a service user/);
  assert.deepEqual(userOptions({ ...u, candidates: null, chosen: undefined }), []);
});

test("no copy in the model carries an em dash", () => {
  const all = [
    ...Object.values(COVERAGE).flatMap((e) => [e.label ?? "", e.tip]),
    ...Object.values(ERROR_CLASS).flatMap((e) => [e.label ?? "", e.tip]),
    ...Object.values(USER_STATE).flatMap((e) => [e.label ?? "", e.tip]),
    ...Object.values(SIGNAL_LABEL),
  ];
  for (const s of all) assert.ok(!s.includes("\u2014"), `em dash in ${s}`);
});
