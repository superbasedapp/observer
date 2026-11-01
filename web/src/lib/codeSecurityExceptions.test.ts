import { test } from "node:test";
import assert from "node:assert/strict";
import {
  baselineApproveBody,
  baselineCommitLabel,
  exceptionGrantBody,
  exceptionStateLabel,
  githooksStateLabel,
  provenanceKeyLabel,
  provenanceLinesLabel,
  provenanceVerificationLabel,
  historySummary,
  pickerLabel,
  type BaselineCommit,
  type SecurityException,
} from "./codeSecurityExceptions.ts";

const pickers = {
  reasons: [
    { id: "false_positive", label: "Not a real problem (false positive)" },
    { id: "test_fixture", label: "Test fixture or example data" },
  ],
  expiries: [
    { id: "7d", label: "7 days" },
    { id: "until_change", label: "Until the file changes (at most 90 days)" },
  ],
};

test("a grant body only carries the server's picker ids", () => {
  assert.deepEqual(exceptionGrantBody("F1", "false_positive", "7d", pickers), {
    finding_id: "F1",
    reason: "false_positive",
    expiry: "7d",
  });
  assert.equal(exceptionGrantBody("F1", "because I say so", "7d", pickers), null);
  assert.equal(exceptionGrantBody("F1", "false_positive", "never", pickers), null);
  assert.equal(exceptionGrantBody("", "false_positive", "7d", pickers), null);
});

const commits: BaselineCommit[] = [
  { sha: "b".repeat(40), when: "2026-10-20T10:00:00Z", subject: "base", merge_base: true },
  { sha: "a".repeat(40), when: "2026-10-21T10:00:00Z", subject: "fix   the\tthing", merge_base: false },
];

test("a baseline approval names only a commit the picker offered", () => {
  assert.deepEqual(baselineApproveBody("p", "a".repeat(40), commits), { project: "p", action: "approve", commit: "a".repeat(40) });
  assert.equal(baselineApproveBody("p", "HEAD", commits), null);
  assert.equal(baselineApproveBody("", "a".repeat(40), commits), null);
});

test("picker and state labels", () => {
  assert.equal(baselineCommitLabel(commits[0]), "bbbbbbbbbbbb 2026-10-20 base (merge base, proposed)");
  assert.equal(baselineCommitLabel(commits[1]), "aaaaaaaaaaaa 2026-10-21 fix the thing");
  const e: SecurityException = {
    id: 1,
    finding_id: "F",
    project_root_hash: "p",
    rule_id: "S-721",
    rel_path: "a.go",
    reason: "test_fixture",
    expiry: "until_change",
    expires_at: "",
    granted_by: "cli",
    granted_at: "",
  };
  assert.equal(exceptionStateLabel(e), "applies");
  assert.equal(exceptionStateLabel({ ...e, ended_at: "x", end_reason: "file_changed" }), "ended: the file changed");
  assert.equal(pickerLabel(pickers.reasons, "test_fixture"), "Test fixture or example data");
  assert.equal(pickerLabel(pickers.reasons, "other"), "other");
});

test("a history scan that did not finish never reads as clean", () => {
  const r = { commits: 3, unknown: 0, remaining: 0, hits: 1, new_findings: 1 };
  assert.equal(historySummary(r, true), "3 commit(s) read, 1 secret hit(s), 1 new finding(s).");
  assert.match(historySummary({ ...r, remaining: 5 }, false), /Not a clean answer\.$/);
});

test("git hook state labels", () => {
  assert.equal(githooksStateLabel({ hook: "pre-commit", installed: true, foreign: true }), "installed, with your own hook");
  assert.equal(githooksStateLabel({ hook: "pre-push", installed: false, foreign: false }), "not installed");
  assert.equal(
    githooksStateLabel({ hook: "pre-push", installed: false, outdated: true, foreign: false }),
    "outdated (an earlier version's block; install again to update it)",
  );
});

test("AI change record labels: human unmeasured is never zero", () => {
  assert.match(provenanceKeyLabel(undefined), /No signing key yet/);
  assert.equal(
    provenanceKeyLabel({ id: "0123456789abcdef0123", storage: "file_key", attestation: "self_attested", created_at: "2026-10-21T10:00:00Z", rotation: "rotate_age" }),
    "Signing key 0123456789ab in a protected file on this machine (no keychain here), made 2026-10-21. Rotation is due.",
  );
  const r = { commit: "a", committed_at: "", ai_lines: 4, human_lines: 0, unknown_lines: 2, human_capture: "none", sessions: [], note_written: false, verification: "verified" };
  assert.equal(provenanceLinesLabel(r), "4 AI, human not measured, 2 unknown");
  assert.equal(provenanceLinesLabel({ ...r, human_capture: "vscode", human_lines: 1 }), "4 AI, 1 human, 2 unknown");
  assert.equal(provenanceVerificationLabel({ ...r, verification: "verified" }), "signature verified");
  assert.equal(
    provenanceVerificationLabel({ ...r, verification: "verification_failed", verification_reason: "key_revoked" }),
    "verification failed (key_revoked)",
  );
});
