import assert from "node:assert/strict";
import test from "node:test";

import {
  acceptAllBody,
  acceptNote,
  acceptOffered,
  acceptOneBody,
  pendingReasons,
  reasonLine,
  trustChip,
  trustPath,
} from "./trustChip.ts";

// Security Phase B: the New Terminal trust chip.

test("trustPath encodes the directory", () => {
  assert.equal(trustPath("/home/u/my repo"), "/api/security/trust?dir=%2Fhome%2Fu%2Fmy%20repo");
});

test("trustChip words each verdict and renders nothing without a reply", () => {
  assert.equal(trustChip(null), null);
  assert.equal(trustChip({ verdict: "clean", codes: [], pending: 0, reasons: [] })?.tone, "ok");
  const flagged = trustChip({ verdict: "flagged", codes: ["git_hookspath"], pending: 0, truncated: true, reasons: [] });
  assert.equal(flagged?.tone, "warn");
  assert.match(flagged?.detail ?? "", /git_hookspath.*not read/);
  const untrusted = trustChip({ verdict: "untrusted", codes: ["mcp_server_command"], pending: 2, reasons: [] });
  assert.equal(untrusted?.tone, "danger");
  assert.match(untrusted?.detail ?? "", /2 item\(s\) not accepted yet: review and accept them below/);
  assert.doesNotMatch(untrusted?.detail ?? "", /observer security trust/);
  assert.equal(trustChip({ verdict: "weird", codes: [], pending: 0, reasons: [] }), null);
});

test("the review panel accepts from the dialog, never only from the CLI", () => {
  const reply = {
    verdict: "untrusted",
    codes: ["mcp_server_command", "git_command_key"],
    pending: 2,
    reasons: [
      { code: "mcp_server_command", level: "untrusted", file: ".mcp.json", key: "mcpServers.x", digest: "sha256:aa" },
      { code: "git_command_key", level: "untrusted", file: ".git/config", key: "core.sshcommand", digest: "sha256:bb", local: true },
      { code: "hook_command", level: "flagged", file: ".claude/settings.json", digest: "sha256:cc", accepted: true },
      { code: "truncated", level: "flagged", file: ".claude/commands/*.md" },
    ],
  };
  assert.deepEqual(
    pendingReasons(reply).map((r) => r.digest),
    ["sha256:aa", "sha256:bb"],
  );
  // "Accept all" names the digests it displayed, never "all": the server
  // accepts exactly those, so a truncated result is no longer a dead end.
  assert.deepEqual(acceptAllBody("/r", reply), { dir: "/r", digests: ["sha256:aa", "sha256:bb"] });
  assert.deepEqual(acceptAllBody("/r", { ...reply, truncated: true }), { dir: "/r", digests: ["sha256:aa", "sha256:bb"] });
  assert.equal(acceptAllBody("/r", { ...reply, reasons: [reply.reasons[2], reply.reasons[3]] }), null);
  assert.equal(acceptAllBody("/r", null), null);
  assert.deepEqual(acceptOneBody("/r", reply.reasons[0]), { dir: "/r", digests: ["sha256:aa"] });
  assert.equal(acceptOneBody("/r", reply.reasons[2]), null);
  assert.equal(acceptOneBody("/r", reply.reasons[3]), null);
  assert.match(reasonLine(reply.reasons[1]), /\(local settings file\)$/);
  assert.doesNotMatch(reasonLine(reply.reasons[1]), /your own/);
  assert.equal(reasonLine(reply.reasons[3]), "flagged truncated: .claude/commands/*.md");
});

test("a managed node whose organization hides Code security: no Accept, a note saying who can accept", () => {
  const note = "Accepting is not offered in this dashboard: Acme manages the Code security page on this machine.";
  const reply = {
    verdict: "untrusted",
    codes: ["mcp_server_command"],
    pending: 1,
    accept_allowed: false,
    accept_note: note,
    reasons: [{ code: "mcp_server_command", level: "untrusted", file: ".mcp.json", digest: "sha256:aa" }],
  };
  // The review still lists the item; only the accept goes.
  assert.equal(pendingReasons(reply).length, 1);
  assert.equal(acceptOffered(reply), false);
  assert.equal(acceptAllBody("/r", reply), null);
  assert.equal(acceptNote(reply), note);
  const chip = trustChip(reply);
  assert.match(chip?.detail ?? "", /review them below/);
  assert.doesNotMatch(chip?.detail ?? "", /accept them below/);
  // No note on the reply: a fallback that still names the terminal accept.
  assert.match(acceptNote({ ...reply, accept_note: undefined }) ?? "", /observer security trust accept/);
});

test("Accept is offered when the reply allows it or an older daemon omits the field", () => {
  const base = { verdict: "untrusted", codes: [], pending: 1, reasons: [] };
  assert.equal(acceptOffered({ ...base, accept_allowed: true }), true);
  assert.equal(acceptOffered(base), true);
  assert.equal(acceptNote(base), null);
  assert.equal(acceptOffered(null), false);
});
