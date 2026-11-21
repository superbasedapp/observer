// Pins the dashboard's initiator labels (lane cli-2): the closed set the
// daemon records, the same words as the CLI's STARTED BY column.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { TERMINAL_INITIATOR_LABELS, initiatorLabel, isAgentInitiated } from "./terminalInitiator.ts";

test("each recorded initiator has its label; none recorded is empty", () => {
  assert.equal(initiatorLabel("agent"), "agent");
  assert.equal(initiatorLabel("human_dashboard"), "you (dashboard)");
  assert.equal(initiatorLabel("human_cli"), "you (cli)");
  assert.equal(initiatorLabel("unknown"), "unknown");
  assert.equal(initiatorLabel(undefined), "");
  assert.equal(initiatorLabel(""), "");
  assert.equal(initiatorLabel("something-new"), "something-new");
  assert.equal(isAgentInitiated("agent"), true);
  assert.equal(isAgentInitiated("human_cli"), false);
});

test("the labels match the CLI's table and the daemon's closed set", () => {
  const cli = readFileSync(new URL("../../../cmd/observer/launch_cli.go", import.meta.url), "utf8");
  const vocab = readFileSync(new URL("../../../internal/termrun/initiator.go", import.meta.url), "utf8");
  for (const [id, label] of Object.entries(TERMINAL_INITIATOR_LABELS)) {
    assert.ok(vocab.includes(`Initiator = "${id}"`), `${id} is not in internal/termrun's closed set`);
    assert.ok(cli.includes(`"${label}"`), `the CLI does not label an initiator "${label}"`);
  }
});
