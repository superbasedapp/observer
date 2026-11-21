// Pins the MCP reputation card's model (mcpReputation.ts, T-496) and the
// guard cloud consent card's model (B-G5, decision P-2).
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  GUARD_CLOUD_FEATURES,
  GUARD_CLOUD_WEBHOOK_SOURCE,
  guardCloudAllOff,
  guardCloudConsentNote,
  guardCloudDisclosure,
  guardCloudFeatureState,
  guardCloudRestartNeeded,
  guardCloudSavedLine,
  guardCloudStopNote,
  guardCloudTurnOff,
  guardCloudTurnOn,
  judgeFieldChanges,
  judgeFieldsProblem,
  optInLine,
  validPackageName,
  type GuardCloudState,
} from "./mcpReputation.ts";

test("the opt-in line points at the consent card, never at config.toml", () => {
  assert.equal(optInLine({ cloud_enabled: true, reputation_enabled: true }), "");
  for (const s of [
    { cloud_enabled: false, reputation_enabled: true },
    { cloud_enabled: true, reputation_enabled: false },
    { cloud_enabled: false, reputation_enabled: false },
  ]) {
    const line = optInLine(s);
    assert.match(line, /Network features/);
    assert.ok(!/config\.toml|\[guard\.cloud\]/.test(line), line);
  }
});

test("package names are checked like the server checks them", () => {
  assert.equal(validPackageName("@modelcontextprotocol/server-filesystem"), true);
  assert.equal(validPackageName("  left-pad "), true);
  assert.equal(validPackageName(""), false);
  assert.equal(validPackageName("a b"), false);
  assert.equal(validPackageName("x".repeat(215)), false);
});

// A daemon answer: every feature off, one webhook in config.toml.
function state(over: Partial<GuardCloudState> = {}): GuardCloudState {
  return {
    cloud_enabled: false,
    guard_active: true,
    payload_max_bytes: 4096,
    field_limit: 200,
    reputation: { enabled: false, active: false, destination: "https://registry.npmjs.org/" },
    llm_judge: {
      enabled: false,
      active: false,
      endpoint: "",
      endpoint_host: "",
      model: "",
      api_key_env: "",
      api_key_set: false,
      fields: ["rule_id", "category", "severity", "decision", "event_kind", "tool", "reason", "target_excerpt", "taint_origin"],
      confidence_floor: 0.7,
      approval_ttl_minutes: 60,
    },
    webhooks: {
      active: false,
      hooks: [{ kind: "slack", host: "hooks.slack.com", min_severity: "high", has_routing_key: false }],
      fields: ["rule_id", "category", "severity", "decision", "tool", "enforced", "reason", "timestamp", "source"],
    },
    ...over,
  };
}

test("a feature reads on only when it would send", () => {
  const s = state();
  assert.deepEqual(GUARD_CLOUD_FEATURES.map((f) => guardCloudFeatureState(s, f)), ["off", "off", "off"]);
  assert.equal(guardCloudFeatureState(state({ webhooks: { active: false, hooks: [], fields: [] } }), "webhooks"), "none_configured");
  const on = state({ cloud_enabled: true, reputation: { enabled: true, active: true, destination: "x" } });
  assert.equal(guardCloudFeatureState(on, "reputation"), "on");
});

test("turning a feature on with the master off names everything else it starts", () => {
  const rows: { name: string; s: GuardCloudState; f: "reputation" | "llm_judge" | "webhooks"; patch: object; starts: string[] }[] = [
    {
      name: "reputation, master off, a webhook configured",
      s: state(),
      f: "reputation",
      patch: { cloud_enabled: true, reputation_enabled: true },
      starts: ["webhooks"],
    },
    {
      name: "reputation, master already on",
      s: state({ cloud_enabled: true, webhooks: { ...state().webhooks, active: true } }),
      f: "reputation",
      patch: { reputation_enabled: true },
      starts: [],
    },
    {
      name: "webhooks turn on through the master switch",
      s: state({ reputation: { enabled: true, active: false, destination: "x" } }),
      f: "webhooks",
      patch: { cloud_enabled: true },
      starts: ["reputation"],
    },
  ];
  for (const r of rows) {
    const c = guardCloudTurnOn(r.s, r.f);
    assert.deepEqual(c.patch, r.patch, r.name);
    assert.deepEqual(c.alsoStarts, r.starts, r.name);
    if (r.starts.length > 0) assert.match(guardCloudConsentNote(r.s, r.f, c), /also turns on the master switch/, r.name);
  }
  const judge = guardCloudTurnOn(state(), "llm_judge", { endpoint: "https://llm.example.com/v1", model: "m", api_key_env: "" });
  assert.deepEqual(judge.patch, { cloud_enabled: true, llm_judge: { enabled: true, endpoint: "https://llm.example.com/v1", model: "m" } });
});

test("turning off needs one switch; webhooks go off with the master and say what else stops", () => {
  const s = state({
    cloud_enabled: true,
    reputation: { enabled: true, active: true, destination: "x" },
    webhooks: { ...state().webhooks, active: true },
  });
  assert.deepEqual(guardCloudTurnOff(s, "reputation").patch, { reputation_enabled: false });
  assert.equal(guardCloudStopNote(guardCloudTurnOff(s, "reputation")), "");
  assert.deepEqual(guardCloudTurnOff(s, "llm_judge").patch, { llm_judge: { enabled: false } });
  const wh = guardCloudTurnOff(s, "webhooks");
  assert.deepEqual(wh.patch, { cloud_enabled: false });
  assert.deepEqual(wh.alsoStops, ["reputation"]);
  assert.match(guardCloudStopNote(wh), /also stops Reputation lookups/);
  assert.deepEqual(guardCloudAllOff(s).alsoStops, ["reputation", "webhooks"]);
});

test("only the judge and webhooks wait for a restart", () => {
  assert.equal(guardCloudRestartNeeded(guardCloudTurnOff(state(), "reputation"), "reputation"), false);
  const master = state({ webhooks: { active: false, hooks: [], fields: [] } });
  assert.equal(guardCloudRestartNeeded(guardCloudTurnOn(master, "reputation"), "reputation"), false);
  assert.equal(guardCloudRestartNeeded(guardCloudTurnOn(state(), "reputation"), "reputation"), true, "it also starts a webhook");
  assert.equal(guardCloudRestartNeeded(guardCloudTurnOff(state(), "llm_judge"), "llm_judge"), true);
  assert.match(guardCloudSavedLine("reputation", true, false), /look a package up now/);
  assert.match(guardCloudSavedLine("llm_judge", true, true), /after the daemon restarts/);
});

test("the judge form keeps unchanged fields out and mirrors the daemon's refusals", () => {
  const s = state({ llm_judge: { ...state().llm_judge, endpoint: "https://a.example/v1", model: "m" } });
  assert.deepEqual(judgeFieldChanges(s, { endpoint: "https://a.example/v1", model: "m2", api_key_env: "" }), { model: "m2" });
  const rows: [string, boolean][] = [
    ["https://llm.example.com/v1/chat/completions", true],
    ["http://localhost:4000/v1", true],
    ["http://127.0.0.1:11434/v1", true],
    ["http://[::1]:8080/v1", true],
    ["http://10.0.0.5/v1", false],
    ["https://u:p@llm.example.com", false],
    ["llm.example.com", false],
    ["", false],
  ];
  for (const [endpoint, ok] of rows) {
    assert.equal(judgeFieldsProblem({ endpoint, model: "", api_key_env: "" }) === "", ok, endpoint);
  }
  assert.match(judgeFieldsProblem({ endpoint: "https://a.example", model: "", api_key_env: "sk-live-1" }), /NAME of an environment variable/);
});

test("each disclosure says what is sent where, from the daemon's facts, with no CLI dead end", () => {
  const s = state({ llm_judge: { ...state().llm_judge, endpoint: "https://llm.example.com/v1", api_key_env: "JUDGE_KEY" } });
  const rep = guardCloudDisclosure(s, "reputation");
  assert.match(rep.to, /registry\.npmjs\.org/);
  const judge = guardCloudDisclosure(s, "llm_judge");
  assert.match(judge.to, /llm\.example\.com/);
  for (const f of s.llm_judge.fields) assert.ok(judge.sends.includes(f), f);
  assert.match(judge.sends, /200 characters/);
  assert.match(judge.sends, /4096 bytes/);
  assert.match(judge.sends, /JUDGE_KEY \(not set/);
  assert.match(judge.effect ?? "", /60-minute approval/);
  const wh = guardCloudDisclosure(s, "webhooks");
  assert.match(wh.to, /hooks\.slack\.com \(slack, high and above\)/);
  for (const f of s.webhooks.fields) assert.ok(wh.sends.includes(f), f);
  for (const d of [rep, judge, wh]) {
    const text = `${d.to} ${d.sends} ${d.when} ${d.effect ?? ""}`;
    assert.ok(!/observer guard|run `/.test(text), text);
    assert.ok(!/[—–]/.test(text), `dash in ${text}`);
  }
  assert.match(GUARD_CLOUD_WEBHOOK_SOURCE, /credentials/);
});
