// The MCP package reputation control's pure model (T-496): the shapes of
// GET / POST /api/guard/mcp/reputation and the lines the card renders. The
// lookup itself is the server's notify.LookupNPMReputation, the function
// `observer guard mcp reputation` runs.
//
// It also holds the guard cloud consent card's model (plan
// docs/plans/dashboard-cli-parity-plan-2026-11-06.md, B-G5, decision P-2):
// GET / PUT /api/guard/cloud, which turns the guard's network features
// (reputation lookups, the LLM judge, the webhooks) on and off. Every
// disclosure line is built from facts the daemon serves (the fields the
// builders send, the bounds, the destinations), never written from memory.

/** GET /api/guard/mcp/reputation. */
export type MCPReputationStatus = {
  cloud_enabled: boolean;
  reputation_enabled: boolean;
  available: boolean;
  registry: string;
  young_days: number;
  off_reason: string;
  confirm_token: string;
};

/** POST /api/guard/mcp/reputation (200). */
export type MCPReputationResult = {
  package: string;
  name: string;
  description?: string;
  latest: string;
  version_count: number;
  created_at?: string;
  modified_at?: string;
  age_days: number;
  maintainers: number;
  /** The CLI's own rendering, line for line. */
  lines: string[];
  young: boolean;
  warning?: string;
};

/** optInLine says what is still needed before a lookup can run, or "" when none is. */
export function optInLine(s: Pick<MCPReputationStatus, "cloud_enabled" | "reputation_enabled">): string {
  if (s.cloud_enabled && s.reputation_enabled) return "";
  return "Off until you turn on Reputation lookups in Network features above. Nothing is looked up before that.";
}

/** validPackageName mirrors the server's check: one non-empty name, no spaces, at most 214 characters. */
export function validPackageName(name: string): boolean {
  const n = name.trim();
  return n.length > 0 && n.length <= 214 && !/\s/.test(n);
}

// ---------------------------------------------------------------- guard cloud

/** One configured webhook, without its credential parts (host only). */
export type GuardCloudWebhook = { kind: string; host: string; min_severity: string; has_routing_key: boolean };

/** GET /api/guard/cloud (and the `state` a PUT returns). */
export type GuardCloudState = {
  cloud_enabled: boolean;
  /** [guard] on with a mode other than off: the judge and webhooks need it. */
  guard_active: boolean;
  payload_max_bytes: number;
  field_limit: number;
  reputation: { enabled: boolean; active: boolean; destination: string };
  llm_judge: {
    enabled: boolean;
    active: boolean;
    endpoint: string;
    endpoint_host: string;
    model: string;
    api_key_env: string;
    api_key_set: boolean;
    fields: string[];
    confidence_floor: number;
    approval_ttl_minutes: number;
  };
  webhooks: { active: boolean; hooks: GuardCloudWebhook[]; fields: string[] };
  confirm_token?: string;
  config_etag?: string;
};

/** The judge's endpoint fields, as the card's form holds them. */
export type GuardCloudJudgeFields = { endpoint: string; model: string; api_key_env: string };

/** PUT /api/guard/cloud body: every field optional. */
export type GuardCloudPatch = {
  cloud_enabled?: boolean;
  reputation_enabled?: boolean;
  llm_judge?: { enabled?: boolean } & Partial<GuardCloudJudgeFields>;
};

export type GuardCloudFeature = "reputation" | "llm_judge" | "webhooks";

/** A feature's state on the card. */
export type GuardCloudFeatureState = "on" | "off" | "none_configured";

export const GUARD_CLOUD_FEATURES: readonly GuardCloudFeature[] = ["reputation", "llm_judge", "webhooks"];

export const GUARD_CLOUD_TITLES: Readonly<Record<GuardCloudFeature, string>> = {
  reputation: "Reputation lookups",
  llm_judge: "LLM judge",
  webhooks: "Webhooks",
};

/** guardCloudFeatureState: on only when it would actually send (the master switch included). */
export function guardCloudFeatureState(s: GuardCloudState, f: GuardCloudFeature): GuardCloudFeatureState {
  switch (f) {
    case "reputation":
      return s.reputation.active ? "on" : "off";
    case "llm_judge":
      return s.llm_judge.active ? "on" : "off";
    case "webhooks":
      if (s.webhooks.hooks.length === 0) return "none_configured";
      return s.webhooks.active ? "on" : "off";
  }
}

/** The features that would start sending if the master switch came on, other than `except`. */
function armedByMaster(s: GuardCloudState, except: GuardCloudFeature): GuardCloudFeature[] {
  if (s.cloud_enabled) return [];
  const out: GuardCloudFeature[] = [];
  if (except !== "reputation" && s.reputation.enabled) out.push("reputation");
  if (except !== "llm_judge" && s.llm_judge.enabled && s.llm_judge.endpoint) out.push("llm_judge");
  if (except !== "webhooks" && s.webhooks.hooks.length > 0) out.push("webhooks");
  return out;
}

/** A switch change: the PUT body and the other features it starts or stops. */
export type GuardCloudChange = { patch: GuardCloudPatch; alsoStarts: GuardCloudFeature[]; alsoStops: GuardCloudFeature[] };

/**
 * guardCloudTurnOn is the change that turns one feature on. A feature needs
 * the master switch too, so a change with the master off turns it on and
 * names every other feature that would then start sending (a webhook already
 * in config.toml, a judge already set up), so the consent covers them.
 */
export function guardCloudTurnOn(s: GuardCloudState, f: GuardCloudFeature, judge?: GuardCloudJudgeFields): GuardCloudChange {
  const patch: GuardCloudPatch = {};
  if (!s.cloud_enabled) patch.cloud_enabled = true;
  if (f === "reputation") patch.reputation_enabled = true;
  if (f === "llm_judge") patch.llm_judge = { enabled: true, ...(judge ? judgeFieldChanges(s, judge) : {}) };
  return { patch, alsoStarts: armedByMaster(s, f), alsoStops: [] };
}

/**
 * guardCloudTurnOff is the change that turns one feature off. Reputation
 * and the judge have their own switch; webhooks do not (their URLs live in
 * config.toml), so turning them off turns the master switch off, which stops
 * every active feature: those are named.
 */
export function guardCloudTurnOff(s: GuardCloudState, f: GuardCloudFeature): GuardCloudChange {
  if (f === "reputation") return { patch: { reputation_enabled: false }, alsoStarts: [], alsoStops: [] };
  if (f === "llm_judge") return { patch: { llm_judge: { enabled: false } }, alsoStarts: [], alsoStops: [] };
  return guardCloudAllOff(s, "webhooks");
}

/** guardCloudAllOff turns the master switch off and names what else stops. */
export function guardCloudAllOff(s: GuardCloudState, except?: GuardCloudFeature): GuardCloudChange {
  const alsoStops = GUARD_CLOUD_FEATURES.filter((f) => f !== except && guardCloudFeatureState(s, f) === "on");
  return { patch: { cloud_enabled: false }, alsoStarts: [], alsoStops };
}

/** judgeFieldChanges: only the judge fields the form changed (an unchanged field is left out). */
export function judgeFieldChanges(s: GuardCloudState, f: GuardCloudJudgeFields): Partial<GuardCloudJudgeFields> {
  const out: Partial<GuardCloudJudgeFields> = {};
  if (f.endpoint.trim() !== s.llm_judge.endpoint) out.endpoint = f.endpoint.trim();
  if (f.model.trim() !== s.llm_judge.model) out.model = f.model.trim();
  if (f.api_key_env.trim() !== s.llm_judge.api_key_env) out.api_key_env = f.api_key_env.trim();
  return out;
}

/** judgeFieldsProblem mirrors the daemon's refusals for the form (the daemon checks again). */
export function judgeFieldsProblem(f: GuardCloudJudgeFields): string {
  const ep = f.endpoint.trim();
  if (!ep) return "Set the endpoint the judge is reached at.";
  let u: URL;
  try {
    u = new URL(ep);
  } catch {
    return "The endpoint must be a full http(s) URL, for example https://llm.example.com/v1/chat/completions.";
  }
  if (u.protocol !== "https:" && u.protocol !== "http:") return "The endpoint must be an http(s) URL.";
  if (u.username || u.password) return "Put no user name or password in the endpoint; name the key's environment variable instead.";
  const host = u.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  const loopback = host === "localhost" || host.endsWith(".localhost") || host === "::1" || /^127\./.test(host);
  if (u.protocol === "http:" && !loopback) return "A judge on another machine must use https; plain http is for this machine only.";
  const env = f.api_key_env.trim();
  if (env && !/^[A-Za-z_][A-Za-z0-9_]{0,127}$/.test(env)) {
    return "The key setting takes the NAME of an environment variable (letters, digits and _), never the key itself.";
  }
  return "";
}

/**
 * guardCloudRestartNeeded: the judge and the webhooks run in the daemon's
 * guard event sweep, built at start, so a change that starts or stops either
 * needs a restart. Reputation lookups read the config on every lookup and
 * work at once.
 */
export function guardCloudRestartNeeded(c: GuardCloudChange, f: GuardCloudFeature): boolean {
  return [f, ...c.alsoStarts, ...c.alsoStops].some((x) => x !== "reputation");
}

/** What a feature sends, where and when: the card's disclosure, from the daemon's facts. */
export type GuardCloudDisclosure = { to: string; sends: string; when: string; effect?: string };

/** guardCloudDisclosure builds one feature's disclosure. */
export function guardCloudDisclosure(s: GuardCloudState, f: GuardCloudFeature): GuardCloudDisclosure {
  const cap = `Secrets are scrubbed from the body before it leaves, and a body over ${s.payload_max_bytes} bytes is not sent.`;
  switch (f) {
    case "reputation":
      return {
        to: `the npm registry (${s.reputation.destination}<package>)`,
        sends: "One HTTPS GET of the package name you look up. No body, nothing about your sessions or code.",
        when: "Only when you press Look up in MCP package reputation below. Nothing looks a package up on its own. Works as soon as it is on.",
      };
    case "llm_judge": {
      const key = s.llm_judge.api_key_env
        ? ` It is authenticated with the key in the environment variable ${s.llm_judge.api_key_env}${s.llm_judge.api_key_set ? "" : " (not set in the daemon's environment)"}.`
        : " No key is sent unless you name an environment variable that holds one.";
      return {
        to: s.llm_judge.endpoint ? `your endpoint ${s.llm_judge.endpoint}` : "the endpoint you set below",
        sends:
          `For each guard verdict that asks or flags (never a deny, never a guard error), one chat request${s.llm_judge.model ? ` to model ${s.llm_judge.model}` : ""} carrying ` +
          `${s.llm_judge.fields.join(", ")}; the reason and target excerpt are cut to ${s.field_limit} characters. ${cap}${key}`,
        when: "On the daemon's sweep of new guard events, while the guard is on. Starts after a daemon restart.",
        effect:
          `A judge "allow" with confidence ${s.llm_judge.confidence_floor} or more on an ask writes a ${s.llm_judge.approval_ttl_minutes}-minute approval ` +
          "of that rule for that session. The judge never denies on its own; every review is recorded as a guard event.",
      };
    }
    case "webhooks": {
      const hosts = s.webhooks.hooks.map((h) => `${h.host} (${h.kind}, ${h.min_severity} and above)`);
      return {
        to: hosts.length > 0 ? hosts.join("; ") : "no webhook is configured",
        sends:
          `For each new guard verdict at or above a webhook's minimum severity: a generic webhook gets ${s.webhooks.fields.join(", ")}; ` +
          "Slack and Discord get one line naming the rule, decision, category, severity, tool and reason; PagerDuty gets that line, the severity and time, " +
          `and rule_id, category, decision, tool and enforced, with your routing key. The reason is cut to ${s.field_limit} characters. ${cap}`,
        when: "On the daemon's sweep of new guard events, while the guard is on. Starts after a daemon restart.",
      };
    }
  }
}

/**
 * GUARD_CLOUD_WEBHOOK_SOURCE is why webhooks are added in config.toml and
 * never here (class C, decision P-4): a webhook URL and a PagerDuty routing
 * key are credentials, which the dashboard neither reads nor writes.
 */
export const GUARD_CLOUD_WEBHOOK_SOURCE =
  "Webhooks are added and removed in config.toml ([[guard.cloud.webhooks]]): a webhook URL and a PagerDuty routing key are credentials, which the dashboard never reads or writes. The master switch turns them all on or off.";

/** guardCloudConsentNote is the turn-on confirm note: what this sends, and what else starts. */
export function guardCloudConsentNote(s: GuardCloudState, f: GuardCloudFeature, c: GuardCloudChange): string {
  const d = guardCloudDisclosure(s, f);
  let note = `Sends to ${d.to}: ${d.sends}`;
  if (d.effect) note += ` ${d.effect}`;
  if (c.alsoStarts.length > 0) {
    note += ` This also turns on the master switch, which starts ${c.alsoStarts.map((x) => GUARD_CLOUD_TITLES[x]).join(" and ")} as configured.`;
  }
  return note;
}

/** guardCloudStopNote names what else a turn-off stops, or "" when it stops nothing else. */
export function guardCloudStopNote(c: GuardCloudChange): string {
  if (c.alsoStops.length === 0) return "";
  return `This turns the master switch off, which also stops ${c.alsoStops.map((x) => GUARD_CLOUD_TITLES[x]).join(" and ")}.`;
}

/** guardCloudSavedLine is the card's line after a save. */
export function guardCloudSavedLine(f: GuardCloudFeature, on: boolean, restart: boolean): string {
  const what = `${GUARD_CLOUD_TITLES[f]} ${on ? "on" : "off"}.`;
  if (restart) return `${what} Saved; it takes effect after the daemon restarts.`;
  return f === "reputation" && on ? `${what} You can look a package up now.` : `${what} Saved.`;
}
