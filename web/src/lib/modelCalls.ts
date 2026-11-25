// modelCalls.ts - the pure model of Your apps > Model calls (hosted AI
// gateway arc, lane L9; the machine's app lane is lane L7's). A lane is a
// loopback address on this machine's proxy (`/up/<id>`) that an app points its
// OpenAI or Anthropic client at, so its model calls are priced exactly, held
// to the app budgets and checked by admission before they leave the machine.
// Off until the user adds a lane, loopback only (decision 8).
//
// Seam S5 (lane L7 owns it): GET /api/apps/lanes, POST /api/apps/lanes,
// DELETE /api/apps/lanes/{id} (owner-local, the confirm token), and
// GET /api/obs/admission/judge. The JSON shapes below are this lane's mock
// until L7 publishes them; every field the page does not strictly need is
// optional, and an unknown field is ignored (the additive rule).
//
// No React, no fetch, no imports besides `import type`: node:test runs it.

/** One app lane as GET /api/apps/lanes lists it. */
export interface AppLane {
  /** The lane id: the `/up/<id>` path segment. */
  id: string;
  /** The provider base URL the lane forwards to (https). */
  upstream: string;
  /** The provider kind, when the daemon names it. */
  kind?: string;
  /** The client family to configure: openai or anthropic. */
  client?: string;
  /** The lane's own address, e.g. http://127.0.0.1:8820/up/openai. */
  base_url: string;
  /** The value for the client's base URL option, when the daemon gives it. */
  client_base_url?: string;
  /** The models the lane forwards; empty or absent means any model. */
  models?: string[] | null;
  /** The app service the lane's calls are counted under. */
  service?: string;
  /** False when the lane is configured but not serving. */
  enabled?: boolean;
}

/** GET /api/apps/lanes. */
export interface AppLanesResult {
  lanes: AppLane[] | null;
  /** The proxy's listen address, e.g. 127.0.0.1:8820. */
  proxy_listen?: string;
  /** False when the daemon's proxy is not running (lanes answer nothing). */
  proxy_running?: boolean;
}

/** POST /api/apps/lanes body. */
export interface AppLaneInput {
  id: string;
  upstream: string;
  models?: string[];
  service?: string;
}

/** Where a lane's judge comes from (GET /api/obs/admission/judge). */
export type JudgeSource = "machine" | "org_relay" | "none";

/** GET /api/obs/admission/judge. */
export interface JudgeInEffect {
  judge: {
    source: JudgeSource | string;
    provider?: string;
    model?: string;
    base_url_host?: string;
    enrolled?: boolean;
    org_judge_available?: boolean;
  } | null;
  note?: string;
}

/** The client families a snippet can be written for. */
export type ClientFamily = "openai" | "anthropic";

/** One provider the add form offers: a known public host. */
export interface LaneProvider {
  /** The suggested lane id, so the address is predictable. */
  id: string;
  label: string;
  upstream: string;
  host: string;
  client: ClientFamily;
  /** The path the client's base URL adds after the lane address. */
  clientSuffix: string;
  /** The environment variable an app usually keeps this provider's key in. */
  keyEnv: string;
  /** A model for the example request. */
  exampleModel: string;
}

/** LANE_PROVIDERS: the providers the add form offers, in display order. */
export const LANE_PROVIDERS: readonly LaneProvider[] = [
  {
    id: "openai",
    label: "OpenAI",
    upstream: "https://api.openai.com",
    host: "api.openai.com",
    client: "openai",
    clientSuffix: "/v1",
    keyEnv: "OPENAI_API_KEY",
    exampleModel: "gpt-5-nano",
  },
  {
    id: "anthropic",
    label: "Anthropic",
    upstream: "https://api.anthropic.com",
    host: "api.anthropic.com",
    client: "anthropic",
    clientSuffix: "",
    keyEnv: "ANTHROPIC_API_KEY",
    exampleModel: "claude-haiku-5-5",
  },
  {
    id: "openrouter",
    label: "OpenRouter",
    upstream: "https://openrouter.ai/api",
    host: "openrouter.ai",
    client: "openai",
    clientSuffix: "/v1",
    keyEnv: "OPENROUTER_API_KEY",
    exampleModel: "openai/gpt-5-nano",
  },
];

/** providerById returns a provider row, or null. */
export function providerById(id: string): LaneProvider | null {
  return LANE_PROVIDERS.find((p) => p.id === id) ?? null;
}

/** hostOf is a URL's host, or the input when it does not parse. */
export function hostOf(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
}

/** providerForLane finds the provider row a lane forwards to, by host. */
export function providerForLane(lane: Pick<AppLane, "upstream">): LaneProvider | null {
  const host = hostOf(lane.upstream).toLowerCase();
  return LANE_PROVIDERS.find((p) => p.host === host) ?? null;
}

/** clientFamily is the client a lane is configured with: the daemon's word
 *  when it gave one, else the provider's, else openai (the most common
 *  shape a custom provider speaks). */
export function clientFamily(lane: Pick<AppLane, "client" | "upstream">): ClientFamily {
  if (lane.client === "anthropic" || lane.client === "openai") return lane.client;
  return providerForLane(lane)?.client ?? "openai";
}

function trimSlash(s: string): string {
  return s.replace(/\/+$/, "");
}

/** clientBaseUrl is the value for the client's base URL option: the daemon's
 *  when it gave one, else the lane address plus the client's path. */
export function clientBaseUrl(lane: Pick<AppLane, "client" | "upstream" | "base_url" | "client_base_url">): string {
  if (lane.client_base_url) return lane.client_base_url;
  const base = trimSlash(lane.base_url);
  return clientFamily(lane) === "openai" ? `${base}/v1` : base;
}

/** lanesOf reads the lane list, tolerating null from an older daemon. */
export function lanesOf(r: AppLanesResult | null | undefined): AppLane[] {
  return [...(r?.lanes ?? [])].sort((a, b) => a.id.localeCompare(b.id));
}

const LANE_ID = /^[a-z0-9][a-z0-9-]{0,31}$/;

/** laneIdError says what is wrong with a new lane id, or "" when it is fine. */
export function laneIdError(id: string, existing: readonly string[] = []): string {
  if (id === "") return "Name the lane.";
  if (!LANE_ID.test(id)) return "Use 1 to 32 lower-case letters, digits or dashes, starting with a letter or digit.";
  if (existing.includes(id)) return "A lane with this name already exists.";
  return "";
}

const SERVICE = /^[a-z0-9._:/-]{1,128}$/;

/** normalizeService lower-cases and trims a service name. */
export function normalizeService(s: string): string {
  return s.trim().toLowerCase();
}

/** serviceError says what is wrong with an optional service name, or "". */
export function serviceError(s: string): string {
  const v = normalizeService(s);
  if (v === "") return "";
  if (v === "*" || v.startsWith("sa:")) return "Use the app's own name.";
  if (!SERVICE.test(v)) return "Use letters, digits and . _ : / - only, up to 128 characters.";
  return "";
}

/** cleanModels trims, drops empties and repeats, keeping the first spelling. */
export function cleanModels(models: readonly string[]): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const m of models) {
    const v = m.trim();
    if (!v || seen.has(v)) continue;
    seen.add(v);
    out.push(v);
  }
  return out;
}

/** laneInput builds the POST body from the add form. */
export function laneInput(form: { id: string; provider: string; models: readonly string[]; service: string }): AppLaneInput | null {
  const p = providerById(form.provider);
  if (!p) return null;
  const body: AppLaneInput = { id: form.id.trim(), upstream: p.upstream };
  const models = cleanModels(form.models);
  if (models.length > 0) body.models = models;
  const service = normalizeService(form.service);
  if (service) body.service = service;
  return body;
}

/** modelsText says which models a lane forwards. */
export function modelsText(lane: Pick<AppLane, "models">): string {
  const n = lane.models?.length ?? 0;
  if (n === 0) return "Any model";
  if (n === 1) return lane.models![0];
  return `${n} models`;
}

/** The snippet languages. */
export type SnippetLang = "python" | "typescript" | "curl";

export const SNIPPET_LANGS: readonly { value: SnippetLang; label: string }[] = [
  { value: "python", label: "Python" },
  { value: "typescript", label: "TypeScript" },
  { value: "curl", label: "curl" },
];

/** keyEnvFor names the env var the snippet reads the provider key from: the
 *  app keeps its own provider key; the lane forwards it unchanged. */
export function keyEnvFor(lane: Pick<AppLane, "upstream" | "client">): string {
  const p = providerForLane(lane);
  if (p) return p.keyEnv;
  return clientFamily(lane) === "anthropic" ? "ANTHROPIC_API_KEY" : "PROVIDER_API_KEY";
}

function exampleModel(lane: Pick<AppLane, "upstream" | "client" | "models">): string {
  if (lane.models && lane.models.length > 0) return lane.models[0];
  const p = providerForLane(lane);
  if (p) return p.exampleModel;
  return clientFamily(lane) === "anthropic" ? "claude-haiku-5-5" : "gpt-5-nano";
}

/** SHELL_SIGIL starts a shell variable reference in the curl snippet. */
const SHELL_SIGIL = "$";

/** SERVICE_HEADER is the header an app names its service with. */
export const SERVICE_HEADER = "X-Superbased-Service";

/** laneSnippet is a plain client configuration for one lane: the client's
 *  base URL set to the lane, the app's own provider key from its env var,
 *  and the service header when the lane names a service. */
export function laneSnippet(lane: AppLane, lang: SnippetLang): string {
  const base = clientBaseUrl(lane);
  const env = keyEnvFor(lane);
  const family = clientFamily(lane);
  const service = lane.service ? normalizeService(lane.service) : "";
  const model = exampleModel(lane);
  // A shell variable reference to the provider key (not money).
  const keyRef = [SHELL_SIGIL, env].join("");
  if (lang === "curl") {
    const svc = service ? `\n  -H "${SERVICE_HEADER}: ${service}" \\` : "";
    if (family === "anthropic") {
      return [
        `curl ${base}/v1/messages \\`,
        `  -H "x-api-key: ${keyRef}" \\`,
        `  -H "anthropic-version: 2023-06-01" \\${svc}`,
        `  -H "content-type: application/json" \\`,
        `  -d '{"model": "${model}", "max_tokens": 256, "messages": [{"role": "user", "content": "Hello"}]}'`,
      ].join("\n");
    }
    return [
      `curl ${base}/chat/completions \\`,
      `  -H "Authorization: Bearer ${keyRef}" \\${svc}`,
      `  -H "Content-Type: application/json" \\`,
      `  -d '{"model": "${model}", "messages": [{"role": "user", "content": "Hello"}]}'`,
    ].join("\n");
  }
  if (lang === "python") {
    const headers = service ? `\n    default_headers={"${SERVICE_HEADER}": "${service}"},` : "";
    if (family === "anthropic") {
      return [
        "import os",
        "from anthropic import Anthropic",
        "",
        "client = Anthropic(",
        `    base_url="${base}",`,
        `    api_key=os.environ["${env}"],${headers}`,
        ")",
      ].join("\n");
    }
    return [
      "import os",
      "from openai import OpenAI",
      "",
      "client = OpenAI(",
      `    base_url="${base}",`,
      `    api_key=os.environ["${env}"],${headers}`,
      ")",
    ].join("\n");
  }
  const headers = service ? `\n  defaultHeaders: { "${SERVICE_HEADER}": "${service}" },` : "";
  if (family === "anthropic") {
    return [
      'import Anthropic from "@anthropic-ai/sdk";',
      "",
      "const client = new Anthropic({",
      `  baseURL: "${base}",`,
      `  apiKey: process.env.${env},${headers}`,
      "});",
    ].join("\n");
  }
  return [
    'import OpenAI from "openai";',
    "",
    "const client = new OpenAI({",
    `  baseURL: "${base}",`,
    `  apiKey: process.env.${env},${headers}`,
    "});",
  ].join("\n");
}

/** LANE_CLI is the command-line twin of the add form (CLI parity), shown
 *  only in a technical tooltip. */
export function laneCli(input: AppLaneInput | null): string {
  if (!input) return "observer apps lane add <id> --upstream <url>";
  const parts = ["observer apps lane add", input.id || "<id>", "--upstream", input.upstream];
  for (const m of input.models ?? []) parts.push("--model", m);
  if (input.service) parts.push("--service", input.service);
  return parts.join(" ");
}

/** laneWriteError reads the daemon's sentence out of a refused write body
 *  ({"error": "..."} or {"message": "..."}), or "" when there is none. */
export function laneWriteError(body: string): string {
  try {
    const v = JSON.parse(body) as { error?: unknown; message?: unknown };
    if (typeof v.message === "string" && v.message.trim()) return v.message.trim();
    if (typeof v.error === "string" && v.error.trim()) return v.error.trim();
  } catch {
    // Plain text.
  }
  return body.trim();
}

// ---------- the judge in effect ----------

/** JUDGE_SOURCE_WORDS: where the judge that decides judged criteria comes
 *  from, in words (a vocab: never the raw value on screen). */
export const JUDGE_SOURCE_WORDS: Readonly<Record<JudgeSource, { label: string; tone: "accent" | "info" | "neutral" }>> = {
  machine: { label: "This machine's judge", tone: "accent" },
  org_relay: { label: "Your organization's judge", tone: "info" },
  none: { label: "No judge", tone: "neutral" },
};

/** judgeSourceOf normalizes a source; an unknown value reads as none. */
export function judgeSourceOf(r: JudgeInEffect | null | undefined): JudgeSource {
  const s = r?.judge?.source;
  return s === "machine" || s === "org_relay" ? s : "none";
}

/** judgeLine is the one sentence under the judge's name. */
export function judgeLine(r: JudgeInEffect | null | undefined): string {
  const src = judgeSourceOf(r);
  const j = r?.judge;
  if (src === "none") return "Judged criteria are not judged until a judge is set.";
  const what = [j?.model, j?.base_url_host ? `at ${j.base_url_host}` : ""].filter(Boolean).join(" ");
  if (src === "org_relay") {
    return what ? `Checks are sent to your organization, which judges with ${what}.` : "Checks are sent to your organization, which judges them.";
  }
  return what ? `Judged on this machine's settings: ${what}.` : "Judged with this machine's own judge settings.";
}

/** judgeOffersOrg reports whether the card should say the organization's
 *  judge is available (enrolled, the org has one, and it is not in use). */
export function judgeOffersOrg(r: JudgeInEffect | null | undefined): boolean {
  const j = r?.judge;
  return judgeSourceOf(r) !== "org_relay" && j?.enrolled === true && j?.org_judge_available === true;
}
