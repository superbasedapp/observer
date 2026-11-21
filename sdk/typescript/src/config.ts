/**
 * SDK settings: one options object, each field mapped to an env var.
 *
 * Resolution for every field: explicit `init()` option, then the
 * `SUPERBASED_*` variable, then the standard OpenTelemetry variable (where
 * one exists), then (destination, gateway URL and credential only) what the
 * local Observer advertises, then the default. Pure over an env record, so it
 * is testable without touching `process.env`.
 *
 * Export goes to a list of destinations (endpoint, headers, timeout each):
 * this machine's Observer, the org or SaaS gateway, or both (D18, contract
 * `contracts/destination.md`). `destinations()` turns the resolved choice
 * into that list; destination.ts makes the choice.
 */

export type Env = Record<string, string | undefined>;

export const DEFAULT_ENDPOINT = "http://127.0.0.1:4318/v1/traces";
export const DEFAULT_SERVICE_NAME = "custom-app";
export const DEFAULT_MAX_CONTENT_CHARS = 8000;
export const DEFAULT_EXPORT_TIMEOUT_MS = 5000;
export const DEFAULT_SHUTDOWN_TIMEOUT_MS = 2000;
/** This machine's Observer dashboard API (admission, discovery, the local control API). */
export const DEFAULT_NODE_URL = "http://127.0.0.1:8081";
/** Discovery timeout (contract destination.md section 4: 500 ms total, one attempt). */
export const DEFAULT_DISCOVER_TIMEOUT_MS = 500;
export const DEFAULT_API_TIMEOUT_MS = 5000;
export const DEFAULT_PROMPT_CACHE_TTL_MS = 60_000;
export const TRACES_PATH = "/v1/traces";
const FALSE_WORDS = ["0", "false", "no", "off", ""];

/** Where SDK data is saved (D18). */
export type DestinationChoice = "local" | "online" | "both";
export const DESTINATION_CHOICES: readonly DestinationChoice[] = ["local", "online", "both"];

/** One OTLP/HTTP export target. */
export interface Destination {
  /** `local` (this machine, or the collector `endpoint` names) or `online` (the org or SaaS gateway). */
  name: "local" | "online";
  endpoint: string;
  headers: Record<string, string>;
  timeoutMs: number;
}

/** Every SDK option, fully resolved. See the README's settings table. */
export interface Settings {
  /**
   * The local destination's OTLP traces URL: the option > SUPERBASED_OTLP_ENDPOINT >
   * (destination `local` only) OTEL_EXPORTER_OTLP_TRACES_ENDPOINT > OTEL_EXPORTER_OTLP_ENDPOINT
   * (+ /v1/traces) > what the machine advertises > the built-in receiver.
   * This field holds the first of the option / env values (or the default);
   * `localTracesUrl(settings, choice)` applies the rest.
   */
  endpoint: string;
  /** Where `endpoint` came from: `argument`, `env` (SUPERBASED_OTLP_ENDPOINT), `otel` (an OTEL_* variable) or `default`. */
  endpointSource: "argument" | "env" | "otel" | "default";
  /** OTEL_EXPORTER_OTLP_HEADERS, OTEL_EXPORTER_OTLP_TRACES_HEADERS, SUPERBASED_OTLP_HEADERS (merged, option on top). The OTEL ones go to the local destination only when it is `local`. */
  headers: Record<string, string>;
  /** SUPERBASED_API_KEY, sent as `Authorization: Bearer` to the gateway only. */
  apiKey: string;
  /** SUPERBASED_SERVICE_NAME > OTEL_SERVICE_NAME > service.name in OTEL_RESOURCE_ATTRIBUTES. */
  serviceName: string;
  /** OTEL_RESOURCE_ATTRIBUTES. */
  resourceAttributes: Record<string, string>;
  /** SUPERBASED_TENANT. */
  tenant: string;
  /** SUPERBASED_USER. */
  user: string;
  /** SUPERBASED_SESSION_ID. */
  sessionId: string;
  /** SUPERBASED_CAPTURE_CONTENT (legacy OBSERVER_CAPTURE_CONTENT). */
  captureContent: boolean;
  /** SUPERBASED_MAX_CONTENT_CHARS. */
  maxContentChars: number;
  /** SUPERBASED_EXPORT_TIMEOUT_MS > OTEL_EXPORTER_OTLP_TRACES_TIMEOUT > OTEL_EXPORTER_OTLP_TIMEOUT. */
  exportTimeoutMs: number;
  /** SUPERBASED_SHUTDOWN_TIMEOUT_MS: bound on flush() and shutdown(). */
  shutdownTimeoutMs: number;
  /** SUPERBASED_EXIT_HOOK: flush pending spans on process `beforeExit`. */
  exitHook: boolean;
  /** SUPERBASED_DEBUG: log each failure to the console (default: at most one line a minute). */
  debug: boolean;
  /** SUPERBASED_RELEASE: the app's release, on the resource as `service.version`. */
  release: string;
  /** SUPERBASED_ENVIRONMENT: the app's environment, on the resource as `deployment.environment.name`. */
  environment: string;
  /** SUPERBASED_TAGS (comma list): tags on every trace (`sbo.tags`). */
  tags: string[];
  /** SUPERBASED_METADATA (`k=v,k2=v2`): metadata on every trace (`sbo.metadata.<k>`). */
  metadata: Record<string, string>;
  /** SUPERBASED_SAMPLE_RATE (0..1), else OTEL_TRACES_SAMPLER[_ARG]. Whole traces are kept or dropped. */
  sampleRate: number;
  /** Whether the sampler is parent-based (a sampled parent keeps its children). */
  parentBased: boolean;
  /** SUPERBASED_DESTINATION: local, online or both. Empty = not chosen (ask the machine, then local). */
  destination: DestinationChoice | "";
  /** Why an explicit destination value was refused ("" when none was, or it was valid). */
  destinationInvalid: string;
  /** Why an environment sampling value was ignored ("" when none was). */
  samplingInvalid: string;
  /** The OTLP traces URL the machine advertised in discovery ("" when none). Internal. */
  advertisedEndpoint: string;
  /** SUPERBASED_ORG_URL: base URL of the org or SaaS gateway (OTLP at `/v1/traces`, control API at `/v1/sdk`). */
  orgUrl: string;
  /** Headers for the gateway: the `headers` option and SUPERBASED_OTLP_HEADERS, never the OTEL_* ones. */
  onlineHeaders: Record<string, string>;
  /** SUPERBASED_NODE_URL: this machine's Observer dashboard API (scheme, host and port). */
  nodeUrl: string;
  /** SUPERBASED_DISCOVER: ask the machine for its destination default. */
  discover: boolean;
  /** SUPERBASED_DISCOVER_TIMEOUT_MS: bound on that request. */
  discoverTimeoutMs: number;
  /** SUPERBASED_API_TIMEOUT_MS: bound on each control API call (scores, prompts, datasets, experiments). */
  apiTimeoutMs: number;
  /** SUPERBASED_PROMPT_CACHE_TTL_MS: how long a fetched prompt is fresh. */
  promptCacheTtlMs: number;
  /** True when `endpoint` was set explicitly (option, SUPERBASED_OTLP_ENDPOINT or an OTEL_* variable). */
  endpointExplicit: boolean;
  /** Where `apiKey` came from: `argument`, `env`, `file` (the machine's credential file) or "". */
  credentialSource: "argument" | "env" | "file" | "";
}

/** The subset a caller may pass to `init()`; unset fields come from env. */
export type SettingsInput = Partial<
  Omit<
    Settings,
    "endpointExplicit" | "endpointSource" | "onlineHeaders" | "destinationInvalid" | "samplingInvalid" | "parentBased" | "destination" | "advertisedEndpoint" | "credentialSource"
  >
> & { destination?: string };

/** Parse the first set boolean-ish env var in `names`; none set gives `def`. */
export function envFlag(env: Env, names: string[], def: boolean): boolean {
  for (const name of names) {
    const raw = env[name];
    if (raw != null) return !FALSE_WORDS.includes(raw.trim().toLowerCase());
  }
  return def;
}

function envStr(env: Env, ...names: string[]): string {
  for (const name of names) {
    const v = (env[name] ?? "").trim();
    if (v) return v;
  }
  return "";
}

function envNum(env: Env, ...names: string[]): number | undefined {
  for (const name of names) {
    const raw = (env[name] ?? "").trim();
    if (raw) {
      const n = Number(raw);
      if (Number.isFinite(n) && n >= 0) return n;
    }
  }
  return undefined;
}

function safeDecode(s: string): string {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}

/** Parse the OTel `k1=v1,k2=v2` list (percent-decoded); malformed members skipped. */
export function parseKvList(raw: string | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!raw) return out;
  for (const member of raw.split(",")) {
    const i = member.indexOf("=");
    if (i < 0) continue;
    const key = safeDecode(member.slice(0, i).trim());
    if (key) out[key] = safeDecode(member.slice(i + 1).trim());
  }
  return out;
}

/** Parse a comma list (empty members dropped). */
export function parseList(raw: string | undefined): string[] {
  return (raw ?? "")
    .split(",")
    .map((t) => t.trim())
    .filter(Boolean);
}

export function resolveEndpoint(explicit: string | undefined, env: Env): string {
  return resolveEndpointWithSource(explicit, env)[0];
}

/** The endpoint and where it came from (see `Settings.endpoint`). */
export function resolveEndpointWithSource(explicit: string | undefined, env: Env): [string, Settings["endpointSource"]] {
  if (explicit) return [explicit, "argument"];
  const sb = envStr(env, "SUPERBASED_OTLP_ENDPOINT");
  if (sb) return [sb, "env"];
  const full = envStr(env, "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT");
  if (full) return [full, "otel"];
  const base = envStr(env, "OTEL_EXPORTER_OTLP_ENDPOINT");
  if (base) return [base.replace(/\/+$/, "") + TRACES_PATH, "otel"];
  return [DEFAULT_ENDPOINT, "default"];
}

export function resolveHeaders(explicit: Record<string, string> | undefined, env: Env): Record<string, string> {
  const out: Record<string, string> = {};
  for (const name of ["OTEL_EXPORTER_OTLP_HEADERS", "OTEL_EXPORTER_OTLP_TRACES_HEADERS", "SUPERBASED_OTLP_HEADERS"]) {
    Object.assign(out, parseKvList(env[name]));
  }
  if (explicit) for (const [k, v] of Object.entries(explicit)) out[String(k)] = String(v);
  return out;
}

function resolveOnlineHeaders(explicit: Record<string, string> | undefined, env: Env): Record<string, string> {
  const out: Record<string, string> = { ...parseKvList(env.SUPERBASED_OTLP_HEADERS) };
  if (explicit) for (const [k, v] of Object.entries(explicit)) out[String(k)] = String(v);
  return out;
}

export function resolveServiceName(explicit: string | undefined, env: Env): string {
  if (explicit) return explicit;
  const v = envStr(env, "SUPERBASED_SERVICE_NAME", "OTEL_SERVICE_NAME");
  if (v) return v;
  return (parseKvList(env.OTEL_RESOURCE_ATTRIBUTES)["service.name"] ?? "").trim() || DEFAULT_SERVICE_NAME;
}

const SAMPLERS: Record<string, [number | undefined, boolean]> = {
  always_on: [1, false],
  always_off: [0, false],
  traceidratio: [undefined, false],
  parentbased_always_on: [1, true],
  parentbased_always_off: [0, true],
  parentbased_traceidratio: [undefined, true],
};

/** A sampling ratio from text: a number in 0..1, else undefined. */
function ratio(raw: string): number | undefined {
  if (!raw) return undefined;
  const n = Number(raw);
  return Number.isFinite(n) && n >= 0 && n <= 1 ? n : undefined;
}

/**
 * The head sampling rate and whether it is parent-based: the option,
 * SUPERBASED_SAMPLE_RATE, then the standard OTEL_TRACES_SAMPLER (+ _ARG). An
 * explicit rate outside 0..1 is a programmer error (RangeError); a bad
 * environment value is ignored and named in `invalid` (review E-38; as
 * Python), so a stray host variable never stops the app.
 */
export function resolveSampling(explicit: number | undefined, env: Env): { rate: number; parentBased: boolean; invalid: string } {
  if (explicit !== undefined && explicit !== null) {
    if (typeof explicit !== "number" || !Number.isFinite(explicit) || explicit < 0 || explicit > 1) {
      throw new RangeError(`@superbased/sdk: sampleRate must be between 0 and 1, not ${String(explicit)}`);
    }
    return { rate: explicit, parentBased: true, invalid: "" };
  }
  const bad: string[] = [];
  const raw = envStr(env, "SUPERBASED_SAMPLE_RATE");
  const own = ratio(raw);
  if (raw && own === undefined) bad.push(`SUPERBASED_SAMPLE_RATE=${JSON.stringify(raw)}`);
  const invalid = () => (bad.length ? `${bad.join(" and ")} is not a number in 0..1; ignored` : "");
  if (own !== undefined) return { rate: own, parentBased: true, invalid: invalid() };
  const row = SAMPLERS[envStr(env, "OTEL_TRACES_SAMPLER").toLowerCase()];
  if (row) {
    let [rate] = row;
    if (rate === undefined) {
      const argRaw = envStr(env, "OTEL_TRACES_SAMPLER_ARG");
      rate = ratio(argRaw);
      if (argRaw && rate === undefined) bad.push(`OTEL_TRACES_SAMPLER_ARG=${JSON.stringify(argRaw)}`);
      rate ??= 1;
    }
    return { rate, parentBased: row[1], invalid: invalid() };
  }
  return { rate: 1, parentBased: true, invalid: invalid() };
}

/**
 * The destination from the option, then SUPERBASED_DESTINATION. An invalid
 * value is refused loudly (reported in `invalid`) and the next source is
 * used (contract destination.md section 1).
 */
export function resolveDestinationChoice(explicit: string | undefined, env: Env): { choice: DestinationChoice | ""; source: string; invalid: string } {
  const sources: Array<[string, string | undefined]> = [
    ["argument", explicit],
    ["env", env.SUPERBASED_DESTINATION],
  ];
  const bad: string[] = [];
  for (const [source, raw] of sources) {
    const v = (raw ?? "").trim().toLowerCase();
    if (!v) continue;
    if ((DESTINATION_CHOICES as readonly string[]).includes(v)) {
      return { choice: v as DestinationChoice, source, invalid: bad.join("; ") };
    }
    bad.push(`destination ${JSON.stringify(raw)} (${source}) is not local, online or both; ignored`);
  }
  return { choice: "", source: "", invalid: bad.join("; ") };
}

export function trimSlash(u: string): string {
  return u.replace(/\/+$/, "");
}

const KNOWN: ReadonlyArray<string> = [
  "endpoint", "headers", "apiKey", "serviceName", "resourceAttributes", "tenant", "user", "sessionId",
  "captureContent", "maxContentChars", "exportTimeoutMs", "shutdownTimeoutMs", "exitHook", "debug",
  "release", "environment", "tags", "metadata", "sampleRate", "destination", "orgUrl",
  "nodeUrl", "discover", "discoverTimeoutMs", "apiTimeoutMs", "promptCacheTtlMs",
];

/** Build settings from explicit options (undefined = unset) over env. */
export function resolveSettings(env: Env, explicit: SettingsInput = {}): Settings {
  for (const k of Object.keys(explicit)) {
    if (!KNOWN.includes(k)) throw new TypeError(`unknown @superbased/sdk setting: ${k}`);
  }
  const pick = <T>(v: T | undefined, d: T): T => (v === undefined || v === null ? d : v);
  const sampling = resolveSampling(explicit.sampleRate, env);
  const dest = resolveDestinationChoice(explicit.destination, env);
  const [endpoint, endpointSource] = resolveEndpointWithSource(explicit.endpoint, env);
  const apiKey = pick(explicit.apiKey, envStr(env, "SUPERBASED_API_KEY"));
  return {
    endpoint,
    endpointSource,
    headers: resolveHeaders(explicit.headers, env),
    apiKey,
    credentialSource: !apiKey ? "" : explicit.apiKey ? "argument" : "env",
    serviceName: resolveServiceName(explicit.serviceName, env),
    resourceAttributes: { ...parseKvList(env.OTEL_RESOURCE_ATTRIBUTES), ...(explicit.resourceAttributes ?? {}) },
    tenant: pick(explicit.tenant, envStr(env, "SUPERBASED_TENANT")),
    user: pick(explicit.user, envStr(env, "SUPERBASED_USER")),
    sessionId: pick(explicit.sessionId, envStr(env, "SUPERBASED_SESSION_ID")),
    captureContent: pick(
      explicit.captureContent,
      envFlag(env, ["SUPERBASED_CAPTURE_CONTENT", "OBSERVER_CAPTURE_CONTENT"], true),
    ),
    maxContentChars: pick(explicit.maxContentChars, envNum(env, "SUPERBASED_MAX_CONTENT_CHARS") ?? DEFAULT_MAX_CONTENT_CHARS),
    exportTimeoutMs: Math.max(
      1,
      pick(
        explicit.exportTimeoutMs,
        envNum(env, "SUPERBASED_EXPORT_TIMEOUT_MS", "OTEL_EXPORTER_OTLP_TRACES_TIMEOUT", "OTEL_EXPORTER_OTLP_TIMEOUT") ??
          DEFAULT_EXPORT_TIMEOUT_MS,
      ),
    ),
    shutdownTimeoutMs: Math.max(
      0,
      pick(explicit.shutdownTimeoutMs, envNum(env, "SUPERBASED_SHUTDOWN_TIMEOUT_MS") ?? DEFAULT_SHUTDOWN_TIMEOUT_MS),
    ),
    exitHook: pick(explicit.exitHook, envFlag(env, ["SUPERBASED_EXIT_HOOK"], true)),
    debug: pick(explicit.debug, envFlag(env, ["SUPERBASED_DEBUG"], false)),
    release: pick(explicit.release, envStr(env, "SUPERBASED_RELEASE")),
    environment: pick(explicit.environment, envStr(env, "SUPERBASED_ENVIRONMENT")),
    tags: pick(explicit.tags, parseList(env.SUPERBASED_TAGS)),
    metadata: pick(explicit.metadata, parseKvList(env.SUPERBASED_METADATA)),
    sampleRate: sampling.rate,
    parentBased: sampling.parentBased,
    destination: dest.choice,
    destinationInvalid: dest.invalid,
    samplingInvalid: sampling.invalid,
    advertisedEndpoint: "",
    orgUrl: trimSlash(pick(explicit.orgUrl, envStr(env, "SUPERBASED_ORG_URL"))),
    onlineHeaders: resolveOnlineHeaders(explicit.headers, env),
    nodeUrl: trimSlash(pick(explicit.nodeUrl, envStr(env, "SUPERBASED_NODE_URL")) || DEFAULT_NODE_URL),
    discover: pick(explicit.discover, envFlag(env, ["SUPERBASED_DISCOVER"], true)),
    discoverTimeoutMs: Math.max(
      0,
      pick(explicit.discoverTimeoutMs, envNum(env, "SUPERBASED_DISCOVER_TIMEOUT_MS") ?? DEFAULT_DISCOVER_TIMEOUT_MS),
    ),
    apiTimeoutMs: Math.max(1, pick(explicit.apiTimeoutMs, envNum(env, "SUPERBASED_API_TIMEOUT_MS") ?? DEFAULT_API_TIMEOUT_MS)),
    promptCacheTtlMs: Math.max(
      0,
      pick(explicit.promptCacheTtlMs, envNum(env, "SUPERBASED_PROMPT_CACHE_TTL_MS") ?? DEFAULT_PROMPT_CACHE_TTL_MS),
    ),
    endpointExplicit: endpointSource !== "default",
  };
}

function hasAuthHeader(h: Record<string, string>): boolean {
  return Object.keys(h).some((k) => k.toLowerCase() === "authorization");
}

/** The online OTLP traces URL ("" when no gateway is configured). */
export function onlineTracesUrl(s: Settings): string {
  return s.orgUrl ? s.orgUrl + TRACES_PATH : "";
}

/**
 * The local OTLP traces URL for a destination choice: the `endpoint` option
 * or SUPERBASED_OTLP_ENDPOINT as given; an OTEL_* endpoint only when the
 * destination is `local` (so an app's existing OTEL variables, pointing at
 * another vendor, never replace the machine under `both`); else what the
 * machine advertised; else the built-in receiver.
 */
export function localTracesUrl(s: Settings, choice: DestinationChoice | "" = s.destination): string {
  if (localEndpointNamed(s, choice)) return s.endpoint;
  return s.advertisedEndpoint || DEFAULT_ENDPOINT;
}

/**
 * Whether the app named the local destination's endpoint itself (the
 * first rungs of `localTracesUrl`), so the machine's advertised receiver is
 * not needed.
 */
export function localEndpointNamed(s: Settings, choice: DestinationChoice | "" = s.destination): boolean {
  return s.endpointSource === "argument" || s.endpointSource === "env" || (s.endpointSource === "otel" && choice === "local");
}

/** Whether the online destination is usable: a gateway URL and a credential. */
export function onlineUsable(s: Settings): boolean {
  return !!onlineTracesUrl(s) && !!s.apiKey;
}

/**
 * Whether the local exporter may carry the credential: only to a collector
 * the app named itself (the `endpoint` option or SUPERBASED_OTLP_ENDPOINT)
 * that is not on loopback. Never to this machine, and never to an endpoint
 * that came from OTEL_EXPORTER_OTLP_* (an app exporting to another vendor
 * must not leak the superbased key there; review finding R-B26).
 */
export function localCarriesKey(s: Settings, endpoint: string): boolean {
  // The machine's file credential goes only to the gateway (contract destination.md section 6).
  return !!s.apiKey && s.credentialSource !== "file" && (s.endpointSource === "argument" || s.endpointSource === "env") && !isLoopbackHost(endpoint);
}

/** Whether a URL's host is loopback. */
export function isLoopbackHost(url: string): boolean {
  try {
    const h = new URL(url).hostname.replace(/^\[|\]$/g, "").toLowerCase();
    return h === "localhost" || h === "::1" || /^127\.\d+\.\d+\.\d+$/.test(h);
  } catch {
    return false;
  }
}

/**
 * Where spans are exported, for a destination choice (D18).
 *
 * - `local`: this machine's Observer (or the collector `endpoint` names).
 *   Headers: the OTEL_* ones (destination `local` only), SUPERBASED_OTLP_HEADERS
 *   and the `headers` option. The credential only per `localCarriesKey`.
 * - `online`: the gateway with `apiKey` as the bearer, configured only from
 *   the SDK's own settings (an app's OTEL_* variables never redirect it).
 * - `both`: one exporter for each; one failing never blocks the other.
 *
 * The degraded cases (contract destination.md section 7): `online` with no
 * usable gateway exports nothing, `both` exports to the machine only; the
 * caller reports why (`destinationProblems`).
 */
export function destinations(s: Settings, choice: DestinationChoice | "" = s.destination): Destination[] {
  const out: Destination[] = [];
  const c = choice || "local";
  if (c === "local" || c === "both") {
    const endpoint = localTracesUrl(s, c);
    const headers = c === "local" ? { ...s.headers } : { ...s.onlineHeaders };
    if (localCarriesKey(s, endpoint) && !hasAuthHeader(headers)) headers.Authorization = `Bearer ${s.apiKey}`;
    out.push({ name: "local", endpoint, headers, timeoutMs: s.exportTimeoutMs });
  }
  if ((c === "online" || c === "both") && onlineUsable(s)) {
    const headers = { ...s.onlineHeaders };
    // The SDK credential always wins over a user or env Authorization header.
    for (const k of Object.keys(headers)) if (k.toLowerCase() === "authorization") delete headers[k];
    headers.Authorization = `Bearer ${s.apiKey}`;
    out.push({ name: "online", endpoint: onlineTracesUrl(s), headers, timeoutMs: s.exportTimeoutMs });
  }
  return out;
}

/** The fix to name when the online destination is not usable (the verb is `observer sdk sign-in`, R-B17). */
export const ONLINE_FIX = "run `observer sdk sign-in`, or set SUPERBASED_ORG_URL and SUPERBASED_API_KEY";

/** Why a destination choice cannot be honoured in full (empty = fine). */
export function destinationProblems(s: Settings, choice: DestinationChoice | ""): string[] {
  if (choice !== "online" && choice !== "both") return [];
  const missing: string[] = [];
  if (!onlineTracesUrl(s)) missing.push("a gateway URL");
  if (!s.apiKey) missing.push("an SDK credential");
  if (!missing.length) return [];
  const effect = choice === "online" ? "nothing is exported" : "exporting to this machine only";
  return [`destination ${choice} is missing ${missing.join(" and ")}; ${effect}. To fix: ${ONLINE_FIX}`];
}
