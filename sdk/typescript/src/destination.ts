/**
 * Data destination (D18; contract `contracts/destination.md`, lane B6).
 *
 * - `local`: this machine's Observer only.
 * - `online`: the org or SaaS gateway only.
 * - `both`: the SDK exports to each itself, through its own exporter, so one
 *   failing destination never blocks the other and `both` never depends on
 *   the machine's push tiers.
 *
 * The choice, first set wins: the `destination` option, then
 * `SUPERBASED_DESTINATION`, then the default this machine advertises at
 * `GET <nodeUrl>/api/sdk/destination` (loopback only, 500 ms, one attempt),
 * then `online` when no machine answered and the app was given a gateway and
 * a credential (`inferred`, a production app), then `local`. Discovery also
 * runs for an explicit `online` / `both` that still lacks a gateway URL or a
 * credential, which the machine supplies (review finding R-B09), and for an
 * explicit `local` / `both` with no endpoint the app named for the local
 * destination: the machine advertises its own receiver (live finding L-01).
 * An explicit `endpoint` only sets where the local destination sends.
 *
 * The gateway URL: `orgUrl`, `SUPERBASED_ORG_URL`, then the `gateway_url`
 * line of the machine's credential file. The credential: `apiKey`,
 * `SUPERBASED_API_KEY`, then that file's key line. The file is read only
 * after the owner, mode and symlink checks of contract section 6. The
 * discovery answer never decides where the key goes (review E-04): it only
 * names the file, and its local URLs are used only when they are loopback.
 * The machine never sends the credential itself.
 *
 * While discovery runs, finished spans wait in a bounded queue and then go
 * to the chosen destination; none are sent to a guess.
 */

import type { Context } from "@opentelemetry/api";
import type { ReadableSpan, Span, SpanProcessor } from "@opentelemetry/sdk-trace-base";

import { DESTINATION_CHOICES, trimSlash, type DestinationChoice, type Settings } from "./config.js";
import { dashboardProblem, expired, expiryNote, readCredentialRecord, type SdkFileState } from "./credfile.js";
import { legsOf, stats } from "./export.js";

/** The machine's discovery route (contract section 4). */
export const DISCOVERY_PATH = "/api/sdk/destination";
export const DISCOVERY_API_VERSION = 1;
/** Most spans held while the destination is being discovered. */
export const DISCOVERY_QUEUE_MAX = 2048;

/** What the machine advertises (api_version 1), reduced to what the SDK uses. */
export interface Discovered {
  destination: DestinationChoice;
  source: string;
  signedIn: boolean;
  localEnabled: boolean;
  localTracesUrl: string;
  admissionUrl: string;
  gatewayUrl: string;
  credentialPresent: boolean;
  credentialFile: string;
  /** The answer's `online.dashboard_url` (additive; links only, never a place the key goes): "" when absent or not https. */
  dashboardUrl: string;
  /** The answer's `local.app_lanes` as it came (the AI gateway helpers read it; loopback-checked there). */
  appLanes: unknown;
  warnings: string[];
  /** Local URLs the answer named that were not loopback, and so were ignored (review E-04). */
  refused: string[];
}

function obj(v: unknown): Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : {};
}

/** Parse the discovery body; null when it is not a usable api_version 1 answer. */
export function parseDiscovery(body: unknown): Discovered | null {
  const d = obj(body);
  if (d.api_version !== DISCOVERY_API_VERSION) return null;
  const rawDest = typeof d.destination === "string" ? d.destination.trim().toLowerCase() : "";
  const destKnown = (DESTINATION_CHOICES as readonly string[]).includes(rawDest);
  const dest = destKnown ? rawDest : "local";
  const local = obj(d.local);
  const online = obj(d.online);
  const s = (o: Record<string, unknown>, k: string) => (typeof o[k] === "string" ? (o[k] as string).trim() : "");
  // The machine's receiver and admission check are on this machine: a remote
  // address there is not the machine speaking (review E-04).
  const refused: string[] = [];
  const unknownDest = destKnown ? [] : [`the discovery answer names an unknown destination ${JSON.stringify(rawDest)}; using local`];
  const loopback = (k: string): string => {
    const v = s(local, k);
    if (v && !isLoopbackUrl(v)) {
      refused.push(`the machine's discovery answer names a non-loopback ${k} (${v}); ignored`);
      return "";
    }
    return v;
  };
  return {
    destination: dest as DestinationChoice,
    source: s(d, "source"),
    signedIn: d.signed_in === true,
    localEnabled: local.enabled !== false,
    localTracesUrl: loopback("otlp_traces_url"),
    admissionUrl: loopback("admission_url"),
    gatewayUrl: trimSlash(s(online, "gateway_url")),
    credentialPresent: online.credential_present === true,
    credentialFile: s(online, "credential_file"),
    dashboardUrl: dashboardProblem(s(online, "dashboard_url")) ? "" : trimSlash(s(online, "dashboard_url")),
    appLanes: local.app_lanes,
    warnings: [...(Array.isArray(d.warnings) ? d.warnings.filter((w): w is string => typeof w === "string") : []), ...unknownDest],
    refused,
  };
}

/** Whether a URL's host is loopback (the only hosts discovery is sent to). */
export function isLoopbackUrl(url: string): boolean {
  try {
    const h = new URL(url).hostname.replace(/^\[|\]$/g, "").toLowerCase();
    return h === "localhost" || h === "::1" || /^127\.\d+\.\d+\.\d+$/.test(h);
  } catch {
    return false;
  }
}

/**
 * The longest discovery waits on a busy event loop (see discoverDestination),
 * or ten windows when the window is longer.
 */
export const DISCOVERY_WALL_CAP_MS = 5000;

/**
 * What a discovery window's timer does when it fires at `now` (it was due at
 * `due`): "rearm" when it fired late (the event loop was busy, so the
 * machine's answer may be waiting behind it) and the wall cap `giveUpAt` is
 * not reached; otherwise "abort".
 */
export function discoveryTimerStep(now: number, due: number, giveUpAt: number, timeoutMs: number): "rearm" | "abort" {
  const lateBy = Math.max(50, timeoutMs / 5);
  return now - due > lateBy && now < giveUpAt ? "rearm" : "abort";
}

/** Ask the machine for its destination default. Never rejects; `error` says why on failure. */
export async function discoverDestination(nodeUrl: string, timeoutMs: number): Promise<{ found: Discovered | null; error: string }> {
  if (!isLoopbackUrl(nodeUrl)) {
    return { found: null, error: `discovery skipped: ${nodeUrl} is not a loopback address` };
  }
  if (!(timeoutMs > 0) || typeof fetch !== "function") return { found: null, error: "discovery off" };
  const controller = new AbortController();
  // The timeout is the machine's budget, not the app's: init() returns at
  // once and the app usually goes on to load its framework synchronously
  // (a cold require of LangChain or the Agents SDK can take seconds on a
  // loaded box). A timer that fires late means the event loop was busy, and
  // the machine's answer may already be waiting behind it, so the window is
  // re-armed for as long as the timers keep firing late, up to a wall cap.
  // Discovery gives up only after one window the loop spent idle with no
  // answer, or at the cap. Spans finished meanwhile are held, not lost.
  const giveUpAt = Date.now() + Math.max(DISCOVERY_WALL_CAP_MS, timeoutMs * 10);
  const arm = (): ReturnType<typeof setTimeout> => {
    const due = Date.now() + timeoutMs;
    const t = setTimeout(() => {
      if (discoveryTimerStep(Date.now(), due, giveUpAt, timeoutMs) === "rearm") timer = arm();
      else controller.abort();
    }, timeoutMs);
    t.unref?.();
    return t;
  };
  let timer = arm();
  try {
    const resp = await fetch(nodeUrl + DISCOVERY_PATH, { headers: { Accept: "application/json" }, signal: controller.signal, redirect: "manual" });
    if (resp.status !== 200) {
      void resp.body?.cancel().catch(() => undefined);
      return { found: null, error: `discovery: HTTP ${resp.status}` };
    }
    let body: unknown;
    try {
      body = JSON.parse(await resp.text());
    } catch {
      return { found: null, error: "discovery: the body is not JSON" };
    }
    const found = parseDiscovery(body);
    return found ? { found, error: "" } : { found: null, error: "discovery: not an api_version 1 answer" };
  } catch (err) {
    const cause = (err as { cause?: { code?: string } }).cause;
    return { found: null, error: `discovery: ${controller.signal.aborted ? `timed out after ${timeoutMs}ms` : (cause?.code ?? String(err))}` };
  } finally {
    clearTimeout(timer);
  }
}

/** The credential file's gateway line (contract destination.md section 6). */
export const CREDENTIAL_GATEWAY_FIELD = "gateway_url";

export { gatewayProblem } from "./credfile.js";

/**
 * Read the machine's SDK credential file under the contract's rules (unix):
 * not a symlink, no group or other permission bits, owned by this user. The
 * first line is `<key_id>.<secret>`; each further line is `name=value`, where
 * `gateway_url` names the only address the key is sent to (review E-04: the
 * address comes from this owner-only file, never from the discovery answer).
 * Unknown names are ignored; a gateway that is not https (or http to this
 * machine) is ignored with an error. Returns the compound and the gateway,
 * or `error` saying why it was refused. On Windows the machine's file is
 * never read: there is no owner check to make, so SUPERBASED_API_KEY is the
 * way (as Python; review R-C33). The SDK-held file (credfile.ts) has its own
 * Windows rule.
 */
export function readCredentialFile(path: string): { key: string; gateway: string; error: string } {
  if (!path) return { key: "", gateway: "", error: "" };
  if (process.platform === "win32") return { key: "", gateway: "", error: "credential files are not read on Windows; set SUPERBASED_API_KEY" };
  const r = readCredentialRecord(path);
  if (!r.record) return { key: "", gateway: "", error: r.error || `credential file ${path}: ENOENT` };
  return { key: r.record.key, gateway: r.record.gateway, error: r.warnings.join("; ") };
}

/** Settings with what the machine supplied filled in; explicit settings win. Also returns problems. */
export function withDiscovered(s: Settings, d: Discovered, choice: DestinationChoice): { settings: Settings; problems: string[] } {
  const problems = [...d.warnings.map((w) => `machine: ${w}`), ...(d.refused ?? [])];
  const out: Settings = { ...s };
  if (d.localTracesUrl) out.advertisedEndpoint = d.localTracesUrl;
  // Where the key goes comes from the owner-only key file, never from the
  // discovery answer (review E-04): discovery only names the file.
  if ((!out.apiKey || !out.orgUrl) && (choice === "online" || choice === "both") && d.credentialPresent && d.credentialFile) {
    const cred = readCredentialFile(d.credentialFile);
    if (!out.apiKey && cred.key) {
      out.apiKey = cred.key;
      out.credentialSource = "file";
    }
    if (!out.orgUrl && cred.gateway) out.orgUrl = cred.gateway;
    if (cred.error) problems.push(cred.error);
  }
  if (!d.localEnabled && (choice === "local" || choice === "both")) {
    problems.push("this machine's Observer has [observability] off, so it refuses local spans; turn it on in the dashboard (Settings > Your apps)");
  }
  return { settings: out, problems };
}

/** The SDK-held file's state after the ladders (sdk-api-surface.md section 1, `sdkFile.state`). */
export type SdkFileUse = "absent" | "used" | "unused" | "refused" | "expired" | "not_read";

/**
 * Settings with the SDK-held file's record filled in (credential ladder
 * record 3; plan 3.4, ruling R10), for a destination that needs the online
 * leg. A key and its gateway travel together: the file's key is used only
 * with the file's own gateway_url, never sent to an address named elsewhere.
 * A key the app gave (option or env) keeps its place, and may take the
 * file's gateway line when it was given none (record 1, as with the
 * machine's file). A key from the machine's record wins, and the file is
 * named as present but unused. An expired key is never used (the fix is
 * setup). Returns the settings, the problems to report, the file's state,
 * and the dashboard base when the file's record is the one in use.
 */
export function withSdkFile(
  s: Settings,
  file: SdkFileState | null,
  choice: DestinationChoice | "",
  now: number = Date.now(),
): { settings: Settings; problems: string[]; use: SdkFileUse; dashboardUrl: string } {
  const out: Settings = { ...s };
  if (!file) return { settings: out, problems: [], use: "not_read", dashboardUrl: "" };
  if (!file.present) return { settings: out, problems: [], use: "absent", dashboardUrl: "" };
  if (!file.record) return { settings: out, problems: [`${file.error}; the next source is used`], use: "refused", dashboardUrl: "" };
  const rec = file.record;
  const problems = [...file.warnings];
  const result = (use: SdkFileUse, dashboardUrl = "") => ({ settings: out, problems, use, dashboardUrl });
  if (choice !== "online" && choice !== "both") return result("unused");
  if (out.apiKey) {
    if (out.credentialSource === "file") {
      problems.push(`the SDK-held credential file ${file.path} is present but unused: this machine's Observer is signed in, and its key is used`);
    } else if (!out.orgUrl && rec.gateway) {
      out.orgUrl = rec.gateway;
    }
    return result("unused");
  }
  if (expired(rec.expiresAt, now)) {
    problems.push(expiryNote(rec.expiresAt, file.path, now));
    return result("expired");
  }
  if (!rec.gateway) {
    problems.push(`the SDK-held credential file ${file.path} names no usable gateway_url; its key is not used`);
    return result("unused");
  }
  if (out.orgUrl && trimSlash(out.orgUrl) !== rec.gateway) {
    problems.push(`the gateway URL the app set (${out.orgUrl}) is not the one the key in ${file.path} belongs to (${rec.gateway}); the file's key is not used`);
    return result("unused");
  }
  out.apiKey = rec.key;
  out.orgUrl = rec.gateway;
  out.credentialSource = "sdk_file";
  const soon = expiryNote(rec.expiresAt, file.path, now);
  if (soon) problems.push(soon);
  return result("used", rec.dashboardUrl);
}

/**
 * The delegate the SDK runs while discovery is in flight: holds finished
 * spans (up to DISCOVERY_QUEUE_MAX; beyond that they are counted as dropped)
 * and hands them to the real delegate once it is known.
 */
export class PendingProcessor implements SpanProcessor {
  private queue: ReadableSpan[] = [];
  private target: SpanProcessor | null = null;
  private settled = false;
  readonly ready: Promise<void>;
  private resolveReady!: () => void;

  constructor() {
    this.ready = new Promise((r) => (this.resolveReady = r));
  }

  /** Counted destinations per span: one while held, then the target's (review E-31). */
  get legs(): number {
    return this.settled && this.target ? legsOf(this.target) : 1;
  }

  /** Install the real delegate (null: drop) and replay what was held. */
  resolve(target: SpanProcessor | null): void {
    if (this.settled) return;
    this.settled = true;
    this.target = target;
    const held = this.queue;
    this.queue = [];
    // A held span was counted once; its replay goes to every destination.
    if (target) stats.handedSpans += held.length * (legsOf(target) - 1);
    for (const s of held) {
      if (!target) {
        stats.droppedSpans += 1;
        continue;
      }
      try {
        target.onEnd(s);
      } catch {
        // never break
      }
    }
    this.resolveReady();
  }

  onStart(span: Span, ctx: Context): void {
    this.target?.onStart(span, ctx);
  }

  onEnd(span: ReadableSpan): void {
    if (this.settled) {
      if (this.target) this.target.onEnd(span);
      else stats.droppedSpans += 1;
      return;
    }
    if (this.queue.length >= DISCOVERY_QUEUE_MAX) {
      stats.droppedSpans += 1;
      return;
    }
    this.queue.push(span);
  }

  async forceFlush(): Promise<void> {
    await this.ready;
    await this.target?.forceFlush();
  }

  async shutdown(): Promise<void> {
    await this.ready;
    await this.target?.shutdown();
  }
}
