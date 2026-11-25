/**
 * The client side of the device sign-in (plan 3.6; the wire is
 * sdk/contract/fixtures/setup/{connect-create,connect-poll,grant-redeem}.json):
 *
 * 1. a redeem secret (32 random bytes, unpadded base64url) stays in memory;
 *    its SHA-256 goes to the create;
 * 2. POST <cloud>/v1/connect/requests with purpose sdk_key: a user code, an
 *    approve URL and a device code (returned once; never printed);
 * 3. GET the request every `interval` seconds with the device code as bearer,
 *    until the person approved and the cloud hands over a key grant;
 * 4. POST <server_url>/api/agent/sdk-credential/grant with the grant and the
 *    redeem secret: the organization's host mints the member's own SDK key.
 *
 * Each answer goes through a pure outcome table (createOutcome, pollOutcome,
 * redeemOutcome) that names setup's next state and exit code. Neither the
 * device code, the redeem secret, the grant nor the key is ever in a message.
 */

import { createHash, randomBytes } from "node:crypto";

import { gatewayProblem, dashboardProblem } from "../credfile.js";
import { obj, retryAfterSeconds, secureOrLoopback, str, type HttpFn } from "./net.js";

/** The production cloud (`--cloud-url` / SUPERBASED_CLOUD_URL replace it). */
export const DEFAULT_CLOUD_URL = "https://cloud.superbased.app";
export const CREATE_PATH = "/v1/connect/requests";
export const REDEEM_PATH = "/api/agent/sdk-credential/grant";
export const REVOKE_PATH = "/v1/sdk/credential/revoke";
/** The client name the create carries (closed vocabulary on the cloud). */
export const CLIENT_NAME = "superbased-sdk-typescript";
/** How long setup waits for an approval when the cloud names no expiry. */
export const DEFAULT_APPROVAL_SECONDS = 900;

/** The exit codes (plan 3.5). */
export const EXIT = { done: 0, internal: 1, person: 2, refused: 3, environment: 4, notSeen: 5 } as const;

/** A new redeem secret: 32 random bytes as unpadded base64url (43 characters). */
export function newRedeemSecret(): string {
  return randomBytes(32).toString("base64url");
}

/** base64url-nopad(SHA-256(ASCII bytes of the secret)): what the create carries (internal/sdkkeygrant RedeemHash). */
export function redeemHash(secret: string): string {
  return createHash("sha256").update(secret, "ascii").digest("base64url");
}

/** A machine name as the create takes it: trimmed, control and bidi characters removed, at most 64 characters. */
export function machineName(raw: string): string {
  const s = raw
    .replace(/[\u0000-\u001f\u007f-\u009f‎‏‪-‮⁦-⁩]/g, "")
    .trim()
    .slice(0, 64)
    .trim();
  return s || "unknown";
}

/** The create body (purpose sdk_key). */
export interface CreateInput {
  clientVersion: string;
  projectName: string;
  machineName: string;
  os: string;
  arch: string;
  team: string;
  redeemHash: string;
}

export function createBody(i: CreateInput): Record<string, string> {
  const lower = (s: string) => s.toLowerCase().replace(/[^a-z0-9_]/g, "_").slice(0, 16) || "unknown";
  return {
    purpose: "sdk_key",
    client: CLIENT_NAME,
    client_version: i.clientVersion,
    project_name: i.projectName,
    machine_name: i.machineName,
    os: lower(i.os),
    arch: lower(i.arch),
    target_hint: i.team,
    redeem_hash: i.redeemHash,
  };
}

/** A stop: setup ends with this exit code and message (the server's message as sent, when it sent one). */
export interface Stop {
  kind: "stop";
  exit: number;
  /** The server's code ("" when none). */
  code: string;
  message: string;
  /** The upgrade link of a plan refusal ("" when none). */
  link: string;
}

const stop = (exit: number, code: string, message: string, link = ""): Stop => ({ kind: "stop", exit, code, message, link });

/** The cloud's error body is {error: <message>, code}; the tenant's is {error: <code>, message}. */
function cloudError(body: unknown): { code: string; message: string } {
  const b = obj(body);
  return { code: str(b, "code"), message: str(b, "error") };
}
function tenantError(body: unknown): { code: string; message: string } {
  const b = obj(body);
  return { code: str(b, "error"), message: str(b, "message") };
}

/** What the create gave setup. */
export interface Created {
  kind: "created";
  requestId: string;
  userCode: string;
  approveUrl: string;
  verifyUrl: string;
  expiresIn: number;
  interval: number;
  /** The bearer for the polls: kept in memory, never printed. */
  deviceCode: string;
}

/** The create's answer to setup's next state (pure). */
export function createOutcome(status: number, body: unknown, retryAfter = ""): Created | Stop {
  if (status === 201) {
    const b = obj(body);
    const c: Created = {
      kind: "created",
      requestId: str(b, "request_id"),
      userCode: str(b, "user_code"),
      approveUrl: str(b, "approve_url"),
      verifyUrl: str(b, "verify_url"),
      expiresIn: typeof b.expires_in === "number" && b.expires_in > 0 ? b.expires_in : DEFAULT_APPROVAL_SECONDS,
      interval: typeof b.interval === "number" && b.interval > 0 ? b.interval : 3,
      deviceCode: str(b, "device_code"),
    };
    if (!c.requestId || !c.userCode || !c.deviceCode || !/^[A-Za-z0-9._~-]{1,64}$/.test(c.requestId) || !secureOrLoopback(c.approveUrl)) {
      return stop(EXIT.environment, "", "The cloud's answer to the sign-in request is not one setup can use; try again later.");
    }
    return c;
  }
  const e = cloudError(body);
  if (status === 429) return stop(EXIT.environment, e.code || "rate_limited", `${e.message || "The cloud is limiting sign-in requests from this network"}. Try again in ${retryAfterSeconds(retryAfter, 60, 3600)} seconds.`);
  if (status === 400 && e.code === "invalid_purpose") return stop(EXIT.environment, e.code, e.message || "This cloud does not take SDK sign-in requests yet.");
  return stop(EXIT.environment, e.code, `The cloud refused the sign-in request (HTTP ${status}${e.code ? `, ${e.code}` : ""})${e.message ? `: ${e.message}` : ""}.`);
}

/** Where an approval points: the chosen dashboard. */
export interface Target {
  orgId: string;
  slug: string;
  kind: string;
  displayName: string;
  serverUrl: string;
  ready: boolean;
}

export type PollState =
  | { kind: "wait"; delayMs: number; note: string }
  | { kind: "grant"; grant: string; target: Target }
  | Stop;

function target(v: unknown): Target {
  const t = obj(v);
  return {
    orgId: str(t, "org_id"),
    slug: str(t, "slug"),
    kind: str(t, "kind"),
    displayName: str(t, "display_name"),
    serverUrl: str(t, "server_url").replace(/\/+$/, ""),
    ready: t.ready === true,
  };
}

/** One poll's answer to setup's next state (pure; contract setup-cases.json device_flow). */
export function pollOutcome(status: number, body: unknown, retryAfter: string, intervalS: number): PollState {
  const b = obj(body);
  const every = (typeof b.interval === "number" && b.interval > 0 ? b.interval : intervalS) * 1000;
  if (status === 200) {
    const st = str(b, "status");
    if (st === "pending") return { kind: "wait", delayMs: every, note: "" };
    if (st === "approved") {
      const t = target(b.target);
      const grant = str(b, "key_grant");
      if (!grant || !t.ready || !t.serverUrl) return { kind: "wait", delayMs: every, note: "Approved. Waiting for your dashboard to be ready..." };
      if (!grant.startsWith("sbsk1.") || gatewayProblem(t.serverUrl)) return stop(EXIT.environment, "", "The cloud named a dashboard address setup cannot use; nothing was redeemed.");
      return { kind: "grant", grant, target: t };
    }
    if (st === "declined") return stop(EXIT.person, "declined", "The sign-in request was declined in the browser; run setup again to start over.");
    if (st === "expired") return stop(EXIT.person, "expired", "The sign-in request expired before it was approved; run setup again.");
    return stop(EXIT.environment, "", `The cloud answered with an unknown status ${JSON.stringify(st)}.`);
  }
  if (status === 429) return { kind: "wait", delayMs: retryAfterSeconds(retryAfter, intervalS) * 1000, note: "" };
  const e = cloudError(body);
  if (status === 409) {
    const m = e.message || "The key grant for this request was already delivered";
    return stop(EXIT.person, e.code, /run setup again/i.test(m) ? m : `${m.replace(/[.;\s]+$/, "")}; run setup again.`);
  }
  if (status === 404) return stop(EXIT.person, e.code || "not_found", "The sign-in request is gone; run setup again.");
  if (status === 401) return stop(EXIT.person, e.code || "unauthorized", "The cloud did not accept this sign-in request's device code; run setup again.");
  if (status >= 500) return { kind: "wait", delayMs: every, note: "" };
  return stop(EXIT.environment, e.code, `The cloud answered HTTP ${status}${e.code ? ` (${e.code})` : ""}.`);
}

/** What the organization's host minted (the key stays inside setup until it is written to the file). */
export interface Minted {
  kind: "minted";
  key: string;
  keyId: string;
  gatewayUrl: string;
  dashboardUrl: string;
  expiresAt: string;
  /** The month's allowance is already used: the refusal body (null when not). */
  planRefusal: Record<string, unknown> | null;
}

/** key_grant_refused reasons that mean "you may not have a key here" (exit 3); the rest mean "run setup again" (exit 2). */
export const REFUSED_REASONS: readonly string[] = ["not_a_member", "member_inactive", "wrong_org"];

/** The redeem's answer to setup's next state (pure; contract setup-cases.json device_flow and first_run_refusals). */
export function redeemOutcome(status: number, body: unknown, retryAfter = ""): Minted | Stop | { kind: "retry"; delayMs: number } {
  const b = obj(body);
  if (status === 201) {
    const key = str(b, "credential");
    const keyId = str(b, "key_id");
    const gatewayUrl = str(b, "gateway_url").replace(/\/+$/, "");
    const dashboardUrl = str(b, "dashboard_url").replace(/\/+$/, "");
    if (!/^[^\s.]+\.\S+$/.test(key) || key.length > 1024 || /[^ -~]/.test(key) || gatewayProblem(gatewayUrl)) {
      return stop(EXIT.environment, "", "The organization's answer did not carry a usable SDK key; nothing was written.");
    }
    const pr = b.plan_refusal;
    return {
      kind: "minted",
      key,
      keyId: keyId || key.slice(0, key.indexOf(".")),
      gatewayUrl,
      dashboardUrl: dashboardUrl && !dashboardProblem(dashboardUrl) ? dashboardUrl : "",
      expiresAt: str(b, "expires_at"),
      planRefusal: pr !== null && typeof pr === "object" && !Array.isArray(pr) ? (pr as Record<string, unknown>) : null,
    };
  }
  if (status === 429) return { kind: "retry", delayMs: retryAfterSeconds(retryAfter, 30) * 1000 };
  const e = tenantError(body);
  if (status === 403 && e.code === "plan_required") return stop(EXIT.refused, e.code, e.message, str(b, "upgrade_url"));
  if (status === 403 && e.code === "key_grant_refused") {
    const reason = str(b, "reason");
    return stop(REFUSED_REASONS.includes(reason) ? EXIT.refused : EXIT.person, reason || e.code, e.message || "The organization refused this approval.");
  }
  if (status === 403 && e.code === "key_grant_not_accepted") return stop(EXIT.refused, e.code, e.message || "This dashboard does not take SDK sign-in approvals.");
  if (status === 404 || e.code === "not_supported") return stop(EXIT.refused, e.code || "not_supported", e.message || "This organization issues no member SDK keys; ask an admin for an app key.");
  if (status === 410) return stop(EXIT.person, e.code || "key_grant_used", e.message || "This approval was already used; run setup again.");
  return stop(EXIT.environment, e.code, `The organization's host answered HTTP ${status}${e.code ? ` (${e.code})` : ""}${e.message ? `: ${e.message}` : ""}.`);
}

/** The phases' clock: tests run it instantly. */
export interface Clock {
  now(): number;
  sleep(ms: number): Promise<void>;
}

export const realClock: Clock = {
  now: () => Date.now(),
  sleep: (ms) => new Promise((r) => setTimeout(r, ms)),
};

/** Create the request (a 429 stops: exit 4, try again later). */
export async function createRequest(http: HttpFn, cloudUrl: string, input: CreateInput): Promise<Created | Stop> {
  const a = await http({ method: "POST", url: cloudUrl.replace(/\/+$/, "") + CREATE_PATH, body: createBody(input) });
  return createOutcome(a.status, a.body, a.retryAfter);
}

/** Poll until a grant or a stop (bounded by the request's expiry). `onNote` hears each new waiting line once. */
export async function pollForGrant(http: HttpFn, cloudUrl: string, c: Created, clock: Clock, onNote: (line: string) => void): Promise<{ kind: "grant"; grant: string; target: Target } | Stop> {
  const deadline = clock.now() + c.expiresIn * 1000;
  const url = `${cloudUrl.replace(/\/+$/, "")}${CREATE_PATH}/${encodeURIComponent(c.requestId)}`;
  let interval = c.interval;
  let lastNote = "";
  let failures = 0;
  while (clock.now() < deadline) {
    let st: PollState;
    try {
      const a = await http({ method: "GET", url, headers: { Authorization: `Bearer ${c.deviceCode}` } });
      failures = 0;
      st = pollOutcome(a.status, a.body, a.retryAfter, interval);
      const b = obj(a.body);
      if (typeof b.interval === "number" && b.interval > 0) interval = b.interval;
    } catch {
      failures += 1;
      if (failures >= 5) return stop(EXIT.environment, "", "The cloud stopped answering while waiting for the approval; run setup again.");
      st = { kind: "wait", delayMs: interval * 1000, note: "" };
    }
    if (st.kind !== "wait") return st;
    if (st.note && st.note !== lastNote) {
      lastNote = st.note;
      onNote(st.note);
    }
    await clock.sleep(st.delayMs);
  }
  return stop(EXIT.person, "expired", "The sign-in request expired before it was approved; run setup again.");
}

/** Redeem the grant on the organization's host (one retry after a 429). */
export async function redeemGrant(
  http: HttpFn,
  serverUrl: string,
  grant: string,
  redeemSecret: string,
  machine: string,
  replacesKeyId: string,
  clock: Clock,
): Promise<Minted | Stop> {
  for (let attempt = 0; attempt < 2; attempt++) {
    const a = await http({
      method: "POST",
      url: serverUrl.replace(/\/+$/, "") + REDEEM_PATH,
      body: { key_grant: grant, redeem_secret: redeemSecret, machine_name: machine, replaces_key_id: replacesKeyId },
    });
    const o = redeemOutcome(a.status, a.body, a.retryAfter);
    if (o.kind !== "retry") return o;
    if (attempt === 0) await clock.sleep(o.delayMs);
  }
  return stop(EXIT.environment, "rate_limited", "The organization's host is limiting requests; run setup again in a minute.");
}

/** Revoke a key with itself (setup --forget). Returns whether the host said it is revoked. */
export async function revokeKey(http: HttpFn, gatewayUrl: string, key: string): Promise<{ revoked: boolean; detail: string }> {
  try {
    const a = await http({ method: "POST", url: gatewayUrl.replace(/\/+$/, "") + REVOKE_PATH, headers: { Authorization: `Bearer ${key}` } });
    if (a.status === 200) return { revoked: true, detail: "" };
    if (a.status === 401) return { revoked: false, detail: "the key was already revoked or is unknown" };
    return { revoked: false, detail: `HTTP ${a.status}` };
  } catch (err) {
    return { revoked: false, detail: err instanceof Error ? err.message : "no answer" };
  }
}
