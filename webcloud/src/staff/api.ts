// The staff console's fetch client (managed-SaaS M6.8; the routes are
// internal/cloudserver/api/staff.go's staffRoutes). It talks ONLY to the
// staff host's own /staff routes: the staff session is the host-only,
// SameSite=Strict __Host-sbci-staff cookie, which a verified passkey
// assertion mints and JS never reads. Every change also carries the staff
// CSRF header (X-SBCI-Staff-CSRF). The CSRF token arrives only from a
// passkey assertion and is kept in this module's memory alone (never in any
// storage): a reload keeps the session for reading, and the next change asks
// for the passkey again, which the server requires anyway when the last
// assertion is older than 15 minutes.

import {
  credentialToJSON,
  toCreationOptions,
  toRequestOptions,
  type CreationOptionsJSON,
  type CredentialLike,
  type RequestOptionsJSON,
} from "./lib/webauthn";
import type { Capability } from "./lib/model";
import type { Section } from "./lib/envelope";

const BASE = "/staff";
const CSRF_HEADER = "X-SBCI-Staff-CSRF";

let csrf: string | null = null;

/** hasStaffCsrf reports whether this page load holds a CSRF token (it was
 *  given by a passkey assertion in this tab). */
export function hasStaffCsrf(): boolean {
  return csrf !== null;
}

/** StaffApiError is a refused or failed staff request: the server's error
 *  code (e.g. reauth_required, csrf_failed, forbidden_role) and message. */
export class StaffApiError extends Error {
  readonly status: number;
  readonly code: string;
  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = "StaffApiError";
    this.status = status;
    this.code = code;
  }
}

/** needsPasskey reports whether an error is cured by verifying the passkey
 *  again (a stale assertion, or no CSRF token in this tab). */
export function needsPasskey(err: unknown): boolean {
  return err instanceof StaffApiError && (err.code === "reauth_required" || err.code === "csrf_failed");
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json" };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (method !== "GET" && csrf) headers[CSRF_HEADER] = csrf;
  const res = await fetch(BASE + path, {
    method,
    headers,
    credentials: "same-origin",
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (res.status === 204) return undefined as T;
  let data: unknown = null;
  try {
    data = await res.json();
  } catch {
    data = null;
  }
  if (!res.ok) {
    // writeErr's body: {"error": message, "code": code}.
    const e = (data ?? {}) as { error?: string; code?: string };
    throw new StaffApiError(res.status, e.code ?? `http_${res.status}`, e.error ?? `Request failed (${res.status})`);
  }
  return data as T;
}

// ---- session ---------------------------------------------------------------

export interface StaffMe {
  staff_id: string;
  display_name: string;
  role: "support" | "ops" | "admin";
  asserted_at: string;
  fresh_until: string;
  expires_at: string;
}

export const getMe = () => request<StaffMe>("GET", "/api/me");

export interface StaffFeatures {
  features: Record<string, boolean>;
  capabilities: Capability[];
  fresh_window_seconds: number;
  max_reason_characters: number;
}

export const getFeatures = () => request<StaffFeatures>("GET", "/api/features");

/** signInWithPasskey runs one assertion: options from the server, the
 *  browser's passkey prompt, the credential back. It keeps the new CSRF
 *  token. It is both sign-in and the re-verification before a change. */
export async function signInWithPasskey(creds: CredentialsContainer): Promise<void> {
  const begin = await request<{ publicKey: RequestOptionsJSON }>("POST", "/auth/webauthn/assert/begin");
  const cred = (await creds.get({ publicKey: toRequestOptions(begin.publicKey) })) as unknown as CredentialLike | null;
  if (!cred) throw new Error("No passkey was chosen.");
  const fin = await request<{ csrf_token: string }>("POST", "/auth/webauthn/assert/finish", { credential: credentialToJSON(cred) });
  csrf = fin.csrf_token;
}

/** registerPasskey registers a passkey with a one-time enrolment code from
 *  the operator (`observer-cloud staff enrol`). */
export async function registerPasskey(creds: CredentialsContainer, code: string, label: string): Promise<void> {
  const begin = await request<{ publicKey: CreationOptionsJSON }>("POST", "/auth/webauthn/register/begin", { enrolment_code: code });
  const cred = (await creds.create({ publicKey: toCreationOptions(begin.publicKey) })) as unknown as CredentialLike | null;
  if (!cred) throw new Error("No passkey was created.");
  await request("POST", "/auth/webauthn/register/finish", { credential: credentialToJSON(cred), label });
}

export async function signOut(): Promise<void> {
  try {
    await request("POST", "/auth/logout");
  } finally {
    csrf = null;
  }
}

// ---- reads -------------------------------------------------------------------

export interface StaffOrg {
  org_id: string;
  kind: string;
  slug: string;
  display_name: string;
  status: string;
  tenancy: string;
  host_id?: string;
  platform_rail_enabled: boolean;
  lifecycle_gen: number;
  created_at: string;
  updated_at: string;
  members: number;
  grant?: { action: string; plan_name?: string; plan_version?: number; effective_until?: string | null };
  subscription?: { status: string; plan_name?: string; plan_version?: number; period_end?: string | null };
  usage?: { day: string; seats: number; members: number };
  entitlements?: { version: number; issued_at: string };
}

export interface SignedDoc {
  version: number;
  key_id: string;
  issued_at: string;
  issued_by: string;
  body?: unknown;
  body_bytes: number;
}

export interface StaffOrgDetail {
  org: StaffOrg;
  grants: {
    seq: number;
    action: string;
    plan_name?: string;
    plan_version?: number;
    effective_until?: string | null;
    actor: string;
    reason: string;
    at: string;
  }[];
  usage: { day: string; seats: number; members: number; sessions?: number; machine_identities?: number }[];
  entitlements?: SignedDoc;
  intents: {
    verb: string;
    state: string;
    attempts: number;
    last_error_class?: string;
    next_attempt_at: string;
    created_at: string;
    done_at?: string | null;
  }[];
  deletion?: { state: string; blocked_reason?: string; created_at: string; updated_at: string; done_at?: string | null };
}

export const listOrgs = () => request<{ orgs: StaffOrg[] }>("GET", "/api/orgs");
export const getOrg = (id: string) => request<StaffOrgDetail>("GET", `/api/orgs/${encodeURIComponent(id)}`);

export interface AvailabilityInput {
  section: Section;
  key: string;
  value: unknown;
  reason: string;
  author: string;
  updated_at: string;
}

export const listAvailability = () => request<{ inputs: AvailabilityInput[] }>("GET", "/api/availability");
export const getAvailabilityDocument = () => request<{ document: SignedDoc | null }>("GET", "/api/availability/document");

export interface StaffAction {
  action_id: string;
  at: string;
  actor: string;
  verb: string;
  subject_staff_id?: string;
  org_id?: string;
  target?: string;
  detail?: unknown;
  reason: string;
  result: string;
}

export interface LogFilter {
  limit?: number;
  org?: string;
  verb?: string;
  actor?: string;
  before?: string;
}

export function listLog(f: LogFilter = {}) {
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(f)) {
    if (v !== undefined && v !== "") q.set(k, String(v));
  }
  const qs = q.toString();
  return request<{ actions: StaffAction[] }>("GET", `/api/log${qs ? `?${qs}` : ""}`);
}

/** getOptional reads a route a coordinating lane adds (behind a feature flag
 *  from GET /staff/api/features); the console renders its JSON generically. */
export const getOptional = (path: string) => request<unknown>("GET", path);

// ---- writes (each one: a fresh passkey assertion, CSRF, a reason, and a
// staff_actions row written by the server in the same transaction) --------

export const setAvailability = (section: Section, key: string, value: unknown, reason: string) =>
  request<unknown>("PUT", `/api/availability/${section}/${encodeURIComponent(key)}`, { value, reason });

export const deleteAvailability = (section: Section, key: string, reason: string) =>
  request<void>("DELETE", `/api/availability/${section}/${encodeURIComponent(key)}`, { reason });

/** setCsrfForTest seeds the token (render tests only). */
export function setCsrfForTest(t: string | null): void {
  csrf = t;
}

/** PlanGrantBody is the staff plan grant write a later ruling may add
 *  (feature plan_grant_write, POST /staff/api/orgs/{id}/plan-grant). Plan
 *  grants are operator-only CLI by W15-D13 today; the route does not exist,
 *  and the console only calls this when the feature probe says it does. */
export interface PlanGrantBody {
  action: "grant" | "revoke";
  plan?: string;
  version?: number;
  until?: string;
  reason: string;
}

export const postPlanGrant = (orgId: string, body: PlanGrantBody) =>
  request<unknown>("POST", `/api/orgs/${encodeURIComponent(orgId)}/plan-grant`, body);
