// Tiny fetch client for the app.superbased.app cloud portal.
//
// Auth model: the session is an httpOnly cookie the browser sends automatically
// on every request (credentials: "include"); JS never reads or sets it. The
// CSRF token is kept ONLY in this module-level variable — it is never
// persisted to localStorage/sessionStorage. (It is also relayed to other
// open tabs over a same-origin BroadcastChannel — see the "Multi-tab CSRF
// sync" section below — which is transient in-memory delivery, not storage,
// so this invariant still holds.) A page reload used to lose it and bounce a
// signed-in user back to the sign-in page (E8); App.tsx now calls
// getSession() on every boot to re-derive a fresh token from the still-live
// session cookie before any route decision is made, so the reload-bounce no
// longer happens for a user with a live cookie.

let csrfToken: string | null = null;
let accountId: string | null = null;
let authMode: AuthMode | null = null;
// The signed-in developer's display identity, kept next to the account id: it
// arrives on the same responses, lives exactly as long, and is cleared by the
// same sign-out. Like the account id it is in-memory only - never persisted.
let profile: AccountProfile | null = null;

/** setCsrf stores the CSRF token in memory after a successful login. */
export function setCsrf(t: string): void {
  csrfToken = t;
}

/** clearCsrf drops the in-memory CSRF token (sign-out / deletion). */
export function clearCsrf(): void {
  csrfToken = null;
  accountId = null;
  authMode = null;
  profile = null;
}

/** hasCsrf reports whether the user is "signed in" for this page load. */
export function hasCsrf(): boolean {
  return csrfToken !== null;
}

/** getAccountId returns the signed-in account id, or null if signed out. */
export function getAccountId(): string | null {
  return accountId;
}

/** getProfile returns the signed-in developer's display identity, or null when
 * signed out or when the server knows no name for this account. */
export function getProfile(): AccountProfile | null {
  return profile;
}

/** getAuthMode returns the signed-in session's auth mode, or null if signed
 * out (or if it has not been learned yet this page load — see
 * getAuthModeHint for the pre-sign-in cached hint). */
export function getAuthMode(): AuthMode | null {
  return authMode;
}

// ---- Auth-mode hint (localStorage, non-sensitive) --------------------------
//
// Before sign-in, the client has no live signal for whether this deployment
// runs WorkOS or dev-auth: /portal/api/session only reports auth_mode on a
// 200 (already-signed-in) response. We cache the last confirmed mode behind
// a plain non-sensitive string hint so a returning dev-auth user's SignIn
// page shows the right form again; a brand new visitor (no hint yet) sees
// the WorkOS button by default, which is the honest production default.

const AUTH_MODE_HINT_KEY = "sbci_auth_mode_hint";

function writeAuthModeHint(mode: AuthMode): void {
  try {
    localStorage.setItem(AUTH_MODE_HINT_KEY, mode);
  } catch {
    // localStorage unavailable (private mode, quota) — the hint is a UX
    // nicety only, never required for correctness.
  }
}

/** getAuthModeHint returns the last confirmed auth_mode cached in this
 * browser, or null if unknown (never signed in here, or storage cleared). */
export function getAuthModeHint(): AuthMode | null {
  try {
    const v = localStorage.getItem(AUTH_MODE_HINT_KEY);
    return v === "workos" || v === "dev" ? v : null;
  } catch {
    return null;
  }
}

// ---- Multi-tab CSRF sync (BroadcastChannel) --------------------------------
//
// A same-origin BroadcastChannel carries the ROTATED RAW token directly to
// every other open tab, in memory only — BroadcastChannel messages are
// transient same-origin postMessage-style delivery, never persisted to
// localStorage/sessionStorage/disk, so this does not weaken the "CSRF token
// never touches storage" invariant above.
//
// Whichever tab actually calls getSession()/login() broadcasts the fresh
// token; every other open tab ADOPTS it directly (no network call), so every
// tab converges on the same, latest token. This replaces an earlier
// version-stamp-in-localStorage protocol: that design made every OTHER tab
// re-call getSession() on seeing the stamp change, which rotates the token
// again server-side and re-triggers the same stamp change on every tab — an
// unbounded rotation storm. Broadcasting the already-rotated token avoids
// that class of bug entirely: listeners never call the network.
//
// Guarded for environments without BroadcastChannel (older Safari, some
// embedded webviews): sync silently degrades to a no-op and each tab tracks
// its own session independently, which is still correct for a single tab.

const CSRF_CHANNEL_NAME = "sbci-csrf";

type CsrfSyncMessage =
  | {
      type: "csrf";
      token: string;
      accountId: string;
      authMode: AuthMode;
      // Carried alongside the account id so a tab that adopts a session also
      // adopts the name to render for it; null means "nothing known", which
      // every reader treats as "fall back to the account id".
      profile: AccountProfile | null;
    }
  | { type: "signed-out" };

const csrfChannel: BroadcastChannel | null =
  typeof BroadcastChannel === "function"
    ? new BroadcastChannel(CSRF_CHANNEL_NAME)
    : null;

function broadcastCsrf(): void {
  if (csrfChannel === null) {
    return;
  }
  if (csrfToken === null || accountId === null || authMode === null) {
    return;
  }
  const msg: CsrfSyncMessage = {
    type: "csrf",
    token: csrfToken,
    accountId,
    authMode,
    profile,
  };
  csrfChannel.postMessage(msg);
}

function broadcastSignedOut(): void {
  const msg: CsrfSyncMessage = { type: "signed-out" };
  csrfChannel?.postMessage(msg);
}

/**
 * onCsrfSync registers a listener for session state broadcast by another
 * same-origin tab: `true` when that tab adopted a live token (this module's
 * in-memory state has already been updated by the time the callback fires),
 * `false` on sign-out. Returns an unsubscribe function. A no-op subscription
 * (never fires, unsubscribe is a no-op) when BroadcastChannel is
 * unavailable — see the guard note above.
 */
export function onCsrfSync(callback: (signedIn: boolean) => void): () => void {
  if (csrfChannel === null) {
    return () => {};
  }
  function onMessage(e: MessageEvent<CsrfSyncMessage>) {
    const msg = e.data;
    if (msg.type === "signed-out") {
      clearCsrf();
      callback(false);
      return;
    }
    csrfToken = msg.token;
    accountId = msg.accountId;
    authMode = msg.authMode;
    // `?? null` tolerates a message from a tab still running the older build,
    // which carries no profile field at all.
    profile = msg.profile ?? null;
    writeAuthModeHint(msg.authMode);
    callback(true);
  }
  csrfChannel.addEventListener("message", onMessage);
  return () => csrfChannel.removeEventListener("message", onMessage);
}

/** ApiError carries the server's honest {error, code} for the UI to render. */
export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
  }
}

interface ErrorBody {
  error?: string;
  code?: string;
}

async function parseError(res: Response): Promise<ApiError> {
  let body: ErrorBody = {};
  try {
    body = (await res.json()) as ErrorBody;
  } catch {
    // Non-JSON error body; fall back to status text.
  }
  const message = body.error ?? res.statusText ?? "request failed";
  const code = body.code ?? "";
  return new ApiError(res.status, code, message);
}

async function getJSON<T>(path: string): Promise<T> {
  const res = await fetch(path, {
    method: "GET",
    credentials: "include",
    headers: { Accept: "application/json" },
  });
  if (!res.ok) {
    throw await parseError(res);
  }
  return (await res.json()) as T;
}

async function mutate<T>(
  path: string,
  method: "POST" | "DELETE",
  body?: unknown,
): Promise<T> {
  const headers: Record<string, string> = {
    Accept: "application/json",
    "Content-Type": "application/json",
  };
  if (csrfToken !== null) {
    headers["X-SBCI-CSRF"] = csrfToken;
  }
  const res = await fetch(path, {
    method,
    credentials: "include",
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!res.ok) {
    throw await parseError(res);
  }
  // Some mutations (logout) may return no content.
  const text = await res.text();
  if (text.length === 0) {
    return undefined as T;
  }
  return JSON.parse(text) as T;
}

// ---- Types ----------------------------------------------------------------

export type AuthMode = "workos" | "dev";

/**
 * AccountProfile is the signed-in developer's own display identity, captured
 * from the identity provider at sign-in. Both halves may be absent, and the
 * whole object is absent when the server knows no name for this account - the
 * UI falls back to the account id in that case rather than rendering a blank.
 */
export interface AccountProfile {
  email: string;
  display_name: string;
}

export interface LoginResult {
  account_id: string;
  csrf_token: string;
  expires_at: string;
  profile?: AccountProfile;
}

export interface SessionResult {
  account_id: string;
  csrf_token: string;
  expires_at: string;
  auth_mode: AuthMode;
  profile?: AccountProfile;
}

export interface Allowance {
  feature: string;
  daily_used: number;
  daily_cap: number;
  monthly_used: number;
  monthly_cap: number;
  concurrency_used: number;
  concurrency_cap: number;
}

export interface UsageWarning {
  window: string;
  level: "warn" | "critical" | "exhausted";
  used: number;
  cap: number;
  used_fraction: number;
}

export interface Overview {
  coverage_disclosure: string;
  jobs_by_state: Record<string, number>;
  jobs_total: number;
  results_total: number;
  last_result_at: string | null;
  allowance: Allowance;
}

// ---- Structural insights (W2) ---------------------------------------------

export interface MixEntry {
  key: string;
  count: number;
}

export interface InsightsDay {
  period: string;
  device_count: number;
  session_count: number;
  action_count: number;
  tokens_in: number;
  tokens_out: number;
  cache_read_tokens: number;
  cost_usd: number;
  tool_mix: MixEntry[];
  model_family_mix: MixEntry[];
  sessions_with_outcomes: number;
  sessions_with_verification: number;
  verification_coverage_band: string;
  outcome_evidence_band: string;
  computed_at: string;
}

export interface InsightsSummary {
  active_days: number;
  session_count: number;
  action_count: number;
  tokens_in: number;
  tokens_out: number;
  cache_read_tokens: number;
  cost_usd: number;
  tool_mix: MixEntry[];
  model_family_mix: MixEntry[];
  sessions_with_outcomes: number;
  sessions_with_verification: number;
  verification_coverage_band: string;
  outcome_evidence_band: string;
  max_device_count: number;
  first_day: string;
  last_day: string;
}

export interface Insights {
  // `devices` is the device count for THIS window — the honest qualifier for
  // every card. `coverage.devices` below is the all-history figure and must
  // never be used to label a windowed card (F13).
  window: { from: string; to: string; days: number; devices: number };
  days: InsightsDay[];
  summary: InsightsSummary;
  coverage: {
    devices: number;
    snapshots: number;
    first_day: string;
    last_day: string;
    days: number;
  };
  enrichment: {
    jobs_by_state: Record<string, number>;
    jobs_total: number;
    results_total: number;
    last_result_at: string | null;
    disclosure: string;
  };
  structural_disclosure: string;
}

export interface StandingGrant {
  purpose: string;
  field_classes: string[];
  schema_version: string;
  data_dictionary_digest: string;
  dictionary_current: boolean;
  consent_generation: number;
  declared_timezone: string;
  source_window_rule: string;
  first_seen_at: string;
  updated_at: string;
  revoked_at: string;
  state: string;
}

export interface GrantsResult {
  grants: StandingGrant[];
  current_schema_version: string;
  current_data_dictionary: string;
  retention_state: string;
  retention_detail: string;
  stored_snapshots: number;
  stored_account_days: number;
  contributing_device_count: number;
}

// UsageView is /portal/api/usage: every Allowance field plus the W4 plan and
// pool fields, the per-window warnings, the job-state breakdown, and the two
// window reset boundaries (D20).
export interface UsageView extends Allowance {
  plan: string;
  plan_label: string;
  plan_version: number;
  budget_pool: string;
  plan_overridden: boolean;
  warnings: UsageWarning[];
  jobs_by_state: Record<string, number>;
  jobs_total: number;
  daily_resets_at: string;
  monthly_resets_at: string;
  concurrency_note: string;
  // W5: whether the resolved plan includes the weekly project digest, how
  // long hosted results are kept, and (only when digest_weekly) how many
  // digests have landed this ISO week.
  digest_weekly: boolean;
  results_retention_days: number;
  digests_this_week?: number;
}

export interface Device {
  id: string;
  thumbprint: string;
  label: string;
  created_at: string;
  revoked: boolean;
}

export interface DevicesResult {
  devices: Device[];
}

export interface ConsentsResult {
  purposes: string[];
  generation: number;
}

// ---- Portal consent choices (F9) ------------------------------------------
//
// These are the PORTAL-plane preferences behind the consent screen, stored
// server-side per account. They are NOT the node's egress consent: a device
// only ever uploads what was granted on the device, and that grant is
// withdrawn there. See internal/cloudserver/api/portalconsent.go.

export interface ConsentPurposeOption {
  id: string;
  mandatory: boolean;
}

export interface ConsentChoices {
  // null ⇒ the consent screen has never been completed for this account. The
  // SPA derives "needs setup" from this, which is why no localStorage marker
  // is involved any more.
  choices: Record<string, boolean> | null;
  purposes: ConsentPurposeOption[];
  updated_at?: string;
  notice: string;
}

export interface DeletionResult {
  id: string;
  state: string;
  jobs_canceled: number;
  devices_revoked: number;
  tokens_revoked: number;
}

export interface AuthConfig {
  auth_mode: AuthMode;
  workos_browser_enabled: boolean;
}

// ---- API functions --------------------------------------------------------

/**
 * login authenticates with the dev-auth broker. On success it stores the CSRF
 * token in memory. A 501 (WorkOS not yet wired) throws an ApiError carrying the
 * server's honest {error, code} so the UI can render the "pending" copy; a 401
 * throws an ApiError with the "invalid credential" message.
 */
export async function login(subject: string): Promise<LoginResult> {
  const res = await fetch("/portal/auth/login", {
    method: "POST",
    credentials: "include",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ broker_token: "dev:" + subject }),
  });
  if (res.status === 401) {
    throw new ApiError(401, "invalid_credential", "invalid credential");
  }
  if (!res.ok) {
    // 501 (WorkOS pending) and any other error surface the server body.
    throw await parseError(res);
  }
  const result = (await res.json()) as LoginResult;
  setCsrf(result.csrf_token);
  accountId = result.account_id;
  profile = result.profile ?? null;
  authMode = "dev";
  writeAuthModeHint("dev");
  broadcastCsrf();
  return result;
}

// getSession callers are serialized through a single in-flight promise: two
// components booting at once (e.g. React StrictMode's double-invoked effects,
// or two tabs' boot effects racing) must still only rotate the server-side
// token ONCE. A second concurrent caller gets the same in-flight promise
// instead of firing its own request.
let sessionInFlight: Promise<SessionResult | null> | null = null;

/**
 * getSession probes the live session cookie and, on success, adopts the
 * freshly rotated CSRF token plus the account id and auth mode, then
 * broadcasts it to other open tabs (see the BroadcastChannel section above).
 * This is the app-boot call that fixes the reload-bounce (E8): call it
 * before deciding whether to render the sign-in page or the app, so a page
 * reload with a still-live cookie lands signed in instead of bouncing to "/".
 *
 * Returns the session on success, or null when signed out — a 401 is the
 * documented "not signed in" response; a 404 is treated the same way as an
 * honest degrade while the server endpoint is still being rolled out. Any
 * other failure (network error, 5xx) also resolves to null so the SPA never
 * hard-crashes on boot; it simply falls back to the sign-in page.
 */
export function getSession(): Promise<SessionResult | null> {
  if (sessionInFlight !== null) {
    return sessionInFlight;
  }
  const p = fetchSession().finally(() => {
    sessionInFlight = null;
  });
  sessionInFlight = p;
  return p;
}

async function fetchSession(): Promise<SessionResult | null> {
  let res: Response;
  try {
    res = await fetch("/portal/api/session", {
      method: "GET",
      credentials: "include",
      cache: "no-store",
      headers: { Accept: "application/json" },
    });
  } catch {
    return null;
  }
  if (res.status === 401 || res.status === 404) {
    clearCsrf();
    return null;
  }
  if (!res.ok) {
    return null;
  }
  let result: SessionResult;
  try {
    result = (await res.json()) as SessionResult;
  } catch {
    return null;
  }
  setCsrf(result.csrf_token);
  accountId = result.account_id;
  profile = result.profile ?? null;
  authMode = result.auth_mode;
  writeAuthModeHint(result.auth_mode);
  broadcastCsrf();
  return result;
}

/** logout ends the session server-side then clears the in-memory CSRF token
 * and tells other open tabs to sign out too. */
export async function logout(): Promise<void> {
  try {
    await mutate<void>("/portal/auth/logout", "POST");
  } finally {
    clearCsrf();
    broadcastSignedOut();
  }
}

export function getOverview(): Promise<Overview> {
  return getJSON<Overview>("/portal/api/overview");
}

export function getUsage(): Promise<UsageView> {
  return getJSON<UsageView>("/portal/api/usage");
}

// DigestSummary is one project's latest weekly digest (W5): Overview lists
// one per project when any exist. Free accounts always get an empty list —
// there is no locked/degraded row to render, since a free plan never has
// digest_weekly and the scheduler never submits a digest job for it.
export interface DigestSummary {
  cloud_project_id: string;
  period_start: string;
  period_end: string;
  created_at: string;
  headline: string;
  themes: string[];
}

export interface DigestsResult {
  digests: DigestSummary[];
}

export function getDigests(): Promise<DigestsResult> {
  return getJSON<DigestsResult>("/portal/api/digests");
}

/** getInsights loads the structural account-day materialization for a bounded
 * window (the server clamps `days` to 1..90). */
export function getInsights(days?: number): Promise<Insights> {
  const q = days === undefined ? "" : "?days=" + String(days);
  return getJSON<Insights>("/portal/api/insights" + q);
}

/** getGrants loads the account's standing-grant registrations plus the
 * retention state the service actually applies to them. */
export function getGrants(): Promise<GrantsResult> {
  return getJSON<GrantsResult>("/portal/api/grants");
}

export function getDevices(): Promise<DevicesResult> {
  return getJSON<DevicesResult>("/portal/api/devices");
}

export function revokeDevice(id: string): Promise<void> {
  return mutate<void>(
    "/portal/api/devices/" + encodeURIComponent(id),
    "DELETE",
  );
}

// ---- Browser sessions ("sign out everywhere", Wave C gap 2.4 residual (b)) -

/** BrowserSession is one live portal sign-in, from GET
 * /portal/api/sessions/browser. `is_current` marks the session making THIS
 * request, computed server-side against the resolved principal. */
export interface BrowserSession {
  id: string;
  created_at: string;
  last_seen_at?: string;
  expires_at: string;
  idle_expires_at?: string;
  is_current: boolean;
}

export interface BrowserSessionsResult {
  sessions: BrowserSession[];
}

/** getBrowserSessions lists every live portal sign-in on this account. */
export function getBrowserSessions(): Promise<BrowserSessionsResult> {
  return getJSON<BrowserSessionsResult>("/portal/api/sessions/browser");
}

export interface RevokeAllSessionsResult {
  status: string;
  revoked: number;
}

/** revokeAllBrowserSessions signs out every live portal session. With
 * `keepCurrent: true` this session's own sign-in survives ("everywhere but
 * here"); otherwise every session including this one is revoked, and the
 * caller should treat itself as signed out immediately after. */
export function revokeAllBrowserSessions(
  keepCurrent: boolean,
): Promise<RevokeAllSessionsResult> {
  return mutate<RevokeAllSessionsResult>(
    "/portal/api/sessions/browser/revoke-all",
    "POST",
    { keep_current: keepCurrent },
  );
}

export function getConsents(): Promise<ConsentsResult> {
  return getJSON<ConsentsResult>("/portal/api/consents");
}

/** getConsentChoices reads the account's portal consent choices. `choices`
 * comes back null when the setup screen has never been completed. */
export function getConsentChoices(): Promise<ConsentChoices> {
  return getJSON<ConsentChoices>("/portal/api/consent");
}

/** saveConsentChoices submits the WHOLE choice set (a purpose left out of the
 * map is stored as declined). The server forces every mandatory purpose to
 * true and rejects any purpose it does not offer, so what comes back is the
 * authoritative stored state — callers should adopt the response rather than
 * assume their request was stored verbatim. */
export function saveConsentChoices(
  choices: Record<string, boolean>,
): Promise<ConsentChoices> {
  return mutate<ConsentChoices>("/portal/api/consent", "POST", { choices });
}

/** requestDeletion is the dev-auth deletion path: the caller re-enters their
 * broker subject to confirm. */
export function requestDeletion(subject: string): Promise<DeletionResult> {
  return mutate<DeletionResult>("/portal/api/deletion-requests", "POST", {
    broker_token: "dev:" + subject,
  });
}

/**
 * requestDeletionWithStepUp is the WorkOS-mode deletion path: the caller
 * supplies the single-use step-up authorization id minted by
 * /portal/auth/workos/start?purpose=step_up&action=deletion (see
 * Privacy.tsx) instead of re-entering a broker subject. The CSRF header is
 * still attached by mutate() as usual — step-up proves re-authentication,
 * not the request's own origin.
 */
export function requestDeletionWithStepUp(
  stepUpAuthorizationId: string,
): Promise<DeletionResult> {
  return mutate<DeletionResult>("/portal/api/deletion-requests", "POST", {
    step_up_authorization_id: stepUpAuthorizationId,
  });
}

/** ExportResult is the metadata for an assembled account-data export (W6d /
 * D11). The bytes are never in the API response — the caller downloads them
 * separately from /portal/api/exports/{id}/download. */
export interface ExportResult {
  export_id: string;
  size_bytes: number;
  created_at: string;
  expires_at: string;
}

/** ExportListResult is the account's live (unexpired) export artifacts. */
export interface ExportListResult {
  exports: ExportResult[];
}

/** requestExport is the dev-auth export path: re-enter the broker subject to
 * confirm, then the server assembles an encrypted, expiring artifact. */
export function requestExport(subject: string): Promise<ExportResult> {
  return mutate<ExportResult>("/portal/api/exports", "POST", {
    broker_token: "dev:" + subject,
  });
}

/** requestExportWithStepUp is the WorkOS-mode export path: supply the
 * single-use step-up authorization id minted by
 * /portal/auth/workos/start?purpose=step_up&action=export. */
export function requestExportWithStepUp(
  stepUpAuthorizationId: string,
): Promise<ExportResult> {
  return mutate<ExportResult>("/portal/api/exports", "POST", {
    step_up_authorization_id: stepUpAuthorizationId,
  });
}

/** listExports returns the account's live export artifacts (newest-first). */
export function listExports(): Promise<ExportListResult> {
  return getJSON<ExportListResult>("/portal/api/exports");
}

/** downloadExport fetches one artifact's JSON over the session and saves it as
 * a file. It is a plain authenticated GET (RLS-scoped server-side); the blob is
 * handed to the browser as a download so the bytes never linger in the URL. */
export async function downloadExport(exportId: string): Promise<void> {
  const res = await fetch(
    "/portal/api/exports/" + encodeURIComponent(exportId) + "/download",
    { method: "GET", credentials: "include" },
  );
  if (!res.ok) {
    throw await parseError(res);
  }
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  try {
    const a = document.createElement("a");
    a.href = url;
    a.download = "superbased-export-" + exportId + ".json";
    document.body.appendChild(a);
    a.click();
    a.remove();
  } finally {
    URL.revokeObjectURL(url);
  }
}

/**
 * getAuthConfig probes the unauthenticated /portal/api/auth-config endpoint
 * so the sign-in page can render the deployment's actual auth surface
 * (WorkOS button, dev-auth form, or an honest "not enabled yet" notice)
 * instead of guessing from a cached hint. A 404 means this server predates
 * the endpoint — callers should fall back to getAuthModeHint().
 */
export async function getAuthConfig(): Promise<AuthConfig> {
  const res = await fetch("/portal/api/auth-config", {
    method: "GET",
    credentials: "include",
    cache: "no-store",
    headers: { Accept: "application/json" },
  });
  if (!res.ok) {
    throw await parseError(res);
  }
  return (await res.json()) as AuthConfig;
}

// ---- Sessions + result corrections (W6c) ----------------------------------
//
// The read surface is the two portal endpoints the W6c backend shipped:
//   GET /portal/api/sessions        — keyset-paginated newest-first list
//   GET /portal/api/sessions/{id}   — detail: each result's AI original,
//                                     revision history, ETag and head marker
// The write is the append-only correction:
//   POST /portal/api/results/{id}/correction  (If-Match ETag + Idempotency-Key)
//
// A correction never overwrites the immutable AI original — it appends a
// revision (R6). The client always sends the result's current ETag as If-Match
// and a fresh idempotency key; a 412 hands back the current ETag so the caller
// can re-read and retry (see postCorrection + SessionDetail's save flow).

/** SessionSummary is one Sessions-list row. `effective_title` is the latest
 * user title correction on the head result, else the head AI title. */
export interface SessionSummary {
  cloud_session_id: string;
  tool: string;
  model_family: string;
  created_at: string;
  result_count: number;
  edited: boolean;
  effective_title: string;
  tombstoned: boolean;
}

export interface SessionsPage {
  sessions: SessionSummary[];
  has_more: boolean;
  next_cursor?: string;
}

/** ResultBody mirrors cloudcontract.Result — the enrichment output. */
export interface ResultBody {
  title: string;
  taxonomy_tags: string[] | null;
  suggested_tags: string[] | null;
  description: string;
  confidence: string;
  evidence_refs: string[] | null;
  limitations: string[] | null;
  // The five NARRATIVE lists: what the session did, whether the stated plans
  // landed, what is broken, what failed or is unresolved, and what to do next.
  // OPTIONAL on the wire (`omitempty` on the Go contract), so a result stored
  // before they existed simply omits them - every render must treat absence as
  // absence, never as an empty section.
  work_done?: string[] | null;
  plans_implemented?: string[] | null;
  issues_found?: string[] | null;
  failures?: string[] | null;
  next_steps?: string[] | null;
  schema_version: string;
}

/** RevisionCorrection is the wire form of a stored revision's normalized
 * correction (cloudcontract.NormalizedCorrection): each field is present only
 * when that revision changed it. SafeText serializes as a plain string. */
export interface RevisionCorrection {
  title?: string;
  description?: string;
  taxonomy_tags?: string[];
  suggested_tags?: string[];
}

export interface ResultRevision {
  revision_seq: number;
  editor: string;
  source: string;
  correction: RevisionCorrection;
  created_at: string;
}

export interface SessionResult {
  result_id: string;
  created_at: string;
  ai_source: boolean;
  superseded: boolean;
  superseded_by?: string;
  etag: string;
  tombstoned: boolean;
  result?: ResultBody;
  revisions: ResultRevision[];
}

export interface SessionDetailView {
  cloud_session_id: string;
  tool: string;
  model_family: string;
  created_at: string;
  head_result_id: string;
  results: SessionResult[];
}

/** ResultCorrection is the request body: an omitted field leaves that field
 * unchanged; a present field replaces it. A present title must be non-empty
 * (the server's Normalize rejects an empty title with 422). */
export interface ResultCorrection {
  title?: string;
  description?: string;
  taxonomy_tags?: string[];
  suggested_tags?: string[];
}

export interface CorrectionResponse {
  result_id: string;
  revision_seq: number;
  etag: string;
  replayed: boolean;
}

/** CorrectionConflict is thrown on a 412 (ETag mismatch): the result changed
 * since it was read. `freshEtag` is the server-provided current ETag (from the
 * response's ETag header) so the caller can re-read and retry against it. */
export class CorrectionConflict extends Error {
  readonly freshEtag: string | null;
  constructor(freshEtag: string | null) {
    super("the result changed since you last read it");
    this.name = "CorrectionConflict";
    this.freshEtag = freshEtag;
  }
}

/** newIdempotencyKey mints a fresh key for one correction intent. One user
 * Save reuses its key across an auto-retry (same intent), so a benign network
 * replay is idempotent; a new Save mints a new key. */
export function newIdempotencyKey(): string {
  try {
    if (typeof crypto !== "undefined" && "randomUUID" in crypto) {
      return crypto.randomUUID();
    }
  } catch {
    /* fall through to the non-crypto fallback */
  }
  return (
    "idem-" +
    Date.now().toString(36) +
    "-" +
    Math.random().toString(36).slice(2, 12)
  );
}

/** getSessions loads one page of the account's enriched sessions. Pass the
 * previous page's `next_cursor` as `after` to page forward. */
export function getSessions(after?: string): Promise<SessionsPage> {
  const q = after === undefined ? "" : "?after=" + encodeURIComponent(after);
  return getJSON<SessionsPage>("/portal/api/sessions" + q);
}

/** getSessionDetail loads one session's results plus revision history. */
export function getSessionDetail(id: string): Promise<SessionDetailView> {
  return getJSON<SessionDetailView>(
    "/portal/api/sessions/" + encodeURIComponent(id),
  );
}

// ---- Community percentiles (W5 / R3) --------------------------------------
//
// The private, floored, k-suppressed cohort band distribution plus where the
// signed-in developer sits in it. There is NO public leaderboard: a developer
// only ever sees their OWN band against an aggregate distribution whose cells
// are suppressed below the cohort floor. The read surface is two endpoints:
//   GET /portal/api/community?metric=&version=&cohort=&window=  — one metric's
//       band distribution for a cohort/window, plus own placement
//   GET /portal/api/community/metrics — the metric + cohort catalogs, used to
//       drive the selectors and the "Metric definitions" panel
//
// `bands` may be EMPTY (window unmaterialized, below the >=30 opt-in floor, or
// unfinalized) — the page renders an honest empty state, never a broken chart.
// Suppressed cells are simply omitted from `bands`, so a band index can be
// absent even when neighbours are present; the page labels each returned band
// from `band_edges` (the width_bucket thresholds) rather than assuming the
// full 0..len(edges) range is present.

/** CommunityBand is one returned (unsuppressed) histogram cell: how many
 * developers in the cohort fell in this band index. */
export interface CommunityBand {
  band: number;
  count: number;
}

/** CommunityOwn is where the signed-in developer sits. `contributed` is false
 * when they are not contributing this metric yet, in which case `value` and
 * `band` are absent (there is no placement to show). */
export interface CommunityOwn {
  contributed: boolean;
  value?: number;
  band?: number;
}

/** CommunityView is GET /portal/api/community: one metric's cohort band
 * distribution for a window, plus the developer's own placement. `band_edges`
 * are the width_bucket thresholds used to label each band as a human range;
 * `bands` omits suppressed cells and may be empty. `cohort_size` is 0 when
 * there are no bands. */
export interface CommunityView {
  cohort_key: string;
  metric_id: string;
  metric_version: number;
  metric_label: string;
  metric_unit: string;
  window_id: string;
  cohort_size: number;
  band_edges: number[];
  bands: CommunityBand[];
  own: CommunityOwn;
}

/** CommunityMetric is one selectable metric from the catalog, carrying the
 * definition text (R3) and its band edges. */
export interface CommunityMetric {
  id: string;
  version: number;
  label: string;
  unit: string;
  description: string;
  band_edges: number[];
}

/** CommunityCohort is one selectable cohort from the catalog. */
export interface CommunityCohort {
  key: string;
  label: string;
  description: string;
}

/** CommunityMetricsView is GET /portal/api/community/metrics: the metric and
 * cohort catalogs that populate the selectors and the definitions panel. */
export interface CommunityMetricsView {
  metrics: CommunityMetric[];
  cohorts: CommunityCohort[];
}

/** CommunityParams are the optional query parameters for getCommunity. All are
 * optional: the server defaults cohort=global, version=1, and picks the most
 * recent finalized window when `window` is omitted. */
export interface CommunityParams {
  metric?: string;
  version?: number;
  cohort?: string;
  window?: string;
}

/** getCommunity loads one metric's cohort band distribution plus the
 * developer's own placement. */
export function getCommunity(params?: CommunityParams): Promise<CommunityView> {
  const q = new URLSearchParams();
  if (params?.metric) q.set("metric", params.metric);
  if (params?.version !== undefined) q.set("version", String(params.version));
  if (params?.cohort) q.set("cohort", params.cohort);
  if (params?.window) q.set("window", params.window);
  const qs = q.toString();
  return getJSON<CommunityView>(
    "/portal/api/community" + (qs.length > 0 ? "?" + qs : ""),
  );
}

/** getCommunityMetrics loads the metric + cohort catalogs. */
export function getCommunityMetrics(): Promise<CommunityMetricsView> {
  return getJSON<CommunityMetricsView>("/portal/api/community/metrics");
}

// ---- Billing (W9 / R4, checkout G2-07 / Wave B) ----------------------------
//
// Paddle is the merchant of record: card data is never collected here. This
// surface reads the account's current plan + subscription state, and — when
// the deployment has a checkout catalogue configured — opens a Paddle.js
// overlay for the actual purchase. Subscription and plan MANAGEMENT (payment
// method, invoices, cancellation) still happens on Paddle's own hosted pages,
// reached through `management_urls` when Paddle has sent them.

/** SubscriptionStatus is the Paddle-sourced lifecycle state of a paid
 * subscription. `canceled` still keeps access until `current_period_end`.
 * `trialing` is the free-trial window before the first charge. `refunded` and
 * `charged_back` are terminal: paid access has been revoked. */
export type SubscriptionStatus =
  | "active"
  | "trialing"
  | "canceled"
  | "past_due"
  | "paused"
  | "refunded"
  | "charged_back";

/** BillingManagementURLs are Paddle's hosted customer-portal links (present
 * only when Paddle has sent them — subscription.updated omits them entirely
 * per Paddle's own docs, so absence is normal, not an error). */
export interface BillingManagementURLs {
  update_payment_method?: string;
  cancel?: string;
}

/** BillingSubscription is the developer's active/most-recent paid subscription
 * as reflected from Paddle. `current_period_end` is when the paid period
 * renews (active) or ends (canceled); `canceled_at` is set once cancellation
 * has been recorded — access continues until `current_period_end`.
 * `trial_ends_at` is set only while `status === "trialing"`. */
export interface BillingSubscription {
  subscription_id: string;
  customer_id: string;
  plan_name: string;
  plan_version: number;
  status: SubscriptionStatus;
  current_period_end?: string;
  canceled_at?: string;
  trial_ends_at?: string;
  management_urls?: BillingManagementURLs;
}

/** CheckoutPrice is one purchasable price in the portal's checkout catalogue. */
export interface CheckoutPrice {
  price_id: string;
  plan_name: string;
  plan_version: number;
  interval: string;
  display: string;
}

/** CheckoutCatalog is the `checkout` slice of GET /portal/api/billing:
 * whether this deployment can open a checkout at all, the Paddle.js
 * environment + client token, the purchasable prices, and the advertised
 * trial length. `available` is false until the operator has provisioned a
 * client token AND at least one price — the Upgrade button renders its honest
 * disabled state until then. */
export interface CheckoutCatalog {
  available: boolean;
  environment: string;
  client_token: string;
  prices: CheckoutPrice[];
  trial_days: number;
}

/** BillingView is GET /portal/api/billing. `has_subscription` is false for
 * free-tier accounts (most): the page then renders the free-plan state. `plan`
 * is the current entitlement snapshot (the same shape as the Usage view) so
 * the caps that are actually in force can be shown regardless of tier.
 * `checkout` is always present (an unconfigured deployment still reports it,
 * with `available: false`). */
export interface BillingView {
  has_subscription: boolean;
  subscription?: BillingSubscription;
  plan?: UsageView;
  checkout: CheckoutCatalog;
}

/** getBilling loads the account's plan + subscription status + checkout
 * catalogue. */
export function getBilling(): Promise<BillingView> {
  return getJSON<BillingView>("/portal/api/billing");
}

/** CheckoutIntent is POST /portal/api/billing/checkout's response: the
 * server-minted, single-use nonce (inside custom_data) that binds the Paddle
 * checkout back to this account. Handed verbatim to Paddle.Checkout.open. */
export interface CheckoutIntent {
  price_id: string;
  expires_at: string;
  custom_data: {
    account_id: string;
    checkout_nonce: string;
  };
}

/** createCheckout mints a checkout intent for the given Paddle price. Throws
 * an ApiError (code "checkout_unavailable") when the deployment has no
 * purchasable plan configured for that price. */
export function createCheckout(priceID: string): Promise<CheckoutIntent> {
  return mutate<CheckoutIntent>("/portal/api/billing/checkout", "POST", {
    price_id: priceID,
  });
}

/**
 * postCorrection appends a user correction to a result. It sends the result's
 * current ETag as If-Match and the caller's idempotency key; a 412 throws a
 * CorrectionConflict carrying the server's fresh ETag. Every other non-2xx
 * throws the server's honest {error, code}. This lives in api.ts because it
 * reads the module-private CSRF token like every other mutation.
 */
export async function postCorrection(
  resultId: string,
  ifMatchEtag: string,
  idempotencyKey: string,
  correction: ResultCorrection,
): Promise<CorrectionResponse> {
  const headers: Record<string, string> = {
    Accept: "application/json",
    "Content-Type": "application/json",
    "If-Match": ifMatchEtag,
    "Idempotency-Key": idempotencyKey,
  };
  if (csrfToken !== null) {
    headers["X-SBCI-CSRF"] = csrfToken;
  }
  const res = await fetch(
    "/portal/api/results/" + encodeURIComponent(resultId) + "/correction",
    {
      method: "POST",
      credentials: "include",
      headers,
      body: JSON.stringify(correction),
    },
  );
  if (res.status === 412) {
    // The server sets the current ETag header so we can re-read and retry.
    throw new CorrectionConflict(res.headers.get("ETag"));
  }
  if (!res.ok) {
    throw await parseError(res);
  }
  return (await res.json()) as CorrectionResponse;
}
