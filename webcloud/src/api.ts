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
// C2: this session's passkey second factor, from the session bootstrap. A
// pending session reaches only the second-factor screen (the server refuses
// everything else with second_factor_required).
let secondFactor: SecondFactorState | null = null;

/** getSecondFactor returns this session's second-factor state, or null when
 * the server did not report one. */
export function getSecondFactor(): SecondFactorState | null {
  return secondFactor;
}

// The personal portal plane's switch as the session read last reported it
// (D-IND-8): "serving" while the old enrichment pages still hold data,
// "retired" once it moved into the personal org. Null = not reported, which
// readers treat as serving (lib/personalModel.ts personalPlaneOf).
let personalPlane: string | null = null;

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
  secondFactor = null;
  personalPlane = null;
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

/** getPersonalPlane returns the personal portal plane switch the session read
 * reported ("serving" | "retired"), or null when it was not reported (an
 * older server), which means serving. */
export function getPersonalPlane(): string | null {
  return personalPlane;
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
      // The personal plane switch (D-IND-8); absent from an older build's
      // message, which reads as serving.
      personalPlane?: string | null;
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
    personalPlane,
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
    personalPlane = msg.personalPlane ?? null;
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
  /** body is the refusal's parsed JSON body, kept for the few refusals that
   * carry more than a message and a code (account_deletion_blocked's
   * `blockers`); read it through a typed helper such as refusalBlockers. */
  readonly body: Readonly<Record<string, unknown>>;
  constructor(status: number, code: string, message: string, body: Record<string, unknown> = {}) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.body = body;
  }
}

interface ErrorBody {
  error?: string;
  code?: string;
  message?: string;
}

// parseError reads the server's refusal. The cloud API writes
// {"error": <message>, "code": <code>} (server.go writeErr); a body that
// instead carries {"error": <code>, "message": <message>} (no "code") is read
// the same way, so either spelling yields the code and the sentence.
async function parseError(res: Response): Promise<ApiError> {
  let body: ErrorBody & Record<string, unknown> = {};
  try {
    const parsed: unknown = await res.json();
    if (parsed !== null && typeof parsed === "object" && !Array.isArray(parsed)) {
      body = parsed as ErrorBody & Record<string, unknown>;
    }
  } catch {
    // Non-JSON error body; fall back to status text.
  }
  if (body.code === undefined && typeof body.message === "string" && typeof body.error === "string") {
    return new ApiError(res.status, body.error, body.message, body);
  }
  const message = body.error ?? res.statusText ?? "request failed";
  const code = body.code ?? "";
  return new ApiError(res.status, code, message, body);
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
  method: "POST" | "PATCH" | "PUT" | "DELETE",
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

/** PersonalPlaneState is the personal portal plane switch (D-IND-8):
 * "serving" while the old enrichment pages still hold the account's data,
 * "retired" once it has moved into the personal org. Absent = serving. */
export type PersonalPlaneState = "serving" | "retired";

export interface SessionResult {
  account_id: string;
  csrf_token: string;
  expires_at: string;
  auth_mode: AuthMode;
  profile?: AccountProfile;
  /** C2: this session's passkey second factor (portalmfa.go). */
  second_factor?: SecondFactorState;
  personal_plane?: PersonalPlaneState;
}

/** SecondFactorState is a session's passkey second factor. */
export interface SecondFactorState {
  /** enrolled: the account holds at least one passkey. */
  enrolled: boolean;
  /** pending: enrolled, and this session has not used its passkey yet. */
  pending: boolean;
  /** method: how this session completed it ("passkey" | "recovery_code"). */
  method?: "passkey" | "recovery_code";
  /** multi_factor: what a team sign-in will be told (a passkey only). */
  multi_factor: boolean;
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
  // Plan v5 (ruling R-AI1): how session enrichment is budgeted. "count" is
  // the daily/monthly enrichment caps above; "tokens" is the tier's token
  // budgets below, and then daily_cap / monthly_cap read 0 because no count
  // cap is enforced. Absent from a server that predates plan v5 (= count).
  budget_unit?: "count" | "tokens";
  enrichment_tier?: string;
  enrichment_tier_version?: number;
  daily_tokens_used?: number;
  daily_token_budget?: number;
  daily_tokens_remaining?: number;
  monthly_tokens_used?: number;
  monthly_token_budget?: number;
  monthly_tokens_remaining?: number;
  // session_token_budget is one session's cumulative cap across
  // re-enrichments; evidence_token_budget is the most evidence one upload
  // may carry (the node sends a smaller selection of a larger session).
  session_token_budget?: number;
  evidence_token_budget?: number;
}

/** isTokenBudgeted reports whether the plan budgets enrichment in tokens
 * (plan v5), so a page shows the token windows rather than the count caps,
 * which read 0 on such a plan. */
export function isTokenBudgeted(view: Pick<UsageView, "budget_unit"> | undefined): boolean {
  return view?.budget_unit === "tokens";
}

/** tokensLeft is the server's remaining figure for a token window, falling
 * back to budget minus used (never below 0) for a server that predates it. */
export function tokensLeft(budget?: number, used?: number, remaining?: number): number {
  if (typeof remaining === "number") return remaining;
  return Math.max((budget ?? 0) - (used ?? 0), 0);
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
  personal_plane?: PersonalPlaneState;
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
  secondFactor = result.second_factor ?? null;
  authMode = result.auth_mode;
  personalPlane = result.personal_plane ?? null;
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
  /** When the subscription entered past_due (W16-D5); set only while it is
   * past_due. */
  past_due_since?: string;
  management_urls?: BillingManagementURLs;
  /** The seat quantity Paddle bills (when known). */
  seat_quantity?: number;
  /** Set when the subscription is billed through the personal dashboard. */
  org_id?: string;
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
 * environment + client token, the purchasable prices, and the trial this
 * account (or org) would get. `available` is false until the operator has
 * provisioned a client token AND at least one price — the Upgrade button
 * renders its honest disabled state until then. `trial_used` is true once the
 * scope has had its free trial: `trial_days` is then 0 and the server opens
 * the checkout on a price billed from the first day. Older servers omit it. */
export interface CheckoutCatalog {
  available: boolean;
  environment: string;
  client_token: string;
  prices: CheckoutPrice[];
  trial_days: number;
  trial_used?: boolean;
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
  /** Wave 17: the deployment can open Paddle's customer portal (invoices,
   * payment method) for this account's subscription. */
  portal_available?: boolean;
  /** The account's own subscription is billed through its personal
   * organization (after its move onto it): the plan lives there, so `plan` is
   * absent and the page reads the subscription's plan instead. */
  paid_through_personal_org?: boolean;
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
  /** The quantity to open the checkout with (wave 17: 1 for a personal
   * plan). Older servers omit it; treat that as 1. */
  quantity?: number;
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

// ---- Orgs (plan 07 M6.5: the console's team orgs) --------------------------
//
// GET/POST /portal/api/orgs, GET/PATCH /portal/api/orgs/{id}, the slug
// availability read, and billing per org (internal/cloudserver/api
// portal_orgs*.go). Every host and link in these responses is built by the
// server from the org's slug; the console never composes a tenant host.

/** OrgStatus is the org's lifecycle state (platformcontract TenantState). */
export type OrgStatus =
  | "provisioning"
  | "active"
  | "suspended"
  | "pending_deletion"
  | "purging"
  | "purged";

/** ProvisioningStage is the console's one word for a create in flight
 * (provisioningRules in portal_orgs.go). */
export type ProvisioningStage =
  | "ready"
  | "closing"
  | "unknown"
  | "failed"
  | "finishing"
  | "waitlisted"
  | "queued"
  | "retrying"
  | "creating";

/** OrgProvisioning is the progress of an org's create. */
export interface OrgProvisioning {
  stage: ProvisioningStage;
  state?: string;
  attempts: number;
  last_error_class?: string;
  next_attempt_at?: string;
  queued_at?: string;
  created_on_host_at?: string;
}

/** PortalOrg is one org as the console shows it. */
export interface PortalOrg {
  org_id: string;
  slug: string;
  display_name: string;
  kind: "personal" | "team";
  status: OrgStatus;
  tenancy: string;
  console_role: "owner" | "admin" | "member";
  is_billing_owner: boolean;
  created_at: string;
  /** host is <slug>.<tenant domain>; absent when none is configured. */
  host?: string;
  /** machines_page_url is the team dashboard's page listing the signed-in
   * user's own machines in this team (server-built; active teams only). The
   * console links to it rather than reading tenants from the browser. */
  machines_page_url?: string;
  /** open_url opens the org's dashboard (active orgs only), built by the
   * server's one link function (tenantlink.go): every "Open your dashboard"
   * button reads it and the console never composes a tenant address. A
   * personal dashboard's address is opened from buttons, never shown as
   * text. (The server still sends the older dashboard_url for one release;
   * nothing here reads it.) */
  open_url?: string;
  /** invite_url is a team dashboard's invite page (active teams only). */
  invite_url?: string;
  /** members is the team's member count from its latest usage report (the
   * org list only; absent before the first report). */
  members?: number;
  provisioning?: OrgProvisioning;
}

/** TeamOrgAllowance is the signed-in account's team count against its cap
 * (portal_orgs.go teamOrgsJSON; default 3, raised on request). */
export interface TeamOrgAllowance {
  used: number;
  limit: number;
  remaining: number;
  /** invite_only is true while the team create allow-list is on (W17,
   * portal_teamallowlist.go); create_allowed then says whether this account
   * is on it, and account_ref is what to quote to support when it is not.
   * Absent on an older server: treated as open. */
  invite_only?: boolean;
  create_allowed?: boolean;
  account_ref?: string;
}

/** OrgsList is GET /portal/api/orgs. */
export interface OrgsList {
  orgs: PortalOrg[];
  tenant_domain: string;
  /** team_orgs is absent when the server could not read it. */
  team_orgs?: TeamOrgAllowance;
  /** team_price is the team plan's catalogue price, shown before a create;
   * absent when none is configured. */
  team_price?: { display: string; interval: string };
}

/** OrgPlan is the plan the org's signed entitlement document carries. */
export interface OrgPlan {
  name: string;
  version: number;
  label: string;
  source: "subscription" | "org_grant" | "launch" | "floor";
  not_after?: string;
  seats_min?: number;
}

/** OrgSeats is the latest usage day the tenant reported. */
export interface OrgSeats {
  in_use: number;
  members: number;
  day: string;
}

/** OrgCaps says what the signed-in user may do with the org. */
export interface OrgCaps {
  rename: boolean;
  view_billing: boolean;
  checkout: boolean;
}

/** OrgDetail is GET /portal/api/orgs/{id} (and the create/rename answer). */
export interface OrgDetail {
  org: PortalOrg;
  launch_url?: string;
  plan?: OrgPlan;
  seats?: OrgSeats;
  can: OrgCaps;
  replayed?: boolean;
}

/** SlugAvailability is GET /portal/api/orgs/slug-availability. */
export interface SlugAvailability {
  slug: string;
  available: boolean;
  reason?: "invalid" | "reserved" | "taken";
  host?: string;
}

export function listOrgs(): Promise<OrgsList> {
  return getJSON<OrgsList>("/portal/api/orgs");
}

export function getOrg(id: string): Promise<OrgDetail> {
  return getJSON<OrgDetail>("/portal/api/orgs/" + encodeURIComponent(id));
}

export function checkSlug(slug: string): Promise<SlugAvailability> {
  return getJSON<SlugAvailability>(
    "/portal/api/orgs/slug-availability?slug=" + encodeURIComponent(slug),
  );
}

/** createTeam creates a team org; the tenant is created in the background. */
export function createTeam(displayName: string, slug: string): Promise<OrgDetail> {
  return mutate<OrgDetail>("/portal/api/orgs", "POST", {
    display_name: displayName,
    slug,
  });
}

/** createPersonalOrg creates the signed-in account's personal org, or returns
 * the one it already has (201 created / 200 existing, the same detail body
 * as a team create). Its tenant is created in the background, like a team's. */
export function createPersonalOrg(): Promise<OrgDetail> {
  return mutate<OrgDetail>("/portal/api/orgs/personal", "POST", {});
}

/** renameOrg sets the org's display name (refused, code org_provisioning,
 * while the team is still being created). */
export function renameOrg(id: string, displayName: string): Promise<OrgDetail> {
  return mutate<OrgDetail>("/portal/api/orgs/" + encodeURIComponent(id), "PATCH", {
    display_name: displayName,
  });
}

/** OrgBillingView is GET /portal/api/orgs/{id}/billing. */
export interface OrgBillingView {
  has_subscription: boolean;
  subscription?: BillingSubscription;
  plan?: OrgPlan;
  checkout: CheckoutCatalog;
  can_checkout: boolean;
  is_billing_owner: boolean;
  /** Wave 17: the billing owner can open Paddle's customer portal. */
  portal_available?: boolean;
}

export function getOrgBilling(id: string): Promise<OrgBillingView> {
  return getJSON<OrgBillingView>(
    "/portal/api/orgs/" + encodeURIComponent(id) + "/billing",
  );
}

/** OrgCheckoutIntent is the org checkout's server-minted custom_data. */
export interface OrgCheckoutIntent {
  price_id: string;
  /** The quantity to open the checkout with: the plan's seat minimum (3 for
   * Team, 10 for Business). Older servers omit it; treat that as 1. */
  quantity?: number;
  expires_at: string;
  custom_data: {
    account_id: string;
    org_id: string;
    checkout_nonce: string;
  };
}

/** PortalSession is a Paddle customer portal link pair (wave 17): `url` is
 * the portal's overview (invoices, payment methods, subscriptions). The
 * links carry a short-lived token; never store them. */
export interface PortalSession {
  url: string;
  cancel?: string;
  update_payment_method?: string;
}

/** createBillingPortalSession opens the account's Paddle customer portal. */
export function createBillingPortalSession(): Promise<PortalSession> {
  return mutate<PortalSession>("/portal/api/billing/portal-session", "POST", {});
}

/** createOrgBillingPortalSession opens an org's Paddle customer portal (its
 * billing owner only). */
export function createOrgBillingPortalSession(id: string): Promise<PortalSession> {
  return mutate<PortalSession>(
    "/portal/api/orgs/" + encodeURIComponent(id) + "/billing/portal-session",
    "POST",
    {},
  );
}

export function createOrgCheckout(id: string, priceID: string): Promise<OrgCheckoutIntent> {
  return mutate<OrgCheckoutIntent>(
    "/portal/api/orgs/" + encodeURIComponent(id) + "/billing/checkout",
    "POST",
    { price_id: priceID },
  );
}

// ---- Deletion: an org's deletion and the account deletion precheck ---------
//
// Plan 07 M6.9 / M7a.1. An org owner requests the deletion of a team org
// (typing the slug to confirm); it waits out a cooling-off window, during
// which an owner can cancel it, and is then purged. The account deletion
// (POST /portal/api/deletion-requests, above) is preceded by a precheck that
// names what blocks it and what it takes with it.

/** OrgDeletionState is where an org's deletion request stands. */
export type OrgDeletionState = "cooling_off" | "canceled" | "purging" | "done" | "blocked";

/** OrgDeletionOrigin says who started the deletion. */
export type OrgDeletionOrigin = "owner" | "account_deletion" | "staff";

/** OrgDeletionStatus is one org deletion request. */
export interface OrgDeletionStatus {
  request_id: string;
  state: OrgDeletionState;
  /** step is the purge's current step, free text for support. */
  step: string;
  origin: OrgDeletionOrigin;
  requested_at: string;
  purge_after: string;
  canceled_at?: string;
  done_at?: string;
  blocked_reason?: string;
  /** can_cancel: the request can still be canceled (cooling off). */
  can_cancel: boolean;
}

/** OrgDeletionRefusal is why the caller cannot request a deletion now
 * ("" when they can). personal_org: a personal org is deleted with the
 * account, never from the team route. billing_cancel_unavailable: the team
 * has a live subscription this deployment cannot cancel automatically. */
export type OrgDeletionRefusal =
  | ""
  | "not_owner"
  | "personal_org"
  | "deletion_open"
  | "org_not_deletable"
  | "billing_cancel_unavailable";

/** OrgDeletionReauth is the re-authentication a deletion request needs:
 * "step_up" (WorkOS re-authentication; a passkey used in this session in
 * the last five minutes also counts), "broker_token" (dev sign-in: re-enter
 * the developer subject) or "unavailable" (this deployment cannot
 * re-authenticate, so no request can be made). */
export type OrgDeletionReauth = "step_up" | "broker_token" | "unavailable";

/** OrgDeletionPreview is what a deletion requested now would do. */
export interface OrgDeletionPreview {
  can_request: boolean;
  refusal: OrgDeletionRefusal;
  cooling_off_days: number;
  /** purge_after is when the purge would start if requested now. */
  purge_after: string;
  live_subscription: boolean;
  members: number;
  /** kept names what survives the purge ("usage_counts", "deletion_record"). */
  kept: string[];
  /** reauth is the re-authentication a request needs (absent from an older
   * server). */
  reauth?: OrgDeletionReauth;
}

/** OrgDeletionView is GET /portal/api/orgs/{id}/deletion. */
export interface OrgDeletionView {
  deletion: OrgDeletionStatus | null;
  preview: OrgDeletionPreview;
}

/** getOrgDeletion reads an org's deletion status and preview (any member). */
export function getOrgDeletion(id: string): Promise<OrgDeletionView> {
  return getJSON<OrgDeletionView>("/portal/api/orgs/" + encodeURIComponent(id) + "/deletion");
}

/** OrgDeletionProof is how a deletion request proves the person is present:
 * the developer subject re-entered (dev sign-in), or the one-use step-up
 * authorization id WorkOS re-authentication minted. Neither is sent when
 * empty: a passkey used in this session in the last five minutes is enough. */
export interface OrgDeletionProof {
  brokerSubject?: string;
  stepUpAuthorizationId?: string;
}

/** requestOrgDeletion asks for the org's deletion (owner). confirmSlug must
 * be the org's slug; refusals: 403 not_owner, 409 personal_org, 409
 * deletion_open, 409 org_not_deletable, 409 billing_cancel_unavailable, 400
 * confirm_mismatch, 401 reauth_required, 403 reauth_mismatch, 403
 * step_up_required (start WorkOS re-authentication), 403 step_up_invalid,
 * 501 provider_not_configured. The broker token is "dev:" + subject, as in
 * requestDeletion. */
export function requestOrgDeletion(
  id: string,
  confirmSlug: string,
  proof: OrgDeletionProof = {},
): Promise<OrgDeletionStatus> {
  const body: { confirm_slug: string; broker_token?: string; step_up_authorization_id?: string } = {
    confirm_slug: confirmSlug,
  };
  const subject = (proof.brokerSubject ?? "").trim();
  if (subject !== "") body.broker_token = "dev:" + subject;
  const stepUp = (proof.stepUpAuthorizationId ?? "").trim();
  if (stepUp !== "") body.step_up_authorization_id = stepUp;
  return mutate<OrgDeletionStatus>("/portal/api/orgs/" + encodeURIComponent(id) + "/deletion", "POST", body);
}

/** cancelOrgDeletion cancels a deletion still cooling off (owner); 409
 * not_cancellable once the purge has started. */
export function cancelOrgDeletion(id: string): Promise<OrgDeletionStatus> {
  return mutate<OrgDeletionStatus>("/portal/api/orgs/" + encodeURIComponent(id) + "/deletion", "DELETE");
}

/** AccountDeletionBlockerCode is why an org blocks the account's deletion. */
export type AccountDeletionBlockerCode =
  | "pays_for_live_org"
  | "billing_owner"
  | "sole_owner_with_members"
  | "sole_owner_alone";

/** OrgRef names an org in the deletion precheck. */
export interface OrgRef {
  org_id: string;
  slug: string;
  display_name: string;
}

/** AccountDeletionBlocker is one org that blocks the account's deletion. */
export interface AccountDeletionBlocker extends OrgRef {
  code: AccountDeletionBlockerCode;
}

/** AccountDeletionPrecheck is GET /portal/api/account/deletion-precheck. */
export interface AccountDeletionPrecheck {
  can_delete: boolean;
  blockers: AccountDeletionBlocker[];
  /** personal_org is deleted with the account. */
  personal_org: OrgRef | null;
  /** memberships_removed: the teams the account leaves; their data stays
   * with the team. */
  memberships_removed: OrgRef[];
}

/** getAccountDeletionPrecheck reads what blocks the account's deletion and
 * what it takes with it. */
export function getAccountDeletionPrecheck(): Promise<AccountDeletionPrecheck> {
  return getJSON<AccountDeletionPrecheck>("/portal/api/account/deletion-precheck");
}

/** refusalBlockers reads the `blockers` array an account_deletion_blocked
 * refusal carries; [] for any other error or a malformed body. */
export function refusalBlockers(err: unknown): AccountDeletionBlocker[] {
  if (!(err instanceof ApiError)) return [];
  const raw = err.body.blockers;
  if (!Array.isArray(raw)) return [];
  return raw.filter(
    (b): b is AccountDeletionBlocker =>
      b !== null && typeof b === "object" && typeof (b as { code?: unknown }).code === "string" &&
      typeof (b as { org_id?: unknown }).org_id === "string",
  );
}

// ---- Passkey second factor (C2; portalmfa.go) ------------------------------

/** PortalPasskey is one of the account's passkeys (no key material). */
export interface PortalPasskey {
  id: string;
  label: string;
  /** synced: the passkey may be synced off the device (backup-eligible). */
  synced: boolean;
  created_at: string;
  last_used_at?: string;
}

/** MFAStatus is GET /portal/api/mfa. */
export interface MFAStatus {
  /** available: this server verifies passkeys. */
  available: boolean;
  session: SecondFactorState;
  recovery_codes_left: number;
  passkeys: PortalPasskey[];
}

/** CeremonyStart is a begin answer: the ceremony token and the options for
 * navigator.credentials (JSON form). */
export interface CeremonyStart {
  ceremony: string;
  options: Record<string, unknown>;
}

export function getMFA(): Promise<MFAStatus> {
  return getJSON<MFAStatus>("/portal/api/mfa");
}

export function beginPasskeyRegistration(label: string): Promise<CeremonyStart> {
  return mutate<CeremonyStart>("/portal/api/mfa/passkeys/register/begin", "POST", { label });
}

export function finishPasskeyRegistration(
  ceremony: string,
  credential: unknown,
): Promise<{ passkey: PortalPasskey; recovery_codes?: string[] }> {
  return mutate("/portal/api/mfa/passkeys/register/finish", "POST", { ceremony, credential });
}

export function removePasskey(id: string): Promise<{ passkeys_left: number }> {
  return mutate("/portal/api/mfa/passkeys/" + encodeURIComponent(id), "DELETE");
}

export function newRecoveryCodes(): Promise<{ recovery_codes: string[] }> {
  return mutate("/portal/api/mfa/recovery-codes", "POST", {});
}

export function beginPasskeyAssertion(): Promise<CeremonyStart> {
  return mutate<CeremonyStart>("/portal/api/mfa/assert/begin", "POST", {});
}

export function finishPasskeyAssertion(
  ceremony: string,
  credential: unknown,
  returnTo: string,
): Promise<{ next: string }> {
  return mutate("/portal/api/mfa/assert/finish", "POST", { ceremony, credential, return_to: returnTo });
}

export function redeemRecoveryCode(
  code: string,
  returnTo: string,
): Promise<{ next: string; recovery_codes_left: number }> {
  return mutate("/portal/api/mfa/recover", "POST", { code, return_to: returnTo });
}

/** OrgSigninPolicy is an org's "require a second factor" setting. */
export interface OrgSigninPolicy {
  require_second_factor: boolean;
  /** can_change: an owner or admin who signed in with a passkey. */
  can_change: boolean;
  /** reason: why an admin cannot change it yet (passkey_signin_required). */
  reason?: string;
}

export function getOrgSigninPolicy(orgId: string): Promise<OrgSigninPolicy> {
  return getJSON<OrgSigninPolicy>("/portal/api/orgs/" + encodeURIComponent(orgId) + "/signin-policy");
}

export function setOrgSigninPolicy(orgId: string, require: boolean): Promise<OrgSigninPolicy> {
  return mutate<OrgSigninPolicy>("/portal/api/orgs/" + encodeURIComponent(orgId) + "/signin-policy", "PUT", {
    require_second_factor: require,
  });
}

/** approveDevice approves a new device (the id its sign-in printed) for the
 * next 15 minutes; needs a session that signed in with a passkey (FR-6). */
export function approveDevice(thumbprint: string): Promise<{ expires_at: string }> {
  return mutate("/portal/api/mfa/devices/approve", "POST", { thumbprint });
}

// ---- Connect a machine (Getting started v2) --------------------------------
// docs/plans/onboarding-v2-connect-flow.md; portal_connect.go. A machine
// running `observer connect` creates a request; this console shows it,
// lets the signed-in person pick a dashboard and approve, and lists what
// was connected.

/** ShareLevel is how much a connected machine sends. */
export type ShareLevel = "summary" | "full";

/** ConnectDisclosure is the exact text shown for a dashboard, with the
 * version and digest the approval sends back (the consent receipt). */
export interface ConnectDisclosure {
  share_level: ShareLevel;
  title: string;
  text: string;
  disclosure_version: string;
  disclosure_sha256: string;
}

/** ConnectChoice is one dashboard the machine can connect to. */
export interface ConnectChoice {
  org_id: string;
  kind: "personal" | "team";
  display_name: string;
  /** slug is a team's name; absent for the personal dashboard. */
  slug?: string;
  status: OrgStatus;
  share_level: ShareLevel;
  disclosure: ConnectDisclosure;
  preselected: boolean;
}

/** ConnectTarget is the dashboard an approved request connected to. */
export interface ConnectTarget {
  org_id: string;
  slug: string;
  kind: "personal" | "team";
  display_name: string;
  share_level: ShareLevel;
}

/** ConnectStatus is a request's state. */
export type ConnectStatus = "pending" | "approved" | "declined" | "expired";

/** ConnectRequestView is GET /portal/api/connect/requests/{id}. */
export interface ConnectRequestView {
  request_id: string;
  status: ConnectStatus;
  /** user_code is set while pending, to compare with the terminal. */
  user_code?: string;
  machine_name: string;
  os: string;
  arch: string;
  observer_version: string;
  created_at: string;
  age_seconds: number;
  expires_in: number;
  network: { prefix: string; same_as_you: boolean };
  choices: ConnectChoice[];
  target: ConnectTarget | null;
  /** open_url opens the chosen dashboard (a button, never text), built by
   * the server (tenantlink.go). The older online_url is not read. */
  open_url?: string;
}

/** ConnectMachine is one recent approval on the account home. */
export interface ConnectMachine {
  request_id: string;
  machine_name: string;
  os: string;
  approved_at: string;
  target: ConnectTarget | null;
  /** open_url opens the dashboard the machine connected to (server-built). */
  open_url?: string;
}

/** ConnectHome is GET /portal/api/connect/machines. */
export interface ConnectHome {
  /** devices is the number of signed-in machines. */
  devices: number;
  recent: ConnectMachine[];
}

export function getConnectRequest(id: string): Promise<ConnectRequestView> {
  return getJSON<ConnectRequestView>("/portal/api/connect/requests/" + encodeURIComponent(id));
}

/** lookupConnectCode turns a typed code into its waiting request. */
export function lookupConnectCode(userCode: string): Promise<{ request_id: string }> {
  return mutate<{ request_id: string }>("/portal/api/connect/lookup", "POST", { user_code: userCode });
}

/** approveConnect connects the machine to the chosen dashboard, sending back
 * the disclosure that was shown. */
export function approveConnect(id: string, choice: ConnectChoice): Promise<ConnectRequestView> {
  return mutate<ConnectRequestView>(
    "/portal/api/connect/requests/" + encodeURIComponent(id) + "/approve",
    "POST",
    {
      target_org_id: choice.org_id,
      disclosure_version: choice.disclosure.disclosure_version,
      disclosure_sha256: choice.disclosure.disclosure_sha256,
    },
  );
}

/** connectNotNow signs the machine in and sends nothing. */
export function connectNotNow(id: string): Promise<ConnectRequestView> {
  return mutate<ConnectRequestView>(
    "/portal/api/connect/requests/" + encodeURIComponent(id) + "/approve",
    "POST",
    { target_org_id: "" },
  );
}

/** declineConnect refuses a request ("This is not my machine"). */
export function declineConnect(id: string): Promise<ConnectRequestView> {
  return mutate<ConnectRequestView>(
    "/portal/api/connect/requests/" + encodeURIComponent(id) + "/decline",
    "POST",
    {},
  );
}

export function getConnectHome(): Promise<ConnectHome> {
  return getJSON<ConnectHome>("/portal/api/connect/machines");
}
