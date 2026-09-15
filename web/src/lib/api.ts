// Minimal API client for the Go dashboard backend.
//
// Endpoints live at /api/* on the same origin (production) or
// proxied to localhost:8820 in `vite dev`. The client returns
// parsed JSON; per-endpoint TypeScript shapes get added as pages
// start wiring real data in Phase 2+.

import { markRemoteAuthLost } from "@/lib/authLoss";
import { getRemoteCSRF, isRemoteView, setRemoteCSRF } from "@/lib/remote";
import type {
  InstanceInfo,
  InstanceTestResult,
  LOCSummaryResponse,
  SessionLOCResponse,
  SessionTagsRequest,
  SessionTagsResponse,
  TagManageRequest,
  TagManageResponse,
  TagRollupResponse,
} from "@/lib/types";

// QueryParams values may be a plain scalar (one `k=v`) or a string ARRAY,
// which serializes as a REPEATED key (`k=a&k=b`) rather than a joined value.
// The repeated form is what /api/sessions?tag=…&tag=… expects for its AND
// semantics; an empty array contributes nothing at all.
export type QueryParams = Record<
  string,
  string | number | boolean | string[] | undefined
>;

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly path: string,
    body: string,
  ) {
    super(`api ${status} ${path}: ${body.slice(0, 200)}`);
  }
}

function buildUrl(path: string, params?: QueryParams): string {
  if (!params) return path;
  const qs = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === "" || v === false) continue;
    if (Array.isArray(v)) {
      // Repeated key, one entry per element — `append`, never `set`, or the
      // last element would silently win over the rest.
      for (const item of v) {
        if (item === "") continue;
        qs.append(k, item);
      }
      continue;
    }
    qs.set(k, String(v));
  }
  const s = qs.toString();
  return s ? `${path}?${s}` : path;
}

function unsafeMethod(init?: RequestInit): boolean {
  const method = (init?.method || "GET").toUpperCase();
  return !["GET", "HEAD", "OPTIONS"].includes(method);
}

type WhoAmI = { authenticated?: boolean; csrf?: string };

// The auth endpoints are exempt from auth-loss detection: /pair 401s on a bad
// secret and /whoami is the probe itself, so treating either as evidence of a
// lost session would fight the pairing gate for the screen (or recurse).
const AUTH_PATHS = ["/api/remote/pair", "/api/remote/whoami"];

// The owner-local management routes use one readable double-submit cookie for
// every privileged panel. Several panels can mount together (Terminals loads
// launch policy + sandbox settings in parallel), and an older daemon may rotate
// that cookie on each GET. A token copied from a sibling response can therefore
// be stale by the time its Save button is clicked. The cookie is deliberately
// readable so the SPA can echo it; always prefer its CURRENT value at mutation
// time. Newer daemons also reuse a valid cookie, making both sides convergent.
const LOCAL_CONFIRM_COOKIE = "sb_remote_confirm";

function currentLocalConfirmToken(fallback: string): string {
  if (typeof document === "undefined") return fallback;
  const prefix = `${LOCAL_CONFIRM_COOKIE}=`;
  for (const part of document.cookie.split(";")) {
    const item = part.trim();
    if (!item.startsWith(prefix)) continue;
    const value = item.slice(prefix.length).trim();
    return value || fallback;
  }
  return fallback;
}

function isAuthEndpoint(path: string): boolean {
  return AUTH_PATHS.some((p) => path === p || path.startsWith(`${p}?`));
}

let whoamiInFlight: Promise<WhoAmI | null> | null = null;

// probeRemoteAuth asks the server who we are, SINGLE-FLIGHT: when a page fires
// twenty requests and all twenty 401, they share ONE /api/remote/whoami round
// trip and one verdict. Returns null when the answer is unknown (local view, or
// the probe itself failed) — an unknown answer is never treated as auth loss,
// so a blip can't flash a "session expired" screen.
function probeRemoteAuth(): Promise<WhoAmI | null> {
  if (!isRemoteView()) return Promise.resolve(null);
  if (whoamiInFlight) return whoamiInFlight;
  whoamiInFlight = (async () => {
    const res = await fetch("/api/remote/whoami", {
      headers: { Accept: "application/json" },
    }).catch(() => null);
    if (!res?.ok) return null;
    return (await res.json().catch(() => null)) as WhoAmI | null;
  })().finally(() => {
    whoamiInFlight = null;
  });
  return whoamiInFlight;
}

async function refreshRemoteCSRF(): Promise<string> {
  const body = await probeRemoteAuth();
  if (!body) return "";
  const csrf = body.authenticated ? body.csrf || "" : "";
  setRemoteCSRF(csrf);
  return csrf;
}

// checkRemoteAuth interprets a 401/403 on a remote-paired device. It CONFIRMS
// the loss with the whoami probe before latching it (requirement: one unlucky
// 401 must not produce a scary screen), and returns a fresh CSRF token when the
// session is in fact still good — which is the pre-existing rotated-CSRF
// recovery, now reachable from reads as well as writes.
async function checkRemoteAuth(): Promise<string> {
  const body = await probeRemoteAuth();
  if (!body) return ""; // probe failed ⇒ unknown ⇒ assume nothing
  if (body.authenticated) {
    const csrf = body.csrf || "";
    setRemoteCSRF(csrf);
    return csrf;
  }
  // Confirmed: the server does not know this device any more.
  setRemoteCSRF("");
  markRemoteAuthLost();
  return "";
}

export async function fetchJSON<T>(
  path: string,
  params?: QueryParams,
  init?: RequestInit,
): Promise<T> {
  const url = buildUrl(path, params);
  const remoteView = isRemoteView();
  const needsRemoteCSRF = unsafeMethod(init) && remoteView;
  let csrf = needsRemoteCSRF ? getRemoteCSRF() || (await refreshRemoteCSRF()) : "";
  const buildInit = (csrfValue: string): RequestInit => {
    const headers = new Headers(init?.headers);
    headers.set("Accept", "application/json");
    // Replace a response-captured owner-local confirm token with the latest
    // cookie value immediately before fetch. This closes cross-panel rotation
    // races without weakening the server's constant-time double-submit check.
    const suppliedConfirm = headers.get("X-Observer-Confirm");
    if (suppliedConfirm !== null) {
      const currentConfirm = currentLocalConfirmToken(suppliedConfirm);
      if (currentConfirm) headers.set("X-Observer-Confirm", currentConfirm);
    }
    if (needsRemoteCSRF && csrfValue) headers.set("X-Remote-CSRF", csrfValue);
    return { ...init, headers };
  };
  let res = await fetch(url, buildInit(csrf));
  // Auth recovery is gated on the REMOTE VIEW, not on the method. It used to be
  // gated on needsRemoteCSRF, which is false for GET/HEAD/OPTIONS — so a device
  // that had lost its session got a raw `api 401 …` on every read with no
  // recovery and no explanation at all.
  if (!res.ok && remoteView && !isAuthEndpoint(path) && (res.status === 401 || res.status === 403)) {
    const next = await checkRemoteAuth();
    if (needsRemoteCSRF && next && next !== csrf) {
      csrf = next;
      res = await fetch(url, buildInit(csrf));
    }
  }
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new ApiError(res.status, url, body);
  }
  return res.json() as Promise<T>;
}

// ---------- session classification (tags / favorites / notes) ----------
//
// Thin typed wrappers over fetchJSON so every caller inherits the remote
// CSRF + auth-recovery handling above rather than reaching for bare fetch.
// docs/plans/session-classification-tags-plan-2026-07-31.md §4.

const jsonPost = (body: unknown): RequestInit => ({
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(body),
});

// fetchTagRollup returns the tag vocabulary plus per-tag session/cost/token
// rollup. Also the source of the TagEditor's suggestion list.
export function fetchTagRollup(signal?: AbortSignal): Promise<TagRollupResponse> {
  return fetchJSON<TagRollupResponse>("/api/sessions/tags", undefined, { signal });
}

// postSessionTags mutates one session's tags/favorite/note/rating/title and
// returns the server's post-mutation truth. `favorite`/`note`/`rating`/
// `title` default to null = "unchanged"; pass a value only when the mutation
// actually touches them (an empty string clears the note/title).
export function postSessionTags(
  sessionId: string,
  patch: Partial<SessionTagsRequest>,
): Promise<SessionTagsResponse> {
  const body: SessionTagsRequest = {
    add: patch.add ?? [],
    remove: patch.remove ?? [],
    favorite: patch.favorite ?? null,
    note: patch.note ?? null,
    rating: patch.rating ?? null,
    title: patch.title ?? null,
  };
  return fetchJSON<SessionTagsResponse>(
    `/api/session/${encodeURIComponent(sessionId)}/tags`,
    undefined,
    jsonPost(body),
  );
}

// manageTags renames or deletes a tag across every session that carries it.
// The request is rename XOR delete — the union type enforces it at the call
// site so a body carrying both can't be constructed.
export function manageTags(req: TagManageRequest): Promise<TagManageResponse> {
  return fetchJSON<TagManageResponse>(
    "/api/sessions/tags/manage",
    undefined,
    jsonPost(req),
  );
}

// ---------- custom tag definitions ----------

export interface TagDefinitionEntry {
  definition: string;
  category?: string;
}
export interface TagDefinitionsResponse {
  definitions: Record<string, TagDefinitionEntry>;
}

// fetchTagDefinitions returns the user's CUSTOM tag definitions. Standard tag
// definitions live in the in-code taxonomy (web/src/lib/tagTaxonomy.ts), not
// here — this is only the glossary a user authored for their own tags.
export function fetchTagDefinitions(
  signal?: AbortSignal,
): Promise<TagDefinitionsResponse> {
  return fetchJSON<TagDefinitionsResponse>("/api/tags/definitions", undefined, {
    signal,
  });
}

// postTagDefinition upserts a custom tag's definition; an empty definition
// clears the stored row.
export function postTagDefinition(
  tag: string,
  definition: string,
  category?: string,
): Promise<{ ok: boolean }> {
  return fetchJSON<{ ok: boolean }>(
    "/api/tags/definitions",
    undefined,
    jsonPost({ tag, definition, category: category ?? "" }),
  );
}

// ---------- instance switcher (remote Observer installs) ----------
//
// Thin typed wrappers over fetchJSON, matching the tag helpers above so every
// caller inherits the remote CSRF + auth-recovery handling.
//
// Both verbs are NAME-ONLY: the profile name travels in the PATH and the body
// is empty, because the daemon resolves the host, the key, the jump host and
// the remote dashboard port from its own operator-authored config. There is
// deliberately no shape here for a caller to pass a host or a port — see
// docs/ssh-terminals.md "Instance switcher".

// connectInstance opens (or re-uses) the SSH local port forward for a named
// instance and returns the resulting row, including the loopback port to open.
export function connectInstance(name: string): Promise<InstanceInfo> {
  return fetchJSON<InstanceInfo>(
    `/api/instances/${encodeURIComponent(name)}/connect`,
    undefined,
    { method: "POST" },
  );
}

// disconnectInstance closes the forward. Idempotent server-side, so a stale UI
// cannot produce a spurious failure.
export function disconnectInstance(name: string): Promise<InstanceInfo> {
  return fetchJSON<InstanceInfo>(
    `/api/instances/${encodeURIComponent(name)}/disconnect`,
    undefined,
    { method: "POST" },
  );
}

// testInstance runs the bounded, non-interactive connectivity probe
// (known_hosts + auth) for a named instance without opening a forward. Same
// name-only-in-path shape as connect/disconnect.
export function testInstance(name: string): Promise<InstanceTestResult> {
  return fetchJSON<InstanceTestResult>(
    `/api/instances/${encodeURIComponent(name)}/test`,
    undefined,
    { method: "POST" },
  );
}

// ---------- lines-of-code authorship ----------
//
// docs/plans/lines-of-code-tracking-plan-2026-09-07.md §3.2. Both endpoints
// are plain reads over node-local `file_changes`; the components normally
// reach them through useApi (which owns abort + polling), and these helpers
// exist for the imperative call sites and to keep the paths in one place.

// sessionLOCPath is the per-session authorship read. Exported so useApi
// callers build the same URL the helper does.
export function sessionLOCPath(sessionId: string): string {
  return `/api/session/${encodeURIComponent(sessionId)}/loc`;
}

// sessionOrgIntelPath is the per-session org-served Cloud Intelligence read —
// the result this node last pulled back from the org server, cached locally.
export function sessionOrgIntelPath(sessionId: string): string {
  return `/api/session/${encodeURIComponent(sessionId)}/org-intel`;
}

// fetchSessionLOC returns one session's line-authorship buckets.
export function fetchSessionLOC(
  sessionId: string,
  signal?: AbortSignal,
): Promise<SessionLOCResponse> {
  return fetchJSON<SessionLOCResponse>(sessionLOCPath(sessionId), undefined, {
    signal,
  });
}

// LOC_SUMMARY_PATH is the window rollup. `days` is the only window knob the
// endpoint takes (no hours, no custom range) and `project` wants a NUMERIC
// project id, which the dashboard's project filter (a root path) cannot
// supply - so callers scope by days and say so rather than passing a filter
// the server would silently drop.
export const LOC_SUMMARY_PATH = "/api/loc/summary";

// fetchLOCSummary returns the window rollup. `projectID` is optional and is
// the numeric project id, never a project root path.
export function fetchLOCSummary(
  days: number,
  projectID?: number,
  signal?: AbortSignal,
): Promise<LOCSummaryResponse> {
  return fetchJSON<LOCSummaryResponse>(
    LOC_SUMMARY_PATH,
    { days, project: projectID },
    { signal },
  );
}

// apiReason extracts the SERVER's own message from an ApiError so the UI can
// show the honest, actionable reason (notably the known_hosts guidance) rather
// than a generic "request failed". Falls back to the raw error text.
export function apiReason(e: unknown): string {
  if (e instanceof ApiError) {
    const marker = `${e.path}: `;
    const at = e.message.indexOf(marker);
    if (at >= 0) {
      const body = e.message.slice(at + marker.length).trim();
      if (body) return body;
    }
    return e.message;
  }
  return e instanceof Error ? e.message : String(e);
}
