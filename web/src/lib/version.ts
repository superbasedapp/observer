// version.ts — check the latest published observer version against
// the npm registry, and compare it to the running daemon's version.
//
// USER-INITIATED ONLY. This is the one documented exception to "zero
// background network calls from the dashboard" (see
// website/docs-src/reference/measurement-honesty.md and
// `observer privacy`) — and as of the 2026-07-30 zero-network
// hardening pass it no longer fires automatically. There is NO
// useEffect that fetches on mount/tab-load/interval. The registry is
// only ever contacted when the operator explicitly clicks "Check for
// updates" (Settings → Health, `useUpdateCheck().checkNow`). The
// TopBar's "↑ vX.Y.Z available" pill is read-only: it displays a
// previously cached result but never triggers a fetch itself.
//
// The same click-gated response ALSO carries an optional
// `superbased.announcement` object (rail R2 of
// docs/plans/dashboard-announcements-banner-plan-2026-07-31.md): the
// registry document is our own published package.json, so a release can
// attach one short banner message to it. That message is read from the
// response this file ALREADY fetches — no second request, no new host,
// no timer, and still nothing at all until the operator clicks. It is
// surfaced by AnnouncementBanner and is always dismissible.

import { useCallback, useState, useSyncExternalStore } from "react";

// SESSION_KEY caches the npm probe across reloads in the same browser
// tab. 6h is well under our typical release cadence (multiple-per-day
// during arc weeks) but long enough that re-opening the dashboard
// doesn't need a fresh click to keep showing yesterday's answer.
// Cleared when the tab closes.
const SESSION_KEY = "sb_latest_version";
const CACHE_TTL_MS = 6 * 60 * 60 * 1000;

// NPM_LATEST_URL serves a tiny JSON with `{version: "1.8.2"}` — plus,
// optionally, our own `superbased.announcement` field (see the header).
// CORS is enabled on registry.npmjs.org for browsers, so this is a
// direct frontend fetch with no proxy round-trip.
const NPM_LATEST_URL =
  "https://registry.npmjs.org/@superbased/observer/latest";

// ReleaseAnnouncement mirrors the Go shape in internal/announce
// (plan §1) exactly — the embedded rail, the org rail and this
// registry-piggyback rail all carry identical fields, so the banner can
// treat them as one list. Plain text only: nothing here is ever
// rendered as HTML.
export type ReleaseAnnouncement = {
  id: string;
  severity: "info" | "notice" | "critical";
  title: string;
  body: string;
  url?: string;
  expires_at: string; // RFC3339, required — banners self-retire
  source: "release" | "org";
  // fixed_in, optional: the release from which the announcement no longer
  // applies (announce.FixedIn; WINNODE2 16b).
  fixed_in?: string;
};

// ANNOUNCE_MAX_BODY mirrors announce.MaxBodyChars.
const ANNOUNCE_MAX_BODY = 280;

// parseAnnouncement validates an untrusted blob from the registry
// response into a ReleaseAnnouncement, or null. It is deliberately
// strict and silent: this input arrives over the public internet, so
// anything unexpected degrades to "no banner" rather than to a broken
// or hostile one. Mirrors announce.Validate + the expiry check in
// announce.Merge (live only while now < expires_at).
export function parseAnnouncement(
  raw: unknown,
  now: number = Date.now(),
): ReleaseAnnouncement | null {
  if (!raw || typeof raw !== "object") return null;
  const a = raw as Record<string, unknown>;
  const str = (v: unknown): string => (typeof v === "string" ? v : "");
  const id = str(a.id).trim();
  const severity = str(a.severity);
  const title = str(a.title).trim();
  const body = str(a.body).trim();
  const expires = str(a.expires_at).trim();
  if (!id || !title || !body || !expires) return null;
  if (severity !== "info" && severity !== "notice" && severity !== "critical") {
    return null;
  }
  if (body.length > ANNOUNCE_MAX_BODY) return null;
  const expiresMs = Date.parse(expires);
  if (!Number.isFinite(expiresMs) || expiresMs <= now) return null;
  // The url is optional and https-only; a non-https link is dropped
  // (the rest of the announcement still shows) rather than trusted.
  let url: string | undefined;
  const rawURL = str(a.url).trim();
  if (rawURL) {
    try {
      if (new URL(rawURL).protocol === "https:") url = rawURL;
    } catch {
      url = undefined;
    }
  }
  const source = str(a.source) === "org" ? "org" : "release";
  const fixedIn = str(a.fixed_in).trim();
  return {
    id,
    severity,
    title,
    body,
    url,
    expires_at: expires,
    source,
    ...(fixedIn ? { fixed_in: fixedIn } : {}),
  };
}

// announcementApplies reports whether an announcement is still news for a
// node running `running` (WINNODE2 16b, announce.ForVersion): one fixed in
// a release the node is at or past is not. A running version that is not a
// release (a dev build, unknown) keeps every announcement.
export function announcementApplies(a: Pick<ReleaseAnnouncement, "fixed_in">, running: string | null | undefined): boolean {
  if (!a.fixed_in || !running) return true;
  const cmp = compareSemver(running, a.fixed_in);
  return cmp === null || cmp < 0;
}

type CacheEntry = {
  version: string;
  fetchedAt: number; // epoch ms
  // announcement is the R2 piggyback field from the same response.
  // Absent on entries written before this field existed, and on every
  // release that ships without a message (the common case).
  announcement?: ReleaseAnnouncement | null;
};

function readCache(): CacheEntry | null {
  if (typeof window === "undefined") return null;
  try {
    const raw = window.sessionStorage.getItem(SESSION_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as CacheEntry;
    if (typeof parsed?.version !== "string") return null;
    if (typeof parsed?.fetchedAt !== "number") return null;
    // Re-validate on read: an announcement cached earlier in this
    // 6h window may have expired since, and expiry is what retires a
    // banner. Never revive one from a stale cache.
    return {
      ...parsed,
      announcement: parseAnnouncement(parsed.announcement),
    };
  } catch {
    return null;
  }
}

function readFreshCache(): CacheEntry | null {
  const cached = readCache();
  if (!cached) return null;
  if (Date.now() - cached.fetchedAt > CACHE_TTL_MS) return null;
  return cached;
}

function writeCache(entry: CacheEntry): void {
  if (typeof window === "undefined") return;
  try {
    window.sessionStorage.setItem(SESSION_KEY, JSON.stringify(entry));
  } catch {
    // Quota / disabled — ignore. The pill just won't cache.
  }
}

// SharedUpdateResult / sharedResult / listeners implement a tiny
// module-level "external store" (React's useSyncExternalStore
// contract). useUpdateCheck() is mounted more than once at a time
// (the TopBar pill AND the Settings Health card) — without a shared
// store each instance had its own local `latest` state, so clicking
// "Check for updates" in one place left the other stale until its own
// remount. Every mounted instance now subscribes to the same
// sharedResult and re-renders the moment ANY instance's checkNow()
// succeeds.
type SharedUpdateResult = {
  version: string | null;
  fetchedAt: number | null;
  // announcement is the R2 message carried by the SAME response, or
  // null. It rides this store for the same reason `version` does: it
  // must be visible to a component (AnnouncementBanner) that is not the
  // one the operator clicked in.
  announcement: ReleaseAnnouncement | null;
};

let sharedResult: SharedUpdateResult = (() => {
  const cached = readFreshCache();
  return {
    version: cached?.version ?? null,
    fetchedAt: cached?.fetchedAt ?? null,
    announcement: cached?.announcement ?? null,
  };
})();

const listeners = new Set<() => void>();

function subscribeShared(listener: () => void): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

function getSharedSnapshot(): SharedUpdateResult {
  return sharedResult;
}

function setSharedResult(next: SharedUpdateResult): void {
  sharedResult = next;
  listeners.forEach((listener) => listener());
}

// UpdateCheckState is what useUpdateCheck() exposes: the last-known
// answer (from a prior click, hydrated from sessionStorage on mount —
// never from a fresh fetch) plus an explicit checkNow() trigger.
export type UpdateCheckState = {
  // latest is the newest version this tab has learned about, from
  // cache or from the last checkNow() call. Null until an operator
  // has clicked "Check for updates" at least once (in this tab, or a
  // prior tab within the last CACHE_TTL_MS).
  latest: string | null;
  // checking is true only while a checkNow() fetch is in flight.
  checking: boolean;
  // error is true when the last checkNow() call failed (network
  // error, non-2xx, or an unparseable body). Cleared on the next
  // successful check.
  error: boolean;
  // lastCheckedAt is the epoch-ms timestamp of the last successful
  // check (from cache or from this tab), or null if none yet.
  lastCheckedAt: number | null;
  // checkNow performs the ONE network call this file ever makes — a
  // GET to registry.npmjs.org — and only runs when the caller invokes
  // it (a button's onClick). Never called automatically.
  checkNow: () => Promise<void>;
};

// useUpdateCheck hydrates from any fresh cached result on mount (no
// network call) and otherwise stays idle until checkNow() is called.
// `latest` / `lastCheckedAt` come from the shared module-level store
// (via useSyncExternalStore) so every mounted instance sees the same
// answer and re-renders together the moment ANY instance's checkNow()
// succeeds; `checking` / `error` stay per-instance local state so
// only the instance the operator actually clicked shows a spinner.
export function useUpdateCheck(): UpdateCheckState {
  const shared = useSyncExternalStore(
    subscribeShared,
    getSharedSnapshot,
    getSharedSnapshot,
  );
  const [checking, setChecking] = useState(false);
  const [error, setError] = useState(false);

  const checkNow = useCallback(async () => {
    setChecking(true);
    setError(false);
    try {
      const res = await fetch(NPM_LATEST_URL, {
        headers: { Accept: "application/json" },
      });
      const json: {
        version?: unknown;
        superbased?: { announcement?: unknown } | null;
      } | null = res.ok ? await res.json() : null;
      const v = typeof json?.version === "string" ? json.version : null;
      if (!v) {
        setError(true);
        return;
      }
      const fetchedAt = Date.now();
      // Rail R2: read (never fetch) the optional announcement the
      // registry document carries alongside the version. A malformed,
      // expired or absent field is simply null.
      const announcement = parseAnnouncement(
        json?.superbased?.announcement,
        fetchedAt,
      );
      writeCache({ version: v, fetchedAt, announcement });
      setSharedResult({ version: v, fetchedAt, announcement });
    } catch {
      setError(true);
    } finally {
      setChecking(false);
    }
  }, []);

  return {
    latest: shared.version,
    checking,
    error,
    lastCheckedAt: shared.fetchedAt,
    checkNow,
  };
}

// getSharedAnnouncement is the useSyncExternalStore getSnapshot for the
// R2 announcement. It returns the object identity held in sharedResult
// (not a fresh object) so React's snapshot-stability check holds.
function getSharedAnnouncement(): ReleaseAnnouncement | null {
  return sharedResult.announcement;
}

// useReleaseAnnouncement exposes rail R2's message to the banner. It is
// READ-ONLY and never fetches: the value is null until some component's
// checkNow() (the "Check for updates" click) has run in this tab, or a
// prior click's result is still in the 6h sessionStorage cache. This is
// the invariant that keeps the zero-background-network claim true — the
// banner surface adds no network behaviour whatsoever.
export function useReleaseAnnouncement(): ReleaseAnnouncement | null {
  return useSyncExternalStore(
    subscribeShared,
    getSharedAnnouncement,
    getSharedAnnouncement,
  );
}

// compareSemver returns -1 / 0 / 1 for a < b / a == b / a > b across
// X.Y.Z[-suffix] strings. Suffix (pre-release tag) is stripped before
// comparing — pre-releases never trigger an "update available" pill,
// since we ship pre-releases only to ad-hoc tag pushes that operators
// shouldn't be alerted to. Returns null for any malformed input.
export function compareSemver(a: string, b: string): number | null {
  const pa = parseSemver(a);
  const pb = parseSemver(b);
  if (!pa || !pb) return null;
  for (let i = 0; i < 3; i++) {
    if (pa[i] < pb[i]) return -1;
    if (pa[i] > pb[i]) return 1;
  }
  return 0;
}

function parseSemver(v: string): [number, number, number] | null {
  if (!v) return null;
  // Strip leading 'v' and any pre-release suffix.
  const core = v.replace(/^v/, "").split(/[-+]/, 1)[0];
  const parts = core.split(".");
  if (parts.length < 3) return null;
  const nums: number[] = [];
  for (let i = 0; i < 3; i++) {
    const n = Number(parts[i]);
    if (!Number.isFinite(n) || n < 0) return null;
    nums.push(n);
  }
  return [nums[0], nums[1], nums[2]];
}

// isUpdateAvailable returns true when latest is a strict semver
// greater than current. Returns false for any non-comparable pair
// (dev build, missing version, malformed string) — defaults to "no
// pill" on uncertainty.
export function isUpdateAvailable(
  current: string | undefined | null,
  latest: string | undefined | null,
): boolean {
  if (!current || !latest) return false;
  if (current === "dev") return false;
  // Pre-release current versions (e.g. "1.8.2-rc.1") also skip — we
  // don't want pre-release builds nagging about a stable release that
  // they're effectively ahead of.
  if (/[-+]/.test(current)) return false;
  const cmp = compareSemver(current, latest);
  return cmp === -1;
}
