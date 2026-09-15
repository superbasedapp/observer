// Typed HTTP client for the observer dashboard's /api/* surface.
//
// Pure Node (no vscode dependency) so unit tests can exercise it
// directly. Uses the global `fetch` (Node >= 18 — VS Code 1.90+ ships
// Node 20).

import type {
  CacheStatusResponse,
  CostResponse,
  DiscoverResponse,
  FileStateResponse,
  HeadlineResponse,
  HealthResponse,
  SessionsResponse,
  WatcherHealthResponse,
} from './types';

/**
 * EditorChangeRequest is the body of POST /api/loc/editor-change.
 *
 * COUNTS ONLY. There is deliberately no field on this type that can
 * carry file text, a line, or an excerpt: the daemon receives how many
 * lines changed and in which buckets, never what they said.
 */
export interface EditorChangeRequest {
  /** Workspace-relative path, forward slashes. The daemon hashes it. */
  path: string;
  /** Absolute path of the workspace folder, so the daemon can resolve the project. */
  workspace_root: string;
  /** Normalized language id from the shared classifier tables. */
  language: string;
  /** Coarse category (code / docs / config). */
  category: string;
  /** Lines the human changed between the last clean snapshot and the save. */
  human: LocStats;
  /** Lines a will-save participant (formatter) changed during the save. */
  system: LocStats;
  human_confidence: string;
  system_confidence: string;
  /** RFC3339 with milliseconds, the EDITOR's clock. */
  saved_at: string;
  /** loc.Version the counts were produced with. */
  classifier_version: number;
  /**
   * possible_agent says the buffer changed in a shape typing does not
   * produce while the document was dirty — an in-editor agent
   * (Copilot Chat agent mode, Cline/Kilo, Cursor) applying a
   * WorkspaceEdit. The daemon books such a save as `unknown` rather than
   * as the developer's own lines. Still counts only: it is a boolean.
   */
  possible_agent: boolean;
}

/** LocStats is the line-count bucket set (mirrors internal/loc.Stats). */
export interface LocStats {
  added_code: number;
  modified_code: number;
  deleted_code: number;
  added_comment: number;
  deleted_comment: number;
  whitespace: number;
  blank: number;
  unknown: number;
}

/**
 * LocEndpointMissingError is thrown when the daemon answers 404 —
 * an older daemon that predates /api/loc/editor-change. The caller
 * stops posting for the rest of the session rather than retrying on
 * every save.
 */
export class LocEndpointMissingError extends Error {
  constructor() {
    super('daemon has no /api/loc/editor-change endpoint');
    this.name = 'LocEndpointMissingError';
  }
}

export interface ClientOptions {
  dashboardPort: number;
  host?: string; // defaults to 127.0.0.1
  fetchImpl?: typeof fetch;
  signalTimeoutMs?: number; // per-request timeout; default 5_000
}

export class Client {
  readonly host: string;
  readonly port: number;
  private readonly fetchImpl: typeof fetch;
  private readonly timeoutMs: number;

  constructor(opts: ClientOptions) {
    this.host = opts.host ?? '127.0.0.1';
    this.port = opts.dashboardPort;
    this.fetchImpl = opts.fetchImpl ?? fetch;
    this.timeoutMs = opts.signalTimeoutMs ?? 5_000;
  }

  url(pathAndQuery: string): string {
    const suffix = pathAndQuery.startsWith('/') ? pathAndQuery : `/${pathAndQuery}`;
    return `http://${this.host}:${this.port}${suffix}`;
  }

  async headline(days = 1): Promise<HeadlineResponse> {
    return this.get<HeadlineResponse>(`/api/analysis/headline?days=${days}`);
  }

  async sessions(limit = 20): Promise<SessionsResponse> {
    return this.get<SessionsResponse>(`/api/sessions?limit=${limit}`);
  }

  async discover(): Promise<DiscoverResponse> {
    return this.get<DiscoverResponse>(`/api/discover`);
  }

  async cost(days = 7, groupBy = 'model'): Promise<CostResponse> {
    return this.get<CostResponse>(
      `/api/cost?days=${days}&group-by=${encodeURIComponent(groupBy)}`,
    );
  }

  async cacheStatus(sessionId?: string): Promise<CacheStatusResponse> {
    const q = sessionId ? `?session=${encodeURIComponent(sessionId)}` : '';
    return this.get<CacheStatusResponse>(`/api/cache/status${q}`);
  }

  async fileState(absolutePath: string): Promise<FileStateResponse> {
    return this.get<FileStateResponse>(
      `/api/file/state?path=${encodeURIComponent(absolutePath)}`,
    );
  }

  async watcherHealth(): Promise<WatcherHealthResponse> {
    return this.get<WatcherHealthResponse>(`/api/health/watcher`);
  }

  async health(): Promise<HealthResponse> {
    // The Go server doesn't expose a dedicated /api/health right now,
    // but a fast HEAD on /api/analysis/headline works as a liveness
    // probe (returns 200 even if the analysis window is empty).
    const res = await this.fetchWithTimeout(this.url('/api/analysis/headline?days=1'), {
      method: 'GET',
    });
    return { ok: res.ok, status: res.status };
  }

  /**
   * postEditorChange reports one save's line counts to the local
   * daemon. It is the ONLY non-GET call this client makes.
   *
   * Wire notes, all load-bearing:
   *
   *  - No `Origin` header. The daemon's browserGuard admits Origin-less
   *    loopback POSTs precisely so a non-browser client can reach this
   *    endpoint; a browser page cannot suppress its own Origin. Node's
   *    fetch sends none unless asked, so this is a "do not add one"
   *    rule rather than a header to set.
   *  - `X-Observer-Token` only when a token is configured. A daemon on
   *    a loopback bind accepts an Origin-less POST without one.
   *  - 2xx (including 204) is success.
   *  - 404 throws LocEndpointMissingError so the caller can stop
   *    posting for the session instead of failing on every save.
   *  - Every other failure throws a plain Error. Callers log it to the
   *    output channel and move on: a daemon that is not running must
   *    never produce a toast on every Ctrl+S. There is no retry — a
   *    save is a discrete event and a stale re-post would double-count.
   */
  async postEditorChange(body: EditorChangeRequest, token?: string): Promise<void> {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (token) {
      headers['X-Observer-Token'] = token;
    }
    const res = await this.fetchWithTimeout(this.url('/api/loc/editor-change'), {
      method: 'POST',
      headers,
      body: JSON.stringify(body),
    });
    if (res.status === 404) {
      throw new LocEndpointMissingError();
    }
    if (!res.ok) {
      throw new Error(
        `SuperBased API /api/loc/editor-change → HTTP ${res.status} ${res.statusText}`,
      );
    }
  }

  /**
   * postExtensionVersion tells the daemon which version of THIS extension is
   * running, so the org's fleet board can show editor/daemon skew (enterprise
   * update management, ruling R6).
   *
   * The daemon cannot discover this on its own - the extension is a separate
   * process on its own release channel - so a node reports an extension
   * version only when one is running and has said so. A node with no extension
   * reports nothing, never "0".
   *
   * Deliberately BEST-EFFORT and silent on failure. This is telemetry about
   * the editor, not a feature the user asked for: an older daemon answers 404
   * or 501, an unenrolled node has nowhere to send it, and neither is worth a
   * toast or a retry loop. It returns whether the report landed so the caller
   * can log one line and stop.
   */
  async postExtensionVersion(version: string): Promise<boolean> {
    try {
      const res = await this.fetchWithTimeout(this.url('/api/update/extension-version'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ version }),
      });
      return res.ok;
    } catch {
      return false;
    }
  }

  private async get<T>(pathAndQuery: string): Promise<T> {
    const res = await this.fetchWithTimeout(this.url(pathAndQuery), { method: 'GET' });
    if (!res.ok) {
      throw new Error(`SuperBased API ${pathAndQuery} → HTTP ${res.status} ${res.statusText}`);
    }
    return (await res.json()) as T;
  }

  private async fetchWithTimeout(input: string, init: RequestInit): Promise<Response> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      return await this.fetchImpl(input, { ...init, signal: controller.signal });
    } finally {
      clearTimeout(timer);
    }
  }
}

export interface BackoffOptions {
  // Fixed retry sequence in ms — first index is the delay BEFORE the
  // second attempt (the first attempt is immediate).
  delaysMs?: readonly number[];
  // Async sleep function — injectable so tests can run instantly.
  sleep?: (ms: number) => Promise<void>;
}

export const DEFAULT_BACKOFF_DELAYS = Object.freeze([200, 500, 1_000, 2_000, 5_000]);

const defaultSleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

/**
 * withBackoff runs `fn` with retries on rejection: attempt #1 fires
 * immediately, then waits delaysMs[0] before attempt #2, etc. Total
 * attempts = delays.length + 1. The last error propagates if every
 * attempt fails.
 */
export async function withBackoff<T>(
  fn: () => Promise<T>,
  opts: BackoffOptions = {},
): Promise<T> {
  const delays = opts.delaysMs ?? DEFAULT_BACKOFF_DELAYS;
  const sleep = opts.sleep ?? defaultSleep;
  let lastErr: unknown;
  for (let attempt = 0; attempt <= delays.length; attempt++) {
    try {
      return await fn();
    } catch (err) {
      lastErr = err;
      if (attempt === delays.length) break;
      await sleep(delays[attempt]);
    }
  }
  throw lastErr;
}
