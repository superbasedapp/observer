// componentsApi: the write calls of Settings > Components, shared by the page
// and by every card that turns one component on in place (ruling SBXD-9), so
// both send the same request: a POST with the local confirm token, read back
// as the server's own sentence.

import { ApiError, apiReason, fetchJSON, localConfirmHeaders } from "./api";

/** componentsPost POSTs a JSON body to a /api/components route with the
 *  local confirm token. */
export async function componentsPost<T>(path: string, body: unknown): Promise<T> {
  return fetchJSON<T>(path, undefined, {
    method: "POST",
    headers: await localConfirmHeaders(),
    body: JSON.stringify(body),
  });
}

/** componentsErrorText is a failed call's sentence: the body's message when
 *  it has one, else the error text. */
export function componentsErrorText(e: unknown): string {
  if (e instanceof ApiError) {
    try {
      const v = JSON.parse(e.body) as { message?: string };
      if (v.message) return v.message;
    } catch {
      // fall through
    }
  }
  return e instanceof Error ? e.message : String(e);
}

/** componentsLocalOnly reports the local-only refusal a remote view meets on
 *  a write route ("reachable only from the local dashboard"). */
export function componentsLocalOnly(e: unknown): boolean {
  return e instanceof ApiError && e.status === 403 && /local dashboard/i.test(apiReason(e));
}
