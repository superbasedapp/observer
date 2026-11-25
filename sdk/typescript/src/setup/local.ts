/**
 * The client side of the local enable (plan 3.7): the one enable seam,
 * `POST /api/apps/enable` on this machine's Observer, with the confirm token
 * `GET /api/apps/status` hands out and `source: "sdk-setup"` for the audit
 * row.
 *
 * On a terminal the person answers y/N to the machine's own consent
 * sentence. With no terminal (an agent runs setup) the person clicks Turn on
 * on the dashboard's AI Apps page; setup opens it and polls the status every
 * 2 s for up to 5 minutes. When no browser can be opened, setup prints the
 * page and `observer apps on` for the person and stops with exit 2; a re-run
 * goes on from there.
 *
 * setup never touches the machine's own SDK credential routes or the
 * Observer sign-in verbs (ledger SDKQS-8, guard R-165): an SDK key on this
 * machine is the person's to mint or install.
 */

import { obj, str, type HttpFn } from "./net.js";
import { EXIT, type Clock } from "./device.js";

export const STATUS_PATH = "/api/apps/status";
export const ENABLE_PATH = "/api/apps/enable";
export const CONFIRM_HEADER = "X-Observer-Confirm";
export const CONFIRM_COOKIE = "sb_remote_confirm";
/** The audit source this caller names (a row in the machine's appsEnableSources). */
export const ENABLE_SOURCE = "sdk-setup";
export const POLL_EVERY_MS = 2000;
export const POLL_FOR_MS = 5 * 60_000;

/** What the status said. */
export interface AppsStatus {
  on: boolean;
  /** The consent sentence the machine serves ("" when none). */
  sentence: string;
  /** Where the receiver listens, when the machine says. */
  receiver: string;
  confirmToken: string;
}

/** Parse GET /api/apps/status (pure). */
export function parseAppsStatus(body: unknown): AppsStatus {
  const b = obj(body);
  const consent = obj(b.consent);
  const receiver = obj(b.receiver);
  const addr = str(receiver, "http_addr");
  return { on: b.on === true, sentence: str(consent, "sentence"), receiver: addr, confirmToken: str(b, "confirm_token") };
}

/** The question asked on a terminal. */
export function enableQuestion(s: AppsStatus): string {
  const where = s.receiver ? ` It listens on ${s.receiver} only.` : " It listens on this computer only.";
  return `Turn on AI Apps on this computer?${where}${s.sentence ? ` ${s.sentence}` : ""} [y/N] `;
}

/** The dashboard page that puts Turn on first. */
export function enablePageUrl(nodeUrl: string): string {
  return `${nodeUrl.replace(/\/+$/, "")}/apps?enable=1&from=setup`;
}

/** The enable answer to setup's next state (pure). */
export function enableOutcome(status: number, body: unknown, text = ""): { ok: true } | { ok: false; exit: number; message: string } {
  if (status === 200) return { ok: true };
  const b = obj(body);
  const detail = str(b, "message") || str(b, "detail") || str(b, "outcome") || text;
  if (status === 400 && /unknown source/.test(detail || "unknown source")) {
    return { ok: false, exit: EXIT.environment, message: "This Observer is older than this setup and does not take its request; run `observer apps on` yourself, then run setup again." };
  }
  if (status === 501) return { ok: false, exit: EXIT.environment, message: "This Observer cannot turn AI Apps on while it runs; run `observer apps on`, or restart `observer start`, then run setup again." };
  if (status === 409) return { ok: false, exit: EXIT.refused, message: `Observer did not turn AI Apps on${detail ? ` (${detail})` : ""}.` };
  return { ok: false, exit: EXIT.environment, message: `Observer answered HTTP ${status} to turning AI Apps on${detail ? ` (${detail})` : ""}.` };
}

/** Read the status. Throws a TransportError when the machine does not answer. */
export async function appsStatus(http: HttpFn, nodeUrl: string): Promise<AppsStatus & { cookie: string }> {
  const a = await http({ method: "GET", url: nodeUrl.replace(/\/+$/, "") + STATUS_PATH, timeoutMs: 3000 });
  const s = parseAppsStatus(a.body);
  // The double-submit cookie the dashboard set; the token in the body is the same value.
  const m = new RegExp(`${CONFIRM_COOKIE}=([^;]+)`).exec(a.setCookie);
  return { ...s, cookie: m ? m[1] : s.confirmToken };
}

/** POST the enable with the confirm token. */
export async function enableApps(http: HttpFn, nodeUrl: string, token: string): Promise<{ ok: true } | { ok: false; exit: number; message: string }> {
  const a = await http({
    method: "POST",
    url: nodeUrl.replace(/\/+$/, "") + ENABLE_PATH,
    headers: { [CONFIRM_HEADER]: token, Cookie: `${CONFIRM_COOKIE}=${token}` },
    body: { source: ENABLE_SOURCE },
    timeoutMs: 20_000,
  });
  return enableOutcome(a.status, a.body);
}

/** Poll the status until AI Apps is on (true) or the window ends (false). */
export async function waitForOn(http: HttpFn, nodeUrl: string, clock: Clock, forMs = POLL_FOR_MS): Promise<boolean> {
  const until = clock.now() + forMs;
  while (clock.now() < until) {
    try {
      if ((await appsStatus(http, nodeUrl)).on) return true;
    } catch {
      // the machine restarting: keep waiting
    }
    await clock.sleep(POLL_EVERY_MS);
  }
  return false;
}
