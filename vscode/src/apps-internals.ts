// Pure logic of "SuperBased: Turn on AI Apps" (first-run plan revision 2,
// section 4.4; review P-09; lane POLISH-F2). No vscode import, so
// test/unit/apps.test.ts exercises it directly.
//
// An extension-only user has no `observer` on PATH, so "run `observer apps
// on`" would fail for them. This action calls the daemon's ONE enable seam
// (POST /api/apps/enable, the same function the dashboard button and the CLI
// call) over the owner-local dashboard API. It adds no enable path of its
// own: with no daemon there is nothing to call, and it says how to start one.
//
// The routes (internal/intelligence/dashboard apps_enable.go):
//   GET  /api/apps/status  the apps block + confirm_token (double submit)
//   POST /api/apps/enable  {"source":"vscode"} -> an EnableReport; 200 only
//                          when AI Apps is on and the receiver listens
// A daemon older than the seam answers 404, a process without it 501: the
// action then says "restart `observer start` to finish" and does nothing
// else (it never restarts the daemon: it is the proxy).

/** The subset of GET /api/apps/status the action reads. */
export interface AppsStatusLite {
  in_build?: boolean;
  component?: string;
  on?: boolean;
  receiver?: { state?: string; http_addr?: string; error?: string };
  consent?: { sentence?: string; receiver_note?: string };
  confirm_token?: string;
}

/** The daemon's EnableReport (internal/planechoice EnableReport). */
export interface EnableReportLite {
  outcome?: string;
  ok?: boolean;
  message?: string;
  fix?: string;
  receiver?: { state?: string; http_addr?: string };
  pending_next_start?: string[];
}

/** What the action shows. */
export interface AppsOutcome {
  /** info: AI Apps is on; error: it is not; restart: the daemon cannot. */
  kind: 'on' | 'already_on' | 'refused' | 'failed' | 'restart' | 'no_daemon';
  message: string;
  /** The one next step, '' when there is none. */
  fix: string;
  /** True when "Open AI Apps" (the dashboard's /apps page) makes sense. */
  openApps: boolean;
}

/** The dashboard page AI Apps opens on. */
export const APPS_ROUTE = '/apps';

/** The reinstall line, the same words `observer apps on` refuses with. */
export const REINSTALL_FIX =
  'Reinstall with `install.sh --edition developer` (Windows: the install.ps1 -Edition developer option).';

/** receiverText is the receiver address with the loopback note. */
export function receiverText(addr: string | undefined, note: string | undefined): string {
  const a = (addr ?? '').trim() || '127.0.0.1:4318';
  return note ? `${a} ${note}` : a;
}

/**
 * refusalFor is the refusal for an apps block that cannot be turned on
 * (not in this build, absent from the edition, blocked), or undefined.
 */
export function refusalFor(st: AppsStatusLite): AppsOutcome | undefined {
  if (st.in_build === false || st.component === 'absent') {
    return {
      kind: 'refused',
      message: 'This edition does not include AI Apps. The developer and full editions have it.',
      fix: REINSTALL_FIX,
      openApps: false,
    };
  }
  if (st.component === 'blocked') {
    return {
      kind: 'refused',
      message: 'AI Apps is blocked on this machine by a rule or your organization.',
      fix: 'See Settings > Components for who blocked it.',
      openApps: false,
    };
  }
  return undefined;
}

/** consentText is the confirmation the action asks before enabling. */
export function consentText(st: AppsStatusLite): string {
  const lines = ['Turning on AI Apps on this machine:'];
  if (st.component !== 'active') lines.push('- adds the AI Apps component');
  lines.push(
    `- starts listening for your app's traces on ${receiverText(undefined, st.consent?.receiver_note)}`,
  );
  lines.push(st.consent?.sentence || 'Stays on this machine.');
  lines.push('Turn it off with `observer apps off` (takes effect at the next start).');
  return lines.join('\n');
}

/** alreadyOn: AI Apps serves and the receiver listens. */
export function alreadyOn(st: AppsStatusLite): AppsOutcome | undefined {
  if (st.on && st.receiver?.state === 'listening') {
    return {
      kind: 'already_on',
      message: `AI Apps is already on. Receiver: listening on ${receiverText(st.receiver.http_addr, st.consent?.receiver_note)}.`,
      fix: '',
      openApps: true,
    };
  }
  return undefined;
}

/** NO_SEAM is what a daemon older than the seam (or one without it) gets. */
export const NO_SEAM: AppsOutcome = {
  kind: 'restart',
  message: 'This daemon cannot turn AI Apps on while it runs.',
  fix:
    'Restart `observer start` to finish (with the proxy route off first if an AI session uses it), or run `observer apps on` in a terminal.',
  openApps: false,
};

/** NO_DAEMON: nothing to call. */
export const NO_DAEMON: AppsOutcome = {
  kind: 'no_daemon',
  message: 'No SuperBased daemon is running, so AI Apps cannot be turned on from the editor yet.',
  fix: 'Run `SuperBased: Start Daemon`, then try again.',
  openApps: false,
};

/**
 * classifyEnable maps the enable route's answer to what the action shows.
 * It never says "on" unless the report says ok (the receiver listens).
 */
export function classifyEnable(
  httpStatus: number,
  report: EnableReportLite | undefined,
  note: string | undefined,
): AppsOutcome {
  if (httpStatus === 404 || httpStatus === 501) return NO_SEAM;
  if (report && report.ok && report.outcome === 'on') {
    let message = `AI Apps is on. Receiver: listening on ${receiverText(report.receiver?.http_addr, note)}.`;
    const pending = report.pending_next_start ?? [];
    if (pending.length > 0) message += ` Starts at the next start of the daemon: ${pending.join(', ')}.`;
    return { kind: 'on', message, fix: '', openApps: true };
  }
  if (report && report.outcome) {
    return {
      kind: report.outcome === 'not_in_build' || report.outcome === 'blocked' || report.outcome === 'refused' ? 'refused' : 'failed',
      message: report.message || `AI Apps was not turned on (${report.outcome}).`,
      fix: report.fix ?? '',
      openApps: false,
    };
  }
  return {
    kind: 'failed',
    message: `AI Apps was not turned on: the daemon answered HTTP ${httpStatus}.`,
    fix: 'Run `SuperBased: Doctor`, or open the dashboard and use its AI Apps button.',
    openApps: false,
  };
}

/** The two HTTP calls the flow makes, injected so tests need no daemon. */
export interface AppsTransport {
  /** GET /api/apps/status: [http status, body or undefined]. */
  status(): Promise<[number, AppsStatusLite | undefined]>;
  /** POST /api/apps/enable with the token: [http status, report or undefined]. */
  enable(token: string): Promise<[number, EnableReportLite | undefined]>;
}

/**
 * runEnable is the whole flow: read the status, refuse or answer
 * already-on, ask (confirm), then call the seam. confirm returns false to
 * stop with nothing changed (undefined is returned).
 */
export async function runEnable(
  t: AppsTransport,
  confirm: (text: string) => Promise<boolean>,
): Promise<AppsOutcome | undefined> {
  const [code, st] = await t.status();
  if (code === 404 || code === 501) return NO_SEAM;
  if (code !== 200 || !st) {
    return {
      kind: 'failed',
      message: `The daemon's AI Apps status could not be read (HTTP ${code}).`,
      fix: 'Run `SuperBased: Doctor`.',
      openApps: false,
    };
  }
  const refused = refusalFor(st);
  if (refused) return refused;
  const on = alreadyOn(st);
  if (on) return on;
  if (!(await confirm(consentText(st)))) return undefined;
  const token = (st.confirm_token ?? '').trim();
  if (!token) return NO_SEAM;
  const [ecode, rep] = await t.enable(token);
  return classifyEnable(ecode, rep, st.consent?.receiver_note);
}
