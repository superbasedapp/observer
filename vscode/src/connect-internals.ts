// Pure helpers for "SuperBased: Sign in and connect" (Getting started v2,
// lane 5): the command (src/connect.ts), the first-run nudge and the account
// status bar item (src/connectStatus.ts).
//
// The command runs `observer connect --json --no-browser [team]` with the
// extension's resolved binary (contract B/D: the same subprocess pattern the
// local dashboard uses) and reads one JSON object per stdout line. The
// browser approval page on the cloud side shows the consent; the extension
// only opens approve_url and reports the outcome in plain words.
//
// State for the nudge and the status bar comes from the daemon's
// GET /api/connect/status (internal/frontdoor.Status), so a connected or
// signed-in machine is never nagged.
//
// Kept vscode-import-free so it is unit-tested under plain node
// (test/unit/connect.test.ts), the costBar-internals.ts convention.

import type { ChildProcess } from 'node:child_process';

// --- the CLI's JSON lines (contract B) ---------------------------------------

/** The approved target, as `observer connect --json` reports it. */
export interface ConnectTarget {
  org_id?: string;
  slug?: string;
  kind?: 'personal' | 'team' | string;
  display_name?: string;
  share_level?: 'summary' | 'full' | string;
}

/** One line of `observer connect --json`. Unknown states are dropped. */
export type ConnectEvent =
  | { state: 'waiting_approval'; approve_url: string; verify_url: string; user_code: string }
  | { state: 'approved'; target: ConnectTarget | null }
  | { state: 'attaching' }
  | { state: 'connected'; display_name: string; kind: string; online_url?: string }
  | { state: 'signed_in_only' }
  | { state: 'error'; code: string; message: string };

const str = (v: unknown): string => (typeof v === 'string' ? v : '');

/**
 * parseConnectLine reads one stdout line. Anything that is not a JSON object
 * with a known `state` returns null (the CLI may print other lines; they go to
 * the Output channel, never to the user as a result).
 */
export function parseConnectLine(line: string): ConnectEvent | null {
  const trimmed = line.trim();
  if (!trimmed.startsWith('{')) return null;
  let raw: unknown;
  try {
    raw = JSON.parse(trimmed);
  } catch {
    return null;
  }
  if (!raw || typeof raw !== 'object') return null;
  const o = raw as Record<string, unknown>;
  switch (o.state) {
    case 'waiting_approval':
      return {
        state: 'waiting_approval',
        approve_url: str(o.approve_url),
        verify_url: str(o.verify_url),
        user_code: str(o.user_code),
      };
    case 'approved': {
      const t = o.target;
      return { state: 'approved', target: t && typeof t === 'object' ? (t as ConnectTarget) : null };
    }
    case 'attaching':
      return { state: 'attaching' };
    case 'connected': {
      const ev: ConnectEvent = { state: 'connected', display_name: str(o.display_name), kind: str(o.kind) };
      const url = str(o.online_url);
      if (url) ev.online_url = url;
      return ev;
    }
    case 'signed_in_only':
      return { state: 'signed_in_only' };
    case 'error':
      return { state: 'error', code: str(o.code), message: str(o.message) };
    default:
      return null;
  }
}

// --- argv ---------------------------------------------------------------------

/**
 * A team name as the user types it: letters, digits and dashes, starting with
 * a letter or digit. A leading dash would read as a flag, so it is refused
 * before the argv is built (the binary is run with execFile-style argv, never
 * a shell, so this is about meaning, not quoting).
 */
const TEAM_SLUG = /^[a-z0-9][a-z0-9-]{0,62}$/;

/** normalizeTeam trims and lowercases; returns '' for an empty entry. */
export function normalizeTeam(raw: string | undefined): string {
  return (raw ?? '').trim().toLowerCase();
}

/** validateTeam returns why a team name cannot be used, or undefined. */
export function validateTeam(raw: string): string | undefined {
  const t = normalizeTeam(raw);
  if (t === '') return 'Enter the team name your admin gave you.';
  if (!TEAM_SLUG.test(t)) return 'Use only letters, numbers and dashes, like acme-dev.';
  return undefined;
}

/** connectArgs builds the argv for one run (contract B/D). */
export function connectArgs(team?: string): string[] {
  const args = ['connect', '--json', '--no-browser'];
  const t = normalizeTeam(team);
  if (t !== '' && validateTeam(t) === undefined) args.push(t);
  return args;
}

// --- running the CLI ------------------------------------------------------------

/** How one run ended. */
export type ConnectOutcome =
  | { kind: 'connected'; displayName: string; targetKind: string; onlineUrl?: string }
  | { kind: 'signed_in_only' }
  | { kind: 'cancelled' }
  | { kind: 'error'; code: string; message: string };

/** What runConnectProcess needs from the host (injected for tests). */
export interface ConnectRunDeps {
  /** Starts the binary with argv; node's child_process.spawn in production. */
  spawn: (file: string, args: string[]) => ChildProcess;
  /** Called for every parsed line, in order. */
  onEvent: (ev: ConnectEvent) => void;
  /** Called for every stdout line that is not a known JSON line, and for stderr. */
  onLog: (line: string) => void;
  /** Aborts the run (the progress notification's Cancel). */
  signal?: AbortSignal;
  /** Hard stop after this long; the approval request itself expires at 900 s. */
  timeoutMs?: number;
}

/** The longest a run may take: the request's 900 s plus slack for attaching. */
export const CONNECT_TIMEOUT_MS = 17 * 60 * 1000;

/** lineSplitter feeds complete lines from a chunked stream to onLine. */
export function lineSplitter(onLine: (line: string) => void): { push: (chunk: string) => void; flush: () => void } {
  let buf = '';
  return {
    push(chunk: string) {
      buf += chunk;
      let i = buf.indexOf('\n');
      while (i >= 0) {
        const line = buf.slice(0, i).replace(/\r$/, '');
        buf = buf.slice(i + 1);
        if (line.trim() !== '') onLine(line);
        i = buf.indexOf('\n');
      }
    },
    flush() {
      if (buf.trim() !== '') onLine(buf.replace(/\r$/, ''));
      buf = '';
    },
  };
}

/** A stderr line that says the binary is too old to know `--json`. */
const OLD_BINARY = /unknown (flag|shorthand flag)|unknown command "connect"/i;

/**
 * runConnectProcess runs one `observer connect --json --no-browser [team]`
 * and resolves with how it ended. The last connected / signed_in_only / error
 * line wins; a non-zero exit with no error line becomes an error that names
 * the exit code. Cancel kills the child.
 */
export function runConnectProcess(binaryPath: string, team: string | undefined, deps: ConnectRunDeps): Promise<ConnectOutcome> {
  return new Promise((resolve) => {
    let settled = false;
    let final: ConnectOutcome | undefined;
    let oldBinary = false;
    // Assigned after spawn; finish may run before that (a spawn that throws).
    let timer: ReturnType<typeof setTimeout> | undefined = undefined;
    let onAbort: () => void = () => undefined;
    const finish = (o: ConnectOutcome): void => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      deps.signal?.removeEventListener('abort', onAbort);
      resolve(o);
    };

    let child: ChildProcess;
    try {
      child = deps.spawn(binaryPath, connectArgs(team));
    } catch (err) {
      finish({ kind: 'error', code: 'spawn_failed', message: (err as Error).message });
      return;
    }

    onAbort = (): void => {
      child.kill();
      finish({ kind: 'cancelled' });
    };
    timer = setTimeout(() => {
      child.kill();
      finish({ kind: 'error', code: 'timeout', message: '' });
    }, deps.timeoutMs ?? CONNECT_TIMEOUT_MS);

    if (deps.signal?.aborted) {
      onAbort();
      return;
    }
    deps.signal?.addEventListener('abort', onAbort);

    const out = lineSplitter((line) => {
      const ev = parseConnectLine(line);
      if (!ev) {
        deps.onLog(line);
        return;
      }
      deps.onEvent(ev);
      if (ev.state === 'connected') {
        final = { kind: 'connected', displayName: ev.display_name, targetKind: ev.kind, onlineUrl: ev.online_url };
      } else if (ev.state === 'signed_in_only') {
        final = { kind: 'signed_in_only' };
      } else if (ev.state === 'error') {
        final = { kind: 'error', code: ev.code, message: ev.message };
      }
    });
    const errLines = lineSplitter((line) => {
      if (OLD_BINARY.test(line)) oldBinary = true;
      deps.onLog(line);
    });
    child.stdout?.setEncoding('utf8');
    child.stderr?.setEncoding('utf8');
    child.stdout?.on('data', (c: string) => out.push(c));
    child.stderr?.on('data', (c: string) => errLines.push(c));
    child.on('error', (err) => finish({ kind: 'error', code: 'spawn_failed', message: err.message }));
    child.on('close', (code) => {
      out.flush();
      errLines.flush();
      if (final) {
        finish(final);
      } else if (oldBinary) {
        finish({ kind: 'error', code: 'unsupported_binary', message: '' });
      } else {
        finish({ kind: 'error', code: 'exit', message: `observer exited with code ${code ?? 'unknown'}` });
      }
    });
  });
}

// --- plain words ------------------------------------------------------------------

/** waitingMessage is the progress line while the browser page is open. */
export function waitingMessage(userCode: string): string {
  return userCode ? `Waiting for approval in your browser, code ${userCode}` : 'Waiting for approval in your browser';
}

/** progressMessage words a CLI state for the progress notification. */
export function progressMessage(ev: ConnectEvent): string | undefined {
  switch (ev.state) {
    case 'waiting_approval':
      return waitingMessage(ev.user_code);
    case 'approved':
      return ev.target ? 'Approved. Connecting this machine...' : 'Approved. Finishing sign-in...';
    case 'attaching':
      return 'Connecting this machine...';
    default:
      return undefined;
  }
}

/** One row of the error table: a CLI code and what the user reads. */
interface ErrorRow {
  codes: string[];
  text: string;
}

/**
 * ERROR_TEXT words known error codes, top-down. A code not listed falls back
 * to the CLI's own message, else a generic sentence.
 */
const ERROR_TEXT: ErrorRow[] = [
  { codes: ['expired'], text: 'The approval request expired. Try again.' },
  { codes: ['declined'], text: 'The request was declined in your browser. Nothing was sent.' },
  { codes: ['rate_limited', 'too_many_requests'], text: 'Too many sign-in attempts. Wait a minute and try again.' },
  { codes: ['network', 'offline', 'unreachable'], text: 'Could not reach SuperBased. Check your internet connection and try again.' },
  { codes: ['team_not_found', 'unknown_team'], text: 'That team was not found. Check the name with your admin.' },
  { codes: ['timeout'], text: 'Sign-in took too long and was stopped. Try again.' },
  {
    codes: ['unsupported_binary'],
    text: 'This version of SuperBased Observer cannot sign in from the editor. Update it, then try again.',
  },
  { codes: ['spawn_failed'], text: 'SuperBased Observer could not be started. Run "SuperBased: Doctor" to check the install.' },
];

/** errorText words an error outcome for the user. */
export function errorText(code: string, message: string): string {
  const row = ERROR_TEXT.find((r) => r.codes.includes(code));
  if (row) return row.text;
  const m = message.trim();
  return m ? `Could not sign in: ${m}` : 'Could not sign in. Open the SuperBased output for details.';
}

/** The account words the user reads for a target kind. */
export function connectedText(displayName: string, targetKind: string): string {
  const name = safeDisplayName(displayName, targetKind);
  return `Connected to ${name}. This machine's AI sessions now show online.`;
}

/** Shown when the user picked "Not now" on the approval page. */
export const SIGNED_IN_ONLY_TEXT = 'Signed in. Nothing is sent from this machine until you connect it.';

// --- names and URLs -------------------------------------------------------------

/**
 * safeDisplayName never shows a personal dashboard's u-... address (Getting
 * started v2 decision): a name that looks like a host or a URL, or an empty
 * one, reads as "your personal dashboard" or "your team".
 */
export function safeDisplayName(raw: string | undefined, kind?: string): string {
  const name = (raw ?? '').trim();
  const looksLikeAddress = /^u-[a-z0-9]/i.test(name) || name.includes('://') || /\.[a-z]{2,}(\/|$)/i.test(name);
  if (name === '' || looksLikeAddress) {
    return kind === 'team' || kind === 'managed' ? 'your team' : 'your personal dashboard';
  }
  return name;
}

/**
 * isSafeOpenURL admits only an absolute https URL, or http on loopback (a
 * local development cloud), before openExternal. The URL comes from the
 * binary's own output; this is defence in depth, not trust in the line.
 */
export function isSafeOpenURL(raw: string | undefined): boolean {
  if (!raw) return false;
  try {
    const u = new URL(raw);
    if (u.username || u.password || u.host === '') return false;
    if (u.protocol === 'https:') return true;
    return u.protocol === 'http:' && (u.hostname === '127.0.0.1' || u.hostname === 'localhost' || u.hostname === '[::1]');
  } catch {
    return false;
  }
}

// --- the daemon's /api/connect/status -----------------------------------------------

/** The daemon route both the nudge and the status bar read. */
export const CONNECT_STATUS_PATH = '/api/connect/status';

/** Poll cadence: the cost bar's 60 s, never faster than an existing item. */
export const CONNECT_STATUS_POLL_MS = 60_000;

/**
 * ConnectStatus mirrors internal/frontdoor.Status. display_name and
 * online_url are read when a daemon serves them (Getting started v2 may add
 * them); older daemons leave them out and the item falls back to destination
 * and the URL the last successful run reported.
 */
export interface ConnectStatus {
  sentence: string;
  kind: 'local' | 'managed' | 'individual' | string;
  destination?: string;
  signed_in: boolean;
  identity_known: boolean;
  locked: boolean;
  display_name?: string;
  online_url?: string;
}

/**
 * fetchConnectStatus reads the route. 404 (older daemon) and 501 (not wired
 * on this dashboard) resolve to null so the item and the nudge stay quiet;
 * any other non-2xx throws.
 */
export async function fetchConnectStatus(url: string, fetchImpl: typeof fetch, timeoutMs: number): Promise<ConnectStatus | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetchImpl(url, { method: 'GET', signal: controller.signal });
    if (res.status === 404 || res.status === 501) return null;
    if (!res.ok) throw new Error(`SuperBased API ${CONNECT_STATUS_PATH} -> HTTP ${res.status} ${res.statusText}`);
    return (await res.json()) as ConnectStatus;
  } finally {
    clearTimeout(timer);
  }
}

/** isConnected: the machine sends to a personal dashboard or a team. */
export function isConnected(st: ConnectStatus): boolean {
  return st.kind !== 'local';
}

// --- the first-run nudge --------------------------------------------------------------

/** What the extension remembers about the nudge (globalState). */
export interface NudgeState {
  /** How many times the notification was shown. */
  shown: number;
  /** When it was last shown, ms since epoch. */
  lastShownAt?: number;
  /** The user picked "Sign in and connect" once; never shown again. */
  done?: boolean;
}

/** The globalState key the nudge state lives under. */
export const NUDGE_STATE_KEY = 'observer.connect.nudge';

/** The nudge returns this long after "Later" (Getting started v2). */
export const NUDGE_REPEAT_MS = 7 * 24 * 60 * 60 * 1000;

/** First activation plus one return; never more. */
export const NUDGE_MAX_SHOWS = 2;

/** The notification text and its buttons. */
export const NUDGE_TEXT =
  'SuperBased Observer is running and capturing your AI sessions. Sign in to see all your machines online and join your team.';
export const NUDGE_SIGN_IN = 'Sign in and connect';
export const NUDGE_DASHBOARD = 'Open dashboard';
export const NUDGE_LATER = 'Later';

interface NudgeInput {
  state: NudgeState;
  status: ConnectStatus | null;
  now: number;
}

interface NudgeRule {
  name: string;
  when: (i: NudgeInput) => boolean;
  show: boolean;
}

/**
 * NUDGE_RULES decide the nudge, top-down; the first matching row wins. One
 * test case per row (test/unit/connect.test.ts). Every unknown reads as
 * "do not show": the nudge never nags on a guess.
 */
export const NUDGE_RULES: readonly NudgeRule[] = [
  { name: 'status unknown', when: (i) => i.status === null, show: false },
  { name: 'set by company', when: (i) => i.status!.locked, show: false },
  { name: 'sign-in state unreadable', when: (i) => !i.status!.identity_known, show: false },
  { name: 'signed in', when: (i) => i.status!.signed_in, show: false },
  { name: 'machine connected', when: (i) => isConnected(i.status!), show: false },
  { name: 'user chose sign in', when: (i) => i.state.done === true, show: false },
  { name: 'shown enough', when: (i) => i.state.shown >= NUDGE_MAX_SHOWS, show: false },
  { name: 'first activation', when: (i) => i.state.shown === 0, show: true },
  {
    name: 'seven days after later',
    when: (i) => i.state.lastShownAt === undefined || i.now - i.state.lastShownAt >= NUDGE_REPEAT_MS,
    show: true,
  },
  { name: 'within seven days of later', when: () => true, show: false },
];

/** decideNudge walks NUDGE_RULES and names the row that decided. */
export function decideNudge(state: NudgeState | undefined, status: ConnectStatus | null, now: number): { show: boolean; rule: string } {
  const input: NudgeInput = { state: state ?? { shown: 0 }, status, now };
  for (const r of NUDGE_RULES) {
    if (r.when(input)) return { show: r.show, rule: r.name };
  }
  return { show: false, rule: 'no rule' };
}

/** nudgeShown is the state after the notification appears. */
export function nudgeShown(state: NudgeState | undefined, now: number): NudgeState {
  const s = state ?? { shown: 0 };
  return { ...s, shown: s.shown + 1, lastShownAt: now };
}

// --- the status bar item ----------------------------------------------------------------

/** What clicking the item does. */
export type ConnectItemAction = { kind: 'connect' } | { kind: 'open'; url: string } | { kind: 'dashboard' };

/** What the item shows. */
export interface ConnectItemModel {
  visible: boolean;
  text: string;
  tooltip: string;
  action: ConnectItemAction;
}

/** What the last successful run reported, kept for daemons that do not serve it. */
export interface RememberedTarget {
  displayName?: string;
  kind?: string;
  onlineUrl?: string;
}

/** The globalState key the remembered target lives under. */
export const REMEMBERED_TARGET_KEY = 'observer.connect.lastTarget';

const HIDDEN_ITEM: ConnectItemModel = { visible: false, text: '', tooltip: '', action: { kind: 'dashboard' } };

/**
 * connectItem decides the account item. Hidden while the state is unknown.
 * Not signed in: click signs in and connects. Connected: shows the target's
 * name and opens its online dashboard (the local one when no safe URL is
 * known). Signed in only: click connects.
 */
export function connectItem(st: ConnectStatus | null, remembered?: RememberedTarget): ConnectItemModel {
  if (!st) return HIDDEN_ITEM;
  if (st.locked || isConnected(st)) {
    const kind = st.kind === 'managed' ? 'team' : 'personal';
    const name = safeDisplayName(st.display_name || st.destination || remembered?.displayName, kind);
    const url = [st.online_url, remembered?.onlineUrl].find((u) => isSafeOpenURL(u));
    return {
      visible: true,
      text: `$(account) SuperBased · ${name}`,
      tooltip: url
        ? `This machine is connected to ${name}. Click to open the online dashboard.`
        : `This machine is connected to ${name}. Click to open the dashboard.`,
      action: url ? { kind: 'open', url } : { kind: 'dashboard' },
    };
  }
  if (!st.identity_known) return HIDDEN_ITEM;
  if (st.signed_in) {
    return {
      visible: true,
      text: '$(account) SuperBased · signed in',
      tooltip: 'Signed in. This machine is not connected yet. Click to connect it.',
      action: { kind: 'connect' },
    };
  }
  return {
    visible: true,
    text: '$(account) SuperBased · not signed in',
    tooltip: 'Click to sign in and connect this machine. SuperBased keeps working locally without an account.',
    action: { kind: 'connect' },
  };
}
