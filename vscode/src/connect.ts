// "SuperBased: Sign in and connect" (Getting started v2, lane 5).
//
// Runs `observer connect --json --no-browser [team]` with the extension's
// resolved binary (contract B/D), opens the approval page with
// vscode.env.openExternal, shows "Waiting for approval in your browser, code
// KTRW-4821" with Cancel, and reports Connected / Signed in only / errors in
// plain words. The consent is shown on the browser approval page, never here;
// the extension sends nothing itself.
//
// One run at a time: a second invocation while one waits says so and offers
// to reopen the approval page. The pure halves (argv, line parsing, wording,
// URL checks) live in connect-internals.ts.

import * as vscode from 'vscode';
import { spawn } from 'node:child_process';
import type { ResolvedBinary } from './binary';
import { output } from './output';
import {
  REMEMBERED_TARGET_KEY,
  SIGNED_IN_ONLY_TEXT,
  connectedText,
  errorText,
  isSafeOpenURL,
  normalizeTeam,
  progressMessage,
  runConnectProcess,
  validateTeam,
  type ConnectEvent,
  type ConnectOutcome,
  type RememberedTarget,
} from './connect-internals';

/** The command ids this file registers. */
export const CONNECT_COMMAND = 'observer.connect';
export const CONNECT_TEAM_COMMAND = 'observer.connectTeam';

/** Options a caller may pass to the connect command. */
export interface ConnectCommandArgs {
  /** A team name to preselect on the approval page. */
  team?: string;
}

/** ConnectController owns the one running sign-in and its listeners. */
export class ConnectController implements vscode.Disposable {
  private running: Thenable<ConnectOutcome> | undefined;
  private lastWaiting: { approveUrl: string; verifyUrl: string; userCode: string } | undefined;
  private readonly _onDidFinish = new vscode.EventEmitter<ConnectOutcome>();
  /** Fires after every run, so the status bar re-reads the daemon. */
  readonly onDidFinish = this._onDidFinish.event;

  constructor(
    private readonly ctx: vscode.ExtensionContext,
    private readonly bin: ResolvedBinary,
  ) {}

  /** register adds both commands to the context. */
  register(): void {
    this.ctx.subscriptions.push(
      vscode.commands.registerCommand(CONNECT_COMMAND, (args?: ConnectCommandArgs) => this.command(args)),
      vscode.commands.registerCommand(CONNECT_TEAM_COMMAND, async () => {
        const team = await askTeam();
        if (team) await this.run(team);
      }),
      this,
    );
  }

  /** remembered is what the last successful run reported. */
  remembered(): RememberedTarget | undefined {
    return this.ctx.globalState.get<RememberedTarget>(REMEMBERED_TARGET_KEY);
  }

  private async command(args?: ConnectCommandArgs): Promise<void> {
    await this.run(typeof args?.team === 'string' ? args.team : undefined);
  }

  /** run starts one sign-in, or points at the one already waiting. */
  async run(team: string | undefined): Promise<ConnectOutcome | undefined> {
    if (this.running) {
      const w = this.lastWaiting;
      const reopen = 'Open approval page';
      const picked = await vscode.window.showInformationMessage(
        w?.userCode
          ? `SuperBased is already waiting for approval in your browser, code ${w.userCode}.`
          : 'SuperBased is already signing in.',
        ...(w ? [reopen] : []),
      );
      if (picked === reopen && w) await openApproval(w.approveUrl, w.verifyUrl, w.userCode);
      return undefined;
    }
    const outcome = vscode.window.withProgress(
      { location: vscode.ProgressLocation.Notification, title: 'SuperBased', cancellable: true },
      (progress, token) => this.runWithProgress(team, progress, token),
    );
    this.running = outcome;
    let result: ConnectOutcome;
    try {
      result = await outcome;
    } finally {
      // Cleared before reporting, so "Try again" can start a new run.
      this.running = undefined;
      this.lastWaiting = undefined;
    }
    await this.remember(result);
    this._onDidFinish.fire(result);
    await this.report(result, team);
    return result;
  }

  /** remember keeps what a run reported, for daemons that do not serve it. */
  private async remember(result: ConnectOutcome): Promise<void> {
    if (result.kind === 'connected') {
      const remembered: RememberedTarget = {
        displayName: result.displayName,
        kind: result.targetKind,
        onlineUrl: isSafeOpenURL(result.onlineUrl) ? result.onlineUrl : undefined,
      };
      await this.ctx.globalState.update(REMEMBERED_TARGET_KEY, remembered);
    } else if (result.kind === 'signed_in_only') {
      await this.ctx.globalState.update(REMEMBERED_TARGET_KEY, undefined);
    }
  }

  private async runWithProgress(
    team: string | undefined,
    progress: vscode.Progress<{ message?: string }>,
    token: vscode.CancellationToken,
  ): Promise<ConnectOutcome> {
    progress.report({ message: 'Starting sign-in...' });
    const abort = new AbortController();
    const sub = token.onCancellationRequested(() => abort.abort());
    output.appendLine(`Sign in and connect: running ${this.bin.path} connect${team ? ` (team ${normalizeTeam(team)})` : ''}`);
    try {
      return await runConnectProcess(this.bin.path, team, {
        spawn: (file, args) => spawn(file, args, { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] }),
        signal: abort.signal,
        onLog: (line) => output.appendLine(`observer connect: ${line}`),
        onEvent: (ev) => this.onEvent(ev, progress),
      });
    } finally {
      sub.dispose();
    }
  }

  private onEvent(ev: ConnectEvent, progress: vscode.Progress<{ message?: string }>): void {
    output.appendLine(`observer connect: state ${ev.state}`);
    const message = progressMessage(ev);
    if (message) progress.report({ message });
    if (ev.state === 'waiting_approval' && !this.lastWaiting) {
      this.lastWaiting = { approveUrl: ev.approve_url, verifyUrl: ev.verify_url, userCode: ev.user_code };
      void openApproval(ev.approve_url, ev.verify_url, ev.user_code);
    }
  }

  private async report(result: ConnectOutcome, team: string | undefined): Promise<void> {
    switch (result.kind) {
      case 'connected': {
        const url = isSafeOpenURL(result.onlineUrl) ? result.onlineUrl : undefined;
        const open = 'Open online dashboard';
        const picked = await vscode.window.showInformationMessage(
          connectedText(result.displayName, result.targetKind),
          ...(url ? [open] : []),
        );
        if (picked === open && url) await vscode.env.openExternal(vscode.Uri.parse(url));
        return;
      }
      case 'signed_in_only': {
        const connect = 'Connect this machine';
        const picked = await vscode.window.showInformationMessage(SIGNED_IN_ONLY_TEXT, connect);
        if (picked === connect) await this.run(team);
        return;
      }
      case 'cancelled':
        output.appendLine('Sign in and connect: cancelled. Nothing was sent.');
        return;
      case 'error': {
        output.appendLine(`Sign in and connect failed: ${result.code} ${result.message}`.trim());
        const retry = 'Try again';
        const details = 'Show details';
        const picked = await vscode.window.showErrorMessage(`SuperBased: ${errorText(result.code, result.message)}`, retry, details);
        if (picked === retry) await this.run(team);
        else if (picked === details) output.show(true);
        return;
      }
    }
  }

  dispose(): void {
    this._onDidFinish.dispose();
  }
}

/** askTeam asks for a team name; undefined when the user backs out. */
async function askTeam(): Promise<string | undefined> {
  const raw = await vscode.window.showInputBox({
    title: 'SuperBased: Connect to a team',
    prompt: 'The team name your admin gave you, like acme-dev.',
    placeHolder: 'team name',
    ignoreFocusOut: true,
    validateInput: (v) => (v.trim() === '' ? undefined : validateTeam(v)),
  });
  if (raw === undefined) return undefined;
  const team = normalizeTeam(raw);
  if (validateTeam(team) !== undefined) return undefined;
  return team;
}

/**
 * openApproval opens the approval page. When the browser cannot be opened
 * (a remote session with no browser, or a URL that fails the check), it
 * offers the code-entry page and the code instead.
 */
async function openApproval(approveUrl: string, verifyUrl: string, userCode: string): Promise<void> {
  let opened = false;
  if (isSafeOpenURL(approveUrl)) {
    try {
      opened = await vscode.env.openExternal(vscode.Uri.parse(approveUrl));
    } catch (err) {
      output.appendLine(`Sign in and connect: could not open the browser: ${(err as Error).message}`);
    }
  } else {
    output.appendLine('Sign in and connect: the approval address was not a safe https address, so it was not opened.');
  }
  if (opened) return;
  const copy = 'Copy code';
  const openVerify = 'Open code page';
  const buttons = isSafeOpenURL(verifyUrl) ? [openVerify, copy] : [copy];
  const picked = await vscode.window.showInformationMessage(
    `Open the SuperBased connect page in any browser and enter code ${userCode || '(see the SuperBased output)'}.`,
    ...buttons,
  );
  if (picked === copy && userCode) await vscode.env.clipboard.writeText(userCode);
  else if (picked === openVerify) await vscode.env.openExternal(vscode.Uri.parse(verifyUrl));
}
