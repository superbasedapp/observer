// "SuperBased: Turn on AI Apps" (first-run plan revision 2, section 4.4;
// lane POLISH-F2): the command-palette action and walkthrough step that
// call the daemon's one AI Apps enable seam. The flow and every message are
// in apps-internals.ts (pure, unit-tested); this file is the vscode glue.

import * as vscode from 'vscode';
import type { DaemonManager } from './daemon';
import { output } from './output';
import { DashboardPanel } from './webview/dashboard';
import { APPS_ROUTE, NO_DAEMON, runEnable, type AppsOutcome } from './apps-internals';

const OPEN_APPS = 'Open AI Apps';
const START = 'Start Daemon';

/** registerAppsOn registers observer.appsOn. */
export function registerAppsOn(ctx: vscode.ExtensionContext, daemon: DaemonManager): void {
  ctx.subscriptions.push(
    vscode.commands.registerCommand('observer.appsOn', async () => {
      const outcome = await turnOnAiApps(daemon);
      if (outcome) await show(outcome, daemon);
    }),
  );
}

/** turnOnAiApps runs the flow against the daemon the extension uses. */
async function turnOnAiApps(daemon: DaemonManager): Promise<AppsOutcome | undefined> {
  if (daemon.getState().status === 'idle') return NO_DAEMON;
  const client = daemon.getClient();
  try {
    return await vscode.window.withProgress(
      { location: vscode.ProgressLocation.Notification, title: 'SuperBased: turning on AI Apps' },
      () =>
        runEnable(
          { status: () => client.appsStatus(), enable: (token) => client.appsEnable(token) },
          async (text) => {
            const pick = await vscode.window.showInformationMessage(text, { modal: true }, 'Turn on');
            return pick === 'Turn on';
          },
        ),
    );
  } catch (err) {
    output.appendLine(`AI Apps enable failed: ${(err as Error).message}`);
    return {
      kind: 'failed',
      message: `AI Apps was not turned on: ${(err as Error).message}`,
      fix: 'Run `SuperBased: Doctor`, or open the dashboard and use its AI Apps button.',
      openApps: false,
    };
  }
}

/** show renders one outcome: info for on, an error with the fix otherwise. */
async function show(o: AppsOutcome, daemon: DaemonManager): Promise<void> {
  const text = o.fix ? `${o.message} ${o.fix}` : o.message;
  output.appendLine(`AI Apps: ${o.kind}: ${text}`);
  if (o.openApps) {
    if ((await vscode.window.showInformationMessage(text, OPEN_APPS)) === OPEN_APPS) {
      DashboardPanel.createOrShow(daemon, APPS_ROUTE);
    }
    return;
  }
  if (o.kind === 'no_daemon') {
    if ((await vscode.window.showWarningMessage(text, START)) === START) {
      await vscode.commands.executeCommand('observer.start');
    }
    return;
  }
  if (o.kind === 'restart') {
    await vscode.window.showWarningMessage(text);
    return;
  }
  await vscode.window.showErrorMessage(text);
}
