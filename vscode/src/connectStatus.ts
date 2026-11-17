// The account status bar item and the first-run nudge (Getting started v2,
// lane 5).
//
// Both read the daemon's GET /api/connect/status (internal/frontdoor.Status),
// so a signed-in or connected machine is never nagged:
//
//   - the item shows "SuperBased · not signed in" (click: sign in and
//     connect) or "SuperBased · <name>" (click: the online dashboard, else the
//     local one);
//   - the notification appears on first activation and once more 7 days after
//     "Later", only while not signed in and not connected, never more. It is
//     never modal and never blocks anything.
//
// Probes on activation and on every daemon state change, then polls at the
// cost bar's cadence (never faster). The rules are in connect-internals.ts.

import * as vscode from 'vscode';
import type { DaemonManager } from './daemon';
import type { StatusBarController } from './status/costBar';
import { output } from './output';
import { CONNECT_COMMAND, type ConnectController } from './connect';
import {
  CONNECT_STATUS_PATH,
  CONNECT_STATUS_POLL_MS,
  NUDGE_DASHBOARD,
  NUDGE_LATER,
  NUDGE_SIGN_IN,
  NUDGE_STATE_KEY,
  NUDGE_TEXT,
  connectItem,
  decideNudge,
  fetchConnectStatus,
  nudgeShown,
  type ConnectItemAction,
  type ConnectStatus,
  type NudgeState,
} from './connect-internals';

const FIRST_PROBE_DELAY_MS = 2_000;
const REQUEST_TIMEOUT_MS = 5_000;
const ITEM_COMMAND = 'observer.accountStatus';

/**
 * createConnectStatus creates the account item and arms the nudge. The item
 * sits left of the today-spend item (priority 101 > 100).
 */
export function createConnectStatus(
  ctx: vscode.ExtensionContext,
  daemon: DaemonManager,
  connect: ConnectController,
): StatusBarController {
  const item = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 101);
  item.name = 'SuperBased: Account';
  item.command = ITEM_COMMAND;
  item.hide();
  ctx.subscriptions.push(item);

  let action: ConnectItemAction = { kind: 'connect' };
  let timer: NodeJS.Timeout | undefined;
  let disposed = false;
  let nudgeChecked = false;

  const read = async (): Promise<ConnectStatus | null> => {
    if (daemon.getState().status === 'idle') return null;
    try {
      return await fetchConnectStatus(daemon.getClient().url(CONNECT_STATUS_PATH), fetch, REQUEST_TIMEOUT_MS);
    } catch (err) {
      output.appendLine(`Account status poll failed: ${(err as Error).message}`);
      return null;
    }
  };

  const refresh = async (): Promise<void> => {
    if (disposed) return;
    const st = await read();
    const model = connectItem(st, connect.remembered());
    action = model.action;
    if (!model.visible) {
      item.hide();
    } else {
      item.text = model.text;
      item.tooltip = model.tooltip;
      item.show();
    }
    if (st && !nudgeChecked) {
      nudgeChecked = true; // once per activation, and only after a real read
      void maybeNudge(ctx, st);
    }
  };

  ctx.subscriptions.push(
    vscode.commands.registerCommand(ITEM_COMMAND, async () => {
      switch (action.kind) {
        case 'open':
          await vscode.env.openExternal(vscode.Uri.parse(action.url));
          return;
        case 'dashboard':
          await vscode.commands.executeCommand('observer.openDashboard');
          return;
        case 'connect':
          await vscode.commands.executeCommand(CONNECT_COMMAND);
          return;
      }
    }),
    daemon.onDidChangeState(() => void refresh()),
    connect.onDidFinish(() => void refresh()),
  );

  timer = setTimeout(async function tick() {
    await refresh();
    if (!disposed) timer = setTimeout(tick, CONNECT_STATUS_POLL_MS);
  }, FIRST_PROBE_DELAY_MS);

  return {
    refresh,
    dispose: () => {
      disposed = true;
      if (timer) clearTimeout(timer);
      item.dispose();
    },
  };
}

/** maybeNudge shows the notification when the rule table says so. */
async function maybeNudge(ctx: vscode.ExtensionContext, st: ConnectStatus): Promise<void> {
  const state = ctx.globalState.get<NudgeState>(NUDGE_STATE_KEY);
  const now = Date.now();
  const decision = decideNudge(state, st, now);
  if (!decision.show) {
    output.appendLine(`Sign-in suggestion not shown: ${decision.rule}`);
    return;
  }
  // Record the show before awaiting the choice: a window closed mid-choice
  // still counts, so the nudge can never come back sooner than 7 days.
  const shown = nudgeShown(state, now);
  await ctx.globalState.update(NUDGE_STATE_KEY, shown);
  const picked = await vscode.window.showInformationMessage(NUDGE_TEXT, NUDGE_SIGN_IN, NUDGE_DASHBOARD, NUDGE_LATER);
  if (picked === NUDGE_SIGN_IN) {
    await ctx.globalState.update(NUDGE_STATE_KEY, { ...shown, done: true });
    await vscode.commands.executeCommand(CONNECT_COMMAND);
  } else if (picked === NUDGE_DASHBOARD) {
    await vscode.commands.executeCommand('observer.openDashboard');
  }
  // Later, Open dashboard and closing it all leave the 7-day return armed.
}
