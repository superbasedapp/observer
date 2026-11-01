import * as vscode from 'vscode';
import type { DaemonManager } from '../daemon';
import { DashboardPanel } from '../webview/dashboard';
import { messagesRoute } from '../notifications/decide';

export function registerLifecycle(
  ctx: vscode.ExtensionContext,
  daemon: DaemonManager,
): vscode.Disposable[] {
  const disposables: vscode.Disposable[] = [
    vscode.commands.registerCommand('observer.start', async () => {
      await daemon.start();
    }),
    vscode.commands.registerCommand('observer.stop', async () => {
      await daemon.stop();
    }),
    vscode.commands.registerCommand('observer.openDashboard', () => {
      DashboardPanel.createOrShow(daemon);
    }),
    // Walkthrough "Choose components" (modular packaging plan 7.1): the
    // dashboard's Settings > Components page in the same panel.
    vscode.commands.registerCommand('observer.openComponents', () => {
      DashboardPanel.createOrShow(daemon, '/settings/components');
    }),
    // Messages from the organization's admins (T-854): the notification's
    // Open and the "N from admin" status bar item land on the conversation.
    vscode.commands.registerCommand('observer.openMessages', (threadId?: unknown) => {
      DashboardPanel.createOrShow(daemon, messagesRoute(typeof threadId === 'string' ? threadId : undefined));
    }),
  ];
  ctx.subscriptions.push(...disposables);
  return disposables;
}
