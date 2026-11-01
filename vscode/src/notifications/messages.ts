// Admin message controller (admin and developer messaging, T-854). Polls
// /api/messages/summary every 60s while the daemon runs. When the developer
// kept the VS Code surface on ([messages] vscode, default on), a newly
// arrived admin message raises one notification (a warning for an alert)
// with Open, Acknowledge (only when the message asked for one) and Later,
// and a status bar item reads "N from admin" while anything is unread.
//
// Dedup follows decide.ts: the org's message id only grows, so the newest
// announced id is kept in globalState and a message is announced once. The
// decision logic is pure (decideAdminMessage / messagesStatusText) and unit
// tested; this file is the vscode glue.

import * as vscode from 'vscode';
import type { DaemonManager } from '../daemon';
import { output } from '../output';
import type { MessagesSummaryResponse } from '../api/types';
import { decideAdminMessage, messagesStatusText } from './decide';

const POLL_MS = 60 * 1000;
const FIRST_PROBE_MS = 10 * 1000;
const STATE_KEY = 'observer.messages.lastNotifiedId';

/** OPEN_MESSAGES_COMMAND opens the dashboard on /messages (optionally one thread). */
export const OPEN_MESSAGES_COMMAND = 'observer.openMessages';

export class AdminMessagesNotifier implements vscode.Disposable {
  private timer: NodeJS.Timeout | undefined;
  private disposed = false;
  private polling = false;
  private readonly item: vscode.StatusBarItem;
  private readonly disposables: vscode.Disposable[] = [];

  constructor(
    private readonly ctx: vscode.ExtensionContext,
    private readonly daemon: DaemonManager,
  ) {
    this.item = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 98);
    this.item.name = 'SuperBased: messages from your admin';
    this.item.command = { title: 'Open messages', command: OPEN_MESSAGES_COMMAND, arguments: [] };
    this.disposables.push(
      this.item,
      this.daemon.onDidChangeState(() => {
        if (this.daemon.getState().status === 'idle') this.item.hide();
        else void this.poll();
      }),
    );
  }

  start(): void {
    this.timer = setTimeout(() => this.tick(), FIRST_PROBE_MS);
  }

  private async tick(): Promise<void> {
    if (this.disposed) return;
    await this.poll();
    if (!this.disposed) this.timer = setTimeout(() => this.tick(), POLL_MS);
  }

  private async poll(): Promise<void> {
    if (this.polling || this.daemon.getState().status === 'idle') return;
    this.polling = true;
    try {
      let data: MessagesSummaryResponse;
      try {
        data = await this.daemon.getClient().messagesSummary();
      } catch (err) {
        // An older daemon (404) or a stopped one: no item, no toast, one log line.
        this.item.hide();
        output.appendLine(`Messages poll failed: ${(err as Error).message}`);
        return;
      }
      this.renderStatus(data);
      const last = this.ctx.globalState.get<number>(STATE_KEY) ?? 0;
      const d = decideAdminMessage(data, last);
      if (d.seen !== last) await this.ctx.globalState.update(STATE_KEY, d.seen);
      if (d.fire && d.text && d.message) void this.announce(d.text, Boolean(d.warn), Boolean(d.canAck), d.message.thread_id, d.message.message_id);
    } finally {
      this.polling = false;
    }
  }

  private renderStatus(data: MessagesSummaryResponse): void {
    const text = messagesStatusText(data);
    if (!text) {
      this.item.hide();
      return;
    }
    const threadId = data.push?.newest?.thread_id;
    this.item.text = `$(mail) ${text}`;
    this.item.tooltip = 'Unread messages from your organization. Click to open them in the dashboard.';
    this.item.command = { title: 'Open messages', command: OPEN_MESSAGES_COMMAND, arguments: threadId ? [threadId] : [] };
    this.item.show();
  }

  private async announce(text: string, warn: boolean, canAck: boolean, threadId: string, messageId: number): Promise<void> {
    const actions = canAck ? ['Open', 'Acknowledge', 'Later'] : ['Open', 'Later'];
    const choice = warn
      ? await vscode.window.showWarningMessage(text, ...actions)
      : await vscode.window.showInformationMessage(text, ...actions);
    if (choice === 'Open') {
      void vscode.commands.executeCommand(OPEN_MESSAGES_COMMAND, threadId);
      return;
    }
    if (choice === 'Acknowledge') {
      try {
        await this.daemon.getClient().ackMessage(messageId);
        void vscode.window.showInformationMessage('Acknowledged. Your admin can see that you have seen it.');
        void this.poll();
      } catch (err) {
        output.appendLine(`Acknowledge failed: ${(err as Error).message}`);
        // Fall back to the dashboard, where the Acknowledge bar does the same.
        void vscode.commands.executeCommand(OPEN_MESSAGES_COMMAND, threadId);
      }
    }
  }

  dispose(): void {
    this.disposed = true;
    if (this.timer) {
      clearTimeout(this.timer);
      this.timer = undefined;
    }
    while (this.disposables.length) {
      try {
        this.disposables.pop()?.dispose();
      } catch {
        /* best effort */
      }
    }
  }
}

