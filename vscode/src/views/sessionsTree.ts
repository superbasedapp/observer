// Sessions TreeView — backed by /api/sessions?limit=20.
//
// Each row's TreeItem carries the SessionRow in `metadata` so the
// openSession / copySessionId commands can read the id without
// re-fetching. Refreshes every 60s and on workspace save.

import * as vscode from 'vscode';
import type { DaemonManager } from '../daemon';
import type { SessionRow } from '../api/types';
import { output } from '../output';
import { basename, formatDuration, formatUSD } from './format';
import { TreePoller, TreeStatus, makePlaceholder } from './treeBase';

const POLL_MS = 60_000;
const LIMIT = 20;

export class SessionItem extends vscode.TreeItem {
  constructor(public readonly row: SessionRow) {
    const project = basename(row.project) || row.project || '(no project)';
    const defaultLabel = `${row.tool} · ${project}`;
    const stats = `${formatUSD(row.cost_usd)} · ${formatDuration(row.duration_seconds)} · ${row.total_actions} actions`;
    // Effective title: the developer's own title (migration 116) wins over
    // the AI/cloud-suggested one, which wins over the plain tool/project
    // label. When a title is shown, the label it replaced moves into the
    // description (ahead of the existing cost/duration/actions stats)
    // instead of being dropped, so that information stays one glance away.
    const title = row.title || row.cloud_title || '';
    super(
      title || defaultLabel,
      vscode.TreeItemCollapsibleState.None,
    );
    this.description = title ? `${defaultLabel} · ${stats}` : stats;
    this.tooltip = buildSessionTooltip(row);
    this.contextValue = 'session';
    this.iconPath = new vscode.ThemeIcon(toolIcon(row.tool));
    this.command = {
      command: 'observer.openSession',
      title: 'Open Session in Dashboard',
      arguments: [this],
    };
  }
}

export class SessionsTreeProvider implements vscode.TreeDataProvider<vscode.TreeItem> {
  private readonly _onDidChangeTreeData = new vscode.EventEmitter<undefined>();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;
  private status: TreeStatus = { kind: 'loading' };
  private rows: SessionRow[] = [];
  private readonly poller: TreePoller;

  constructor(private readonly daemon: DaemonManager) {
    this.poller = new TreePoller(() => this.refreshNow(), POLL_MS);
  }

  start(ctx: vscode.ExtensionContext): void {
    this.poller.start();
    ctx.subscriptions.push(
      this.poller,
      this.daemon.onDidChangeState(() => this.refresh()),
      vscode.workspace.onDidSaveTextDocument(() => this.refresh()),
    );
  }

  refresh(): void {
    void this.refreshNow();
  }

  private async refreshNow(): Promise<void> {
    const state = this.daemon.getState();
    if (state.status === 'idle') {
      this.status = { kind: 'idle' };
      this.rows = [];
      this.fire();
      return;
    }
    try {
      const res = await this.daemon.getClient().sessions(LIMIT);
      this.rows = Array.isArray(res.rows) ? res.rows : [];
      this.status = this.rows.length === 0 ? { kind: 'empty' } : { kind: 'live' };
      this.fire();
    } catch (err) {
      output.appendLine(`Sessions tree poll failed: ${(err as Error).message}`);
      this.status = { kind: 'error', message: (err as Error).message };
      this.fire();
    }
  }

  private fire(): void {
    this._onDidChangeTreeData.fire(undefined);
  }

  getTreeItem(element: vscode.TreeItem): vscode.TreeItem {
    return element;
  }

  getChildren(): vscode.TreeItem[] {
    switch (this.status.kind) {
      case 'idle':
        return [
          makePlaceholder('Daemon not running', {
            command: { command: 'observer.start', title: 'Start Daemon' },
          }),
        ];
      case 'loading':
        return [makePlaceholder('Loading…')];
      case 'error':
        return [
          makePlaceholder('Failed to load — check Output channel', {
            tooltip: this.status.message,
          }),
        ];
      case 'empty':
        return [makePlaceholder('Run `observer scan` to backfill history')];
      case 'live':
        return this.rows.map((row) => new SessionItem(row));
    }
  }
}

function toolIcon(tool: string): string {
  switch (tool) {
    case 'claude-code':
    case 'cline':
    case 'cowork':
      return 'sparkle';
    case 'codex':
    case 'codex-cli':
      return 'rocket';
    case 'cursor':
      return 'edit';
    case 'copilot':
    case 'copilot-cli':
      return 'github';
    default:
      return 'circle-outline';
  }
}

function buildSessionTooltip(row: SessionRow): vscode.MarkdownString {
  const md = new vscode.MarkdownString();
  md.supportThemeIcons = true;
  const lines = [
    `**${row.tool}** — \`${row.id}\``,
    ...(row.title ? [`**Title**: ${row.title}`] : []),
    ...(!row.title && row.cloud_title ? [`**AI title**: ${row.cloud_title}`] : []),
    `**Project**: ${row.project || '(none)'}`,
    `**Cost**: ${formatUSD(row.cost_usd)} (${row.cost_reliability})`,
    `**Duration**: ${formatDuration(row.duration_seconds)}`,
    `**Actions**: ${row.total_actions}`,
    `**Models**: ${(row.models ?? []).join(', ') || '—'}`,
  ];
  md.appendMarkdown(lines.join('\n\n'));
  return md;
}
