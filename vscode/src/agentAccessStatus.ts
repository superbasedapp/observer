// "MCP access" status bar item (Agent Access P10, doc3 §15 "VS Code").
//
// Reads GET /api/mcp-access/status from the local daemon - the same payload
// behind the dashboard Security page's "MCP access" section, whose `status`
// is the `observer mcp status --json` body. Shows the approved-server count
// with the relay's health; the tooltip carries relay state, coverage
// summary and effective state. Click -> a quick pick with per-server state
// and a Connect action that opens the ORG dashboard's My Connections page
// (the `observer mcp connect` URL; R-S3-1).
//
// Inert and hidden when the daemon has no route, the relay is disabled, or
// the node is not enrolled. Probes on activation and on every daemon state
// change, then polls at the cost bar's cadence (never faster).

import * as vscode from 'vscode';
import type { DaemonManager } from './daemon';
import type { StatusBarController } from './status/costBar';
import { output } from './output';
import {
  MCP_ACCESS_PATH,
  MCP_ACCESS_POLL_MS,
  agentAccessItem,
  agentAccessQuickPick,
  fetchAgentAccessStatus,
  type AgentAccessResponse,
  type AgentAccessView,
} from './agentAccessStatus-internals';

const FIRST_PROBE_DELAY_MS = 1_500;
const REQUEST_TIMEOUT_MS = 5_000;
const COMMAND_ID = 'observer.mcpAccess';

export function createAgentAccessStatusBar(
  ctx: vscode.ExtensionContext,
  daemon: DaemonManager,
): StatusBarController {
  // Sits left of the cache item (priority 98 < 99 < 100).
  const item = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 98);
  item.name = 'SuperBased: MCP access';
  item.command = COMMAND_ID;
  item.hide();
  ctx.subscriptions.push(item);

  let last: AgentAccessView | undefined;
  let hiddenReason = '';
  let timer: NodeJS.Timeout | undefined;
  let disposed = false;

  const refresh = async (): Promise<void> => {
    if (disposed) return;
    if (daemon.getState().status === 'idle') {
      last = undefined;
      item.hide();
      return;
    }
    let resp: AgentAccessResponse | null;
    try {
      resp = await fetchAgentAccessStatus(daemon.getClient().url(MCP_ACCESS_PATH), fetch, REQUEST_TIMEOUT_MS);
    } catch (err) {
      output.appendLine(`MCP access status poll failed: ${(err as Error).message}`);
      last = undefined;
      item.hide(); // the cost item already surfaces daemon trouble
      return;
    }
    const model = agentAccessItem(resp);
    if (!model.visible) {
      if (model.hiddenReason && model.hiddenReason !== hiddenReason) {
        output.appendLine(`MCP access status item hidden: ${model.hiddenReason}`);
      }
      hiddenReason = model.hiddenReason ?? '';
      last = undefined;
      item.hide();
      return;
    }
    hiddenReason = '';
    last = resp as AgentAccessView;
    item.text = model.text;
    const md = new vscode.MarkdownString(model.tooltip.join('\n'));
    md.supportThemeIcons = true;
    item.tooltip = md;
    item.backgroundColor = model.warning ? new vscode.ThemeColor('statusBarItem.warningBackground') : undefined;
    item.show();
  };

  const showPick = async (): Promise<void> => {
    await refresh();
    if (!last) {
      void vscode.window.showInformationMessage(
        `SuperBased: MCP access is not active on this machine${hiddenReason ? ` (${hiddenReason})` : ''}.`,
      );
      return;
    }
    const entries = agentAccessQuickPick(last);
    const picked = await vscode.window.showQuickPick(
      entries.map((e) => ({ label: e.label, description: e.description, detail: e.detail, entry: e })),
      { title: 'SuperBased: MCP access', placeHolder: 'Approved MCP servers on this machine', matchOnDescription: true },
    );
    if (!picked) return;
    const action = picked.entry.action;
    if (action.kind === 'connect') {
      await vscode.env.openExternal(vscode.Uri.parse(action.url));
    } else if (action.kind === 'dashboard') {
      await vscode.commands.executeCommand('observer.openDashboard');
    }
  };
  ctx.subscriptions.push(vscode.commands.registerCommand(COMMAND_ID, showPick));

  timer = setTimeout(async function tick() {
    await refresh();
    if (!disposed) timer = setTimeout(tick, MCP_ACCESS_POLL_MS);
  }, FIRST_PROBE_DELAY_MS);
  ctx.subscriptions.push(daemon.onDidChangeState(() => void refresh()));

  return {
    refresh,
    dispose: () => {
      disposed = true;
      if (timer) clearTimeout(timer);
      item.dispose();
    },
  };
}
