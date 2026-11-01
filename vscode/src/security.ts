// Code security diagnostics (security pillar plan section 6.1, lane
// sec-c3): Problems-panel diagnostics for the open findings in open files,
// a status-bar count, and the command "Observer: Show code security
// findings". Polls GET /api/security/editor for each workspace folder.
// Hidden, and never polled, while the `security` component is not active
// (the component gate) or observer.securityDiagnostics.enabled is false.
// Pure decisions live in security-internals.ts.

import * as path from 'node:path';
import * as vscode from 'vscode';
import type { DaemonManager } from './daemon';
import type { ComponentGate } from './components';
import { output } from './output';
import {
  planDiagnostics,
  quickPickLabel,
  relativeTo,
  statusLabel,
  type DiagPlan,
  type DiagSeverity,
  type SecurityEditorFinding,
} from './security-internals';

const POLL_MS = 30_000;
const FIRST_PROBE_DELAY_MS = 2_000;

/** The component the surface belongs to. */
const SECURITY_COMPONENT = 'security';

const SEVERITY: Readonly<Record<DiagSeverity, vscode.DiagnosticSeverity>> = {
  error: vscode.DiagnosticSeverity.Error,
  warning: vscode.DiagnosticSeverity.Warning,
  information: vscode.DiagnosticSeverity.Information,
  hint: vscode.DiagnosticSeverity.Hint,
};

/** One workspace folder's last answer. */
interface FolderState {
  root: string;
  plan: Map<string, DiagPlan[]>;
  findings: SecurityEditorFinding[];
}

export function registerSecurityDiagnostics(
  ctx: vscode.ExtensionContext,
  daemon: DaemonManager,
  gate: Pick<ComponentGate, 'componentInactive'>,
): void {
  const cfg = vscode.workspace.getConfiguration('observer');
  if (!cfg.get<boolean>('securityDiagnostics.enabled', true)) {
    output.appendLine('Code security diagnostics disabled by observer.securityDiagnostics.enabled');
    return;
  }
  const collection = vscode.languages.createDiagnosticCollection('observer-security');
  const item = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 98);
  item.name = 'SuperBased: Code security';
  item.command = 'observer.showSecurityFindings';
  item.hide();
  ctx.subscriptions.push(collection, item);

  let folders: FolderState[] = [];
  let timer: NodeJS.Timeout | undefined;
  let disposed = false;

  const publish = (doc: vscode.TextDocument): void => {
    if (doc.uri.scheme !== 'file') return;
    for (const f of folders) {
      const rel = relativeTo(f.root, doc.uri.fsPath);
      if (!rel) continue;
      const plans = f.plan.get(rel) ?? [];
      collection.set(
        doc.uri,
        plans.map((p) => {
          const line = Math.min(p.line, Math.max(0, doc.lineCount - 1));
          const d = new vscode.Diagnostic(doc.lineAt(line).range, p.message, SEVERITY[p.severity]);
          d.source = 'Observer code security';
          d.code = p.code;
          return d;
        }),
      );
      return;
    }
  };

  const render = (): void => {
    collection.clear();
    for (const doc of vscode.workspace.textDocuments) publish(doc);
    const count = folders.reduce((n, f) => n + f.findings.length, 0);
    if (count === 0) {
      item.hide();
      return;
    }
    item.text = statusLabel(count);
    item.tooltip = 'Open code security findings in this workspace. Click to list them.';
    item.show();
  };

  const clear = (): void => {
    folders = [];
    collection.clear();
    item.hide();
  };

  const refresh = async (): Promise<void> => {
    if (disposed) return;
    if (daemon.getState().status === 'idle' || gate.componentInactive(SECURITY_COMPONENT)) {
      clear();
      return;
    }
    const next: FolderState[] = [];
    for (const wf of vscode.workspace.workspaceFolders ?? []) {
      if (wf.uri.scheme !== 'file') continue;
      try {
        const resp = await daemon.getClient().securityEditor(wf.uri.fsPath);
        const findings = resp.findings ?? [];
        next.push({ root: path.resolve(resp.project_root || wf.uri.fsPath), plan: planDiagnostics(findings), findings });
      } catch (err) {
        // An older daemon without the route, the module compiled out, or a
        // failed read: show nothing for this folder rather than stale rows.
        output.appendLine(`Code security feed unavailable for ${wf.name}: ${(err as Error).message}`);
      }
    }
    folders = next;
    render();
  };

  ctx.subscriptions.push(
    vscode.workspace.onDidOpenTextDocument(publish),
    vscode.workspace.onDidCloseTextDocument((doc) => collection.delete(doc.uri)),
    vscode.workspace.onDidChangeWorkspaceFolders(() => void refresh()),
    daemon.onDidChangeState(() => void refresh()),
    vscode.commands.registerCommand('observer.showSecurityFindings', async () => {
      await refresh();
      const rows = folders.flatMap((f) => f.findings.map((x) => ({ ...quickPickLabel(x), root: f.root, finding: x })));
      if (rows.length === 0) {
        void vscode.window.showInformationMessage('SuperBased: no open code security findings in this workspace.');
        return;
      }
      const pick = await vscode.window.showQuickPick(rows, { placeHolder: 'Open code security findings', matchOnDescription: true });
      if (!pick) return;
      const uri = vscode.Uri.file(path.join(pick.root, ...pick.finding.rel_path.split('/')));
      const line = Math.max(0, (pick.finding.start_line || 1) - 1);
      await vscode.window.showTextDocument(uri, { selection: new vscode.Range(line, 0, line, 0) });
    }),
    {
      dispose: () => {
        disposed = true;
        if (timer) clearTimeout(timer);
      },
    },
  );

  timer = setTimeout(async function tick() {
    await refresh();
    if (!disposed) timer = setTimeout(tick, POLL_MS);
  }, FIRST_PROBE_DELAY_MS);
}
