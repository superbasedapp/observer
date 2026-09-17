import * as vscode from 'vscode';
import { resolveBinary } from './binary';
import { registerCommands } from './commands';
import { registerViewCommands } from './commands/views';
import { DaemonManager } from './daemon';
import type { DaemonMode } from './daemon-internals';
import { output } from './output';
import { registerInstructionFilesCodeLens } from './codelens/instructionFiles';
import { registerInstructionCommands } from './commands/instructions';
import { registerFileFreshness } from './decorations/fileFreshness';
import { BudgetNotifier } from './notifications/budget';
import { WatcherLagNotifier } from './notifications/watcherLag';
import { createCostStatusBar, StatusBarController } from './status/costBar';
import { createCacheStatusBar } from './status/cacheBar';
import { registerLocTracker } from './loc/tracker';
import { registerTerminalProfile } from './terminal/profile';
import { TodayTreeProvider } from './views/todayTree';
import { SessionsTreeProvider } from './views/sessionsTree';
import { DiscoveryTreeProvider } from './views/discoveryTree';
import { CostsTreeProvider } from './views/costsTree';
import { shouldDeferActivation, untrustedWorkspaceWarning } from './trust-internals';

let manager: DaemonManager | undefined;
let statusBar: StatusBarController | undefined;
let cacheStatusBar: StatusBarController | undefined;
let trustSubscription: vscode.Disposable | undefined;

export async function activate(ctx: vscode.ExtensionContext): Promise<void> {
  output.appendLine('SuperBased extension activating');

  // P1-5: refuse to resolve or spawn the observer binary in an untrusted
  // workspace. A cloned repo's .vscode/settings.json must never be able to
  // pick the executable this extension runs. observer.binary.path and
  // observer.binary.preferPathBinary are already machine-scoped and listed
  // in capabilities.untrustedWorkspaces.restrictedConfigurations
  // (package.json), so VS Code itself won't apply a workspace-level value
  // for them here — this is a defense-in-depth check that additionally
  // defers the whole daemon lifecycle (resolve/spawn/attach) until trust is
  // granted, rather than relying solely on the setting being ignored.
  if (shouldDeferActivation(vscode.workspace.isTrusted)) {
    const message = untrustedWorkspaceWarning();
    output.appendLine(message);
    void vscode.window.showWarningMessage(message);
    trustSubscription?.dispose();
    trustSubscription = vscode.workspace.onDidGrantWorkspaceTrust(() => {
      trustSubscription?.dispose();
      trustSubscription = undefined;
      output.appendLine('Workspace trust granted — resuming activation.');
      void activate(ctx);
    });
    ctx.subscriptions.push(trustSubscription);
    return;
  }

  try {
    const bin = await resolveBinary(ctx);
    output.appendLine(
      `Resolved binary: ${bin.path} (version ${bin.version}, source ${bin.source})`,
    );
    await ctx.globalState.update('observer.binaryPath', bin.path);

    const cfg = vscode.workspace.getConfiguration('observer');
    const mode = (cfg.get<string>('daemon.mode') ?? 'detect') as DaemonMode;
    manager = new DaemonManager({
      binary: bin,
      dashboardPort: cfg.get<number>('dashboard.port') ?? 8081,
      proxyPort: cfg.get<number>('proxy.port') ?? 8820,
      mode,
    });
    ctx.subscriptions.push(manager);
    output.appendLine(`Daemon mode: ${mode}`);
    await manager.reconcile();

    // Tell the daemon which extension version is running (enterprise update
    // management W5, ruling R6), so an org's fleet board can show
    // editor/daemon skew. AFTER reconcile, because before it there may be no
    // daemon listening; best-effort and never awaited into a failure path -
    // this is a report about the editor, not a feature the user asked for.
    void manager
      .getClient()
      .postExtensionVersion(ctx.extension.packageJSON.version ?? '')
      .then((ok) => {
        if (!ok) {
          output.appendLine(
            'Extension version not reported: the daemon has no /api/update/extension-version endpoint (older build, or update management is off).',
          );
        }
      });

    registerCommands(ctx, bin, manager);

    statusBar = createCostStatusBar(ctx, manager);
    if (statusBar) {
      ctx.subscriptions.push(statusBar);
    }

    cacheStatusBar = createCacheStatusBar(ctx, manager);
    if (cacheStatusBar) {
      ctx.subscriptions.push(cacheStatusBar);
    }

    const today = new TodayTreeProvider(manager);
    const sessions = new SessionsTreeProvider(manager);
    const discovery = new DiscoveryTreeProvider(manager);
    const costs = new CostsTreeProvider(manager);
    ctx.subscriptions.push(
      vscode.window.registerTreeDataProvider('observer.today', today),
      vscode.window.registerTreeDataProvider('observer.sessions', sessions),
      vscode.window.registerTreeDataProvider('observer.discovery', discovery),
      vscode.window.registerTreeDataProvider('observer.costs', costs),
    );
    today.start(ctx);
    sessions.start(ctx);
    discovery.start(ctx);
    costs.start(ctx);
    registerViewCommands(ctx, manager, { today, sessions, discovery, costs });

    registerTerminalProfile(ctx, manager);
    registerInstructionFilesCodeLens(ctx);
    registerInstructionCommands(ctx, bin);
    registerFileFreshness(ctx, manager);
    registerLocTracker(ctx, manager);

    const budget = new BudgetNotifier(ctx, manager);
    budget.start();
    ctx.subscriptions.push(budget);

    const watcherLag = new WatcherLagNotifier(manager);
    watcherLag.start();
    ctx.subscriptions.push(watcherLag);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    output.appendLine(`Activation failed: ${message}`);
    void vscode.window.showErrorMessage(`SuperBased: ${message}`);
    throw err;
  }
}

export function deactivate(): void {
  output.appendLine('SuperBased extension deactivating');
  statusBar?.dispose();
  statusBar = undefined;
  cacheStatusBar?.dispose();
  cacheStatusBar = undefined;
  manager?.dispose();
  manager = undefined;
  output.dispose();
}
