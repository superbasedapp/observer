import * as vscode from 'vscode';
import type { ResolvedBinary } from '../binary';
import type { DaemonManager } from '../daemon';
import { registerAppsOn } from '../apps';
import { registerDoctor } from './doctor';
import { registerLaunch } from './launch';
import { registerLifecycle } from './lifecycle';
import { registerCopyProxyEnv } from './proxyEnv';

// Commands that are declared in package.json but not yet implemented
// land here as stubs so palette invocations don't no-op silently.
// Each stub is replaced by a real handler at its owning milestone:
//   start / stop / openDashboard        — M1 (live; see lifecycle.ts)
//   copyProxyEnv                        — M4 (live; see proxyEnv.ts)
//   init / initWithMCP                  — future
//   enroll                              — replaced by observer.connect
//                                         ("Sign in and connect", connect.ts)
const STUBS: Array<{ id: string; milestone: string }> = [
  { id: 'observer.init', milestone: 'M3+' },
  { id: 'observer.initWithMCP', milestone: 'M3+' },
];

export function registerCommands(
  ctx: vscode.ExtensionContext,
  bin: ResolvedBinary,
  daemon: DaemonManager,
): void {
  ctx.subscriptions.push(registerDoctor(ctx, bin));
  registerLaunch(ctx, bin);
  registerLifecycle(ctx, daemon);
  registerCopyProxyEnv(ctx, daemon);
  // AI Apps (lane POLISH-F2): calls the daemon's one enable seam.
  registerAppsOn(ctx, daemon);
  for (const { id, milestone } of STUBS) {
    ctx.subscriptions.push(
      vscode.commands.registerCommand(id, async () => {
        await vscode.window.showInformationMessage(
          `${id} is not yet implemented (planned for ${milestone}).`,
        );
      }),
    );
  }
}
