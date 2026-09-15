// SuperBased Observer prompt-submit guard bridge for commandcode's
// Mods SDK (commandcode.ai/docs/mods, live-fetched 2026-09-07).
//
// commandcode mods are no-build TypeScript files (jiti-compiled at
// load time) that register hooks via a factory-function parameter:
//
//   cmd.hooks({
//     transformInput({text}) { ... }
//   })
//
// This bridge shells out to `observer hook command-code
// transformInput` on every user-typed prompt, mirroring the same
// argv shape every other prompt-submit dialect this repo speaks uses
// (internal/hook/promptsubmit.go) — the receiver on the observer side
// is the SAME shared HandlePromptSubmitGuarded seam every other
// vendor's hook goes through. See docs/guard-prompt.md.
//
// UNVERIFIED (disclosed): the exact module EXPORT shape the Mods SDK
// loader expects (default-exported factory function vs. a top-level
// side-effecting call against an ambient `cmd`) could not be verified
// against a live commandcode install — the vendor's own docs describe
// the HOOK REGISTRATION call (`cmd.hooks({...})`) precisely, but not
// how a mod FILE hands the loader its `cmd` parameter. This file uses
// the default-export-factory convention, the shape the vendor's own
// phrasing ("registered via the factory function parameter cmd")
// most directly implies. `observer doctor --probe-hook command-code`
// probes the OBSERVER-side receiver only (this file's own subprocess
// contract), not whether commandcode's loader actually invokes this
// export shape — that would need a live commandcode install to
// confirm.
//
// Fails OPEN on any error (binary missing, non-zero unexpected exit,
// malformed reply, timeout): a guard/observer failure must NEVER
// block the developer's own prompt.

import { execFileSync } from "node:child_process";

// OBSERVER_BIN_DEFAULT is substituted at install time by
// commandcodemod.WritePlugin with the resolved observer binary path —
// mirrors internal/hook/hermesplugin's OBSERVER_BIN_DEFAULT
// placeholder convention exactly.
const OBSERVER_BIN_DEFAULT = "{{OBSERVER_BIN_DEFAULT}}";
const OBSERVER_BIN = process.env.OBSERVER_BIN || OBSERVER_BIN_DEFAULT;

// OBSERVER_CONFIG_DEFAULT is substituted at install time by
// commandcodemod.WritePlugin/WritePluginBridge with the operator's
// --config path (Options.ConfigPath), when one was set — mirrors
// OBSERVER_BIN_DEFAULT's placeholder convention exactly, so a custom
// config path survives into the registered hook invocation the same
// way it does for every other writer's `--config <path>` suffix
// (internal/hook/register.go's configFlagSuffix family). Stays "" for
// a stock install with no custom config path. The runtime
// OBSERVER_CONFIG env override still takes precedence over both.
const OBSERVER_CONFIG_DEFAULT = "{{OBSERVER_CONFIG_DEFAULT}}";
const OBSERVER_CONFIG = process.env.OBSERVER_CONFIG || OBSERVER_CONFIG_DEFAULT;

// OBSERVER_WSL_BIN / WSL_DISTRO are substituted ONLY by
// commandcodemod.WritePluginBridge — the command-code-windows cross-OS
// bridge target (internal/hook/register.go::registerCommandCodeWindows).
// Both stay "" for every native install (WritePlugin never fills them
// in). When OBSERVER_WSL_BIN is non-empty AND this mod is running on
// win32, resolveExec() below shells out through wsl.exe instead of
// exec'ing a Windows-side observer binary directly — so the hook
// executes inside the WSL daemon's own OS-context and its db.Open
// resolves the daemon's own DB natively, mirroring every other
// *-windows registrar's wsl.exe wrapper (CLAUDE.md: "Don't try to
// bridge cross-OS hook capture at the storage layer"). The decision is
// made HERE at hook-fire time, not baked into a static command string,
// because this Node process is the one that actually knows its own
// platform.
const OBSERVER_WSL_BIN = "{{OBSERVER_WSL_BIN}}";
const WSL_DISTRO = "{{WSL_DISTRO}}";

interface TransformInputArgs {
  text: string;
}

interface ResolvedExec {
  bin: string;
  args: string[];
}

// resolveExec picks the observer invocation for this run: the wsl.exe
// bridge form when this mod was installed for the command-code-windows
// target (OBSERVER_WSL_BIN set) AND we are actually on win32 today,
// otherwise the plain native form every other install uses.
function resolveExec(): ResolvedExec {
  const args = ["hook", "command-code", "transformInput"];
  if (OBSERVER_CONFIG) {
    args.push("--config", OBSERVER_CONFIG);
  }
  if (process.platform === "win32" && OBSERVER_WSL_BIN) {
    return { bin: "wsl.exe", args: ["-d", WSL_DISTRO, "--", OBSERVER_WSL_BIN, ...args] };
  }
  return { bin: OBSERVER_BIN, args };
}

interface ObserverGuardReply {
  action?: "continue" | "handled" | "transform";
  message?: string;
  text?: string;
}

export default function (cmd: any) {
  cmd.hooks({
    transformInput({ text }: TransformInputArgs) {
      try {
        const { bin, args } = resolveExec();
        const output = execFileSync(bin, args, {
          input: JSON.stringify({ text }),
          timeout: 5000,
          encoding: "utf8",
        });
        const reply: ObserverGuardReply = JSON.parse(output);
        if (reply && reply.action === "handled") {
          return { action: "handled", message: reply.message };
        }
        if (reply && reply.action === "transform" && typeof reply.text === "string") {
          return { action: "transform", text: reply.text };
        }
        return { action: "continue" };
      } catch {
        // Fail OPEN — see the file header.
        return { action: "continue" };
      }
    },
  });
}
