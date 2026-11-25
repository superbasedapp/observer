/**
 * `superbased-sdk setup` (`npx @superbased/sdk setup`): the command's entry.
 * Built to dist/esm/setup/cli.js; scripts/build.mjs writes the bin launcher
 * dist/setup/cli.js that calls `main`. Node built-ins only: the runtime SDK
 * is loaded by the hello phase alone, and the runtime never imports setup.
 */

import { readFileSync } from "node:fs";
import { createInterface } from "node:readline";

import { defaultDeps, runSetup } from "./run.js";

interface PackageFile {
  version?: string;
}

/** This package's version (its own package.json). */
export function packageVersion(url: URL = new URL("../../../package.json", import.meta.url)): string {
  try {
    return (JSON.parse(readFileSync(url, "utf8")) as PackageFile).version ?? "0.0.0";
  } catch {
    return "0.0.0";
  }
}

/** A y/N question on the terminal (the prompt on stderr, so stdout stays clean). */
export function askOnTerminal(question: string): Promise<boolean> {
  return new Promise((resolve) => {
    const rl = createInterface({ input: process.stdin, output: process.stderr, terminal: true });
    rl.question(question, (answer) => {
      rl.close();
      resolve(/^\s*y(es)?\s*$/i.test(answer));
    });
    rl.on("SIGINT", () => {
      rl.close();
      resolve(false);
    });
  });
}

/** Run the command; resolves the exit code. */
export async function main(argv: readonly string[]): Promise<number> {
  return runSetup(argv, defaultDeps(packageVersion(), askOnTerminal));
}
