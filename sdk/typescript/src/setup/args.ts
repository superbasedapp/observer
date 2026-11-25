/**
 * setup's command line (pure). `superbased-sdk setup [flags]`; `npx
 * @superbased/sdk setup` runs it.
 */

import type { DestinationFlag } from "./plan.js";

export interface SetupArgs {
  command: "setup" | "help";
  destination: DestinationFlag;
  /** Set up the key alone (Go and Java projects): no detection, no install, no init line. */
  keyOnly: boolean;
  replace: boolean;
  forget: boolean;
  status: boolean;
  json: boolean;
  /** A team slug the approval page selects first (`target_hint`). */
  team: string;
  /** A self-hosted organization (setup says how to get a key there; ruling R3). */
  orgUrl: string;
  cloudUrl: string;
  nodeUrl: string;
  dir: string;
  install: boolean;
  browser: boolean;
}

export const USAGE = `Usage: npx @superbased/sdk setup [options]

Adds superbased tracing to the app in this folder: installs the SDK and the
instrumentation for the model libraries it uses, sets up where traces go,
sends one hello trace and prints its link, then the one line to add.

  --online        your online dashboard (a browser approval; the key is kept
                  in a file only your user account can read, never printed)
  --local         this computer's Observer (asks before turning AI Apps on)
  --both          both
  --key-only      set up the key alone (for Go and Java apps): no install,
                  no init line
  --replace       with --online: a new key in place of the one kept here
  --status        say what is set up (never the key)
  --forget        revoke the key kept here and remove its file
  --json          one JSON object per step on stdout, for agents
  --team <slug>   preselect a team dashboard on the approval page
  --no-install    print the install command instead of running it
  --no-browser    print the approval link without opening a browser
  --dir <path>    the app's folder (default: this one)

Exit codes: 0 done (the trace arrived); 2 waiting for a person (approval
expired, declined, or a step only they can take); 3 refused (the plan or the
organization); 4 environment (no supported project, an install failed);
5 sent, not seen within 60 s (the link is still printed); 1 usage or error.`;

/** Parse argv (without node and the script). Throws a TypeError naming a bad argument. */
export function parseArgs(argv: readonly string[], env: Record<string, string | undefined> = {}): SetupArgs {
  const out: SetupArgs = {
    command: "setup",
    destination: "",
    keyOnly: false,
    replace: false,
    forget: false,
    status: false,
    json: false,
    team: "",
    orgUrl: "",
    cloudUrl: (env.SUPERBASED_CLOUD_URL ?? "").trim(),
    nodeUrl: (env.SUPERBASED_NODE_URL ?? "").trim(),
    dir: "",
    install: true,
    browser: true,
  };
  const args = [...argv];
  if (args[0] === "setup") args.shift();
  else if (!args.length || args[0] === "help" || args[0] === "--help" || args[0] === "-h") return { ...out, command: "help" };
  else throw new TypeError(`unknown command ${JSON.stringify(args[0])}; the command is: setup`);
  const value = (flag: string): string => {
    const v = args.shift();
    if (v === undefined || v.startsWith("--")) throw new TypeError(`${flag} needs a value`);
    return v;
  };
  while (args.length) {
    const raw = args.shift()!;
    const eq = raw.startsWith("--") ? raw.indexOf("=") : -1;
    const a = eq > 0 ? raw.slice(0, eq) : raw;
    if (eq > 0) args.unshift(raw.slice(eq + 1));
    switch (a) {
      case "--local":
      case "--online":
      case "--both": {
        const d = a.slice(2) as DestinationFlag;
        if (out.destination && out.destination !== d) throw new TypeError("choose one of --local, --online and --both");
        out.destination = d;
        break;
      }
      case "--key-only":
        out.keyOnly = true;
        break;
      case "--replace":
        out.replace = true;
        break;
      case "--forget":
        out.forget = true;
        break;
      case "--status":
        out.status = true;
        break;
      case "--json":
        out.json = true;
        break;
      case "--no-install":
        out.install = false;
        break;
      case "--no-browser":
        out.browser = false;
        break;
      case "--team":
        out.team = value(a).trim().toLowerCase();
        if (!/^[a-z0-9][a-z0-9-]{0,62}$/.test(out.team)) throw new TypeError("--team takes a team's slug (letters, digits, dashes)");
        break;
      case "--org-url":
        out.orgUrl = value(a).trim();
        break;
      case "--cloud-url":
        out.cloudUrl = value(a).trim();
        break;
      case "--node-url":
        out.nodeUrl = value(a).trim();
        break;
      case "--dir":
        out.dir = value(a);
        break;
      case "--help":
      case "-h":
        return { ...out, command: "help" };
      default:
        throw new TypeError(`unknown option ${JSON.stringify(a)}`);
    }
  }
  if (out.replace && out.destination === "local") throw new TypeError("--replace goes with --online (or --both)");
  if (out.forget && out.status) throw new TypeError("choose one of --forget and --status");
  return out;
}
