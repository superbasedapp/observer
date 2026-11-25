/**
 * setup, phase by phase (plan 3.5): detect, choose the destination,
 * install, the credential or the enable, hello, next steps. The planner
 * (plan.ts) decides; this file only executes, with every outside effect
 * injected (`Deps`), so the contract tests drive it against loopback stubs.
 *
 * setup never names, offers or tests the AI gateway (ledger SDKQS-10), and
 * never calls the machine's SDK credential routes or the `observer sdk`
 * verbs (SDKQS-8).
 */

import { homedir, hostname } from "node:os";
import { isAbsolute, resolve } from "node:path";

import { expired, expiryNote, readSdkCredentialFile, type SdkFileState } from "../credfile.js";
import { normaliseServiceName, serviceNameLadder, stripScope } from "../project.js";
import { parseArgs, USAGE, type SetupArgs } from "./args.js";
import { removeCredentialFile, writeCredentialFile, defaultWriteDeps, type WriteDeps } from "./credwrite.js";
import {
  DEFAULT_CLOUD_URL,
  EXIT,
  createRequest,
  machineName,
  newRedeemSecret,
  pollForGrant,
  realClock,
  redeemGrant,
  redeemHash,
  revokeKey,
  type Clock,
  type Stop,
} from "./device.js";
import { DEFAULT_NODE_URL, discoverMachine, onPath, openBrowser, readProject, runInstall } from "./facts.js";
import { refusalLines, sendHello } from "./hello.js";
import { appsStatus, enableApps, enablePageUrl, enableQuestion, waitForOn } from "./local.js";
import { httpFetch, isLoopback, secureOrLoopback, type HttpFn } from "./net.js";
import { Reporter, type Sink } from "./output.js";
import {
  answer,
  detect,
  heldFact,
  installArgv,
  installPackages,
  nextSteps,
  otherLanguageAdvice,
  planDestination,
  type DestinationFacts,
  type DestinationPlan,
  type Detected,
} from "./plan.js";

/** Everything setup reaches outside itself. */
export interface Deps {
  env: Record<string, string | undefined>;
  cwd: string;
  home: string;
  platform: string;
  hostname: string;
  arch: string;
  /** stdin and stdout are terminals (a person can answer). */
  tty: boolean;
  stdout: Sink;
  stderr: Sink;
  http: HttpFn;
  clock: Clock;
  /** Ask a y/N question on the terminal. */
  ask: (question: string) => Promise<boolean>;
  openBrowser: (url: string) => Promise<boolean>;
  install: (argv: readonly string[], dir: string) => Promise<number>;
  onPath: (name: string) => boolean;
  write: WriteDeps;
  /** This package's version (the SDK it installs is `^<version>`). */
  version: string;
  /** The runtime the hello goes through (tests may hand one in). */
  runtime?: Parameters<typeof sendHello>[2];
}

/** The default dependencies for a real run. */
export function defaultDeps(version: string, ask: (q: string) => Promise<boolean>): Deps {
  const env = process.env as Record<string, string | undefined>;
  let home = "";
  try {
    home = homedir();
  } catch {
    home = "";
  }
  return {
    env,
    cwd: process.cwd(),
    home,
    platform: process.platform,
    hostname: hostname(),
    arch: process.arch,
    tty: process.stdin.isTTY === true && process.stdout.isTTY === true,
    stdout: { write: (s) => process.stdout.write(s) },
    stderr: { write: (s) => process.stderr.write(s) },
    http: httpFetch,
    clock: realClock,
    ask,
    openBrowser: (url) => openBrowser(url, env),
    install: (argv, dir) => runInstall(argv, dir),
    onPath: (name) => onPath(name, env),
    write: defaultWriteDeps,
    version,
  };
}

/** Whether the held file counts (valid, a gateway, not expired). */
function facts0(held: SdkFileState, deps: Deps): boolean {
  return heldFact(held, deps.clock.now()) !== "";
}

function heldState(deps: Deps): SdkFileState {
  return readSdkCredentialFile(deps.env, deps.home, deps.platform);
}

/** End with an error: the lines for people, and the `error` phase (every exit ends with `done` or `error`). */
function fail(out: Reporter, exit: number, code: string, lines: readonly string[], extra: Record<string, unknown> = {}): number {
  for (const l of lines) out.say(l);
  out.event("error", { code, message: lines.join(" "), exit, ...extra });
  return exit;
}

function stopWith(out: Reporter, s: Stop): number {
  const lines = [s.message];
  if (s.link) lines.push(s.code === "plan_required" ? `Change the plan: ${s.link}` : s.link);
  return fail(out, s.exit, s.code, lines, s.link ? { upgrade_url: s.link } : {});
}

/** setup --status: what is set up (never the key). */
async function status(out: Reporter, deps: Deps, nodeUrl: string): Promise<number> {
  const held = heldState(deps);
  const machine = await discoverMachine(deps.http, nodeUrl);
  const r = held.record;
  const fields: Record<string, unknown> = {
    credential_file: held.path,
    present: held.present,
    valid: !!r,
    key_id: r?.keyId ?? "",
    gateway_url: r?.gateway ?? "",
    dashboard_url: r?.dashboardUrl ?? "",
    destination: r?.destination ?? "",
    expires_at: r?.expiresAt ?? "",
    machine: machine.answers ? { signed_in: machine.signedIn, apps_on: machine.appsOn } : null,
  };
  out.say(`SDK key file: ${held.path || "(no path: set SUPERBASED_CREDENTIAL_FILE)"}`);
  if (!held.present) out.say("  not set up (run setup --online)");
  else if (!r) out.say(`  refused: ${held.error}`);
  else {
    out.say(`  key ${r.keyId}, sends to ${r.gateway || "(no gateway)"}, destination ${r.destination || "(none)"}`);
    if (r.dashboardUrl) out.say(`  dashboard ${r.dashboardUrl}`);
    if (r.expiresAt) out.say(`  expires ${r.expiresAt}`);
    const note = expiryNote(r.expiresAt, held.path, deps.clock.now());
    if (note) out.say(`  ${note}`);
    for (const w of held.warnings) out.say(`  ${w}`);
  }
  if (!machine.answers) out.say("Observer on this computer: not answering");
  else {
    out.say(`Observer on this computer: AI Apps ${machine.appsOn ? "on" : "off"}${machine.signedIn ? "; signed in (its own key is used first)" : ""}`);
    if (machine.signedIn && r) out.say(`  the key file is present but unused while Observer is signed in`);
  }
  out.event("status", fields);
  out.event("done", { exit: EXIT.done });
  return EXIT.done;
}

/** setup --forget: revoke the held key with itself, then remove the file. */
async function forget(out: Reporter, deps: Deps): Promise<number> {
  const held = heldState(deps);
  if (!held.present) {
    out.say(`No SDK key file at ${held.path || "(no path)"}; nothing to forget.`);
    out.event("forget", { credential_file: held.path, removed: false, revoked: false });
    out.event("done", { exit: EXIT.done });
    return EXIT.done;
  }
  let revoked = false;
  let detail = "the file could not be read";
  if (held.record?.gateway) {
    out.secret(held.record.key);
    ({ revoked, detail } = await revokeKey(deps.http, held.record.gateway, held.record.key));
  }
  const removed = removeCredentialFile(held.path);
  out.say(revoked ? `Revoked the SDK key ${held.record?.keyId ?? ""} and removed ${held.path}.` : `Removed ${held.path}; the key was not revoked (${detail}): revoke it on your dashboard (AI apps > SDK keys) if it may still be used.`);
  out.event("forget", { credential_file: held.path, removed, revoked });
  out.event("done", { exit: EXIT.done });
  return EXIT.done;
}

/** The service name setup announces and the hello carries: the project's, else the folder's. */
function serviceFor(pkgName: string, dir: string, env: Record<string, string | undefined>): string {
  const r = serviceNameLadder(undefined, env, { manifestName: pkgName, entryDir: dir });
  return normaliseServiceName(r.name) || "custom-app";
}

/** Run setup. Returns the exit code; never throws. */
export async function runSetup(argv: readonly string[], deps: Deps): Promise<number> {
  let args: SetupArgs;
  const early = new Reporter(argv.includes("--json"), deps.stdout, deps.stderr);
  try {
    args = parseArgs(argv, deps.env);
  } catch (err) {
    // A command line setup cannot run is the environment's (exit 4), like a self-hosted --org-url.
    const message = err instanceof Error ? err.message : String(err);
    early.warn(`setup: ${message}`);
    early.warn(USAGE);
    early.event("error", { code: "usage", message, exit: EXIT.environment });
    return EXIT.environment;
  }
  if (args.command === "help") {
    deps.stdout.write(USAGE + "\n");
    return EXIT.done;
  }
  const out = new Reporter(args.json, deps.stdout, deps.stderr);
  try {
    return await phases(args, out, deps);
  } catch (err) {
    // An unexpected error: its message (never a secret: the reporter takes any out); the stack only on stderr.
    const message = err instanceof Error ? err.message : String(err);
    out.warn(`setup: ${message}`);
    if (err instanceof Error && err.stack && deps.env.SUPERBASED_DEBUG) out.warn(err.stack);
    out.event("error", { code: "unexpected", message, exit: EXIT.internal });
    return EXIT.internal;
  }
}

async function phases(args: SetupArgs, out: Reporter, deps: Deps): Promise<number> {
  const dir = args.dir ? (isAbsolute(args.dir) ? args.dir : resolve(deps.cwd, args.dir)) : deps.cwd;
  const nodeUrl = (args.nodeUrl || DEFAULT_NODE_URL).replace(/\/+$/, "");
  const cloudUrl = (args.cloudUrl || DEFAULT_CLOUD_URL).replace(/\/+$/, "");
  try {
    if (!isLoopback(new URL(nodeUrl))) throw new Error();
  } catch {
    return fail(out, EXIT.environment, "usage", [`--node-url / SUPERBASED_NODE_URL must be this computer's Observer (a loopback address), not ${nodeUrl}.`]);
  }
  if (!secureOrLoopback(cloudUrl)) return fail(out, EXIT.environment, "usage", [`The cloud address must be https: ${cloudUrl}`]);

  if (args.status) return status(out, deps, nodeUrl);
  if (args.forget) return forget(out, deps);

  // Ruling R3: hosted organizations only.
  if (args.orgUrl) {
    return fail(out, EXIT.environment, "self_hosted", [
      `${args.orgUrl} is a self-hosted organization; setup's sign-in is for organizations hosted at superbased.app.`,
      "Use an admin-issued key in SUPERBASED_API_KEY (with SUPERBASED_ORG_URL), or sign Observer in on a machine that runs it; see https://superbased.app/docs/sdk/keys-and-scopes",
    ]);
  }

  // 1. Detect.
  let detected: Detected | null = null;
  let pkgName = "";
  const project = readProject(dir);
  if (!args.keyOnly) {
    detected = detect(project);
    if (detected.language !== "typescript") {
      out.event("detect", { language: null, other: detected.other || null });
      return fail(out, EXIT.environment, "no_supported_language", [otherLanguageAdvice(detected.other)]);
    }
  }
  pkgName = typeof project.packageJson?.name === "string" ? stripScope(project.packageJson.name) : "";
  const service = serviceFor(pkgName, dir, deps.env);
  if (detected) {
    out.say(`Found a Node project "${service}" (${detected.packageManager}, ${detected.next ? "Next.js" : detected.moduleType === "esm" ? "ESM" : "CommonJS"})${detected.targets.length ? `, using ${detected.targets.join(", ")}` : ""}.`);
    out.event("detect", {
      language: "typescript",
      service,
      package_manager: detected.packageManager,
      module_type: detected.moduleType,
      next: detected.next,
      targets: detected.targets,
      entries: detected.entries,
    });
  }

  // 2. Choose the destination.
  const machine = await discoverMachine(deps.http, nodeUrl);
  const held = heldState(deps);
  for (const w of held.warnings) out.warn(w);
  if (held.present && !held.record) out.warn(`${held.error}; setup will set up a new key`);
  else if (held.record && !facts0(held, deps)) {
    out.warn(
      expired(held.record.expiresAt, deps.clock.now())
        ? `the SDK key in ${held.path} expired on ${held.record.expiresAt}; setup will set up a new key`
        : `the SDK key file ${held.path} names no usable gateway; setup will set up a new key`,
    );
  }
  const facts: DestinationFacts = {
    flag: args.destination,
    replace: args.replace,
    machine,
    observerOnPath: machine.answers ? true : deps.onPath("observer"),
    held: heldFact(held, deps.clock.now()),
    tty: deps.tty,
  };
  let plan: DestinationPlan = planDestination(facts);
  for (const n of plan.notes) out.say(n);
  if (plan.ask) {
    const q = plan.ask === "local_or_online" ? "Also send traces to your online dashboard? [y/N] " : "Set up your online dashboard instead? [y/N] ";
    plan = answer(plan, await deps.ask(q), facts);
  }
  out.event("destination", { row: plan.row, destination: plan.destination || null, credential: plan.credential, enable: plan.enable, notes: plan.notes });
  if (!plan.destination) return fail(out, plan.exit || EXIT.person, plan.row, []);

  // 3. Install.
  if (detected) {
    const pkgs = installPackages(detected, project, deps.version);
    const argv = installArgv(detected.packageManager, pkgs);
    if (argv.length && !args.install) {
      out.say(`Install: ${argv.join(" ")}`);
      out.event("install", { command: argv, ran: false });
    } else if (argv.length) {
      out.say(`Installing: ${argv.join(" ")}`);
      const code = await deps.install(argv, dir);
      out.event("install", { command: argv, ran: true, exit_code: code });
      if (code !== 0) return fail(out, EXIT.environment, "install_failed", [`The install failed (exit ${code}); run it yourself, then run setup again.`]);
    } else {
      out.event("install", { command: [], ran: false });
    }
  }

  // 4. The credential, or the enable.
  if (plan.credential === "device" && !held.path) {
    return fail(out, EXIT.environment, "no_credential_path", ["There is no place for the SDK key file here (no home folder or %LOCALAPPDATA%): set SUPERBASED_CREDENTIAL_FILE to a path only you can read, then run setup again."]);
  }
  if (plan.credential === "device") {
    const code = await deviceSignIn(args, out, deps, cloudUrl, service, plan.destination === "both" ? "both" : "online", held);
    if (code !== EXIT.done) return code;
  }
  if (plan.enable) {
    const code = await localEnable(out, deps, nodeUrl);
    if (code !== EXIT.done) return code;
  }

  // 5. Hello and arrival.
  const hello = await sendHello({ destination: plan.destination, serviceName: service, nodeUrl }, deps.http, deps.runtime);
  try {
    if (hello.kind === "refused") return fail(out, EXIT.refused, "plan_refusal", hello.lines);
    if (hello.kind === "failed") return fail(out, hello.exit, "hello_failed", [hello.message]);
    out.say("Sent a hello trace; checking it arrived...");
    out.event("hello", { trace_id: hello.traceId });
    const arrived = await hello.arrival(deps.http, deps.clock);
    const link = hello.onlineUrl || hello.localUrl;
    if (typeof arrived === "object") return fail(out, arrived.exit, "arrival", arrived.message.split("\n"));
    if (arrived === "arrived") {
      out.say(link ? `Your first trace: ${link}` : "Your first trace arrived; open your dashboard's AI apps page.");
      if (hello.onlineUrl && hello.localUrl) out.say(`On this computer: ${hello.localUrl}`);
    } else {
      out.say(`Sent, not seen yet (it can take a minute)${link ? `: ${link}` : "."}`);
    }
    // 6. Next steps, then done.
    if (detected) printNext(out, detected);
    const exit = arrived === "arrived" ? EXIT.done : EXIT.notSeen;
    out.event("done", { trace_id: hello.traceId, trace_url: link, ...(hello.localUrl && hello.onlineUrl ? { local_trace_url: hello.localUrl } : {}), arrived: arrived === "arrived", exit });
    return exit;
  } finally {
    await hello.shutdown();
  }
}

/** The device sign-in (3.6) and the file write. */
async function deviceSignIn(args: SetupArgs, out: Reporter, deps: Deps, cloudUrl: string, service: string, destination: "online" | "both", held: SdkFileState): Promise<number> {
  const secret = newRedeemSecret();
  out.secret(secret);
  const machine = machineName(deps.hostname);
  const created = await createRequest(deps.http, cloudUrl, {
    clientVersion: deps.version,
    projectName: service,
    machineName: machine,
    os: deps.platform,
    arch: deps.arch,
    team: args.team,
    redeemHash: redeemHash(secret),
  });
  if (created.kind === "stop") return stopWith(out, created);
  out.secret(created.deviceCode);
  out.say(`Approve in your browser: ${created.approveUrl}  (code ${created.userCode})`);
  out.say("This SDK key is the only key traces need. It is kept in a file on this computer that only your user account can read, and it is never printed.");
  out.event("approve", { approve_url: created.approveUrl, user_code: created.userCode, verify_url: created.verifyUrl, expires_in: created.expiresIn });
  if (args.browser) await deps.openBrowser(created.approveUrl);
  const got = await pollForGrant(deps.http, cloudUrl, created, deps.clock, (note) => out.say(note));
  if (got.kind === "stop") return stopWith(out, got);
  out.secret(got.grant);
  out.say(`Approved for ${got.target.displayName || got.target.slug}. Setting up the key...`);
  const minted = await redeemGrant(deps.http, got.target.serverUrl, got.grant, secret, machine, args.replace ? (held.record?.keyId ?? "") : "", deps.clock);
  if (minted.kind === "stop") return stopWith(out, minted);
  out.secret(minted.key);
  let warn = "";
  try {
    warn = writeCredentialFile(
      held.path,
      { key: minted.key, gatewayUrl: minted.gatewayUrl, destination, dashboardUrl: minted.dashboardUrl, expiresAt: minted.expiresAt },
      deps.write,
    );
  } catch (err) {
    out.event("credential", { written: false, path: held.path });
    return fail(out, EXIT.environment, "write_failed", [err instanceof Error ? err.message : "could not write the SDK key file", "The key was not kept; fix the folder's permissions and run setup again (revoke the new key on your dashboard: AI apps > SDK keys)."]);
  }
  if (warn) out.warn(warn);
  out.say(`Saved the SDK key for ${got.target.displayName || got.target.slug} to ${held.path}${minted.expiresAt ? ` (expires ${minted.expiresAt})` : ""}.`);
  out.event("credential", { written: true, path: held.path, key_id: minted.keyId, gateway_url: minted.gatewayUrl, dashboard_url: minted.dashboardUrl, expires_at: minted.expiresAt, org_slug: got.target.slug });
  if (minted.planRefusal) return fail(out, EXIT.refused, "plan_refusal", refusalLines(429, minted.planRefusal));
  return EXIT.done;
}

/** The local enable (3.7). */
async function localEnable(out: Reporter, deps: Deps, nodeUrl: string): Promise<number> {
  let st;
  try {
    st = await appsStatus(deps.http, nodeUrl);
  } catch {
    return fail(out, EXIT.environment, "observer_not_answering", ["Observer stopped answering; start it with `observer start` and run setup again."]);
  }
  if (st.on) return EXIT.done;
  if (deps.tty) {
    const yes = await deps.ask(enableQuestion(st));
    if (!yes) {
      out.event("enable", { asked: "terminal", on: false });
      return fail(out, EXIT.person, "declined", ["AI Apps stays off. Turn it on later with `observer apps on`, or run setup again."]);
    }
    const r = await enableApps(deps.http, nodeUrl, st.cookie || st.confirmToken);
    out.event("enable", { asked: "terminal", on: r.ok });
    if (!r.ok) return fail(out, r.exit, "enable_failed", [r.message]);
    out.say("AI Apps is on.");
    return EXIT.done;
  }
  const page = enablePageUrl(nodeUrl);
  const opened = await deps.openBrowser(page);
  out.say(`Turn on AI Apps on this computer: ${opened ? "click Turn on in the page that opened" : "open"} ${page} (or run \`observer apps on\`).`);
  if (st.sentence) out.say(st.sentence);
  out.event("enable", { asked: "dashboard", enable_url: page, opened });
  if (!opened) return fail(out, EXIT.person, "waiting_for_enable", []);
  if (!(await waitForOn(deps.http, nodeUrl, deps.clock))) return fail(out, EXIT.person, "waiting_for_enable", ["AI Apps is still off; run setup again once it is on."]);
  out.say("AI Apps is on.");
  return EXIT.done;
}

/** Phase 6: the one init line, the start-script change, or the Next.js hook. */
function printNext(out: Reporter, d: Detected): void {
  const n = nextSteps(d);
  out.say("");
  out.say("Next:");
  if (n.kind === "cjs") {
    out.say(`  Add this as the first line of ${n.where || "your app's entry file"}:`);
    out.say(`    ${n.initLine}`);
  } else if (n.kind === "esm") {
    if (n.startScript) {
      out.say("  Change the start script in package.json to:");
      out.say(`    "start": ${JSON.stringify(n.startScript)}`);
    } else {
      out.say("  Start the app with:");
      out.say(`    ${n.nodeOptions} <your start command>`);
    }
  } else {
    out.say(`  Add ${n.file!.path}:`);
    for (const l of n.file!.content.trimEnd().split("\n")) out.say(`    ${l}`);
    out.say(`  and in next.config, serverExternalPackages: ${JSON.stringify(n.externalPackages)}`);
  }
  out.say("  Then run the app once: its first trace's link is printed on the terminal.");
  out.say("Make it richer:");
  for (const r of n.richer) out.say(`  ${r}`);
  out.event("next", {
    kind: n.kind,
    init_line: n.initLine || null,
    where: n.where,
    start_script: n.startScript,
    node_options: n.kind === "esm" ? n.nodeOptions : "",
    file: n.file,
    server_external_packages: n.externalPackages,
    richer: n.richer,
  });
}

