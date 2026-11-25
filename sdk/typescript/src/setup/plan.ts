/**
 * The setup planner (plan 3.5): pure decision tables over plain facts. The
 * CLI gathers the facts (facts.ts) and executes the plan; nothing here reads
 * the disk, the network or the terminal, so every row is a test case.
 *
 * Tables, each walked top down:
 * - the project manifest rules (language, package manager, module type);
 * - the package-manager table (the install command);
 * - the destination plan table (what to set up, given the flags and the
 *   machine's state);
 * - the next-steps rules (the one init line, the ESM start-script change,
 *   Next.js's instrumentation hook).
 */

import { TARGET_INFO, packageOf, type InstrumentTarget, type TargetInfo } from "../targets.js";

// --- detection ---------------------------------------------------------------

/** What setup read from the project folder. */
export interface ProjectInput {
  /** File names present at the project root (`package.json`, `pnpm-lock.yaml`, `go.mod`, ...). */
  files: readonly string[];
  /** The parsed package.json (null when there is none, or it is not JSON). */
  packageJson: PackageJson | null;
  /** npm packages installed in the project's node_modules (by name). */
  installed: readonly string[];
}

export interface PackageJson {
  name?: unknown;
  type?: unknown;
  main?: unknown;
  scripts?: unknown;
  dependencies?: unknown;
  devDependencies?: unknown;
  packageManager?: unknown;
}

export type PackageManager = "npm" | "pnpm" | "yarn" | "bun";
export type ModuleType = "esm" | "cjs";

/** What the project is, as setup decided it. */
export interface Detected {
  /** `typescript` (a package.json: any Node project), or "" when this setup supports none here. */
  language: "typescript" | "";
  /** The other language the folder is (`python`, `go`, `java`), for the advice; "" when none. */
  other: "python" | "go" | "java" | "";
  packageManager: PackageManager;
  /** Where the package manager came from: `packageManager` (the package.json field), a lock file name, or `default`. */
  packageManagerSource: string;
  moduleType: ModuleType;
  next: boolean;
  /** The targets the project uses (their detect packages are dependencies or installed). */
  targets: InstrumentTarget[];
  /** The entry file candidates, best first. */
  entries: string[];
  /** The start script, when package.json has one. */
  startScript: string;
}

/** Lock files to package managers, in order (a packageManager field wins over all). */
export const LOCK_FILES: ReadonlyArray<readonly [string, PackageManager]> = [
  ["pnpm-lock.yaml", "pnpm"],
  ["yarn.lock", "yarn"],
  ["bun.lock", "bun"],
  ["bun.lockb", "bun"],
  ["package-lock.json", "npm"],
  ["npm-shrinkwrap.json", "npm"],
];

/** Manifests of the other languages, when there is no package.json (the setup to use is named in {@link otherLanguageAdvice}). */
export const OTHER_MANIFESTS: ReadonlyArray<readonly [string, Detected["other"]]> = [
  ["pyproject.toml", "python"],
  ["requirements.txt", "python"],
  ["setup.py", "python"],
  ["Pipfile", "python"],
  ["go.mod", "go"],
  ["pom.xml", "java"],
  ["build.gradle", "java"],
  ["build.gradle.kts", "java"],
];

/** Common entry files, after the start script's and `main`. */
export const ENTRY_GUESSES: readonly string[] = [
  "server.js", "index.js", "app.js", "main.js", "server.mjs", "index.mjs", "app.mjs", "server.ts", "index.ts", "app.ts", "main.ts",
  "src/server.ts", "src/index.ts", "src/main.ts", "src/app.ts", "src/server.js", "src/index.js", "src/main.js", "src/app.js",
];

function obj(v: unknown): Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : {};
}

function deps(p: PackageJson | null): Set<string> {
  return new Set([...Object.keys(obj(p?.dependencies)), ...Object.keys(obj(p?.devDependencies))]);
}

/** The file a start script runs with node (`node server.js`, `node --env-file=.env dist/index.js`), "" when none. */
export function scriptEntry(script: string): string {
  const words = script.trim().split(/\s+/);
  const i = words.findIndex((w) => w === "node" || w.endsWith("/node") || w === "tsx" || w === "ts-node");
  if (i < 0) return "";
  for (const w of words.slice(i + 1)) {
    if (w.startsWith("-")) continue;
    if (/\.(c|m)?(j|t)s$/.test(w) || !w.includes(".")) return w;
    return "";
  }
  return "";
}

/** Detect the project from what setup read (pure). */
export function detect(input: ProjectInput): Detected {
  const p = input.packageJson;
  const out: Detected = {
    language: "",
    other: "",
    packageManager: "npm",
    packageManagerSource: "default",
    moduleType: "cjs",
    next: false,
    targets: [],
    entries: [],
    startScript: "",
  };
  if (!input.files.includes("package.json") || !p) {
    for (const [file, lang] of OTHER_MANIFESTS) {
      if (input.files.includes(file)) {
        out.other = lang;
        return out;
      }
    }
    return out;
  }
  out.language = "typescript";
  const pm = typeof p.packageManager === "string" ? /^(npm|pnpm|yarn|bun)@/.exec(p.packageManager.trim()) : null;
  if (pm) {
    out.packageManager = pm[1] as PackageManager;
    out.packageManagerSource = "packageManager";
  } else {
    for (const [file, m] of LOCK_FILES) {
      if (input.files.includes(file)) {
        out.packageManager = m;
        out.packageManagerSource = file;
        break;
      }
    }
  }
  const scripts = obj(p.scripts);
  out.startScript = typeof scripts.start === "string" ? scripts.start : "";
  const d = deps(p);
  const have = (pkg: string) => d.has(pkg) || input.installed.includes(pkg);
  out.next = have("next");
  out.targets = TARGET_INFO.filter((t) => t.detect.some(have)).map((t) => t.name);
  const entries: string[] = [];
  const fromScript = scriptEntry(out.startScript);
  if (fromScript) entries.push(fromScript.replace(/^\.\//, ""));
  if (typeof p.main === "string" && p.main.trim()) entries.push(p.main.trim().replace(/^\.\//, ""));
  for (const g of ENTRY_GUESSES) if (input.files.includes(g)) entries.push(g);
  out.entries = [...new Set(entries)];
  const first = out.entries[0] ?? "";
  if (p.type === "module") out.moduleType = /\.cjs$|\.cts$/.test(first) ? "cjs" : "esm";
  else out.moduleType = /\.mjs$|\.mts$/.test(first) ? "esm" : "cjs";
  return out;
}

/** What to tell a person whose folder is another language's project. */
export function otherLanguageAdvice(language: Detected["other"]): string {
  switch (language) {
    case "python":
      return "This is a Python project: run `uvx superbased-sdk setup` (or `pip install superbased-sdk && python -m superbased_sdk setup`) in it.";
    case "go":
    case "java":
      return `This is a ${language === "go" ? "Go" : "Java"} project: \`npx @superbased/sdk setup --key-only\` sets up the key the ${language === "go" ? "Go" : "Java"} SDK reads; add the SDK by hand (https://superbased.app/docs/sdk/overview).`;
    default:
      return "No package.json here: run setup in your app's folder (or use --key-only to set up the key alone).";
  }
}

// --- install -----------------------------------------------------------------

/** The package-manager table: the command that adds packages. */
export const INSTALL_COMMANDS: Readonly<Record<PackageManager, readonly string[]>> = {
  npm: ["npm", "install"],
  pnpm: ["pnpm", "add"],
  yarn: ["yarn", "add"],
  bun: ["bun", "add"],
};

/**
 * The packages to add: the SDK (`@superbased/sdk@^<setup's version>`) unless
 * present, and each detected auto target's instrumentation package unless
 * present (its version left to the package manager, within the SDK's peer
 * range). An `auto: false` target (openai-agents) is detected, not installed.
 * The register entry's own dependency comes with the SDK.
 */
export function installPackages(d: Detected, input: ProjectInput, sdkVersion: string): string[] {
  const have = deps(input.packageJson);
  const present = (pkg: string) => have.has(pkg) || input.installed.includes(pkg);
  const out: string[] = [];
  if (!present("@superbased/sdk")) out.push(`@superbased/sdk@^${sdkVersion}`);
  for (const name of d.targets) {
    const t = TARGET_INFO.find((x) => x.name === name) as TargetInfo;
    if (!t.auto || present(t.package)) continue;
    out.push(t.package);
  }
  return out;
}

/** A package spec safe to put on a command line (no shell characters). */
export const SAFE_PACKAGE_SPEC = /^(@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*(@[\^~]?[0-9A-Za-z.+-]+)?$/;

/** The install argv for a package manager ([] when there is nothing to add). Every spec is checked against {@link SAFE_PACKAGE_SPEC}. */
export function installArgv(pm: PackageManager, packages: readonly string[]): string[] {
  if (!packages.length) return [];
  for (const p of packages) if (!SAFE_PACKAGE_SPEC.test(p)) throw new Error(`setup: refusing to install ${JSON.stringify(p)}`);
  return [...INSTALL_COMMANDS[pm], ...packages];
}

// --- the destination plan ----------------------------------------------------

/** The flag the person gave ("" = none). */
export type DestinationFlag = "" | "local" | "online" | "both";

/** What the machine said (discovery on SUPERBASED_NODE_URL, 500 ms). */
export interface MachineFact {
  answers: boolean;
  signedIn: boolean;
  /** AI Apps is on (`local.enabled`). */
  appsOn: boolean;
}

/**
 * The held-file fact the plan reads (pure): the file's destination when it is
 * there, valid, carries a usable gateway and has not expired; else "". An
 * expired or refused file counts as missing, so a rerun of setup (or setup
 * --key-only, the fix the SDKs' expiry warning names) runs the device flow
 * with no --replace (lead ruling).
 */
export function heldFact(
  read: { record: { gateway: string; destination: string; expiresAt: string } | null },
  now: number,
): "" | "online" | "both" {
  const r = read.record;
  if (!r || !r.gateway) return "";
  const at = r.expiresAt ? Date.parse(r.expiresAt) : NaN;
  if (!Number.isNaN(at) && at <= now) return "";
  return r.destination === "both" ? "both" : "online";
}

/** The facts the destination plan is decided from. */
export interface DestinationFacts {
  flag: DestinationFlag;
  replace: boolean;
  machine: MachineFact;
  /** `observer` is on PATH. */
  observerOnPath: boolean;
  /** The SDK-held file is there and valid, with this destination ("" when there is none, or it was refused). */
  held: "" | "online" | "both";
  /** A person can answer a question here (stdin and stdout are terminals). */
  tty: boolean;
}

/** How setup gets the key for the online leg. */
export type CredentialPlan = "none" | "held" | "machine" | "device";

/** A question setup asks on a terminal before it goes on. */
export type Question = "" | "local_or_online" | "online_instead";

/** What setup does, as the plan table decided it. */
export interface DestinationPlan {
  /** The table row that decided (one test case per row). */
  row: string;
  /** Where the hello goes ("" = setup stops). */
  destination: "" | "local" | "online" | "both";
  credential: CredentialPlan;
  /** Local AI Apps must be turned on first (the person's approval, 3.7). */
  enable: boolean;
  /** Ask this first (a terminal only); the answer picks between `destination` and `alternative`. */
  ask: Question;
  /** The destination a "yes" picks (for `ask`). */
  alternative: "" | "online" | "both";
  /** Lines to say. */
  notes: string[];
  /** When `destination` is "": the exit code. */
  exit: number;
}

/** The installer line for a person (ruling R8: setup never installs Observer itself). */
export const INSTALLER_LINE = "curl -fsSL https://superbased.app/install.sh | sh -s -- --apps --service";

const ADD_ONLINE = "Traces stay on this computer. To send them to your online dashboard too, run `setup --both` (`setup --online` sends them online only).";

interface PlanRow {
  id: string;
  when: (f: DestinationFacts) => boolean;
  plan: (f: DestinationFacts) => Omit<DestinationPlan, "row">;
}

const base = (o: Partial<DestinationPlan>): Omit<DestinationPlan, "row"> => ({
  destination: "",
  credential: "none",
  enable: false,
  ask: "",
  alternative: "",
  notes: [],
  exit: 0,
  ...o,
});

/** How the online leg gets its key: the held file unless replacing, Observer's own when signed in, else the device sign-in. */
function onlineCredential(f: DestinationFacts): CredentialPlan {
  if (f.held && !f.replace) return "held";
  if (f.machine.signedIn) return "machine";
  return "device";
}

/**
 * The destination plan table (plan 3.5), walked top down. Rows 1 to 5 of the
 * plan's table are `machine_signed_in`, `machine_apps_on`, `machine_apps_off`,
 * `observer_not_running` and `no_observer`; the rows before them are the
 * flags and the held file.
 */
export const DESTINATION_ROWS: readonly PlanRow[] = [
  // An SDK-held file is there: no second sign-in (idempotent), unless --replace.
  {
    id: "held",
    when: (f) => !!f.held && !f.replace && (f.flag === "" || f.flag === "online" || f.flag === "both") && !(f.flag === "" && f.machine.signedIn),
    plan: (f) => {
      const dest = f.flag || f.held;
      return base({ destination: dest, credential: "held", enable: dest === "both" && f.machine.answers && !f.machine.appsOn, notes: ["Using the SDK key already on this computer (run with --online --replace for a new one)."] });
    },
  },
  {
    id: "local_machine",
    when: (f) => f.flag === "local" && f.machine.answers,
    plan: (f) => base({ destination: "local", enable: !f.machine.appsOn }),
  },
  {
    id: "local_not_running",
    when: (f) => f.flag === "local" && f.observerOnPath,
    plan: () => base({ notes: ["Observer is installed but not running; start it with `observer start`, then run setup again."], exit: 4 }),
  },
  {
    id: "local_no_observer",
    when: (f) => f.flag === "local",
    plan: () => base({ notes: ["Observer is not installed on this computer. To trace locally, install it (this starts Observer and turns AI Apps on):", INSTALLER_LINE, "Then run setup again. Or run setup with --online to use your online dashboard instead."], exit: 4 }),
  },
  {
    id: "online_signed_in",
    // R10: setup never writes a file beside Observer's own key, --replace included.
    when: (f) => (f.flag === "online" || f.flag === "both") && f.machine.signedIn,
    plan: (f) =>
      f.flag === "online"
        ? base({ destination: "online", credential: "machine", notes: ["Observer is already signed in, so its own key is used; no second key is set up."] })
        : base({ destination: "both", credential: "machine", enable: !f.machine.appsOn, notes: ["Observer is already signed in; your apps send to both (no second key is set up)."] }),
  },
  {
    id: "online",
    when: (f) => f.flag === "online",
    plan: (f) => base({ destination: "online", credential: onlineCredential({ ...f, machine: { ...f.machine, signedIn: false } }) }),
  },
  {
    id: "both_machine",
    when: (f) => f.flag === "both" && f.machine.answers,
    plan: (f) => base({ destination: "both", credential: onlineCredential({ ...f, machine: { ...f.machine, signedIn: false } }), enable: !f.machine.appsOn }),
  },
  {
    id: "both_no_machine",
    when: (f) => f.flag === "both",
    plan: (f) => base({ destination: "both", credential: onlineCredential({ ...f, machine: { ...f.machine, signedIn: false } }), notes: ["No Observer answers on this computer, so traces go online until it runs."] }),
  },
  // Plan 3.5 table, row 1.
  {
    id: "machine_signed_in",
    when: (f) => f.machine.answers && f.machine.signedIn,
    plan: (f) => base({ destination: "both", credential: "machine", enable: !f.machine.appsOn, notes: ["Observer is already signed in; your apps send to both."] }),
  },
  // Row 2.
  {
    id: "machine_apps_on",
    when: (f) => f.machine.answers && f.machine.appsOn,
    plan: (f) => (f.tty ? base({ destination: "local", ask: "local_or_online", alternative: "both", credential: "none" }) : base({ destination: "local", notes: [ADD_ONLINE] })),
  },
  // Row 3.
  {
    id: "machine_apps_off",
    when: (f) => f.machine.answers,
    plan: () => base({ destination: "local", enable: true, notes: ["Or use your online dashboard instead: run setup with --online."] }),
  },
  // Row 4.
  {
    id: "observer_not_running",
    when: (f) => f.observerOnPath,
    plan: (f) =>
      f.tty
        ? base({ ask: "online_instead", alternative: "online", credential: "device", notes: ["Observer is installed but not running; start it with `observer start` and run setup again for local traces."] })
        : base({ notes: ["Observer is installed but not running; start it with `observer start` and run setup again, or run setup with --online for your online dashboard."], exit: 4 }),
  },
  // Row 5.
  {
    id: "no_observer",
    when: () => true,
    plan: () => base({ destination: "online", credential: "device", notes: ["No Observer on this computer: setting up your online dashboard (recommended). For local traces instead, run setup with --local."] }),
  },
];

/** Decide the destination plan (pure). */
export function planDestination(f: DestinationFacts): DestinationPlan {
  for (const r of DESTINATION_ROWS) if (r.when(f)) return { row: r.id, ...r.plan(f) };
  return { row: "none", ...base({ exit: 4 }) };
}

/** After the person answered a question: the plan with their answer applied (pure). */
export function answer(p: DestinationPlan, yes: boolean, f: DestinationFacts): DestinationPlan {
  if (!p.ask) return p;
  if (!yes) {
    if (p.ask === "online_instead") return { ...p, ask: "", destination: "", credential: "none", exit: 2 };
    return { ...p, ask: "", credential: "none" };
  }
  const dest = p.alternative;
  const credential = dest === "online" || dest === "both" ? onlineCredential({ ...f, machine: { ...f.machine, signedIn: false } }) : "none";
  return { ...p, ask: "", destination: dest, credential };
}

// --- next steps --------------------------------------------------------------

/** What to tell the agent or the person to do next (the one init line, or the start-script change). */
export interface NextSteps {
  /** `cjs`, `esm` or `next`. */
  kind: "cjs" | "esm" | "next";
  /** The one line (CommonJS), or "" (ESM: the start command; Next.js: the hook file). */
  initLine: string;
  /** Where it goes ("" when unknown). */
  where: string;
  /** The new start script (ESM), or "" when NODE_OPTIONS is the way. */
  startScript: string;
  /** For a start command setup cannot edit. */
  nodeOptions: string;
  /** Next.js: the file to add and its content. */
  file: { path: string; content: string } | null;
  /** Next.js: the packages to list in next.config's serverExternalPackages. */
  externalPackages: string[];
  /** Lines for making the traces richer (never the AI gateway). */
  richer: string[];
}

export const INIT_LINE_CJS = 'require("@superbased/sdk").init()';
export const REGISTER_FLAG = "--import @superbased/sdk/register";
export const NEXT_INSTRUMENTATION = [
  "export async function register() {",
  '  if (process.env.NEXT_RUNTIME === "nodejs") {',
  '    await import("@superbased/sdk/register");',
  "  }",
  "}",
  "",
].join("\n");

/** The richer-traces pointers (plan 3.5 phase 6). */
export const RICHER: readonly string[] = [
  'Wrap your request handler in observe(fn, { kind: Kind.AGENT, name: "handle-request" }) so each request is one trace.',
  "Name the end user with propagateAttributes({ user: <an opaque id, never an email> }, () => ...).",
  "Docs: https://superbased.app/docs/sdk/overview",
];

/** The start script with the register flag added after `node` ("" when the script does not run node directly). */
export function withRegisterFlag(script: string): string {
  if (!script) return "";
  if (script.includes("@superbased/sdk/register")) return script;
  const m = /(^|\s|&&\s*)(node)(\s)/.exec(script);
  if (!m) return "";
  const at = m.index + m[1].length + m[2].length;
  return `${script.slice(0, at)} ${REGISTER_FLAG}${script.slice(at)}`;
}

/** The next steps for a detected project (pure). */
export function nextSteps(d: Detected): NextSteps {
  const out: NextSteps = { kind: "cjs", initLine: "", where: "", startScript: "", nodeOptions: "", file: null, externalPackages: [], richer: [...RICHER] };
  if (d.next) {
    out.kind = "next";
    out.file = { path: d.entries.some((e) => e.startsWith("src/")) ? "src/instrumentation.ts" : "instrumentation.ts", content: NEXT_INSTRUMENTATION };
    out.externalPackages = ["@superbased/sdk", ...d.targets.map((t) => packageOf(TARGET_INFO.find((x) => x.name === t)!.library))];
    return out;
  }
  if (d.moduleType === "esm") {
    out.kind = "esm";
    // The app's own start script with the flag, else one that runs the entry with it.
    out.startScript = withRegisterFlag(d.startScript) || (d.entries[0] ? `node ${REGISTER_FLAG} ${d.entries[0]}` : "");
    out.nodeOptions = `NODE_OPTIONS="${REGISTER_FLAG}"`;
    out.where = "package.json scripts.start";
    return out;
  }
  out.initLine = INIT_LINE_CJS;
  out.where = d.entries[0] ?? "";
  return out;
}
