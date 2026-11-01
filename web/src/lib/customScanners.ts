// Custom scanners (component security.scan.custom; security pillar plan
// section 8.6, Phase D3): the pure helpers behind the Code security page's
// Scanners card. Every choice is a picker over a closed set the server
// sends (D-571); nothing here invents an option.

export const CUSTOM_ROUTE = "/api/security/scanners/custom";

export type CustomLimits = {
  wall_seconds: number;
  memory_mib: number;
  cpu_seconds: number;
  output_mib: number;
  child_processes: number;
  file_mib: number;
};

export type CustomPickers = {
  limits: Record<string, number[]>;
  children_unit: string;
  inputs: string[];
  outputs: string[];
  caches: string[];
  categories: string[];
  severities: string[];
};

export type CustomManifest = {
  name: string;
  version: string;
  template?: string;
  executable: string;
  executable_sha256?: string;
  argv: string[];
  input: string;
  output: string;
  limits: CustomLimits;
  companions?: { path: string; sha256?: string }[];
  cache: string;
  self_test?: { fixture: string; expect_rules: string[] };
  network: { mode: string; hosts?: string[] };
  category: string;
  severity_map: { source: string; property?: string; levels: Record<string, string> };
};

export type CustomSelfTest = {
  ran: boolean;
  passed: boolean;
  at?: string;
  missing?: string[];
  detail?: string;
};

export type CustomRecord = {
  id: string;
  manifest: CustomManifest;
  manifest_sha256: string;
  pin: string;
  accepted_at: string;
  accepted_via: string;
  org_approved?: boolean;
  exec_note?: string;
  self_test: CustomSelfTest;
};

export type CustomTemplate = { id: string; title: string; note: string };

export type CustomList = {
  scanners: CustomRecord[];
  unreadable?: Record<string, string>;
  templates: CustomTemplate[];
  pickers: CustomPickers;
  confirm_token: string;
};

export type CustomPrepared = {
  ID: string;
  Manifest: CustomManifest;
  FileSHA256: string;
  ManifestSHA256: string;
  Candidates: { Executable: string[] | null; Companions: (string[] | null)[] | null };
  Pin: string;
  ExecNote: string;
  OrgApproved: boolean;
  Replaces: boolean;
  Note: string;
};

export type CustomChoices = {
  executable?: string;
  companions?: string[];
  input?: string;
  output?: string;
  limits?: Partial<CustomLimits>;
  cache?: string;
  network_none?: boolean;
  category?: string;
  severity?: Record<string, string>;
};

export type CustomRunReport = {
  driver: string;
  verdict: { Outcome: string; Reason: string };
  findings: number;
  refused: number;
  closed: number;
  isolation?: string;
  not_isolated_why?: string;
  containment: { Rung: string; Contained: boolean; Label: string };
  runner_outcome: string;
  detail?: string;
  network?: string;
  toolchain_skew?: string;
};

// LIMIT_LABEL names each limit picker; the child-process unit comes from
// the server per OS (tasks on Linux, processes on Windows and macOS).
const LIMIT_LABEL: Readonly<Record<string, string>> = {
  wall_seconds: "Wall time (seconds)",
  memory_mib: "Memory (MiB)",
  cpu_seconds: "CPU time (seconds)",
  output_mib: "Output (MiB)",
  child_processes: "Child processes",
  file_mib: "Largest file written (MiB)",
};

export function limitLabel(field: string, childrenUnit: string): string {
  const base = LIMIT_LABEL[field] ?? field;
  return field === "child_processes" ? `${base}, counted in ${childrenUnit}` : base;
}

// selfTestWords says what the self-test state means for a run with no
// findings: "scanned" is not "clean" (JSP-12).
export function selfTestWords(st: CustomSelfTest | undefined, hasSelfTest: boolean): { tone: "ok" | "warn" | "danger"; text: string } {
  if (!hasSelfTest) return { tone: "warn", text: "no self-test: a run with no findings is unknown, never clean" };
  if (!st?.ran) return { tone: "warn", text: "self-test not run yet: runs stay unknown" };
  if (st.passed) return { tone: "ok", text: "self-test passed" };
  const missing = st.missing?.length ? ` (missing ${st.missing.join(", ")})` : "";
  return { tone: "danger", text: `self-test failed${missing}: runs stay unknown` };
}

// isolationWords is the run's isolation and containment line.
export function isolationWords(rep: CustomRunReport): string {
  const iso = rep.isolation ? `isolated (${rep.isolation})` : `not isolated: ${rep.not_isolated_why ?? "no reason given"}`;
  const line = `${iso}; ${rep.containment.Label || "containment unknown"}`;
  // A manifest with declared hosts: the server's sentence says they are
  // not enforced.
  return rep.network ? `${line}; ${rep.network}` : line;
}

// verdictWords is the run's verdict.
export function verdictWords(rep: CustomRunReport): string {
  const r = rep.verdict.Reason ? ` (${rep.verdict.Reason.replaceAll("_", " ")})` : "";
  return `${rep.verdict.Outcome.replaceAll("_", " ")}${r}`;
}

// readyToAccept: the confirm dialog shows exactly one prepared manifest and
// its digest; accepting sends that digest back.
export function readyToAccept(p: CustomPrepared | null): boolean {
  return p !== null && /^[0-9a-f]{64}$/.test(p.ManifestSHA256);
}

// runProjectOptions turns the known projects (GET /api/projects, as
// picker options keyed by root path) into the run picker's options, with a
// leading "choose" row so nothing runs until a project is picked.
export function runProjectOptions(projects: readonly { id: string; label: string }[]): { value: string; label: string }[] {
  return [
    { value: "", label: projects.length ? "Choose a project" : "No projects yet: one appears once an AI tool session runs in it" },
    ...projects.map((p) => ({ value: p.id, label: `${p.label} (${p.id})` })),
  ];
}

// hostsLabel is the network picker's label for declared hosts: the list is
// not enforced, and the label says so plainly.
export function hostsLabel(hosts: readonly string[]): string {
  return `the declared hosts ${hosts.join(", ")} (not enforced: the scanner can reach any host, and the run is not isolated)`;
}
