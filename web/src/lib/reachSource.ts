// reachSource - the wire types and the plain-words helpers of the Scanners
// card's Go source check row (OS and CI vulnerability scanning plan section
// 14.5 item 3b, 3b-src): osv-scanner's Go call analysis, once per go.mod,
// which runs this machine's Go toolchain on the project. Off per project
// until the developer opts in. GET and PUT
// /api/security/reach/go-source?project=<root hash>; POST .../run starts one.

/** One go.mod's stored answer. */
export type ReachSourceRun = {
  target: string;
  reason?: string;
  reason_text?: string;
  called: number;
  not_called: number;
  /** The Go release the standard library was evaluated at (the go.mod's). */
  assumed_go?: string;
};

/** GET /api/security/reach/go-source. */
export type ReachSourceStatus = {
  project: string;
  compiled: boolean;
  selected: boolean;
  opted_in: boolean;
  allow_unisolated: boolean;
  opted_at?: string;
  surface?: string;
  isolation_available: boolean;
  text: string;
  memory_mib: number;
  timeout_seconds: number;
  max_modules: number;
  running: boolean;
  last_error?: string;
  runs: ReachSourceRun[];
  confirm_token?: string;
};

/** reachSourceHeading is the row's one-line state. */
export function reachSourceHeading(v: ReachSourceStatus): string {
  if (!v.compiled) return "The Go source check is not in this build.";
  if (!v.selected) return "The Go source check is off: turn it on with its switch above.";
  if (!v.opted_in) return "Off for this project. It runs only after you opt in, and only when you start it.";
  if (v.running) return "Running: one go.mod at a time.";
  return "On for this project. It runs only when you start it.";
}

/** reachSourceIsolationLine says how a run would be held. */
export function reachSourceIsolationLine(v: Pick<ReachSourceStatus, "isolation_available" | "allow_unisolated">): string {
  if (v.isolation_available) return "Runs in the isolation component's no-network run.";
  if (v.allow_unisolated) return "Isolation is not available here; you allowed it to run without it (labelled not isolated).";
  return "Isolation is not available here, so a run is refused unless you allow it to run without it.";
}

/** reachSourceCanRun reports whether the Run button may start a run. */
export function reachSourceCanRun(v: ReachSourceStatus): boolean {
  return v.compiled && v.selected && v.opted_in && !v.running && (v.isolation_available || v.allow_unisolated);
}

/** reachSourceRunLine is one go.mod's answer in words. */
export function reachSourceRunLine(r: ReachSourceRun): string {
  if (r.reason) return `not checked: ${r.reason_text || r.reason}`;
  let s = `${r.called} package${r.called === 1 ? "" : "s"} with a listed function called, ${r.not_called} with none called`;
  if (r.assumed_go) s += `; standard library evaluated at go${r.assumed_go} from the go.mod`;
  return s;
}

/** reachSourceCapsLine is the developer's caps in words. */
export function reachSourceCapsLine(v: Pick<ReachSourceStatus, "memory_mib" | "timeout_seconds" | "max_modules">): string {
  const gib = v.memory_mib / 1024;
  const mem = Number.isInteger(gib) ? `${gib} GiB` : `${v.memory_mib} MiB`;
  return `Caps: ${mem} per go.mod (GOMEMLIMIT at 90 %), ${v.timeout_seconds} s per go.mod, at most ${v.max_modules} go.mod files ([security.reach.go]).`;
}
