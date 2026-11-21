import { test } from "node:test";
import assert from "node:assert/strict";
import type { CoverageResponse, CoverageRun, CoverageSupported } from "./codeSecurityApi.ts";
import type { ScanOnline, ScanStep, SecurityProject, SecurityRun } from "./codeSecurity.ts";
import {
  capList,
  coverageSummary,
  detectedNotScanned,
  ecosystemForPath,
  ecosystemRows,
  fileMatches,
  filterProjects,
  hasCoverage,
  idleHiddenLine,
  latestRuns,
  needsOnline,
  onlineCheckAction,
  supportedOnlineAction,
  problemRunText,
  problemRuns,
  projectEcosystems,
  reasonAction,
  reasonGroups,
  setupNoticeLine,
  setupNotices,
  supportNote,
  ONLINE_ONLY_OPEN_NOTE,
} from "./secCoverage.ts";

const isSetup = (r?: string) => r === "not_installed" || r === "disabled";

const supported: CoverageSupported[] = [
  { ecosystem: "npm", files: ["package-lock.json", "package.json"], drivers: ["scalibr", "osv"], advisory_source: "OSV npm", database_installed: true, online_only: false },
  { ecosystem: "Go", files: ["go.mod", "go.sum"], drivers: ["scalibr"], advisory_source: "OSV Go", database_installed: false, online_only: false },
  { ecosystem: "Conan", files: ["conan.lock"], drivers: ["osv"], advisory_source: "", database_installed: false, online_only: false, note: "OSV has no Conan ecosystem" },
  { ecosystem: "NuGet", files: ["*.csproj"], drivers: ["osv"], advisory_source: "OSV NuGet", database_installed: false, online_only: true },
  { ecosystem: "Ruby", files: ["Gemfile.lock"], drivers: ["osv"], advisory_source: "OSV RubyGems", database_installed: true, online_only: false, note: "lockfile only" },
];

function run(over: Partial<CoverageRun>): CoverageRun {
  return { driver: "scalibr", started_at: "2026-11-06T10:00:00Z", outcome: "ok", files_scanned: 1, scanned: [], skipped: [], skipped_total: 0, ...over };
}

const cov: CoverageResponse = {
  supported,
  reasons: { no_lockfile: "No lockfile was found" },
  projects: [
    {
      project_root_hash: "h1",
      name: "alpha",
      active: true,
      runs: [
        run({ scanned: ["npm", "Go"], skipped: [{ path: "web/package.json", reason: "no_lockfile" }, { path: "conan.lock", reason: "no_advisory_data" }], skipped_total: 2 }),
        run({ driver: "osv", scanned: ["npm"], skipped: [{ path: "web/package.json", reason: "no_lockfile" }], skipped_total: 1 }),
      ],
    },
    {
      project_root_hash: "h2",
      name: "beta",
      active: true,
      runs: [run({ scanned: ["npm"], skipped: [{ path: "go.mod", reason: "unpinned_version" }, { path: "app/App.csproj", reason: "needs_online_lookup" }], skipped_total: 5 })],
    },
    { project_root_hash: "h3", name: "gamma", active: false, runs: [] },
  ],
};

test("reasonAction: one row per reason, unknown is empty", () => {
  const cases: [string, string][] = [
    ["no_lockfile", "Commit a lockfile"],
    ["unpinned_version", "Pin exact versions"],
    ["no_extractor", "Not supported yet"],
    ["needs_online_lookup", "Scan these projects with online checks"],
    ["no_advisory_data", "No vulnerability data exists for this ecosystem"],
    ["isolation_refused", "The isolated scan could not start for this project"],
    ["unknown", ""],
    ["something_new", ""],
  ];
  for (const [r, want] of cases) assert.equal(reasonAction(r), want, r);
});

test("fileMatches: names, globs and path tails", () => {
  const cases: [string, string, boolean][] = [
    ["go.mod", "a/b/go.mod", true],
    ["go.mod", "a/b/ugo.mod", false],
    ["*.csproj", "app/App.csproj", true],
    ["*.csproj", "app/App.csproj.bak", false],
    ["gradle/libs.versions.toml", "x/gradle/libs.versions.toml", true],
    ["GEMFILE.LOCK", "Gemfile.lock", true],
    ["go.mod", "C:\\p\\go.mod", true],
  ];
  for (const [p, f, want] of cases) assert.equal(fileMatches(p, f), want, `${p} ${f}`);
});

test("ecosystemForPath: first supported match, else empty", () => {
  assert.equal(ecosystemForPath("web/package.json", supported), "npm");
  assert.equal(ecosystemForPath("a/App.csproj", supported), "NuGet");
  assert.equal(ecosystemForPath("README.md", supported), "");
});

test("ecosystemForPath: a found but unread file still names its ecosystem", () => {
  const withUnread = [{ ecosystem: "Hex", files: ["mix.lock"], unread_files: ["rebar.lock", "mix.exs"], drivers: ["scalibr"], advisory_source: "OSV Hex", database_installed: false, online_only: false }];
  assert.equal(ecosystemForPath("apps/x/rebar.lock", withUnread), "Hex");
  assert.equal(ecosystemForPath("mix.lock", withUnread), "Hex");
});

test("latestRuns keeps the newest run per driver", () => {
  const runs = [run({ started_at: "1" }), run({ started_at: "2", scanned: ["Go"] }), run({ driver: "osv", started_at: "0" })];
  const got = latestRuns(runs);
  assert.deepEqual(got.map((r) => `${r.driver}:${r.started_at}`), ["osv:0", "scalibr:2"]);
});

test("projectEcosystems: sorted union of the latest runs", () => {
  assert.deepEqual(projectEcosystems(cov.projects[0]), ["Go", "npm"]);
  assert.deepEqual(projectEcosystems(cov.projects[2]), []);
});

test("supportNote: one case per honest remark", () => {
  assert.equal(supportNote(supported[0]), null);
  assert.deepEqual(supportNote(supported[2]), { tone: "warn", text: "OSV has no Conan ecosystem" });
  assert.deepEqual(supportNote({ ...supported[2], note: "" }), { tone: "warn", text: "No advisory data" });
  assert.deepEqual(supportNote({ ...supported[2], note: "not read in this build: OSV publishes advisories" }), { tone: "warn", text: "Not read in this build: OSV publishes advisories" });
  assert.deepEqual(supportNote(supported[3]), { tone: "warn", text: "Online checks only" });
  // With the online check already open the row stops saying to turn it on.
  assert.deepEqual(supportNote(supported[3], true), { tone: "neutral", text: ONLINE_ONLY_OPEN_NOTE });
  assert.doesNotMatch(ONLINE_ONLY_OPEN_NOTE, /turn on/);
  assert.deepEqual(supportNote(supported[4]), { tone: "neutral", text: "lockfile only" });
  assert.deepEqual(supportNote({ ...supported[2], note: undefined }), { tone: "warn", text: "No advisory data" });
});

test("ecosystemRows: scanned projects, detected-only projects, order", () => {
  const rows = ecosystemRows(cov);
  const npm = rows.find((r) => r.ecosystem === "npm")!;
  assert.deepEqual(npm.scanned.map((p) => p.name), ["alpha", "beta"]);
  const go = rows.find((r) => r.ecosystem === "Go")!;
  assert.deepEqual(go.scanned.map((p) => p.name), ["alpha"]);
  assert.deepEqual(go.detectedOnly.map((p) => p.name), ["beta"]);
  const conan = rows.find((r) => r.ecosystem === "Conan")!;
  assert.deepEqual(conan.detectedOnly.map((p) => p.name), ["alpha"]);
  assert.equal(rows[0].ecosystem, "npm");
  assert.equal(rows[rows.length - 1].ecosystem, "Ruby");
});

test("ecosystemRows: an ecosystem a run scanned that the list lacks gets a row", () => {
  const c: CoverageResponse = { ...cov, projects: [{ project_root_hash: "h", name: "x", active: true, runs: [run({ scanned: ["Zig"] })] }] };
  const z = ecosystemRows(c).find((r) => r.ecosystem === "Zig")!;
  assert.equal(z.supported, null);
  assert.equal(z.scanned.length, 1);
});

test("detectedNotScanned lists only skipped-only ecosystems", () => {
  const got = detectedNotScanned(cov).map((d) => d.ecosystem).sort();
  assert.deepEqual(got, ["Conan", "Go", "NuGet"]);
});

test("reasonGroups: grouped, deduped across drivers, hidden counted, words from the server", () => {
  const groups = reasonGroups(cov);
  const lock = groups.find((g) => g.reason === "no_lockfile")!;
  assert.equal(lock.entries.length, 1);
  assert.equal(lock.words, "No lockfile was found");
  assert.equal(lock.action, "Commit a lockfile");
  // beta skipped_total 5 with 2 listed: 3 files are counted under unknown.
  const unknown = groups.find((g) => g.reason === "unknown")!;
  assert.equal(unknown.hidden, 3);
  assert.equal(unknown.count, 3);
  assert.equal(unknown.words, "unknown");
  const unpinned = groups.find((g) => g.reason === "unpinned_version")!;
  assert.equal(unpinned.words, "unpinned version");
  const counts = groups.map((g) => g.count);
  assert.deepEqual(counts, [...counts].sort((a, b) => b - a));
  // Each group names its projects (what a group action scans), sorted.
  assert.deepEqual(groups.find((g) => g.reason === "needs_online_lookup")!.projectHashes, ["h2"]);
  assert.deepEqual(lock.projectHashes, ["h1"]);
});

// The online-only files' "Check online" (dashboard CLI parity plan, decision P-1).

test("needsOnline: a project whose latest run left an online-only file", () => {
  assert.equal(needsOnline(cov.projects[1]), true);
  assert.equal(needsOnline(cov.projects[0]), false);
  assert.equal(needsOnline(cov.projects[2]), false);
});

test("onlineCheckAction: none, set up, busy or a scan of the projects with online checks", () => {
  const ready: ScanStep[] = [{ id: "deps", label: "Dependencies (OSV)", ready: true }];
  const notReady: ScanStep[] = [{ id: "deps", label: "Dependencies (OSV)", ready: false, reason: "not_installed" }];
  const open: ScanOnline = { step: "deps", open: true };
  const off: ScanOnline = { step: "deps", open: false, reason: "online_checks_off" };
  const scalibr: ScanOnline = { step: "deps", open: false, reason: "online_needs_scalibr" };
  const cases: { name: string; online?: ScanOnline; steps: ScanStep[]; projects: string[]; running: boolean; kind: string; label?: RegExp }[] = [
    { name: "no projects", online: open, steps: ready, projects: [], running: false, kind: "none" },
    { name: "no online check on this node", steps: ready, projects: ["h1"], running: false, kind: "none" },
    { name: "the dependency step is not ready", online: open, steps: notReady, projects: ["h1"], running: false, kind: "setup", label: /dependency scanners in Scanners/ },
    { name: "the dependency step is missing", online: open, steps: [], projects: ["h1"], running: false, kind: "setup", label: /dependency scanners/ },
    { name: "online checks off", online: off, steps: ready, projects: ["h1"], running: false, kind: "setup", label: /Scanners > Package checks/ },
    { name: "only osv-scanner on", online: scalibr, steps: ready, projects: ["h1"], running: false, kind: "setup", label: /SCALIBR driver/ },
    { name: "a scan is running", online: open, steps: ready, projects: ["h1"], running: true, kind: "busy", label: /^Check online$/ },
    { name: "one project", online: open, steps: ready, projects: ["h1"], running: false, kind: "scan", label: /^Check online$/ },
    { name: "several projects", online: open, steps: ready, projects: ["h1", "h2"], running: false, kind: "scan", label: /^Check 2 projects online$/ },
  ];
  for (const c of cases) {
    const a = onlineCheckAction({ online: c.online, steps: c.steps, projects: c.projects, running: c.running });
    assert.equal(a.kind, c.kind, c.name);
    if (c.label && a.kind !== "none") assert.match(a.label, c.label, c.name);
  }
  const scan = onlineCheckAction({ online: { step: "deps", open: true, relay: true }, steps: ready, projects: ["h1", "h2"], running: false });
  assert.equal(scan.kind, "scan");
  if (scan.kind === "scan") {
    // The start body scans exactly these projects, the dependency step only, online.
    assert.deepEqual(scan.body, { projects: ["h1", "h2"], steps: ["deps"], online: true });
    assert.match(scan.sends, /organization's relay/);
  }
  const why = onlineCheckAction({ online: off, steps: ready, projects: ["h1"], running: false });
  if (why.kind === "setup") {
    assert.match(why.why, /Online package checks are off/);
    assert.equal(why.fix, "package-checks");
  }
});

test("supportedOnlineAction: the supported row's control, with or without projects", () => {
  const ready: ScanStep[] = [{ id: "deps", label: "Dependencies (OSV)", ready: true }];
  const open: ScanOnline = { step: "deps", open: true };
  const off: ScanOnline = { step: "deps", open: false, reason: "online_checks_off" };
  const cases: { name: string; online?: ScanOnline; projects: string[]; kind: string; label?: RegExp }[] = [
    { name: "projects and an open gate: check them online", online: open, projects: ["h1", "h2"], kind: "scan", label: /^Check 2 projects online$/ },
    { name: "projects and a closed gate: where to turn it on", online: off, projects: ["h1"], kind: "setup", label: /Scanners > Package checks/ },
    { name: "no project and a closed gate: still where to turn it on", online: off, projects: [], kind: "setup", label: /Scanners > Package checks/ },
    { name: "no project and an open gate: nothing to check", online: open, projects: [], kind: "none" },
    { name: "no online check in this build", projects: [], kind: "none" },
  ];
  for (const c of cases) {
    const a = supportedOnlineAction({ online: c.online, steps: ready, projects: c.projects, running: false });
    assert.equal(a.kind, c.kind, c.name);
    if (c.label && a.kind !== "none") assert.match(a.label, c.label, c.name);
  }
});

test("coverageSummary and hasCoverage", () => {
  assert.deepEqual(coverageSummary(cov), { projectsWithRuns: 2, ecosystemsScanned: 2, filesSkipped: 8 });
  assert.equal(hasCoverage(cov), true);
  assert.equal(hasCoverage({ ...cov, projects: [cov.projects[2]] }), false);
  assert.equal(hasCoverage(null), false);
});

function srun(over: Partial<SecurityRun>): SecurityRun {
  return { driver: "osv", scope: "scheduled", outcome: "not_scanned", reason: "not_installed", findings: 0, started_at: "", duration_ms: 0, ...over };
}
function proj(hash: string, name: string, active: boolean, runs: SecurityRun[]): SecurityProject {
  return { project_root_hash: hash, name, active, state: "clean", reason: "", blocking: 0, open: 0, counts: [], runs };
}

test("setupNotices: once per (driver, reason), counted by project", () => {
  const ps = [
    proj("a", "a", true, [srun({}), srun({ driver: "opengrep", reason: "disabled" })]),
    proj("b", "b", true, [srun({}), srun({ driver: "scalibr", outcome: "failed", reason: "isolation_refused" })]),
  ];
  assert.deepEqual(setupNotices(ps, isSetup), [
    { driver: "osv", reason: "not_installed", projects: 2 },
    { driver: "opengrep", reason: "disabled", projects: 1 },
  ]);
});

test("setupNoticeLine: known and unknown setup reasons", () => {
  assert.equal(setupNoticeLine({ driver: "osv", reason: "not_installed", projects: 3 }), "osv-scanner is not installed, so 3 projects were not scanned with it.");
  assert.equal(setupNoticeLine({ driver: "opengrep", reason: "disabled", projects: 1 }), "Opengrep is turned off, so 1 project was not scanned with it.");
  assert.match(setupNoticeLine({ driver: "x", reason: "weird_thing", projects: 2 }), /^x is not set up \(weird thing\)/);
});

test("problemRuns drops setup reasons; problemRunText names the reason in words", () => {
  const runs = [srun({}), srun({ driver: "scalibr", outcome: "failed", reason: "isolation_refused" }), srun({ driver: "native", outcome: "ok", reason: "" })];
  const got = problemRuns(runs, isSetup);
  assert.equal(got.length, 1);
  assert.equal(problemRunText(got[0]), "Dependencies (scalibr): failed (isolation refused the run)");
  assert.equal(problemRunText({ driver: "osv", outcome: "failed", reason: "child exited" }), "Dependencies (osv): failed (child exited)");
  assert.equal(problemRunText({ driver: "osv", outcome: "unknown", reason: undefined }), "Dependencies (osv): unknown");
});

test("filterProjects: search by name or path, idle switch, hidden count", () => {
  const ps = [
    { ...proj("a", "alpha", true, []), root_path: "/w/alpha" },
    { ...proj("b", "2026-10-04_063002", false, []), root_path: "/tmp/x" },
    { ...proj("c", "alpine", false, []), root_path: "/w/alpine" },
  ];
  assert.deepEqual(filterProjects(ps, "", false).rows.map((p) => p.name), ["alpha"]);
  assert.equal(filterProjects(ps, "", false).hiddenIdle, 2);
  assert.equal(filterProjects(ps, "", true).rows.length, 3);
  assert.equal(filterProjects(ps, "alp", true).rows.length, 2);
  assert.equal(filterProjects(ps, "/TMP", true).rows[0].name, "2026-10-04_063002");
  assert.equal(filterProjects(ps, "alp", false).hiddenIdle, 1);
});

test("idleHiddenLine and capList", () => {
  assert.equal(idleHiddenLine(0), "");
  assert.equal(idleHiddenLine(1), "1 idle project hidden");
  assert.equal(idleHiddenLine(112), "112 idle projects hidden");
  assert.deepEqual(capList([1, 2, 3, 4], 2), { shown: [1, 2], more: 2 });
  assert.deepEqual(capList([1], 5), { shown: [1], more: 0 });
});
