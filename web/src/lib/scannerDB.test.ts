import assert from "node:assert/strict";
import test from "node:test";

import {
  scannerDBAcceptLabel,
  scannerDBLine,
  scannerDBStage,
  exploitCitations,
  exploitKindLine,
  imageDriverLine,
  imageDriverOptions,
  imageDriverPatch,
  megabytes,
  osDBLine,
  osReleaseNotes,
  osSizesLine,
  osvInstallFor,
  trivyDBAcceptLabel,
  trivyDBLine,
  trivyEngineLine,
  type ScannerImageStatus,
  type ScannerOSDBStatus,
  type ScannerTrivyDBStatus,
  type ScannerTrivyImageStatus,
  type ScannerDBStatus,
} from "./scannerDB.ts";

function status(over: Partial<ScannerDBStatus>): ScannerDBStatus {
  return {
    accepted: false,
    approx_mb: 300,
    source: "osv-vulnerabilities.storage.googleapis.com",
    text: "",
    managed: false,
    blocked: "database_not_accepted",
    installed: 0,
    ...over,
  };
}

test("stage: managed, waiting and accepted; unknown reads null", () => {
  assert.equal(scannerDBStage(null), null);
  assert.equal(scannerDBStage(status({})), "waiting");
  assert.equal(scannerDBStage(status({ accepted: true, blocked: undefined })), "accepted");
  assert.equal(scannerDBStage(status({ managed: true })), "managed");
});

test("before the accept the line names the size, the source and that nothing is scanned", () => {
  const line = scannerDBLine(status({}));
  assert.ok(line.includes("about 300 MB"), line);
  assert.ok(line.includes("osv-vulnerabilities.storage.googleapis.com"), line);
  assert.ok(line.includes("not scanned"), line);
  assert.ok(!line.toLowerCase().includes("clean"), line);
  assert.equal(scannerDBAcceptLabel(status({})), "Accept and download about 300 MB");
});

test("after the accept the line says where and who", () => {
  const line = scannerDBLine(status({ accepted: true, accepted_at: "2026-10-21T09:00:00Z", accepted_on: "cli", by: "dev" }));
  assert.ok(line.includes("(cli, dev)") && line.includes("automatic"), line);
});

// ------------------------------------------------- OS, image, Trivy, exploit

function osStatus(over: Partial<ScannerOSDBStatus>): ScannerOSDBStatus {
  return {
    accepted: false,
    text: "",
    source: "superbased.app",
    sizes: [
      { name: "Debian", approx_mb: 62 },
      { name: "Alpine", approx_mb: 7 },
    ],
    managed: false,
    installed: [],
    disk_bytes: 0,
    ...over,
  };
}

test("OS databases: one line per stage, never clean before the accept", () => {
  const cases: { name: string; os: ScannerOSDBStatus; want: string[] }[] = [
    { name: "waiting", os: osStatus({}), want: ["not downloaded", "superbased.app only", "not scanned"] },
    { name: "managed", os: osStatus({ managed: true }), want: ["organization's mirror", "nothing to accept"] },
    { name: "accepted, none yet", os: osStatus({ accepted: true, accepted_on: "dashboard", by: "dev" }), want: ["(dashboard, dev)", "no release downloaded yet"] },
    {
      name: "accepted, two installed",
      os: osStatus({
        accepted: true,
        accepted_on: "cli",
        disk_bytes: 69_000_000,
        installed: [
          { distro: "debian", version: "12", artifact: "Debian-12", epoch: "e", bytes: 61_000_000 },
          { distro: "alpine", version: "3.20", artifact: "Alpine-3.20", epoch: "e", bytes: 8_000_000 },
        ],
      }),
      want: ["2 releases installed", "69 MB on disk"],
    },
  ];
  for (const c of cases) {
    const line = osDBLine(c.os);
    for (const w of c.want) assert.ok(line.includes(w), `${c.name}: ${line}`);
    assert.ok(!line.toLowerCase().includes("clean"), `${c.name}: ${line}`);
  }
  assert.equal(osSizesLine(osStatus({})), "Debian up to 62 MB, Alpine up to 7 MB");
  assert.deepEqual(
    osReleaseNotes({ distro: "alpine", version: "3.20", artifact: "a", epoch: "e", bytes: 1, fixed_only: true, last_error: "feed_unavailable" }),
    ["fixed issues only", "last refresh failed: feed_unavailable"],
  );
});

function image(over: Partial<ScannerImageStatus>): ScannerImageStatus {
  return { driver: "scalibr", default: "scalibr", choices: ["scalibr", "trivy"], scalibr_compiled: true, trivy_compiled: true, ...over };
}

test("image driver: the picker offers the compiled drivers and patches only a change", () => {
  const opts = imageDriverOptions(image({}));
  assert.deepEqual(opts.map((o) => o.value), ["scalibr", "trivy"]);
  assert.ok(opts[0].label.endsWith("(default)") && !opts[1].label.endsWith("(default)"), JSON.stringify(opts));
  const cases: { name: string; img: ScannerImageStatus; next: string; want: unknown }[] = [
    { name: "same as in force", img: image({}), next: "scalibr", want: null },
    { name: "not compiled", img: image({ choices: ["trivy"], driver: "trivy", default: "trivy" }), next: "scalibr", want: null },
    { name: "unknown", img: image({}), next: "grype", want: null },
    { name: "default to trivy", img: image({}), next: "trivy", want: { key: "security.scan.image.driver", value: "trivy", was: "" } },
    {
      name: "configured back",
      img: image({ driver: "trivy", configured: "trivy" }),
      next: "scalibr",
      want: { key: "security.scan.image.driver", value: "scalibr", was: "trivy" },
    },
  ];
  for (const c of cases) assert.deepEqual(imageDriverPatch(c.img, c.next), c.want, c.name);
  assert.ok(imageDriverLine(image({})).includes("this build's default"));
  assert.ok(imageDriverLine(image({ driver: "trivy", configured: "trivy" })).includes("set in [security.scan.image] driver"));
  assert.ok(imageDriverLine(image({ choices: ["trivy"], driver: "trivy", default: "trivy" })).includes("only image driver"));
  assert.ok(imageDriverLine(image({ choices: [] })).includes("cannot be scanned"));
});

function trivyDB(over: Partial<ScannerTrivyDBStatus>): ScannerTrivyDBStatus {
  return {
    accepted: false,
    text: "",
    source: "ghcr.io",
    approx_download_mb: 140,
    approx_disk_mb: 1700,
    managed: false,
    installed: false,
    ...over,
  };
}

test("Trivy: the engine and database lines per state", () => {
  const engine = (over: Partial<ScannerTrivyImageStatus>): ScannerTrivyImageStatus => ({
    selected: true,
    installed: true,
    pinned: true,
    tested_version: "0.75.0",
    db: trivyDB({}),
    ...over,
  });
  assert.ok(trivyEngineLine(engine({ selected: false })).includes("switch above"));
  assert.ok(trivyEngineLine(engine({ installed: false })).includes("not installed"));
  // The guided install is the IaC scanners card on the same tab, never a
  // Settings place that does not exist (dashboard CLI parity plan, B-CS2).
  assert.ok(trivyEngineLine(engine({ installed: false })).includes("IaC scanners card"));
  assert.ok(!trivyEngineLine(engine({ installed: false })).includes("Settings >"));
  assert.ok(trivyEngineLine(engine({})).includes("pinned") && trivyEngineLine(engine({})).includes("0.75.0"));
  const cases: { name: string; db: ScannerTrivyDBStatus; want: string[] }[] = [
    { name: "waiting", db: trivyDB({}), want: ["about 140 MB", "about 1700 MB on disk", "ghcr.io", "not scanned"] },
    { name: "managed", db: trivyDB({ managed: true }), want: ["does not serve Trivy's database yet", "nothing is accepted"] },
    { name: "accepted, not yet", db: trivyDB({ accepted: true, accepted_on: "cli" }), want: ["not downloaded yet"] },
    {
      name: "accepted, installed, failed refresh",
      db: trivyDB({ accepted: true, accepted_on: "dashboard", installed: true, bytes: 1_690_000_000, last_error: "feed_unavailable" }),
      want: ["installed", "1690 MB on disk", "Last refresh failed: feed_unavailable"],
    },
  ];
  for (const c of cases) {
    const line = trivyDBLine(c.db);
    for (const w of c.want) assert.ok(line.includes(w), `${c.name}: ${line}`);
  }
  assert.equal(trivyDBAcceptLabel(trivyDB({})), "Accept and download about 140 MB");
});

test("exploit data: unavailable never reads not exploited; citations only as set", () => {
  const cases: { reason?: string; available: boolean; want: string }[] = [
    { available: true, want: "installed, 2026.11.03" },
    { available: false, reason: "not_installed", want: "comes with the OSV databases" },
    { available: false, reason: "stale", want: "data unavailable: older than its age floor" },
    { available: false, reason: "file_mismatch", want: "does not match its record" },
    { available: false, reason: "unreadable", want: "cannot read it" },
    { available: false, reason: "something new", want: "data unavailable" },
  ];
  for (const c of cases) {
    const line = exploitKindLine({ kind: "security.kev", name: "CISA KEV", installed: c.available, available: c.available, reason: c.reason, version: "2026.11.03" });
    assert.ok(line.startsWith("CISA KEV: ") && line.includes(c.want), line);
    assert.ok(!line.includes("not exploited"), line);
  }
  // A download that failed after the accept says so, never "after their accept".
  const failed = { kind: "security.kev", name: "CISA KEV", checked_at: "2026-11-06T10:00:00Z", last_error: "not published" };
  const notDownloaded = exploitKindLine({ ...failed, installed: false, available: false, reason: "not_installed" });
  assert.ok(notDownloaded.includes("failed (not published)") && notDownloaded.includes("tries again"), notDownloaded);
  assert.ok(!notDownloaded.includes("after their accept"), notDownloaded);
  const kept = exploitKindLine({ ...failed, installed: true, available: true, version: "2026.11.03" });
  assert.ok(kept.startsWith("CISA KEV: installed, 2026.11.03") && kept.includes("installed data stays in use"), kept);
  const stale = exploitKindLine({ ...failed, installed: true, available: false, reason: "stale" });
  assert.ok(stale.includes("older than its age floor") && stale.includes("failed (not published)"), stale);
  // A closed gate names its reason; a reason this build does not know still reads plainly.
  const gate = (blocked: string, reason = "not_installed", available = false) =>
    exploitKindLine({ kind: "security.epss", name: "FIRST EPSS", installed: reason !== "not_installed", available, reason, blocked });
  assert.ok(gate("database_missing").includes("database source does not carry it"), gate("database_missing"));
  assert.ok(gate("feed_unavailable").includes("no content-feed key"), gate("feed_unavailable"));
  assert.ok(gate("database_not_accepted").includes("after their accept"), gate("database_not_accepted"));
  assert.ok(gate("something_new").includes("not fetched (something new)"), gate("something_new"));
  assert.ok(gate("database_missing", "stale").includes("older than its age floor; not refreshed:"), gate("database_missing", "stale"));
  assert.deepEqual(exploitCitations({ kinds: [] }), []);
  assert.deepEqual(exploitCitations({ kinds: [], epss_citation: "EPSS scores: FIRST" }), ["EPSS scores: FIRST"]);
  assert.equal(megabytes(0), "0 MB");
  assert.equal(megabytes(300_000), "1 MB");
});

test("osvInstallFor: the osv-scanner row only, and only with a way to offer", () => {
  const offer = { intro: "i", docs_url: "u", ways: [{ label: "With Go", command: "go install x" }], outro: "o" };
  assert.equal(osvInstallFor("security.scan.osv", offer), offer);
  assert.equal(osvInstallFor("security.scan.scalibr", offer), null);
  assert.equal(osvInstallFor("security.scan.osv", undefined), null);
  assert.equal(osvInstallFor("security.scan.osv", { ...offer, ways: [] }), null);
});
