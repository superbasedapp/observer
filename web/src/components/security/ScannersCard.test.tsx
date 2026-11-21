// Component tests of the Code security page's Scanners card (OS-2 UI lane):
// the image driver row with its picker, the OS release databases' accept,
// Trivy's database accept and the exploit data with FIRST's EPSS citation,
// rendered with react-dom/server under node's test runner
// (scripts/test-components.mjs). The pure lines are pinned in
// src/lib/scannerDB.test.ts; these prove the card renders them: an accept
// button only while an accept is owed (never on a managed node, never
// before its driver is selected), a picker only when the build has a
// choice, and the citation only when the daemon set it.

import { test } from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { ScannersCard, type SecurityScanners } from "@/components/security/ScannersCard";
import type { OSVScannerInstall, ScannerDBStatus, ScannerImageStatus, ScannerOSDBStatus, ScannerTrivyImageStatus } from "@/lib/scannerDB";

function osDB(over: Partial<ScannerOSDBStatus> = {}): ScannerOSDBStatus {
  return {
    accepted: false,
    text: "OS consent text",
    source: "superbased.app",
    sizes: [{ name: "Debian", approx_mb: 62 }],
    managed: false,
    installed: [],
    disk_bytes: 0,
    ...over,
  };
}

function trivy(over: Partial<ScannerTrivyImageStatus> = {}): ScannerTrivyImageStatus {
  return {
    selected: true,
    installed: true,
    pinned: true,
    tested_version: "0.75.0",
    db: { accepted: false, text: "Trivy consent", source: "ghcr.io", approx_download_mb: 140, approx_disk_mb: 1700, managed: false, installed: false },
    ...over,
  };
}

function image(over: Partial<ScannerImageStatus> = {}): ScannerImageStatus {
  return { driver: "scalibr", default: "scalibr", choices: ["scalibr", "trivy"], scalibr_compiled: true, trivy_compiled: true, trivy: trivy(), ...over };
}

function card(db: Partial<ScannerDBStatus>): string {
  const data: SecurityScanners = {
    drivers: [],
    databases: [],
    attribution: "",
    db: { accepted: true, approx_mb: 300, source: "superbased.app", text: "", managed: false, installed: 3, ...db },
  };
  return renderToStaticMarkup(<ScannersCard data={data} onChanged={() => {}} />);
}

test("the OS databases offer their accept only while it is owed", () => {
  const cases = [
    { name: "waiting", os: osDB(), button: true, want: /not downloaded/ },
    { name: "accepted", os: osDB({ accepted: true, accepted_on: "dashboard" }), button: false, want: /download accepted/ },
    { name: "managed", os: osDB({ managed: true }), button: false, want: /nothing to accept/ },
  ];
  for (const c of cases) {
    const html = card({ os: c.os });
    assert.match(html, /data-testid="scanner-os-db"/, c.name);
    assert.equal(html.includes('data-testid="scanner-os-db-accept-open"'), c.button, c.name);
    assert.match(html, c.want, c.name);
  }
  const installed = card({
    os: osDB({
      accepted: true,
      installed: [{ distro: "alpine", version: "3.20", artifact: "Alpine-3.20", epoch: "ep1", source: "feed", bytes: 5_500_000, fixed_only: true }],
      disk_bytes: 5_500_000,
    }),
  });
  assert.match(installed, /data-testid="scanner-os-releases"/);
  assert.match(installed, /alpine 3\.20/);
  assert.match(installed, /fixed issues only/);
});

test("the image row: a picker only when the build has a choice", () => {
  const two = card({ image: image() });
  assert.match(two, /data-testid="scanner-image-driver-picker"/);
  assert.match(two, /OSV-SCALIBR[^<]*\(default\)/);
  const one = card({ image: image({ choices: ["trivy"], driver: "trivy", default: "trivy", scalibr_compiled: false }) });
  assert.doesNotMatch(one, /scanner-image-driver-picker/);
  assert.match(one, /only image driver in this build/);
});

test("Trivy's database accept shows only while its driver is selected and the accept is owed", () => {
  const cases = [
    { name: "selected, waiting", t: trivy(), button: true },
    { name: "not selected", t: trivy({ selected: false }), button: false },
    { name: "accepted", t: trivy({ db: { ...trivy().db, accepted: true, accepted_on: "cli" } }), button: false },
    { name: "managed", t: trivy({ db: { ...trivy().db, managed: true } }), button: false },
  ];
  for (const c of cases) {
    const html = card({ image: image({ trivy: c.t }) });
    assert.equal(html.includes('data-testid="scanner-trivy-db-accept-open"'), c.button, c.name);
  }
  assert.match(card({ image: image({ trivy: trivy({ db: { ...trivy().db, managed: true } }) }) }), /does not serve Trivy&#x27;s database yet/);
});

test("the EPSS citation shows only when the daemon set it", () => {
  const without = card({
    exploit: { kinds: [{ kind: "security.epss", name: "FIRST EPSS", installed: false, available: false, reason: "not_installed" }] },
  });
  assert.match(without, /data-testid="scanner-exploit-data"/);
  assert.doesNotMatch(without, /scanner-exploit-citation/);
  assert.doesNotMatch(without, /not exploited/);
  const withCite = card({
    exploit: {
      kinds: [{ kind: "security.epss", name: "FIRST EPSS", installed: true, available: true, version: "v2026.06.15" }],
      epss_citation: "EPSS scores: FIRST, Exploit Prediction Scoring System (EPSS), https://www.first.org/epss",
    },
  });
  assert.match(withCite, /data-testid="scanner-exploit-citation"/);
  assert.match(withCite, /https:\/\/www\.first\.org\/epss/);
});

// The osv-scanner row's "How to install" (dashboard CLI parity plan B-CS3):
// the vendor's ways, the same offer the CLI's install-osv-scanner prints,
// on that row only and only when the daemon sent it.
test("the osv-scanner row carries How to install, no other row does", () => {
  const offer: OSVScannerInstall = {
    intro: "osv-scanner is not bundled with Observer",
    docs_url: "https://google.github.io/osv-scanner/installation/",
    ways: [
      { label: "With Go", command: "go install github.com/google/osv-scanner/v2/cmd/osv-scanner@v2.6.0" },
      { label: "A release binary", url: "https://github.com/google/osv-scanner/releases/tag/v2.6.0", note: "linux amd64 sha256 ca69" },
    ],
    outro: "Observer installs nothing by itself.",
  };
  const driver = (component: string) => ({ component, driver: component, kind: "process", compiled: true, platform: "supported", beta: false, note: "" });
  const render = (osv_install?: OSVScannerInstall) =>
    renderToStaticMarkup(
      <ScannersCard
        data={{ drivers: [driver("security.scan.scalibr"), driver("security.scan.osv")], databases: [], attribution: "", osv_install }}
        onChanged={() => {}}
      />,
    );
  const html = render(offer);
  assert.equal(html.match(/data-testid="osv-install-help"/g)?.length, 1);
  assert.match(html, /How to install/);
  assert.match(html, /go install github\.com\/google\/osv-scanner\/v2\/cmd\/osv-scanner@v2\.6\.0/);
  assert.match(html, /linux amd64 sha256 ca69/);
  assert.match(html, /installs nothing by itself/);
  assert.doesNotMatch(render(undefined), /osv-install-help/);
});
