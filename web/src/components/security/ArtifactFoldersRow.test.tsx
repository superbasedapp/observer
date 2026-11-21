// Component tests of the Scanners card's build artifact folders row (M3L-2
// item 4, operator ruling 2026-11-05), rendered with react-dom/server under
// node's test runner (scripts/test-components.mjs). The row lists a
// project's candidate folders with what their headers say they hold, every
// one off until a switch is clicked, and it appears on the Scanners card
// only while the SCALIBR driver, which reads artifacts, is in the build.

import { test } from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { ArtifactFoldersView } from "@/components/security/ArtifactFoldersRow";
import { ScannersCard, type SecurityScanners } from "@/components/security/ScannersCard";
import { artifactCounts, artifactHeading, artifactStateLine, type ArtifactFolder, type ArtifactFolders } from "@/lib/artifactFolders";

function folder(over: Partial<ArtifactFolder> = {}): ArtifactFolder {
  return { dir: "bin", enabled: false, default: true, present: true, summary: "2 ELF executables, 1 JAR", ...over };
}

function view(folders: ArtifactFolder[], over: Partial<ArtifactFolders> = {}): ArtifactFolders {
  return { project: "/p", folders, text: "Turning a folder on lets every scan read it.", driver_compiled: true, ...over };
}

const render = (v: ArtifactFolders) => renderToStaticMarkup(<ArtifactFoldersView view={v} busy={false} onToggle={() => {}} />);

test("every discovered folder is listed off, with what its headers say it holds", () => {
  const html = render(view([folder(), folder({ dir: "build", default: false, summary: "1 JAR" })]));
  assert.match(html, /data-testid="scanner-artifacts-view"/);
  assert.equal((html.match(/data-testid="scanner-artifact-folder"/g) ?? []).length, 2);
  assert.match(html, /bin\//);
  assert.match(html, /2 ELF executables, 1 JAR/);
  assert.match(html, /off: never opened/);
  assert.doesNotMatch(html, /checked=""/);
  assert.match(html, /0 of 2 folders on\. A folder is never opened until you turn it on\./);
  assert.match(html, /Turning a folder on lets every scan read it\./);
});

test("a folder turned on reads on, and the count follows", () => {
  const v = view([folder({ enabled: true }), folder({ dir: "dist", summary: "no executables, JARs or wheels" })]);
  const html = render(v);
  assert.match(html, /on: every scan reads it/);
  assert.match(html, /checked=""/);
  assert.match(html, /1 of 2 folders on/);
  assert.deepEqual(artifactCounts(v), { on: 1, total: 2 });
});

test("a folder turned on that is gone says so, and a bound that ended the look says more", () => {
  const html = render(view([folder({ enabled: true, present: false, summary: "folder not found" }), folder({ dir: "out", default: false, truncated: true })]));
  assert.match(html, /on, but the folder is gone/);
  assert.match(html, /more than shown/);
  assert.equal(artifactStateLine(folder({ enabled: true, present: false })), "on, but the folder is gone");
});

test("without the SCALIBR driver no switch is offered and the heading says why", () => {
  const html = render(view([folder()], { driver_compiled: false }));
  assert.match(html, /not in this build/);
  assert.match(html, /disabled=""/);
  assert.equal(artifactHeading(view([])), "No build output folders found in this project.");
  assert.equal(artifactHeading(view([folder()])), "0 of 1 folder on. A folder is never opened until you turn it on.");
});

function scanners(compiled: boolean): SecurityScanners {
  return {
    drivers: [
      {
        component: "security.scan.scalibr",
        driver: "scalibr",
        kind: "inventory",
        compiled,
        platform: "linux",
        beta: false,
        note: "",
      },
    ],
    databases: [],
    attribution: "",
  };
}

test("the Scanners card shows the row only where the SCALIBR driver is linked and a project exists", () => {
  const projects = [{ project_root_hash: "abc", label: "app" }];
  const has = (compiled: boolean, ps: typeof projects) =>
    renderToStaticMarkup(<ScannersCard data={scanners(compiled)} onChanged={() => {}} projects={ps} />).includes('data-testid="scanner-artifacts"');
  assert.equal(has(true, projects), true);
  assert.equal(has(false, projects), false);
  assert.equal(has(true, []), false);
});
