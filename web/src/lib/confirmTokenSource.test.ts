import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

// The operator's report (2026-11-18): clicking Install for pi in the New
// Terminal popover showed a raw component_not_installed body for the REMOTE
// component. The install route belongs to terminals; the refusal came from
// the popover reading its confirm token from /api/remote/config, a route of
// the Remote dashboard component (off by default in the developer edition).
// A local write takes its token from localConfirmHeaders (the core command-job
// list mints it). These are the surfaces that used the remote route.
const LOCAL_WRITERS = [
  "../components/NewTerminalDialog.tsx",
  "../components/DashboardInstallRecord.tsx",
  "../components/SandboxSetupPanel.tsx",
  "../components/arena/ArenaTab.tsx",
  "../pages/settings/ETWCapturerCard.tsx",
];

for (const rel of LOCAL_WRITERS) {
  test(`${rel} takes its confirm token from the core, not the Remote dashboard`, () => {
    const src = readFileSync(new URL(rel, import.meta.url), "utf8");
    assert.doesNotMatch(src, /fetchJSON<[^>]*>\("\/api\/remote\/config"\)/, `${rel} reads the remote config`);
    assert.match(src, /localConfirmHeaders\(\)/, `${rel} does not send the local confirm token`);
  });
}

test("the New Terminal install renders its refusal through the one renderer", () => {
  const src = readFileSync(new URL("../components/NewTerminalDialog.tsx", import.meta.url), "utf8");
  assert.match(src, /setErr\(errorNote\(e, installErrorMessage\)\)/);
  assert.match(src, /<ApiErrorNotice\s+note=\{err\}/);
});
