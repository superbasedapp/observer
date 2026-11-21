// Component tests of the Security assessments card (docs/plans/security-
// assessments-module-plan-2026-11-13.md section 11): the card's kind rows and
// runs list, the plan dialog and the New terminal dialog's task mode for a
// server-sandboxed assessment, rendered with react-dom/server under node's
// test runner (scripts/test-components.mjs, no DOM). Clicks cannot be
// simulated; what a click sends is the pure functions pinned in
// src/lib/secAssess.test.ts, and these prove the components render what
// those build from.

import { test } from "node:test";
import assert from "node:assert/strict";
import { PassThrough } from "node:stream";
import type { ReactElement } from "react";
import { renderToPipeableStream, renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router-dom";
import { NewTerminalDialog } from "@/components/NewTerminalDialog";
import { SecAssessCard } from "@/components/secassess/SecAssessCard";
import { AssessPlanDialog } from "@/components/secassess/AssessPlanDialog";
import { AssessRunsList } from "@/components/secassess/AssessRunsList";
import { AssessScopePicker } from "@/components/secassess/AssessScopePicker";
import { AssessStartPlan } from "@/components/secassess/AssessStartPlan";
import { apiCache } from "@/lib/useApi";
import type { SecurityProject } from "@/lib/codeSecurity";
import {
  ASSESS_LIST_PATH,
  assessPlanPath,
  assessTaskFor,
  type AssessKind,
  type AssessList,
  type AssessPlan,
  type AssessRelaxPlan,
  type AssessRelaxRow,
  type AssessRun,
  type AssessScope,
  type AssessStart,
} from "@/lib/secAssess";

const consoleError = console.error;
console.error = (...args: unknown[]) => {
  if (typeof args[0] === "string" && args[0].includes("useLayoutEffect does nothing on the server")) return;
  consoleError(...args);
};

function renderAll(el: ReactElement): Promise<string> {
  return new Promise((resolve, reject) => {
    let html = "";
    const sink = new PassThrough();
    sink.on("data", (c) => (html += c.toString()));
    sink.on("end", () => resolve(html));
    const s = renderToPipeableStream(el, {
      onAllReady() {
        s.pipe(sink);
      },
      onShellError: reject,
      onError: reject,
    });
  });
}

const base: AssessKind = {
  id: "threat_model",
  title: "Threat model",
  summary: "A STRIDE-style threat model.",
  mode: "Read-only",
  launchable: true,
  sandbox: "optional",
  target: "none",
  files: ["report.md", "findings.sarif"],
  note: "Read-only. The agent reads the repository.",
};
const pentest: AssessKind = {
  ...base,
  id: "pentest_local",
  title: "Penetration test (your own app, local)",
  summary: "A time-boxed test of one development server.",
  mode: "Sandboxed",
  sandbox: "required",
  target: "required",
};
const rasp: AssessKind = {
  ...base,
  id: "rasp",
  title: "Runtime protection (RASP)",
  summary: "Protection inside the running, deployed application.",
  mode: "Not agent-shaped",
  launchable: false,
  sandbox: "na",
  reason: "Runtime protection runs inside the deployed application.",
  pointer: "AI Apps observes the inputs and outputs of an app you build.",
};

function run(over: Partial<AssessRun> = {}): AssessRun {
  return {
    id: "20261114-ab12cd",
    created_at: "2026-11-14T00:00:00Z",
    kind: "threat_model",
    kind_title: "Threat model",
    tool: "claude-code",
    project_root_hash: "h1",
    project_name: "api",
    seeded: true,
    sandboxed: false,
    state: "started",
    files: { report: false, sarif: false, commands: false },
    report_bytes: 0,
    ...over,
  };
}

const project = { project_root_hash: "h1", name: "api", root_path: "/home/u/api", active: true } as SecurityProject;

function list(over: Partial<AssessList> = {}): AssessList {
  return { kinds: [base, pentest, rasp], runs: [], import_available: true, launch: true, ...over };
}

function card(): string {
  return renderToStaticMarkup(
    <MemoryRouter>
      <SecAssessCard projects={[project]} />
    </MemoryRouter>,
  );
}

test("the card lists every kind with its mode, Start for a launchable one and Why not for RASP", async () => {
  await apiCache.fetch(ASSESS_LIST_PATH, async () => list());
  const html = card();
  assert.equal((html.match(/data-testid="assess-kind"/g) ?? []).length, 3);
  assert.match(html, /Threat model/);
  assert.match(html, /Read-only/);
  assert.match(html, /Sandboxed/);
  assert.match(html, /Not agent-shaped/);
  assert.equal((html.match(/>Start</g) ?? []).length, 2);
  assert.match(html, />Why not\?</);
  // The reason stays folded until asked for.
  assert.doesNotMatch(html, /Runtime protection runs inside the deployed application/);
  assert.match(html, /data-help-id="card.code_security_assess"/);
  assert.match(html, /data-testid="assess-empty"/);
});

test("a kind the machine cannot run now says why on the card", async () => {
  await apiCache.fetch(ASSESS_LIST_PATH, async () =>
    list({ kinds: [base, { ...pentest, blocked: "No sandbox that confines the network is available.", blocked_code: "sandbox_unavailable" }] }),
  );
  const html = card();
  assert.match(html, /data-testid="assess-kind-blocked"/);
  assert.match(html, /Cannot start on this machine right now: No sandbox that confines the network is available\./);
});

test("Start is disabled when the dashboard cannot start a terminal", async () => {
  await apiCache.fetch(ASSESS_LIST_PATH, async () => list({ launch: false }));
  const html = card();
  assert.match(html, /<button[^>]*disabled=""[^>]*>[^<]*(<[^>]*>)*[^<]*Start/);
});

test("runs show the state, where they ran and the next step; a findings file offers Import", async () => {
  const html = renderToStaticMarkup(
    <MemoryRouter>
      <AssessRunsList
        importAvailable
        onReport={() => {}}
        runs={[
          run(),
          run({ id: "r2", state: "findings_ready", files: { report: true, sarif: true, commands: false } }),
          run({
            id: "r3",
            kind: "pentest_local",
            kind_title: "Penetration test (your own app, local)",
            sandboxed: true,
            backend: "bwrap",
            target: "http://localhost:3000/",
            state: "imported",
            files: { report: true, sarif: true, commands: false },
            import: { at: "t", outcome: "imported", prepared: 2, findings: 2, new: 1, with_lineage: 0 },
          }),
        ]}
      />
    </MemoryRouter>,
  );
  assert.equal((html.match(/data-testid="assess-run"/g) ?? []).length, 3);
  assert.match(html, /Waiting for the agent to write its report/);
  assert.match(html, />running</);
  assert.match(html, />findings ready</);
  assert.match(html, />Import findings</);
  assert.match(html, /http:\/\/localhost:3000\/ · in a sandbox \(bwrap\)/);
  assert.match(html, /2 findings imported \(1 new\)/);
  // An imported run links to its findings by run id; it offers no second import.
  assert.match(html, /href="\/code-security\?tab=findings[^"]*q=r3/);
  assert.equal((html.match(/>Import findings</g) ?? []).length, 1);
  assert.equal((html.match(/>Read report</g) ?? []).length, 2);
});

// The first live run (2026-11-15): a pen test whose terminal exited within seconds read "running" and
// "Waiting for the agent to write its report" for hours, with "ended when the terminal closed" beside it.
test("a run that ended with nothing written says it ended, why, and offers nothing to read or import", () => {
  const html = renderToStaticMarkup(
    <MemoryRouter>
      <AssessRunsList
        importAvailable
        onReport={() => {}}
        runs={[
          run({
            id: "dead",
            kind: "pentest_local",
            kind_title: "Penetration test (your own app, local)",
            sandboxed: true,
            backend: "bwrap",
            target: "http://localhost:3000/",
            state: "ended_empty",
            files: { report: false, sarif: false, commands: false },
            ended_at: "2026-11-15T10:00:00Z",
            end_why: "terminal_gone",
            can_stop: false,
            time_box_minutes: 45,
          }),
        ]}
      />
    </MemoryRouter>,
  );
  assert.match(html, />ended without a result</);
  assert.match(html, /The agent wrote nothing into the run folder \(ended when the terminal closed\)/);
  assert.doesNotMatch(html, /Waiting for the agent/);
  assert.doesNotMatch(html, />running</);
  assert.doesNotMatch(html, />Stop</);
  assert.doesNotMatch(html, />Read report</);
  assert.doesNotMatch(html, />Import findings</);
});

test("Import is disabled, with the reason, when the SARIF import is not selected", () => {
  const html = renderToStaticMarkup(
    <MemoryRouter>
      <AssessRunsList
        importAvailable={false}
        onReport={() => {}}
        runs={[run({ state: "import_unavailable", files: { report: true, sarif: true, commands: false }, import: { at: "t", outcome: "unavailable", reason: "component_not_selected", prepared: 0, findings: 0, new: 0, with_lineage: 0 } })]}
      />
    </MemoryRouter>,
  );
  assert.match(html, /The SARIF import is not turned on/);
  assert.match(html, /<button[^>]*disabled=""/);
  assert.match(html, />Import again</);
  // The condition is text above the list with a link to where it is changed (UX-12), not only a hover reason.
  const note = html.slice(html.indexOf('data-testid="assess-import-off"'), html.indexOf('data-testid="assess-runs"'));
  assert.match(note, /Importing findings is turned off/);
  assert.match(note, /<a[^>]*href="\/settings\/components\?component=security\.scan\.sarif-import"[^>]*>Turn it on in Settings &gt; Components<\/a>/);
  // Said once for the list, not once per row.
  const two = renderToStaticMarkup(
    <MemoryRouter>
      <AssessRunsList
        importAvailable={false}
        onReport={() => {}}
        runs={[
          run({ id: "i1", state: "import_unavailable", files: { report: true, sarif: true, commands: false } }),
          run({ id: "i2", state: "import_unavailable", files: { report: true, sarif: true, commands: false } }),
        ]}
      />
    </MemoryRouter>,
  );
  assert.equal((two.match(/data-testid="assess-import-off"/g) ?? []).length, 1);
});

test("nothing is said about importing when the import is on, or when no run could be imported", () => {
  const withFiles = run({ state: "import_unavailable", files: { report: true, sarif: true, commands: false } });
  const on = renderToStaticMarkup(
    <MemoryRouter>
      <AssessRunsList importAvailable onReport={() => {}} runs={[withFiles]} />
    </MemoryRouter>,
  );
  assert.doesNotMatch(on, /assess-import-off/);
  const nothing = renderToStaticMarkup(
    <MemoryRouter>
      <AssessRunsList importAvailable={false} onReport={() => {}} runs={[run()]} />
    </MemoryRouter>,
  );
  assert.doesNotMatch(nothing, /assess-import-off/);
});

test("a cloud run counts its command list by class and marks a crossing", () => {
  const html = renderToStaticMarkup(
    <MemoryRouter>
      <AssessRunsList
        importAvailable
        onReport={() => {}}
        runs={[
          run({ id: "ok", kind: "cspm_readonly", cloud: { read_only: 4, secret_material: 0, mutating: 0, unknown: 0 } }),
          run({ id: "bad", kind: "cspm_readonly", cloud: { read_only: 3, secret_material: 0, mutating: 1, unknown: 0 }, boundary_crossed: true }),
        ]}
      />
    </MemoryRouter>,
  );
  assert.match(html, /The agent listed 4 cloud commands: 4 read-only\./);
  assert.match(html, /Outside the read-only boundary\. The agent listed 4 cloud commands: 3 read-only, 1 that change something\./);
});

const confinedPlan: AssessPlan = {
  confirm_token: "tok",
  run_id: "20261114-ab12cd",
  kind: pentest,
  project: { project_root_hash: "h1", name: "api", root_path: "/home/u/api", on_disk: true },
  ok: true,
  target: "http://localhost:3000/",
  target_typed: true,
  candidates: [{ url: "http://localhost:3000/", name: "dev" }, { url: "http://localhost:5173/" }],
  boundary: ["The only target is the address given below.", "Do not do anything destructive."],
  prompt: "You are a penetration tester testing http://localhost:3000/.",
  backend: "bwrap",
  tier: "proxy_only",
  allowed_tools: ["claude-code"],
  seeds: { "claude-code": "leading_positional" },
  residual: "The sandbox's only route out is Observer's model proxy.",
};

function planDialog(kind: AssessKind): ReactElement {
  return (
    <MemoryRouter>
      <AssessPlanDialog kind={kind} projects={[project]} launch onClose={() => {}} readKey="t" />
    </MemoryRouter>
  );
}

test("the plan dialog shows the target, the confirmation sentence, the boundary, the sandbox and the task", async () => {
  await apiCache.fetch(`${assessPlanPath("pentest_local", "h1")}&n=t`, async () => confinedPlan);
  const html = renderToStaticMarkup(planDialog(pentest));
  assert.match(html, /data-testid="assess-plan"/);
  assert.match(html, /data-testid="assess-target"/);
  assert.match(html, /http:\/\/localhost:5173\//);
  assert.match(html, /This is my own application, running on this machine, and http:\/\/localhost:3000\/ is the only thing the agent may test\./);
  assert.match(html, /data-testid="assess-confirm"/);
  assert.equal((html.match(/<li>The only target is the address given below\.<\/li>/g) ?? []).length, 1);
  assert.match(html, /Sandbox: bwrap, network through Observer&#x27;s model proxy only\./);
  assert.match(html, /The sandbox&#x27;s only route out is Observer&#x27;s model proxy\./);
  assert.match(html, /data-testid="assess-prompt-text"/);
  assert.match(html, /You are a penetration tester testing http:\/\/localhost:3000\//);
  // Unconfirmed, and with no dock in this test, Choose agent cannot be pressed.
  assert.match(html, /<button[^>]*disabled=""[^>]*>[^<]*(<[^>]*>)*[^<]*Choose agent/);
  // The reason is text beside the button, which the button names (UX-12), and not only a hover.
  const why = /<p id="([^"]+)"[^>]*data-testid="assess-choose-reason"[^>]*>Confirm the target first<\/p>/.exec(html);
  assert.ok(why, "the reason the button waits is printed in the footer");
  assert.match(html, new RegExp(`<button[^>]*aria-describedby="${why![1]}"[^>]*disabled=""|<button[^>]*disabled=""[^>]*aria-describedby="${why![1]}"`));
  // The consent sits in the target's own section, before the guardrails and the list of what the agent is told not to do.
  const target = html.slice(html.indexOf('data-testid="assess-target"'));
  assert.ok(target.indexOf('data-testid="assess-confirm"') > 0);
  assert.ok(target.indexOf('data-testid="assess-confirm"') < target.indexOf("</section>"), "the consent is inside the target section");
  assert.ok(html.indexOf('data-testid="assess-confirm"') < html.indexOf('data-testid="assess-boundary-list"'));
});

test("a plan the server refuses shows the rule's sentence and no task", async () => {
  const refused: AssessPlan = {
    ...confinedPlan,
    ok: false,
    rule: "E7",
    code: "sandbox_unavailable",
    reason: "No sandbox that confines the network is available on this machine.",
    prompt: undefined,
    backend: undefined,
  };
  await apiCache.fetch(`${assessPlanPath("pentest_local", "h1")}&n=t`, async () => refused);
  const html = renderToStaticMarkup(planDialog(pentest));
  assert.match(html, /This cannot start here/);
  assert.match(html, /No sandbox that confines the network is available on this machine\./);
  assert.doesNotMatch(html, /data-testid="assess-confirm"/);
  assert.doesNotMatch(html, /data-testid="assess-prompt-text"/);
});

test("the plan dialog of a kind with no launch explains why and offers no Choose agent", () => {
  const html = renderToStaticMarkup(planDialog(rasp));
  assert.match(html, /Nothing to launch/);
  assert.match(html, /Runtime protection runs inside the deployed application\./);
  assert.match(html, /AI Apps observes the inputs and outputs of an app you build\./);
  assert.doesNotMatch(html, /Choose agent/);
  assert.doesNotMatch(html, /data-testid="assess-project"/);
});

test("the project picker starts on the project assessed last, and on the first active one when there is no run", () => {
  const other = { project_root_hash: "h2", name: "billing", root_path: "/home/u/billing", active: true } as SecurityProject;
  const dialog = (runs: AssessRun[]) =>
    renderToStaticMarkup(
      <MemoryRouter>
        <AssessPlanDialog kind={base} projects={[project, other]} runs={runs} launch onClose={() => {}} readKey="t" />
      </MemoryRouter>,
    );
  // No run to go by: the first project of the list, as before.
  let html = dialog([]);
  assert.match(html, /<option value="h1" selected=""/);
  assert.match(html, /In api/);
  // The newest run is on the second project: the picker and the dialog's subtitle start there.
  html = dialog([run({ id: "r-old", project_root_hash: "h1", created_at: "2026-11-10T00:00:00Z" }), run({ id: "r-new", project_root_hash: "h2", project_name: "billing", created_at: "2026-11-14T00:00:00Z" })]);
  assert.match(html, /<option value="h2" selected=""/);
  assert.doesNotMatch(html, /<option value="h1" selected=""/);
  assert.match(html, /In billing/);
});

function taskDialog(plan: AssessPlan): ReactElement {
  return (
    <MemoryRouter>
      <NewTerminalDialog onClose={() => {}} onLaunched={() => {}} task={assessTaskFor(plan)} />
    </MemoryRouter>
  );
}

test("task mode for a sandboxed assessment says the server sets the sandbox up and fixes the folder", async () => {
  const html = await renderAll(taskDialog(confinedPlan));
  assert.match(html, /data-testid="new-terminal-task"/);
  assert.match(html, /Penetration test \(your own app, local\)/);
  assert.match(html, /data-testid="new-terminal-task-sandbox"/);
  assert.match(html, /never run unsandboxed/);
  assert.match(html, /data-testid="new-terminal-task-folder"[^>]*>\/home\/u\/api</);
  // The dialog's own workspace choice is not offered: the route derives it.
  assert.doesNotMatch(html, /new-terminal-sandbox-source/);
});

test("task mode for an unconfined assessment leaves the dialog's own sandbox controls alone", async () => {
  const plan: AssessPlan = { ...confinedPlan, kind: base, target: undefined, target_typed: false, allowed_tools: null };
  const html = await renderAll(taskDialog(plan));
  assert.match(html, /data-testid="new-terminal-task"/);
  assert.doesNotMatch(html, /new-terminal-task-sandbox/);
});

// --- Guardrails for one run (plan section 13) ------------------------------

const scannerRow: AssessRelaxRow = {
  key: "R-179",
  type: "rule",
  title: "Allow network and vulnerability scanners (guard rule R-179)",
  lifts: "This lifts that one rule for this run, for the project's terminal only.",
  why: "w",
  route: "self",
  row: "C4",
  reason: "Your tick is the consent.",
  ticked: false,
};
const tierRow: AssessRelaxRow = {
  key: "tier",
  type: "tier",
  title: "Run under the wider sandbox network (the listed hosts only)",
  lifts: "The sandbox's network tier is wider than proxy_only.",
  why: "w",
  route: "refused",
  row: "T1",
  code: "tier_above_max",
  reason: "The configured maximum tier is proxy_only, so no wider network is offered.",
  ticked: false,
};

function relaxOf(over: Partial<AssessRelaxPlan> = {}): AssessRelaxPlan {
  return {
    tenancy: "individual",
    scope: "session",
    scope_words: "for this terminal's session only",
    minutes: 60,
    reported: false,
    report_row: "R3",
    enrolled: false,
    tier_live: "proxy_only",
    tier_hosts: [],
    rows: [scannerRow, tierRow],
    lines: [],
    ...over,
  };
}

test("the plan dialog lists the guardrails with who consents, and offers none that is refused", async () => {
  await apiCache.fetch(`${assessPlanPath("pentest_local", "h1")}&n=t`, async () => ({ ...confinedPlan, relax: relaxOf() }));
  const html = renderToStaticMarkup(planDialog(pentest));
  assert.match(html, /data-testid="assess-relax"/);
  assert.match(html, /data-help-id="card.code_security_assess_relax"/);
  assert.match(html, /Nothing is lifted unless you\s+tick it/);
  // The scanner row is offered as a tick and says whose consent it is; the refused tier row has no tick and says why.
  assert.match(html, /data-testid="assess-relax-R-179"/);
  assert.match(html, /You approve this/);
  assert.match(html, /Your tick is the consent\./);
  assert.match(html, /data-testid="assess-relax-tier"/);
  assert.match(html, /The configured maximum tier is proxy_only, so no wider network is offered\./);
  assert.equal((html.match(/type="checkbox"/g) ?? []).length, 2, "one tick for the guardrail, one for the target confirmation");
  // Nothing ticked: no scope claim, and the run is not reported.
  assert.doesNotMatch(html, /data-testid="assess-relax-scope"/);
  assert.match(html, /This run is not reported to your organization\./);
  // The ordinary button.
  assert.match(html, /Choose agent/);
  assert.doesNotMatch(html, /Ask my organization/);
});

test("the guardrails intro names the kind it is for: a red team exercise is not called a pen test", async () => {
  const redTeam: AssessKind = { ...pentest, id: "red_team_local", title: "Red team exercise (your own app, local)" };
  await apiCache.fetch(`${assessPlanPath("red_team_local", "h1")}&n=t`, async () => ({ ...confinedPlan, kind: redTeam, relax: relaxOf() }));
  await apiCache.fetch(`${assessPlanPath("pentest_local", "h1")}&n=t`, async () => ({ ...confinedPlan, relax: relaxOf() }));
  const strip = (h: string) => h.replace(/<!-- -->/g, "").replace(/&#x27;/g, "'");
  const red = strip(renderToStaticMarkup(planDialog(redTeam)));
  assert.match(red, /A red team exercise can need one lifted for this run only\./);
  assert.doesNotMatch(red, /A pen test can need one lifted/);
  const pen = strip(renderToStaticMarkup(planDialog(pentest)));
  assert.match(pen, /A pen test can need one lifted for this run only\./);
});

test("a plan with no relaxation rows shows no guardrails section and no behaviour change", async () => {
  await apiCache.fetch(`${assessPlanPath("pentest_local", "h1")}&n=t`, async () => confinedPlan);
  const html = renderToStaticMarkup(planDialog(pentest));
  assert.doesNotMatch(html, /data-testid="assess-relax"/);
  assert.match(html, /Choose agent/);
});

test("a ticked guardrail the organization decides makes the button Ask my organization", async () => {
  // A run held for the organization carries its ticks; its plan has no answer yet here,
  // which is the same plan a fresh ticked row reads.
  const orgPlan: AssessPlan = { ...confinedPlan, relax: relaxOf({ tenancy: "managed", rows: [{ ...scannerRow, route: "org_request", row: "C5", reason: "Your organization governs this rule here, so it has to approve." }, tierRow], reported: true, report_row: "R1" }) };
  const held = run({
    id: "20261114-ab12cd",
    kind: "pentest_local",
    phase: "held",
    state: "held",
    target: "http://localhost:3000/",
    relax: [{ key: "R-179", type: "rule", route: "org_request", state: "" }],
  });
  await apiCache.fetch(`${assessPlanPath("pentest_local", "h1", "http://localhost:3000/", { rules: ["R-179"], tier: false }, held.id)}&n=t`, async () => orgPlan);
  const html = renderToStaticMarkup(
    <MemoryRouter>
      <AssessPlanDialog kind={pentest} heldRun={held} projects={[project]} launch onClose={() => {}} readKey="t" />
    </MemoryRouter>,
  );
  assert.match(html, /Ask my organization/);
  assert.match(html, /Your organization approves this/);
  assert.match(html, /Your organization governs this rule here/);
  assert.match(html, /ends at its own expiry/);
  assert.match(html, /Runs on a node your organization manages are reported to it/);
  assert.doesNotMatch(html, />Choose agent</);
  // The project and the guardrails are the held run's own, and cannot be changed here.
  assert.match(html, /<select[^>]*disabled=""/);
  assert.match(html, /<input[^>]*type="checkbox"[^>]*disabled=""[^>]*checked=""/);
});

test("a held run that is approved says Approved: start, with the answer for each rule", async () => {
  const orgPlan: AssessPlan = {
    ...confinedPlan,
    relax: relaxOf({ tenancy: "managed", rows: [{ ...scannerRow, route: "org_request", row: "C5" }, tierRow] }),
    held: { at: "t", ready: true, rules: [{ rule: "R-179", state: "approved", grant_id: 31 }] },
  };
  const held = run({ id: "20261114-ab12cd", kind: "pentest_local", phase: "held", state: "held", target: "http://localhost:3000/", relax: [{ key: "R-179", type: "rule", route: "org_request", state: "" }] });
  await apiCache.fetch(`${assessPlanPath("pentest_local", "h1", "http://localhost:3000/", { rules: ["R-179"], tier: false }, held.id)}&n=t`, async () => orgPlan);
  const html = renderToStaticMarkup(
    <MemoryRouter>
      <AssessPlanDialog kind={pentest} heldRun={held} projects={[project]} launch onClose={() => {}} readKey="t" />
    </MemoryRouter>,
  );
  assert.match(html, /Your organization approved this/);
  assert.match(html, /R-179: approved \[grant G-31\]/);
  assert.match(html, /Approved: start/);
});

test("a held run shows the organization's answer, Cancel request, and a start only once approved", () => {
  const waiting = run({
    id: "w1",
    kind: "pentest_local",
    kind_title: "Penetration test (your own app, local)",
    phase: "held",
    state: "held",
    reported: true,
    target: "http://localhost:3000/",
    held: { at: "t", ready: false, rules: [{ rule: "R-179", state: "waiting", request_id: 101 }] },
  });
  const ready = run({
    id: "w2",
    kind: "pentest_local",
    kind_title: "Penetration test (your own app, local)",
    phase: "held",
    state: "held",
    held: { at: "t", ready: true, rules: [{ rule: "R-179", state: "approved", grant_id: 31 }] },
  });
  const narrower = run({
    id: "w3",
    phase: "held",
    state: "held",
    held: { at: "t", ready: false, rules: [{ rule: "R-179", state: "narrower", grant_id: 40, why: "it is for another project" }] },
  });
  const html = renderToStaticMarkup(
    <MemoryRouter>
      <AssessRunsList importAvailable onReport={() => {}} onStartHeld={() => {}} runs={[waiting, ready, narrower]} />
    </MemoryRouter>,
  );
  assert.equal((html.match(/data-testid="assess-run-held"/g) ?? []).length, 3);
  assert.match(html, />waiting for your organization</);
  assert.match(html, /R-179: waiting for your organization \[request #101\]/);
  assert.match(html, />reported to your organization</);
  assert.match(html, /R-179: approved \[grant G-31\]/);
  assert.match(html, />approved: start</);
  assert.match(html, /R-179: approved, but narrower than asked \[grant G-40\] \(it is for another project\)/);
  assert.equal((html.match(/>Cancel request</g) ?? []).length, 3);
  assert.equal((html.match(/>Approved: start</g) ?? []).length, 1, "only the approved run can start");
  assert.match(html, /<button[^>]*disabled=""[^>]*>[^<]*(<[^>]*>)*[^<]*Waiting for your organization/);
  // A held run has no terminal, so no agent line and no import.
  assert.match(html, /http:\/\/localhost:3000\/ · not started/);
  assert.doesNotMatch(html, />Import findings</);
});

test("a run that lifted a guardrail lists each one, how it ended and how many verdicts it changed", () => {
  const html = renderToStaticMarkup(
    <MemoryRouter>
      <AssessRunsList
        importAvailable
        onReport={() => {}}
        runs={[
          run({
            id: "g1",
            kind: "pentest_local",
            sandboxed: true,
            backend: "bwrap",
            reported: true,
            ended_at: "2026-11-14T01:00:00Z",
            relax: [
              { key: "R-179", type: "rule", route: "self", state: "ended", end_reason: "terminal_exit", scope: "session" },
              { key: "tier", type: "tier", route: "self", state: "ended", hosts: ["registry.npmjs.org"] },
            ],
            relaxed: { exact: 2, approx: 0 },
          }),
          run({
            id: "g2",
            relax: [{ key: "R-179", type: "rule", route: "org_request", state: "org_grant", grant_id: 31 }],
          }),
        ]}
      />
    </MemoryRouter>,
  );
  assert.equal((html.match(/data-testid="assess-run-relax"/g) ?? []).length, 2);
  assert.match(html, /Network and vulnerability scanner rule lifted: ended \(ended when the terminal closed\)/);
  assert.match(html, /Wider sandbox network: ended \(hosts: registry\.npmjs\.org\)/);
  assert.match(html, /2 commands that the guard would have stopped ran under this run&#x27;s approval\./);
  assert.match(html, /Network and vulnerability scanner rule lifted: under your organization&#x27;s grant \(grant G-31\)/);
  assert.match(html, />reported to your organization</);
  // A run that lifted nothing shows no guardrail list at all.
  const plain = renderToStaticMarkup(
    <MemoryRouter>
      <AssessRunsList importAvailable onReport={() => {}} runs={[run()]} />
    </MemoryRouter>,
  );
  assert.doesNotMatch(plain, /assess-run-relax/);
  assert.doesNotMatch(plain, /reported to your organization/);
});

test("a live run past its time box shows Over its time box, the git check pending and Stop", () => {
  const html = renderToStaticMarkup(
    <MemoryRouter>
      <AssessRunsList
        importAvailable
        onReport={() => {}}
        runs={[
          run({
            id: "live",
            time_box_minutes: 45,
            time_box_action: "stop_button",
            deadline: "2026-11-14T00:45:00Z",
            over_time_box: true,
            can_stop: true,
            audit: "pending",
            audit_words: "Checked when the run ends",
            audit_limits: "Files git ignores are not covered.",
            has_data: true,
          }),
        ]}
      />
    </MemoryRouter>,
  );
  assert.match(html, /data-testid="assess-run-timebox"/);
  assert.match(html, /Over its 45-minute time box\. Nothing closes the terminal for you; use Stop when you are ready\./);
  assert.match(html, /data-testid="assess-run-audit"/);
  assert.match(html, /Git check: Checked when the run ends\./);
  assert.match(html, /data-help-id="card.code_security_assess_limits"/);
  assert.match(html, />Stop</);
  // A live run keeps its launch snapshot: no Delete while the terminal is live.
  assert.doesNotMatch(html, /Delete evidence/);
});

test("an ended run offers Delete evidence, never Stop, and says how it ended and what the git check found", () => {
  const html = renderToStaticMarkup(
    <MemoryRouter>
      <AssessRunsList
        importAvailable
        onReport={() => {}}
        runs={[
          run({
            id: "done",
            state: "report_ready",
            files: { report: true, sarif: false, commands: false },
            time_box_minutes: 60,
            ended_at: "2026-11-14T00:40:00Z",
            end_why: "stopped",
            over_time_box: false,
            audit: "changed",
            audit_words: "Git state changed during the run window",
            has_data: true,
          }),
        ]}
      />
    </MemoryRouter>,
  );
  assert.match(html, /Within its 60-minute time box; stopped from this page\./);
  assert.match(html, /Git check: Git state changed during the run window\./);
  assert.match(html, /text-warn/);
  assert.match(html, />Delete evidence</);
  assert.doesNotMatch(html, />Stop</);
  assert.doesNotMatch(html, /Waiting for the agent/);
});

test("a run recorded before time boxes shows no time or git line, and a held run neither", () => {
  const html = renderToStaticMarkup(
    <MemoryRouter>
      <AssessRunsList
        importAvailable
        onReport={() => {}}
        runs={[run({ id: "old", state: "report_ready", files: { report: true, sarif: false, commands: false } }), run({ id: "held", state: "held", phase: "held", time_box_minutes: 45 })]}
      />
    </MemoryRouter>,
  );
  assert.doesNotMatch(html, /assess-run-timebox/);
  assert.doesNotMatch(html, /assess-run-audit/);
  assert.doesNotMatch(html, />Stop</);
});

test("an unreadable run history is said, never shown as no assessments", async () => {
  await apiCache.fetch(ASSESS_LIST_PATH, async () => list({ runs_unreadable: true, runs_error: "run_record_unreadable" }));
  const html = card();
  assert.match(html, /data-testid="assess-runs-unreadable"/);
  assert.match(html, /The run history could not be read/);
  assert.match(html, /The run record \(secassess-runs\.json\) cannot be read, so runs may be missing from this list\. Nothing was deleted\./);
  assert.doesNotMatch(html, /data-testid="assess-empty"/);
});

test("the unreadable run record callout names the file, the recovery steps and what they cost, and has no move-aside button", async () => {
  const file = "/home/u/.observer/secassess-runs.json";
  await apiCache.fetch(ASSESS_LIST_PATH, async () => list({ runs_unreadable: true, runs_error: "run_record_unreadable", runs_file: file }));
  const html = card();
  // The file the server named, in full.
  assert.match(html, /data-testid="assess-runs-unreadable-file"[^>]*>The record is \/home\/u\/\.observer\/secassess-runs\.json\.</);
  // The steps, in order, as a list; the recovery is open without a click.
  assert.match(html, /How to recover/);
  assert.match(html, /aria-expanded="true"/);
  const steps = html.match(/<ol[^>]*aria-label="Steps to recover"[^>]*>(.*?)<\/ol>/)?.[1] ?? "";
  assert.deepEqual(
    [...steps.matchAll(/<li>(.*?)<\/li>/g)].map((m) => m[1].replace(/&#x27;/g, "'")),
    [
      "Close any other Observer that has this file open.",
      "In Observer's data folder, rename secassess-runs.json to secassess-runs.json.bad.",
      "Reopen this page.",
    ],
  );
  // What happens to the list, and what stays.
  assert.match(html, /While it cannot be read no run can be started, stopped, checked or imported/);
  assert.match(html, /data-testid="assess-runs-unreadable-cost"[^>]*>The run list and each listed run(&#x27;|')s stored evidence/);
  assert.match(html, /the reports under \.observer\/assessments in each project are untouched/);
  // Deliberately no button that moves the file: the only buttons are the kinds' Start buttons and the disclosure.
  const callout = html.slice(html.indexOf('data-testid="assess-runs-unreadable"'));
  const region = callout.slice(0, callout.indexOf("</ol>"));
  assert.doesNotMatch(region, /Move aside|Rename the file|Fix it/i);
  assert.equal((region.match(/<button/g) ?? []).length, 1, "only the disclosure's own toggle");
  assert.doesNotMatch(html, /verified|confirmed|\bclean\b/i);
});

test("an older server's unreadable run record still names the file", async () => {
  await apiCache.fetch(ASSESS_LIST_PATH, async () => list({ runs_unreadable: true, runs_error: "run_record_unreadable" }));
  const html = card();
  assert.match(html, /The record is secassess-runs\.json, in Observer(&#x27;|')s data folder\./);
});

test("a readable run record shows no recovery callout", async () => {
  await apiCache.fetch(ASSESS_LIST_PATH, async () => list({ runs: [run({ id: "ok1" })] }));
  const html = card();
  assert.doesNotMatch(html, /assess-runs-unreadable/);
  assert.doesNotMatch(html, /How to recover/);
});

test("the plan dialog lists the settings in force and says what the checks do not do", async () => {
  const plan: AssessPlan = {
    ...confinedPlan,
    limits: {
      time_box_minutes: 90,
      time_box_action: "auto_close",
      boundary_audit: true,
      audit_policy: "untracked_reported",
      audit_limits: "Files git ignores are not covered.",
      relaxation_note: "approvals end at your cap, 60 minutes in",
    },
  };
  await apiCache.fetch(`${assessPlanPath("pentest_local", "h1")}&n=t`, async () => plan);
  const html = renderToStaticMarkup(planDialog(pentest));
  assert.match(html, /data-testid="assess-limits"/);
  assert.match(html, /Settings in force for this run/);
  assert.match(html, /Time box: 90 minutes\. Observer closes the terminal at the deadline\./);
  assert.match(html, /approvals end at your cap, 60 minutes in/);
  assert.match(html, /Files git ignores are not covered\./);
  assert.match(html, /It does not check that the agent&#x27;s reasoning is right\./);
  assert.match(html, /data-help-id="card.code_security_assess_limits"/);
});

const zeroRefs = { found: 0, exists: 0, claimed_not_found: 0, missing: 0, invalid: 0, unchecked: 0 };

function modelRows(runs: AssessRun[]): string {
  return renderToStaticMarkup(
    <MemoryRouter>
      <AssessRunsList importAvailable onReport={() => {}} runs={runs} />
    </MemoryRouter>,
  );
}

test("a sandboxed run whose record names no backend says so, and one that names it does not (N-20)", () => {
  const html = modelRows([
    run({ id: "old1", kind: "threat_model", sandboxed: true, state: "model_ready", contract: "threatmodel.v1", files: modelFiles }),
    run({ id: "new1", kind: "pentest_local", kind_title: "Penetration test (your own app, local)", sandboxed: true, backend: "bwrap", target: "http://localhost:3000/", state: "model_ready", contract: "pentest.v1", files: modelFiles }),
    run({ id: "bare1", kind: "threat_model", sandboxed: false, state: "model_ready", contract: "threatmodel.v1", files: modelFiles }),
  ]);
  const rows = html.split('data-testid="assess-run"').slice(1);
  assert.equal(rows.length, 3);
  assert.match(plainText(rows[0]), /in a sandbox \(backend not recorded for this run\)/);
  assert.match(plainText(rows[1]), /http:\/\/localhost:3000\/ · in a sandbox \(bwrap\)/);
  assert.doesNotMatch(plainText(rows[1]), /not recorded/);
  // A run that was not sandboxed says that, and no sandbox it never had is missing.
  assert.match(plainText(rows[2]), /not sandboxed/);
  assert.doesNotMatch(plainText(rows[2]), /not recorded/);
});

test("a validation line without its conditions says they were not recorded, and one with them does not (N-20)", () => {
  const refs = { ...zeroRefs, found: 7, exists: 1 };
  const old = modelRows([run({ id: "v1", state: "validated", contract: "threatmodel.v1", files: modelFiles, validation: { state: "valid", at: "2026-11-14T02:00:00Z", refs } })]);
  assert.match(plainText(old), /References: 7 found near the cited line, 1 exists with nothing matched near the cited line\. How many lines from the cited line a reference could match was not recorded for this check\./);
  const fresh = modelRows([run({ id: "v2", state: "validated", contract: "threatmodel.v1", files: modelFiles, validation: { state: "valid", at: "2026-11-14T02:00:00Z", refs, ref_window_lines: 5 } })]);
  assert.match(plainText(fresh), /A reference is found when its text is on a code line within 5 lines of the first cited line\./);
  assert.doesNotMatch(plainText(fresh), /was not recorded/);
});

test("a run with a written model offers Validate; a validated one says what was checked", () => {
  const written = run({
    id: "m1",
    state: "model_ready",
    contract: "threatmodel.v1",
    files: { report: true, sarif: false, commands: false, model: true },
    ended_at: "2026-11-14T01:00:00Z",
  });
  const validated = run({
    id: "m2",
    state: "validated",
    contract: "threatmodel.v1",
    files: { report: true, sarif: false, commands: false, model: true },
    ended_at: "2026-11-14T01:00:00Z",
    validation: { state: "partial", at: "2026-11-14T02:00:00Z", refused: 1, refs: { ...zeroRefs, found: 4, missing: 1 } },
  });
  const html = modelRows([written, validated]);
  assert.match(html, />model written</);
  assert.match(html, />validated</);
  // One Validate button (the written model); the current validation is not offered again.
  assert.equal((html.match(/>Validate</g) ?? []).length, 1);
  assert.match(html, /data-testid="assess-run-validation"/);
  assert.match(html, /Model checked: 1 item was refused\. References: 4 found near the cited line, 1 missing\./);
  // The words never claim the agent was right.
  assert.doesNotMatch(html, /verified|confirmed|no weaknesses|is clean/i);
});

test("a stale validation is said and offered again; a live run asks first", () => {
  const stale = run({
    id: "m3",
    state: "model_ready",
    contract: "pentest.v1",
    files: { report: true, sarif: false, commands: false, model: true },
    ended_at: "2026-11-14T01:00:00Z",
    validation: { state: "valid", at: "t", stale: true, refs: zeroRefs },
  });
  const live = run({
    id: "m4",
    state: "model_ready",
    contract: "pentest.v1",
    can_stop: true,
    files: { report: false, sarif: false, commands: false, model: true },
    time_box_minutes: 45,
  });
  const html = modelRows([stale, live]);
  assert.match(html, /The model changed after this check; check it again\./);
  assert.match(html, />Validate again</);
  assert.match(html, />Validate anyway</);
});

test("a refused model reads as refused with its reason, and a legacy run shows no model line", () => {
  const refused = run({
    id: "m5",
    state: "invalid",
    contract: "threatmodel.v1",
    files: { report: true, sarif: false, commands: false, model: true },
    ended_at: "2026-11-14T01:00:00Z",
    validation: { state: "invalid", at: "t", fatal: "not_json", refs: zeroRefs },
  });
  const legacy = run({ id: "m6", state: "report_ready", files: { report: true, sarif: false, commands: false } });
  const html = modelRows([refused, legacy]);
  assert.match(html, />model refused</);
  assert.match(html, /Model refused: it is not JSON\./);
  assert.equal((html.match(/data-testid="assess-run-validation"/g) ?? []).length, 1);
  // A refused model that has not changed is not offered again: the agent has to rewrite it first.
  assert.equal((html.match(/>Validate/g) ?? []).length, 0);
});

// --- The model contract's import and plan lines (depth plan W1c) -----------

const modelFiles = { report: true, sarif: false, commands: false, model: true };
const okValidation = { state: "valid", at: "2026-11-14T02:00:00Z", refs: { ...zeroRefs, found: 2 } };

test("a validated model run offers Import findings; the agent's findings file plays no part", () => {
  const validated = run({
    id: "i1",
    state: "validated",
    contract: "threatmodel.v1",
    files: modelFiles,
    ended_at: "2026-11-14T01:00:00Z",
    validation: okValidation,
  });
  const html = modelRows([validated]);
  assert.match(html, />Import findings</);
  assert.match(html, />validated</);
  // Not validated yet: the model is offered Validate, not Import.
  const written = run({ id: "i2", state: "model_ready", contract: "threatmodel.v1", files: modelFiles, ended_at: "2026-11-14T01:00:00Z" });
  const w = modelRows([written]);
  assert.match(w, />Validate</);
  assert.doesNotMatch(w, />Import findings</);
});

test("an imported model run says what was imported and how many were not, and why", () => {
  const imported = run({
    id: "i3",
    state: "imported",
    contract: "threatmodel.v1",
    files: modelFiles,
    ended_at: "2026-11-14T01:00:00Z",
    validation: okValidation,
    import: {
      at: "t",
      outcome: "imported",
      prepared: 2,
      findings: 2,
      new: 2,
      with_lineage: 0,
      derived: { considered: 9, kept: 2, no_location: 3, under_min_band: 2, over_cap: 2, min_band: "high", cap: 2 },
    },
  });
  const html = modelRows([imported]);
  assert.match(html, />imported</);
  assert.match(html, /2 findings imported \(2 new\)\. 7 of 9 not imported: 3 with no location in the code, 2 under your minimum band \(high\), 2 past your cap of 2\./);
  assert.match(html, /See these findings/);
  assert.doesNotMatch(html, />Import findings</);
  // The import's own ceiling is named in words, apart from a cap the developer set.
  const ceiling = run({
    id: "i4",
    state: "imported",
    contract: "pentest.v1",
    files: modelFiles,
    ended_at: "2026-11-14T01:00:00Z",
    validation: okValidation,
    import: { at: "t", outcome: "imported", prepared: 1000, findings: 1000, new: 1000, with_lineage: 0, derived: { considered: 1250, kept: 1000, over_ceiling: 250 } },
  });
  assert.match(modelRows([ceiling]), /250 past the import(&#x27;|')s own 1000-result ceiling/);
});

test("an import that derived nothing reads as nothing to import, never as clean, and can be tried again", () => {
  const none = run({
    id: "i5",
    state: "no_findings",
    contract: "threatmodel.v1",
    files: modelFiles,
    ended_at: "2026-11-14T01:00:00Z",
    validation: okValidation,
    import: { at: "t", outcome: "no_findings", prepared: 0, findings: 0, new: 0, with_lineage: 0, derived: { considered: 2, kept: 0, no_location: 2 } },
  });
  const html = modelRows([none]);
  assert.match(html, />nothing to import</);
  assert.match(html, /Nothing was derived to import from 2 candidates\. 2 of 2 not imported: 2 with no location in the code\./);
  assert.match(html, />Import again</);
  assert.doesNotMatch(html, /\bclean\b|no weaknesses|is secure|verified|confirmed/i);
  assert.doesNotMatch(html, /See these findings/);
});

test("a lost stored copy asks for the model to be checked again", () => {
  const lost = run({
    id: "i6",
    state: "import_failed",
    contract: "pentest.v1",
    files: modelFiles,
    ended_at: "2026-11-14T01:00:00Z",
    validation: okValidation,
    import: { at: "t", outcome: "failed", reason: "model_unavailable", prepared: 0, findings: 0, new: 0, with_lineage: 0 },
  });
  const html = modelRows([lost]);
  assert.match(html, /stored copy of the checked model is gone/);
  assert.match(html, />Validate again</);
  assert.match(html, />Import again</);
});

test("a checked model too large to keep says so, in its own words, and does not offer to check it again", () => {
  const big = run({
    id: "i7",
    state: "import_failed",
    contract: "pentest.v1",
    files: modelFiles,
    ended_at: "2026-11-14T01:00:00Z",
    validation: okValidation,
    import: { at: "t", outcome: "failed", reason: "model_too_large_to_keep", prepared: 0, findings: 0, new: 0, with_lineage: 0 },
  });
  const html = modelRows([big]);
  assert.match(html, /The checked model is too large to keep, so no findings can be derived from it\./);
  assert.match(html, /Checking it again will not change that: have the agent write a smaller assessment\.json, then check that\./);
  // Checking it again cannot help, so Validate is not offered (a lost copy does offer it, above).
  assert.doesNotMatch(html, />Validate</);
  assert.doesNotMatch(html, />Validate again</);
  assert.doesNotMatch(html, /stored copy of the checked model is gone/);
  assert.doesNotMatch(html, /The import failed\./);
  assert.doesNotMatch(html, /verified|confirmed|\bclean\b/i);
});

test("a model whose references ran out of budget reads as only partly checked, with where to change the budget", () => {
  const partly = run({
    id: "p1",
    state: "validated",
    contract: "threatmodel.v1",
    files: modelFiles,
    ended_at: "2026-11-14T01:00:00Z",
    validation: { state: "partial", at: "2026-11-14T02:00:00Z", refs: { ...zeroRefs, found: 7, exists: 1, unchecked: 3 } },
  });
  const html = modelRows([partly]);
  assert.match(html, /Model checked: 3 references could not be checked within the check(&#x27;|')s budget, so the model is only partly checked\./);
  assert.match(html, /The budget is set in Settings &gt; Guard &gt; Code security\./);
  // The tally stays, in the corrected words.
  assert.match(html, /References: 7 found near the cited line, 1 exists with nothing matched near the cited line, 3 not checked\./);
  assert.match(html, /class="[^"]*text-warn[^"]*"\s+data-testid="assess-run-validation"/);
  assert.doesNotMatch(html, /some items were left out|nothing was refused|found at the cited line/);
  assert.doesNotMatch(html, /verified|confirmed|\bclean\b/i);
});

test("a partly checked git check is shown as a warning in its own words, never as no change", () => {
  const html = modelRows([
    run({
      id: "g1",
      state: "report_ready",
      files: { report: true, sarif: false, commands: false },
      time_box_minutes: 60,
      ended_at: "2026-11-14T00:40:00Z",
      end_why: "stopped",
      over_time_box: false,
      audit: "partly_checked",
      audit_words: "No change seen in the files that could be compared; some changed files could not be compared",
      audit_limits: "Changed and untracked files are compared by their content, up to 400 paths.",
    }),
  ]);
  assert.match(html, /Git check: No change seen in the files that could be compared; some changed files could not be compared\./);
  assert.match(html, /class="[^"]*text-warn[^"]*"\s+data-testid="assess-run-audit"/);
  assert.doesNotMatch(html, /Git check: No git change seen/);
  assert.doesNotMatch(html, /\bclean\b|verified|confirmed/i);
  // Its help is the one entry that explains the comparison's limits.
  assert.match(html, /data-help-id="card.code_security_assess_limits"/);
});

const tmPlan: AssessPlan = {
  confirm_token: "tok",
  run_id: "3fa9c2d17b0e4a56",
  kind: base,
  project: { project_root_hash: "h1", name: "api", root_path: "/work/api", on_disk: true },
  ok: true,
  target_typed: false,
  candidates: [],
  boundary: ["This is a read-only assessment."],
  prompt: "SECURITY ASSESSMENT: Threat model of api.",
  prompt_sha256: "ab".repeat(32),
  allowed_tools: null,
  seeds: {},
  limits: {
    time_box_minutes: 60,
    time_box_action: "stop_button",
    boundary_audit: true,
    audit_policy: "strict",
    audit_limits: "It sees only what git sees.",
  },
  model: {
    prompt_version: "tm.2",
    frameworks: "stride_ai",
    method_extras: "attack_trees",
    self_check: true,
    import_min_band: "medium",
    findings_cap: 100,
    rerun_dedup: true,
  },
};

test("the plan dialog lists the model contract's settings in force beside the time box", async () => {
  await apiCache.fetch(`${assessPlanPath("threat_model", "h1")}&n=t`, async () => tmPlan);
  const html = renderToStaticMarkup(planDialog(base));
  assert.match(html, /data-testid="assess-limits"/);
  assert.match(html, /Time box: 60 minutes/);
  assert.match(html, /structured assessment\.json \(task version tm\.2\)/);
  assert.match(html, /Frameworks asked for: STRIDE and the AI frameworks\./);
  assert.match(html, /Abuse cases and attack trees: Attack trees only\./);
  assert.match(html, /told to check its own file with Observer before it finishes/);
  assert.match(html, /On import: findings at medium risk and above, at most 100, highest risk first; a re-run updates the findings you already imported\./);
  // The words say what is checked, never that the agent is right.
  assert.doesNotMatch(html, /verified|is clean/i);
});

// --- The depth plan's choices and facts on the plan dialog (W3 and W4) -------

/** tagOf is the opening tag of the first element of the given name whose tag
 *  holds the attribute text (an input by its test id, say), or "". */
function tagOf(html: string, name: string, has: string): string {
  for (const m of html.matchAll(new RegExp(`<${name}\\b[^>]*>`, "g"))) if (m[0].includes(has)) return m[0];
  return "";
}

/** buttonTag is the opening tag of the first button whose text holds the label. */
function buttonTag(html: string, label: string): string {
  for (const part of html.split("<button").slice(1)) {
    const open = part.slice(0, part.indexOf(">") + 1);
    const inner = part.slice(part.indexOf(">") + 1, part.indexOf("</button>"));
    if (inner.replace(/<[^>]*>/g, "").includes(label)) return "<button" + open;
  }
  return "";
}
const isDisabled = (tag: string) => / disabled=""/.test(tag);
const isChecked = (tag: string) => / checked=""/.test(tag);

const depthTm: AssessPlan = {
  ...tmPlan,
  run_id: "3fa9c2d17b0e4a57",
  scope: { dirs: ["cmd", "internal", "web"], paths: [], note: "", max_paths: 8, max_note: 200 },
  grounding: { mode: "full", sections: ["languages", "manifests", "infra", "spec", "dependencies", "findings"], bytes: 3174, dropped: 0, ai_app: true },
  previous: {
    options: [
      { id: "00000000000000a1", created_at: "2026-11-13T09:00:00Z", scope: ["cmd/api"] },
      { id: "00000000000000a0", created_at: "2026-11-12T09:00:00Z" },
    ],
    selected: "00000000000000a1",
    default_run: "00000000000000a1",
    note: "Observer gives the agent nothing from the earlier run and asks it not to open other runs' folders. That is a request, not a barrier.",
  },
};

test("a threat model plan offers the scope, the comparison and the project facts, and nothing of a pen test", async () => {
  await apiCache.fetch(`${assessPlanPath("threat_model", "h1")}&n=t`, async () => depthTm);
  const html = renderToStaticMarkup(planDialog(base));
  // Scope: the top-level folders to tick, a typed place, a note, and the default in words.
  assert.match(html, /data-testid="assess-scope"/);
  assert.match(html, /data-help-id="card.code_security_assess_scope"/);
  for (const d of ["cmd", "internal", "web"]) assert.match(html, new RegExp(`data-testid="assess-scope-dir-${d}"`));
  assert.match(html, /data-testid="assess-scope-input"/);
  assert.match(html, /data-testid="assess-scope-note"/);
  assert.match(html, /By default the whole project is covered\./);
  assert.match(html, /0 of 200 characters\. It goes into the task as your own words/);
  assert.doesNotMatch(html, /data-testid="assess-scope-chips"/, "nothing chosen, no chips");
  assert.doesNotMatch(html, /data-testid="assess-scope-refused"/);
  // The typed place's Add button waits for text.
  assert.ok(isDisabled(buttonTag(html, "Add")), "Add waits for a place");
  // Comparison: no comparison first, then each earlier run, the server's pick selected, and its sentence.
  assert.match(html, /data-testid="assess-previous"/);
  assert.match(html, /data-help-id="card.code_security_assess_previous"/);
  assert.match(html, /<option value="none">No comparison<\/option>/);
  assert.match(html, /<option value="00000000000000a1"[^>]*selected=""[^>]*>Threat model, [^<]*scope cmd\/api<\/option>/);
  assert.match(html, /<option value="00000000000000a0">Threat model, [A-Z][a-z]{2} \d+, 2026/);
  assert.match(html, /Compared with the earlier run \(Threat model, [^)]*\) once the new model is checked\./);
  // A run is named by what it is and when, never by its identifier (UX-7).
  assert.doesNotMatch(html, />[^<]*[Rr]un 00000000000000a/);
  assert.match(html, /Observer gives the agent nothing from the earlier run and asks it not to open other runs(&#x27;|') folders\. That is a request, not a barrier\./);
  assert.doesNotMatch(html, /Nothing from the earlier run is given to the agent/);
  // The facts digest joins the settings in force, with its help entry.
  assert.match(html, /The task carries a digest of facts from the project: 6 sections, 3\.1 KiB\. Observer found signs that it is an AI application\./);
  assert.match(html, /data-help-id="card.code_security_assess_grounding"/);
  // None of the pen test's sections are here.
  assert.doesNotMatch(html, /data-testid="assess-start"|data-testid="assess-before"/);
  assert.doesNotMatch(html, /verified|confirmed|\bclean\b|vulnerable|authentic/i);
  // The launch still reads Choose agent, and the task is shown.
  assert.match(html, /Choose agent/);
  assert.match(html, /data-testid="assess-prompt-text"/);
});

test("a threat model plan with no earlier checked run says there is nothing to compare, and shows no picker", async () => {
  const noPrev: AssessPlan = { ...depthTm, run_id: "3fa9c2d17b0e4a58", previous: { options: [], selected: "", default_run: "", note: "" } };
  await apiCache.fetch(`${assessPlanPath("threat_model", "h1")}&n=t`, async () => noPrev);
  const html = renderToStaticMarkup(planDialog(base));
  assert.match(html, /No earlier checked threat model of this project exists, so there is nothing to compare with\./);
  assert.doesNotMatch(html, /assess-previous-select/);
  // A server that sends no sentence still gets the true one under the picker's place.
  assert.match(html, /data-testid="assess-previous-note"[^>]*>Observer gives the agent nothing from the earlier run and asks it not to open other runs(&#x27;|') folders\. That is a request, not a barrier\./);
});

test("a held threat model shows its chosen places as chips, its refused place with the reason, and cannot be edited", async () => {
  const held = run({
    id: "00000000000000e1",
    kind: "threat_model",
    phase: "held",
    state: "held",
    scope: { paths: ["cmd/api", "../etc"], note: "payment flow" },
    previous_run: "00000000000000a0",
  });
  const choices = { scopePaths: ["cmd/api", "../etc"], scopeNote: "payment flow", previousRun: "00000000000000a0" };
  const withRefusal: AssessPlan = {
    ...depthTm,
    run_id: "00000000000000e1",
    scope: {
      ...depthTm.scope!,
      paths: ["cmd/api"],
      note: "payment flow",
      refused: [{ path: "../etc", reason: "It is outside the project." }],
    },
    previous: { ...depthTm.previous!, selected: "00000000000000a0" },
  };
  await apiCache.fetch(`${assessPlanPath("threat_model", "h1", "", { rules: [], tier: false }, held.id, choices)}&n=t`, async () => withRefusal);
  const html = renderToStaticMarkup(
    <MemoryRouter>
      <AssessPlanDialog kind={base} heldRun={held} projects={[project]} launch onClose={() => {}} readKey="t" />
    </MemoryRouter>,
  );
  // The chosen places are chips; the refused one is a warning chip and is listed with its reason.
  assert.match(html, /data-testid="assess-scope-chip-cmd\/api"/);
  assert.match(html, /data-testid="assess-scope-chip-\.\.\/etc"/);
  assert.match(html, /data-testid="assess-scope-refused"[^>]*>.*It is outside the project\./);
  assert.match(html, /2 of 8 places chosen\./);
  // The line says what the server accepted, not what was typed.
  assert.match(html, /The task asks the agent to model only cmd\/api\. It may read the rest for what calls it or what it calls/);
  assert.doesNotMatch(html, /model only cmd\/api, \.\.\/etc/);
  // A held run's scope is fixed: no remove buttons, no typed place, a disabled note holding the note.
  assert.doesNotMatch(html, /aria-label="Remove /);
  assert.doesNotMatch(html, /data-testid="assess-scope-input"/);
  const noteTag = tagOf(html, "input", 'data-testid="assess-scope-note"');
  assert.ok(isDisabled(noteTag) && noteTag.includes('value="payment flow"'), noteTag);
  assert.ok(isDisabled(tagOf(html, "select", 'data-testid="assess-previous-select"')), "the comparison is fixed too");
  assert.match(html, /<option value="00000000000000a0"[^>]*selected=""/);
});

const depthPt: AssessPlan = {
  ...confinedPlan,
  run_id: "3fa9c2d17b0e4a60",
  candidates: [{ url: "http://localhost:3000/", name: "dev", source: ".claude/launch.json" }, { url: "http://localhost:5173/" }],
  limits: {
    time_box_minutes: 45,
    time_box_action: "stop_button",
    boundary_audit: true,
    audit_policy: "untracked_reported",
    audit_limits: "It sees only what git sees.",
    request_budget: 600,
    pace_rps: 5,
  },
  model: {
    prompt_version: "pt.2",
    categories: "all",
    self_check: true,
    import_min_band: "low",
    findings_cap: 0,
    rerun_dedup: true,
    grounding: "full",
    secret_mode: "mask",
    secret_mode_effective: "warn",
    request_budget: 600,
    pace_rps: 5,
  },
  grounding: { mode: "without_findings", sections: ["languages", "manifests", "start"], bytes: 900, dropped: 2, ai_app: false },
  start: {
    plans: [
      { command: "npm run dev", port: 3000, source: "package.json scripts" },
      { command: "python manage.py runserver 8000", port: 8000, source: "manage.py", prepare: ["python manage.py migrate"], needs: ["db"] },
    ],
    selected_command: "npm run dev",
    edit: "npm run dev",
    edited: false,
    none_found: false,
  },
  preflight: [
    { id: "lock", level: "info", text: "An API spec was found at openapi.json." },
    { id: "env", level: "warn", text: "2 environment files are in this folder." },
    { id: "deps", level: "likely_fails", text: "No node_modules folder: the sandbox cannot install packages, so install them outside it first." },
  ],
  env: { files: [".env", ".env.local"], count: 2, configured: "mask", effective: "warn", line: "2 .env files are in this folder and are readable inside the sandbox." },
  tools: [
    { id: "curl", purpose: "Send HTTP requests", command: "curl", present: true, guarded: false, fallback: "" },
    { id: "nmap", purpose: "Scan ports", command: "nmap", present: false, guarded: true, fallback: "The agent sends the requests itself." },
    { id: "python3", purpose: "Run the request helper", command: "python3", present: null, guarded: false, fallback: "" },
  ],
  safety: [
    { id: "target", rule: "Only the target you confirmed is tested", prompt: true, helper: "-", observer: "The sandbox's network", observer_kind: "prevents", prompt_only: false },
    { id: "pace", rule: "At most 5 requests a second", prompt: true, helper: "-", observer: "-", observer_kind: "", prompt_only: true },
    { id: "git", rule: "Do not destroy tracked files", prompt: true, helper: "-", observer: "A git check afterwards", observer_kind: "detects", prompt_only: false },
    { id: "time", rule: "Stay inside the time box", prompt: true, helper: "-", observer: "The deadline and the Stop button", observer_kind: "stops", prompt_only: false },
    { id: "odd", rule: "Something new", prompt: true, helper: "-", observer: "A check Observer has no word for", observer_kind: "guarantees", prompt_only: false },
  ],
};

test("a pen test plan shows how the application starts: the offered commands, the one chosen, the typed field", async () => {
  await apiCache.fetch(`${assessPlanPath("pentest_local", "h1")}&n=t`, async () => depthPt);
  const html = renderToStaticMarkup(planDialog(pentest));
  assert.match(html, /data-testid="assess-start"/);
  assert.match(html, /data-help-id="card.code_security_assess_start"/);
  // The server's pick is the one checked; the second and the "none" row are not.
  assert.ok(isChecked(tagOf(html, "input", 'data-testid="assess-start-plan-0"')), "the first plan is the pick");
  assert.ok(!isChecked(tagOf(html, "input", 'data-testid="assess-start-plan-1"')));
  assert.ok(!isChecked(tagOf(html, "input", 'data-testid="assess-start-none"')));
  assert.match(html, />npm run dev</);
  assert.match(html, />Port 3000</);
  assert.match(html, />Read from package\.json scripts</);
  // The second plan's steps are listed with the words that say they do not run unless chosen.
  assert.match(html, />Preparation steps, not run unless you choose to: python manage\.py migrate</);
  assert.doesNotMatch(html, />Runs first/);
  assert.match(html, />Needs: db\. The sandbox has no container engine\.</);
  // The server's pick has no steps, so there is no opt-in under it.
  assert.doesNotMatch(html, /data-testid="assess-prepare"/);
  assert.match(html, /No declared command: the agent looks for one itself/);
  // The field holds the command in force, and its button waits for a change.
  assert.ok(tagOf(html, "input", 'data-testid="assess-start-input"').includes('value="npm run dev"'));
  assert.ok(isDisabled(buttonTag(html, "Use this command")), "nothing to use yet");
  assert.match(html, /The agent is told to start the application with: npm run dev\./);
  assert.doesNotMatch(html, /\(typed by you\)/);
  assert.doesNotMatch(html, /data-testid="assess-start-error"/);
  // The address candidates say where they were read from.
  assert.match(html, /from \.claude\/launch\.json/);
  // A pen test has no scope or comparison.
  assert.doesNotMatch(html, /data-testid="assess-scope"|data-testid="assess-previous"/);
});

test("a typed start command is shown as typed, with the server's reason when it was refused", async () => {
  const typed: AssessPlan = {
    ...depthPt,
    run_id: "3fa9c2d17b0e4a61",
    ok: false,
    code: "start_invalid",
    reason: "The start command has a character that is not accepted: |.",
    prompt: undefined,
    start: { ...depthPt.start!, selected_command: "", edit: "", edited: true, error: "The start command has a character that is not accepted: |." },
  };
  await apiCache.fetch(`${assessPlanPath("pentest_local", "h1")}&n=t`, async () => typed);
  const html = renderToStaticMarkup(planDialog(pentest));
  assert.match(html, /data-testid="assess-start-error"[^>]*>The start command has a character that is not accepted: \|\./);
  assert.match(html, /role="alert"/);
  assert.match(html, /No start command is declared, so the agent is told to find one itself\./);
  // Refused plan: the dialog's own refusal callout shows too, and there is no task.
  assert.match(html, /This cannot start here/);
  assert.doesNotMatch(html, /data-testid="assess-prompt-text"/);
});

test("a project with no start command says so and offers the field, not a list", async () => {
  const none: AssessPlan = {
    ...depthPt,
    run_id: "3fa9c2d17b0e4a62",
    start: { plans: [], selected_command: "", edit: "", edited: false, none_found: true },
  };
  await apiCache.fetch(`${assessPlanPath("pentest_local", "h1")}&n=t`, async () => none);
  const html = renderToStaticMarkup(planDialog(pentest));
  assert.match(html, /No start command could be read from the project(&#x27;|')s files; the agent will look for one or you can type it\./);
  assert.doesNotMatch(html, /data-testid="assess-start-plan-0"|data-testid="assess-start-none"/);
  assert.match(html, /data-testid="assess-start-input"/);
  // Said once (UX-11): the second sentence the start section used to add is gone, and with no list above the field it does not begin with "Or".
  assert.doesNotMatch(html, /No start command was found/);
  assert.equal((html.match(/No start command could be read/g) ?? []).length, 1);
  assert.match(html, />Type the command</);
  assert.doesNotMatch(html, />Or type the command</);
});

test("the server's no-start-command note is said once, in the start section, and not again under Before it starts", async () => {
  const note = { id: "no_start_command", level: "warn", text: "The project's files name 1 start command, but none that can be written as a plain command; the agent will look for one or you can type it." };
  const none: AssessPlan = {
    ...depthPt,
    run_id: "3fa9c2d17b0e4a63",
    start: { plans: [], selected_command: "", edit: "", edited: false, none_found: true },
    preflight: [note, { id: "start_port", level: "warn", text: "A different fact about the port." }],
  };
  await apiCache.fetch(`${assessPlanPath("pentest_local", "h1")}&n=t`, async () => none);
  const html = renderToStaticMarkup(planDialog(pentest));
  assert.equal((html.match(/name 1 start command/g) ?? []).length, 1, "the server's sentence is shown once");
  assert.match(html, /data-testid="assess-start-none-found"[^>]*>The project(&#x27;|')s files name 1 start command/);
  assert.doesNotMatch(html, /data-testid="assess-preflight-no_start_command"/);
  assert.match(html, /data-testid="assess-preflight-start_port"/, "a different note still lists");
});

test("a field that offers a typed address or command beside a list says Or, and one with no list above it does not", async () => {
  const withBoth: AssessPlan = {
    ...depthPt,
    run_id: "3fa9c2d17b0e4a64",
    start: { plans: [{ command: "npm run dev", port: 3000, source: "package.json" }], selected_command: "npm run dev", edit: "npm run dev", edited: false, none_found: false },
  };
  await apiCache.fetch(`${assessPlanPath("pentest_local", "h1")}&n=t`, async () => withBoth);
  const html = renderToStaticMarkup(planDialog(pentest));
  assert.match(html, />Or type the command</);
  assert.match(html, />Or type the address of your development server</);
  const noCandidates: AssessPlan = { ...withBoth, run_id: "3fa9c2d17b0e4a65", candidates: [], start: { plans: [], selected_command: "", edit: "", edited: false, none_found: true } };
  await apiCache.fetch(`${assessPlanPath("pentest_local", "h1")}&n=t`, async () => noCandidates);
  const bare = renderToStaticMarkup(planDialog(pentest));
  assert.match(bare, />Type the address of your development server</);
  assert.doesNotMatch(bare, />Or type /);
});

test("a pen test plan lists what Observer noticed, the environment files, the tools and what holds each rule", async () => {
  await apiCache.fetch(`${assessPlanPath("pentest_local", "h1")}&n=t`, async () => depthPt);
  const html = renderToStaticMarkup(planDialog(pentest));
  assert.match(html, /data-testid="assess-before"/);
  // The notes read likely-to-fail first, then worth knowing, then notes, each with its words.
  const deps = html.indexOf("data-testid=\"assess-preflight-deps\"");
  const env = html.indexOf("data-testid=\"assess-preflight-env\"");
  const lock = html.indexOf("data-testid=\"assess-preflight-lock\"");
  assert.ok(deps > 0 && deps < env && env < lock, `order ${deps} ${env} ${lock}`);
  assert.match(html, />Likely to fail</);
  assert.match(html, />Worth knowing</);
  assert.match(html, />Note</);
  assert.match(html, /the sandbox cannot install packages, so install them outside it first\./);
  // The environment files: the server's sentence, and the names only.
  assert.match(html, /data-testid="assess-env"/);
  assert.match(html, /2 \.env files are in this folder and are readable inside the sandbox\./);
  assert.match(html, /Named: \.env, \.env\.local\./);
  // Only the top level is counted, and the dialog says so beside the server's sentence.
  assert.match(html, /data-testid="assess-env-top-level"[^>]*>Only environment files at the top level of this folder are counted\. Those in subfolders are not;/);
  // The two folded lists are real <details>, closed.
  assert.match(html, /<details[^>]*data-testid="assess-tools"/);
  assert.doesNotMatch(html, /<details[^>]*open=""[^>]*data-testid="assess-tools"/);
  assert.match(html, />Tools in the sandbox</);
  assert.match(html, /Send HTTP requests\. Found in the sandbox(&#x27;|')s standard folders\./);
  assert.match(html, /Scan ports\. Not found in the sandbox(&#x27;|')s standard folders\. The agent sends the requests itself\. It may need your answer: Observer(&#x27;|')s guard can ask before it runs\./);
  assert.doesNotMatch(html, /\(R-179\)/);
  assert.match(html, /Run the request helper\. Observer could not tell whether it is there; the agent checks for itself\./);
  assert.match(html, /<details[^>]*data-testid="assess-safety"/);
  assert.match(html, />What holds each rule</);
  // Each rule says how it is held, from the row's observer_kind: only a check that prevents reads as held outside the task.
  const heldOf = (id: string) => html.slice(html.indexOf(`data-testid="assess-safety-${id}"`)).split("</li>")[0].replace(/<[^>]*>/g, "|");
  assert.match(heldOf("target"), /\|Held outside the task\|/);
  assert.match(heldOf("pace"), /\|Held by the task only\|/);
  assert.match(heldOf("git"), /\|Checked afterwards, not prevented\|/);
  assert.match(heldOf("time"), /\|You can stop the run; the limit is advisory\|/);
  assert.match(heldOf("odd"), /\|Noted outside the task, not a guarantee\|/);
  assert.match(heldOf("odd"), /Observer notes: A check Observer has no word for/);
  assert.doesNotMatch(html, /Also held outside the task/);
  assert.equal((html.match(/>Held outside the task</g) ?? []).length, 1, "one rule is held outside the task, not every rule with a cell");
  assert.match(html, /Observer: The sandbox(&#x27;|')s network/);
  assert.match(html, />Held by the task only</);
  // Advice is not a refusal: the plan is still ready to start once the target is confirmed.
  assert.match(html, /data-testid="assess-confirm"/);
  assert.doesNotMatch(html, /verified|confirmed by|\bclean\b|vulnerable|authentic|\bsecure\b/i);
});

test("a pen test's settings in force name the request limits, the project facts and what happens to environment files", async () => {
  await apiCache.fetch(`${assessPlanPath("pentest_local", "h1")}&n=t`, async () => depthPt);
  const html = renderToStaticMarkup(planDialog(pentest));
  assert.match(html, /Request budget 600, at most 5 a second\. Held by the task only: nothing between the agent and the target counts them\./);
  assert.match(html, /The task carries a digest of facts from the project, without the open findings: 3 sections, 900 bytes\. 2 strings were left out/);
  assert.match(html, /Environment files: Hide in the sandbox is chosen, but the sandbox this run will use cannot hide files, so it acts as a warning\./);
  assert.match(html, /Test categories: /);
  // The limits list keeps its test id and its help entry.
  assert.match(html, /data-testid="assess-limits"/);
  assert.match(html, /data-help-id="card.code_security_assess_limits"/);
});

test("a plan from an older server, with none of the new blocks, renders as it did and shows none of the new sections", async () => {
  await apiCache.fetch(`${assessPlanPath("pentest_local", "h1")}&n=t`, async () => confinedPlan);
  const html = renderToStaticMarkup(planDialog(pentest));
  for (const id of ["assess-scope", "assess-previous", "assess-start", "assess-before", "assess-preflight", "assess-tools", "assess-safety", "assess-env"]) {
    assert.doesNotMatch(html, new RegExp(`data-testid="${id}"`), id);
  }
  assert.match(html, /data-testid="assess-target"/);
  assert.match(html, /data-testid="assess-prompt-text"/);
  // A candidate with no source reads as before.
  assert.doesNotMatch(html, /from \.claude|>from /);
  // And so does a threat model plan with none of them.
  await apiCache.fetch(`${assessPlanPath("threat_model", "h1")}&n=t`, async () => tmPlan);
  const tm = renderToStaticMarkup(planDialog(base));
  for (const id of ["assess-scope", "assess-previous", "assess-start", "assess-before"]) assert.doesNotMatch(tm, new RegExp(`data-testid="${id}"`), id);
  assert.match(tm, /Choose agent/);
});

test("the scope picker shows a typed place with its Add button ready, and the chips with a remove button", () => {
  const scope: AssessScope = { dirs: ["cmd", "internal"], paths: ["cmd"], note: "", max_paths: 8, max_note: 200 };
  const html = renderToStaticMarkup(
    <AssessScopePicker scope={scope} paths={["cmd", "web/app"]} note="" typed="internal/db" locked={false} onPaths={() => {}} onNote={() => {}} onTyped={() => {}} />,
  );
  assert.ok(tagOf(html, "input", 'data-testid="assess-scope-input"').includes('value="internal/db"'));
  // Add is enabled with text in the field.
  assert.ok(!isDisabled(buttonTag(html, "Add")), "Add is ready");
  assert.ok(isChecked(tagOf(html, "input", 'data-testid="assess-scope-dir-cmd"')));
  assert.ok(!isChecked(tagOf(html, "input", 'data-testid="assess-scope-dir-internal"')));
  // A typed place is a chip too, with a button that names what it removes.
  assert.match(html, /data-testid="assess-scope-chip-web\/app"/);
  assert.match(html, /aria-label="Remove web\/app from the scope"/);
  assert.match(html, /2 of 8 places chosen\./);
  // The server's limits are used, and a missing limit falls back to the plan's own 8 and 200.
  const fallback = renderToStaticMarkup(
    <AssessScopePicker scope={{ ...scope, max_paths: 0, max_note: 0 }} paths={["cmd"]} note="hi" typed="" locked={false} onPaths={() => {}} onNote={() => {}} onTyped={() => {}} />,
  );
  assert.match(fallback, /1 of 8 places chosen\./);
  assert.match(fallback, /2 of 200 characters\./);
  assert.match(fallback, /maxLength="200"|maxlength="200"/i);
});

test("the start field's Use this command is ready only when what is typed differs from the command in force", () => {
  const start: AssessStart = { plans: [{ command: "npm run dev", source: "package.json scripts" }], selected_command: "npm run dev", edit: "npm run dev", edited: false, none_found: false };
  const render = (draft: string | undefined, chosen?: string) =>
    renderToStaticMarkup(<AssessStartPlan start={start} chosen={chosen} draft={draft} locked={false} onChoose={() => {}} onDraft={() => {}} onUse={() => {}} />);
  const waiting = (h: string) => isDisabled(buttonTag(h, "Use this command"));
  assert.ok(waiting(render(undefined)));
  assert.ok(waiting(render("npm run dev")), "the same text is not a change");
  assert.ok(!waiting(render("npm start")));
  assert.match(render("npm start"), /value="npm start"/);
  // A chosen "none" empties the field and checks the none row; a typed command unchecks the list.
  const none = render(undefined, "none");
  assert.ok(isChecked(tagOf(none, "input", 'data-testid="assess-start-none"')));
  assert.ok(tagOf(none, "input", 'data-testid="assess-start-input"').includes('value=""'));
  const typed = render(undefined, "make dev");
  assert.ok(!isChecked(tagOf(typed, "input", 'data-testid="assess-start-plan-0"')));
  assert.match(typed, /value="make dev"/);
  // A held run cannot change it.
  const locked = renderToStaticMarkup(<AssessStartPlan start={start} chosen={undefined} draft={undefined} locked onChoose={() => {}} onDraft={() => {}} onUse={() => {}} />);
  assert.doesNotMatch(locked, /data-testid="assess-start-input"/);
  assert.ok(isDisabled(tagOf(locked, "input", 'data-testid="assess-start-plan-0"')));
});

test("a run row says what a threat model was scoped to and what it is compared with", () => {
  const html = renderToStaticMarkup(
    <MemoryRouter>
      <AssessRunsList
        importAvailable
        onReport={() => {}}
        runs={[
          run({ id: "s1", scope: { paths: ["cmd/api", "internal/db"], note: "payment flow" }, previous_run: "00000000000000a1" }),
          run({ id: "s2" }),
          run({ id: "00000000000000a1", created_at: "2026-11-13T09:00:00Z" }),
        ]}
      />
    </MemoryRouter>,
  );
  assert.equal((html.match(/data-testid="assess-run-scope"/g) ?? []).length, 1, "only the run that has a scope or a comparison shows the line");
  assert.match(html, /Scope: cmd\/api, internal\/db\. Note: payment flow\. Compared with the earlier run \(Threat model, [A-Z][a-z]{2} \d+, 2026, [^)]*\): shown once the model is checked/);
  assert.doesNotMatch(html, /Compared with run /);
  assert.doesNotMatch(html, /verified|confirmed|\bclean\b/i);
});

test("a run row says its comparison was not made when the earlier run's copy is gone, and never says it was made", () => {
  const html = renderToStaticMarkup(
    <MemoryRouter>
      <AssessRunsList
        importAvailable
        onReport={() => {}}
        runs={[
          run({ id: "c1", previous_run: "00000000000000a1", compare_state: "previous_missing" }),
          run({ id: "c2", previous_run: "00000000000000a1", compare_state: "ok" }),
          run({ id: "c3", scope: { paths: [], note: "only the payment flow" }, previous_run: "00000000000000a0", compare_state: "too_large" }),
          run({ id: "c4", previous_run: "ffffffffffffffff", compare_state: "ok" }),
          run({ id: "00000000000000a1", created_at: "2026-11-13T09:00:00Z" }),
          run({ id: "00000000000000a0", created_at: "2026-11-12T09:00:00Z" }),
        ]}
      />
    </MemoryRouter>,
  );
  assert.match(html, /Not compared with the earlier run \(Threat model, [A-Z][a-z]{2} \d+, 2026, [^)]*\): Observer no longer has a usable checked copy of it/);
  assert.match(html, />Compared with the earlier run \(Threat model, [A-Z][a-z]{2} \d+, 2026, [^)]*\)</);
  // An earlier run the list no longer holds is said so, not named by its identifier.
  assert.match(html, />Compared with an earlier run that is no longer in the list</);
  assert.doesNotMatch(html, /ffffffffffffffff/);
  // The note is the developer's own words and the task carries it whether or not a place was chosen.
  assert.match(html, /Note: only the payment flow\. Compared with the earlier run \(Threat model, [A-Z][a-z]{2} \d+, 2026, [^)]*\), but the comparison was too large to keep/);
  assert.doesNotMatch(html, /shown once the model is checked/, "every one of these has an outcome");
});

// --- Start plans by choice and folder, and the opt-in to preparation steps (W4) ---

const dir2: AssessStart = {
  plans: [
    { command: "npm run dev", port: 5173, source: "launch.json", cwd: "web", choice: "web::npm run dev" },
    { command: "npm run dev", port: 3000, source: "package.json scripts" },
    { command: "python manage.py runserver 8000", port: 8000, source: "manage.py", prepare: ["python manage.py migrate", "python manage.py loaddata seed"], needs: ["db"] },
  ],
  selected_command: "web::npm run dev",
  edit: "npm run dev",
  edited: false,
  none_found: false,
};

test("two start plans with the same command in different folders are told apart by their choice, and the folder is shown", () => {
  const render = (chosen?: string, over: Partial<AssessStart> = {}) =>
    renderToStaticMarkup(<AssessStartPlan start={{ ...dir2, ...over }} chosen={chosen} draft={undefined} locked={false} onChoose={() => {}} onDraft={() => {}} onUse={() => {}} />);
  // The server's pick is the one in web/, not the same command in the project's own folder.
  const pick = render();
  assert.ok(isChecked(tagOf(pick, "input", 'data-testid="assess-start-plan-0"')), "the plan in web/ is the pick");
  assert.ok(!isChecked(tagOf(pick, "input", 'data-testid="assess-start-plan-1"')), "the same command in the project's folder is not");
  assert.match(pick, />In the folder web\/</);
  assert.equal((pick.match(/In the folder/g) ?? []).length, 1, "only the plan with a folder says one");
  // The field holds the command, not the choice string.
  assert.ok(tagOf(pick, "input", 'data-testid="assess-start-input"').includes('value="npm run dev"'));
  assert.doesNotMatch(tagOf(pick, "input", 'data-testid="assess-start-input"'), /web::/);
  assert.match(pick, /The agent is told to start the application with: npm run dev \(in web\/\)\./);
  // Choosing the other one by its choice string (its command) checks that one.
  const other = render("npm run dev", { selected_command: "npm run dev" });
  assert.ok(!isChecked(tagOf(other, "input", 'data-testid="assess-start-plan-0"')));
  assert.ok(isChecked(tagOf(other, "input", 'data-testid="assess-start-plan-1"')));
  assert.match(other, /The agent is told to start the application with: npm run dev\./);
  // An older server with no choice or folder at all still checks the plan by its command.
  const old: AssessStart = { plans: [{ command: "npm run dev", source: "package.json scripts" }], selected_command: "npm run dev", edit: "npm run dev", edited: false, none_found: false };
  const oldHtml = renderToStaticMarkup(<AssessStartPlan start={old} chosen={undefined} draft={undefined} locked={false} onChoose={() => {}} onDraft={() => {}} onUse={() => {}} />);
  assert.ok(isChecked(tagOf(oldHtml, "input", 'data-testid="assess-start-plan-0"')));
  assert.doesNotMatch(oldHtml, /In the folder/);
});

test("the preparation steps are an opt-in under the selected plan: unticked by default, the steps listed, and why", () => {
  const render = (chosen: string | undefined, prepare?: boolean, over: Partial<AssessStart> = {}, locked = false) =>
    renderToStaticMarkup(
      <AssessStartPlan start={{ ...dir2, ...over }} chosen={chosen} draft={undefined} locked={locked} prepare={prepare} onChoose={() => {}} onDraft={() => {}} onUse={() => {}} onPrepare={() => {}} />,
    );
  const dj = "python manage.py runserver 8000";
  // A selected plan that has steps offers the checkbox, off, with the steps and the sentence.
  const off = render(dj);
  assert.match(off, /data-testid="assess-prepare"/);
  const box = tagOf(off, "input", 'data-testid="assess-prepare-check"');
  assert.ok(box !== "" && !isChecked(box) && !isDisabled(box), box);
  assert.match(off, />Run the preparation steps first</);
  assert.match(off, /data-testid="assess-prepare-steps"[^>]*><li[^>]*>python manage\.py migrate<\/li><li[^>]*>python manage\.py loaddata seed<\/li>/);
  assert.match(off, /Preparation steps can change local data in the project, for example its database file\./);
  // The steps are listed once: the plan row does not repeat them under the selected plan.
  assert.doesNotMatch(off, /Preparation steps, not run unless you choose to/);
  assert.doesNotMatch(off, /The agent is told to run the preparation steps first|It is told to run the preparation steps first/);
  // A plan without steps, a typed command and "none" offer nothing to tick.
  for (const chosen of [undefined, "npm run dev", "make dev", "none"]) {
    assert.doesNotMatch(render(chosen), /data-testid="assess-prepare"/, String(chosen));
  }
  // Ticked: checked, and the plan line says the steps run first.
  const on = render(dj, true, { selected_command: dj, prepare: true });
  assert.ok(isChecked(tagOf(on, "input", 'data-testid="assess-prepare-check"')));
  assert.match(on, /The agent is told to start the application with: python manage\.py runserver 8000\. It is told to run the preparation steps first\./);
  // The unselected plan still lists its steps, with the words that say they are not run unless chosen.
  assert.match(render(undefined), />Preparation steps, not run unless you choose to: python manage\.py migrate; python manage\.py loaddata seed</);
  // A held run's choice is shown as its server echoed it, and cannot be changed.
  const heldOn = render(dj, undefined, { selected_command: dj, prepare: true }, true);
  const heldBox = tagOf(heldOn, "input", 'data-testid="assess-prepare-check"');
  assert.ok(isChecked(heldBox) && isDisabled(heldBox), heldBox);
  const heldOff = render(dj, undefined, { selected_command: dj }, true);
  assert.ok(!isChecked(tagOf(heldOff, "input", 'data-testid="assess-prepare-check"')));
  // The developer's own tick wins over the echo.
  assert.ok(!isChecked(tagOf(render(dj, false, { selected_command: dj, prepare: true }), "input", 'data-testid="assess-prepare-check"')));
});

test("a pen test plan whose server pick has preparation steps shows the opt-in unticked, from the plan itself", async () => {
  const withSteps: AssessPlan = {
    ...depthPt,
    run_id: "3fa9c2d17b0e4a70",
    start: { ...dir2, selected_command: "python manage.py runserver 8000", edit: "python manage.py runserver 8000" },
  };
  await apiCache.fetch(`${assessPlanPath("pentest_local", "h1")}&n=t`, async () => withSteps);
  const html = renderToStaticMarkup(planDialog(pentest));
  assert.match(html, /data-testid="assess-prepare"/);
  assert.ok(!isChecked(tagOf(html, "input", 'data-testid="assess-prepare-check"')), "off until the developer ticks it");
  assert.match(html, />Run the preparation steps first</);
  assert.ok(isChecked(tagOf(html, "input", 'data-testid="assess-start-plan-2"')));
  assert.ok(tagOf(html, "input", 'data-testid="assess-start-input"').includes('value="python manage.py runserver 8000"'));
  // The server echoes the opt-in of a plan read with it: the box is ticked.
  const ticked: AssessPlan = { ...withSteps, run_id: "3fa9c2d17b0e4a71", start: { ...withSteps.start!, prepare: true } };
  await apiCache.fetch(`${assessPlanPath("pentest_local", "h1")}&n=t`, async () => ticked);
  assert.ok(isChecked(tagOf(renderToStaticMarkup(planDialog(pentest)), "input", 'data-testid="assess-prepare-check"')));
});

test("the scope note field shows the note the dialog holds, and the scope picker says the task carries it with or without places", () => {
  const scope: AssessScope = { dirs: ["cmd"], paths: [], note: "", max_paths: 8, max_note: 200 };
  const render = (note: string, paths: string[] = []) =>
    renderToStaticMarkup(<AssessScopePicker scope={scope} paths={paths} note={note} typed="" locked={false} onPaths={() => {}} onNote={() => {}} onTyped={() => {}} />);
  // A fresh field holds the note; a note and no place is shown, and is still "your own words".
  const noPlace = render("only the payment flow");
  assert.ok(tagOf(noPlace, "input", 'data-testid="assess-scope-note"').includes('value="only the payment flow"'));
  assert.match(noPlace, /21 of 200 characters\. It goes into the task as your own words/);
  assert.match(noPlace, /By default the whole project is covered\./);
  // The same picker for another note (another project, a plan read again) shows that note, never the earlier one.
  assert.ok(tagOf(render(""), "input", 'data-testid="assess-scope-note"').includes('value=""'));
  assert.ok(tagOf(render("billing", ["cmd"]), "input", 'data-testid="assess-scope-note"').includes('value="billing"'));
});

// --- The request helper on the plan (depth plan W5b) -------------------------

/** helperText is the text of the plan's request helper block. */
function helperBlock(html: string): string {
  const a = html.indexOf('data-testid="assess-helper"');
  assert.ok(a >= 0, "the request helper block is on the plan");
  const rest = html.slice(a);
  const b = rest.indexOf("</section>");
  return rest.slice(0, b >= 0 ? b : undefined);
}

function plainText(html: string): string {
  return html
    .replace(/<[^>]*>/g, " ")
    .replace(/&#x27;/g, "'")
    .replace(/&quot;/g, '"')
    .replace(/&gt;/g, ">")
    .replace(/&lt;/g, "<")
    .replace(/&amp;/g, "&")
    .replace(/\s+/g, " ");
}

test("a pen test plan with the request helper on lists probe.py and probe.json, the folder, the budget and pace, and says the log is a file the agent can write", async () => {
  const on: AssessPlan = { ...depthPt, run_id: "20261114-ab12cd", probe: { state: "on", files: ["probe.py", "probe.json"], dir: ".observer/assessments/20261114-ab12cd", budget: 600, pace_rps: 5 } };
  await apiCache.fetch(`${assessPlanPath("pentest_local", "h1")}&n=t`, async () => on);
  const html = renderToStaticMarkup(planDialog(pentest));
  const block = helperBlock(html);
  assert.match(block, /data-helper-state="on"/);
  assert.match(plainText(block), /^.*Request helper/);
  assert.match(block, /data-help-id="card\.code_security_assess_probe"/);
  assert.match(block, /<code[^>]*>probe\.py<\/code>/);
  assert.match(block, /<code[^>]*>probe\.json<\/code>/);
  assert.match(block, /<ul[^>]*aria-label="Files written into the run folder"/);
  const t = plainText(block);
  assert.match(t, /Observer writes these two files into the run folder before the agent starts; the helper sends requests to the target address only, applies the pace and the request budget, and logs each request to probes\.jsonl\. The log is a file the agent can write\./);
  assert.match(t, /In the run folder \.observer\/assessments\/20261114-ab12cd in the project\./);
  assert.match(t, /Request budget: 600 requests\./);
  assert.match(t, /Pace: at most 5 requests a second\./);
  assert.match(t, /A request the agent makes another way, with curl or its own code, is not logged, and a finding that rests on it reads No log\./);
  // It comes after what Observer noticed and before the settings in force, and the limits line no longer says only the task holds them.
  assert.ok(html.indexOf('data-testid="assess-before"') < html.indexOf('data-testid="assess-helper"'));
  assert.ok(html.indexOf('data-testid="assess-helper"') < html.indexOf('data-testid="assess-limits"'));
  assert.match(plainText(html), /Request budget 600, at most 5 a second\. Held by the task, and by the request helper for the requests that go through it\./);
  assert.doesNotMatch(plainText(html), /Request budget 600, at most 5 a second\. Held by the task only/);
  assert.doesNotMatch(t, /verified|confirmed|\bclean\b|vulnerable|authentic|\bsecure\b|\bsafe\b/i);
});

test("a pen test plan with the request helper off says nothing is written and every finding's evidence reads No log", async () => {
  const off: AssessPlan = { ...depthPt, run_id: "20261114-ab12ce", probe: { state: "off", dir: ".observer/assessments/20261114-ab12ce", budget: 600, pace_rps: 5 } };
  await apiCache.fetch(`${assessPlanPath("pentest_local", "h1")}&n=t`, async () => off);
  const html = renderToStaticMarkup(planDialog(pentest));
  const block = helperBlock(html);
  assert.match(block, /data-helper-state="off"/);
  assert.doesNotMatch(block, /probe\.py|probe\.json|assess-helper-files/);
  assert.match(plainText(block), /The request helper is off \(a setting\): nothing is written, and every finding's evidence reads No log\./);
  assert.match(plainText(block), /The setting is "Request helper for penetration tests" \(Settings > Guard > Code security\)\./);
  assert.doesNotMatch(block.replace(/data-setting="[^"]*"/g, ""), /probe_helper/);
  // The line that names the setting is followed by the way to its row (N-10; its address and its managed case are in AssessSettingLink.test.tsx).
  assert.match(plainText(block), /Open the setting "Request helper for penetration tests"/);
  // The request limits stay with the task alone.
  assert.match(plainText(html), /Request budget 600, at most 5 a second\. Held by the task only: nothing between the agent and the target counts them\./);
});

test("a pen test plan with the request helper left out says why, and that every finding's evidence reads No log", async () => {
  const held: AssessPlan = {
    ...depthPt,
    run_id: "20261114-ab12cf",
    probe: { state: "withheld", withheld_reason: "python3 was not seen in the sandbox's standard folders, so the request helper is left out.", dir: ".observer/assessments/20261114-ab12cf", budget: 600, pace_rps: 5 },
  };
  await apiCache.fetch(`${assessPlanPath("pentest_local", "h1")}&n=t`, async () => held);
  const html = renderToStaticMarkup(planDialog(pentest));
  const block = helperBlock(html);
  assert.match(block, /data-helper-state="withheld"/);
  assert.doesNotMatch(block, /probe\.py|probe\.json|assess-helper-files/);
  assert.match(plainText(block), /python3 was not seen in the sandbox's standard folders, so the request helper is left out\. Every finding's evidence reads No log\./);
  // A plan with no probe member (a kind that sends no requests, or an older server) has no block at all.
  await apiCache.fetch(`${assessPlanPath("pentest_local", "h1")}&n=t`, async () => depthPt);
  assert.doesNotMatch(renderToStaticMarkup(planDialog(pentest)), /data-testid="assess-helper"/);
});

test("a run row shows what the workspace secret mask covered, in a warning when it was partial", () => {
  const html = renderToStaticMarkup(
    <MemoryRouter>
      <AssessRunsList
        importAvailable
        onReport={() => {}}
        runs={[
          run({
            id: "m1",
            secret_mode: "mask",
            secret_mask: { reported: true, masked: 2, complete: false, gaps: 3, words: "2 files hidden inside the box; 3 places could not be covered.", partial: true },
          }),
          run({ id: "m2", secret_mode: "warn", secret_mode_why: "backend_cannot_mask" }),
          run({ id: "m3" }),
        ]}
      />
    </MemoryRouter>,
  );
  assert.equal((html.match(/data-testid="assess-run-mask"/g) ?? []).length, 2, "only a run that asked for the mask or lost it shows the line");
  assert.match(html, /Environment files: 2 files hidden inside the box; 3 places could not be covered\./);
  assert.match(html, /Hide in the sandbox was chosen, but the sandbox this run will use cannot hide files, so it acted as a warning\./);
  assert.doesNotMatch(html, /verified|confirmed|safe|secure/i);
});
