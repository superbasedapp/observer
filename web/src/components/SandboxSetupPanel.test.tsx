// Component tests of the sandbox setup panel (sandbox installation
// lifecycle plan section 3.7 and 10), rendered with react-dom/server under
// node's test runner (scripts/test-components.mjs). Server rendering runs no
// effect, so the panel is fed fixture data through its test seeds; the copy
// itself is pinned in src/lib/sandboxSetup.test.ts.

import { test } from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router-dom";
import { SandboxSetupPanel } from "@/components/SandboxSetupPanel";
import { SandboxBackendsList, SandboxSetupRowsList } from "@/components/SandboxSettingsCard";
import type { SandboxBackendAvail } from "@/lib/types";
import type { SandboxSetupPlan, SandboxSetupSummary } from "@/lib/sandboxSetupTypes";
import { setupLine } from "@/lib/sandboxSetup";

const setupSummaries: SandboxSetupSummary[] = [
  { backend: "bwrap", label: "Bubblewrap", ready: true },
  { backend: "cloud-hypervisor", label: "Cloud Hypervisor", ready: false, next: "Cloud Hypervisor" },
  { backend: "openshell", label: "OpenShell", ready: false, blocked: "OpenShell does not run in WSL2" },
];

const setupPlan: SandboxSetupPlan = {
  backend: "cloud-hypervisor",
  label: "Cloud Hypervisor",
  next: 1,
  ready: false,
  checked: false,
  fingerprint: "fp-1",
  steps: [
    {
      prereq: "component",
      kind: "component",
      label: "Sandboxes and VMs module: VM",
      state: "done",
      class: "auto",
      channel: "component_select",
      can_run: false,
      can_undo: true,
    },
    {
      prereq: "cloud-hypervisor",
      kind: "program",
      label: "Cloud Hypervisor",
      state: "missing",
      class: "auto",
      channel: "pinned_download",
      can_run: true,
      can_undo: false,
      consent: {
        pin: "cloud-hypervisor-linux-amd64",
        version: "54.0",
        sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        bytes: 4_800_000,
        source: "vendor_release",
      },
      docs: "sandboxed-terminals.md#microvm-sandboxes-cloud-hypervisor-beta",
    },
    {
      prereq: "virtiofsd",
      kind: "program",
      label: "virtiofsd",
      state: "missing",
      class: "guide",
      channel: "pm",
      display: "sudo apt-get install -y virtiofsd",
      display_is_command: true,
      can_run: false,
      can_undo: false,
    },
    {
      prereq: "kvm-device",
      kind: "kernel_feature",
      label: "/dev/kvm",
      state: "blocked",
      class: "never",
      channel: "none",
      display: "WSL2 needs nested virtualization turned on in your Windows .wslconfig.",
      after: "reboot",
      can_run: false,
      can_undo: false,
      docs: "sandboxed-terminals.md#the-probe",
    },
    {
      prereq: "e2fsprogs",
      kind: "program",
      label: "e2fsprogs",
      state: "in_flight",
      class: "elevated",
      channel: "pm",
      disclosure: "Installs a system package with your password.",
      can_run: false,
      can_undo: false,
      record: {
        id: 9,
        tool: "e2fsprogs",
        channel: "apt",
        command: "sudo apt-get install -y e2fsprogs",
        status: "installing",
        installed_at: "2026-11-06T09:00:00Z",
        can_uninstall: false,
        can_forget: false,
        terminal_handle: "h-9",
        maybe_waiting_for_input: true,
        subject_kind: "sandbox",
        backend: "cloud-hypervisor",
      },
    },
    {
      prereq: "enable",
      kind: "enable",
      label: "Turn on Cloud Hypervisor",
      state: "missing",
      class: "auto",
      channel: "sandbox_enable",
      can_run: true,
      can_undo: false,
    },
  ],
};

function render(compact: boolean, plan: SandboxSetupPlan = setupPlan): string {
  return renderToStaticMarkup(
    <MemoryRouter>
      <SandboxSetupPanel compact={compact} backend="cloud-hypervisor" initialSummaries={setupSummaries} initialPlan={plan} onTerminal={() => {}} />
    </MemoryRouter>,
  );
}

// stepHTML returns the markup of one step's list item.
function stepHTML(html: string, prereq: string): string {
  const m = html.match(new RegExp(`<li data-step="${prereq}"[\\s\\S]*?</li>`));
  assert.ok(m, `no step ${prereq}`);
  return m[0];
}

test("the row chooser is a picker of the offered rows, on the preselected row", () => {
  const html = render(true);
  assert.match(html, /<select id="sandbox-setup-backend"/);
  assert.match(html, /<option value="bwrap">Bubblewrap \(set up\)<\/option>/);
  assert.match(html, /<option value="cloud-hypervisor" selected="">Cloud Hypervisor \(next: Cloud Hypervisor\)<\/option>/);
  assert.match(html, /<option value="openshell">OpenShell \(cannot run here\)<\/option>/);
  assert.match(html, /Cloud Hypervisor is not set up yet\. Next: Cloud Hypervisor\./);
  assert.match(html, /Check this machine/);
  assert.match(html, /Re-check/);
});

test("each step shows its chip and the button its class offers", () => {
  const html = render(true);
  assert.match(stepHTML(html, "component"), /Done/);
  assert.doesNotMatch(stepHTML(html, "component"), /Turn on/);
  assert.match(stepHTML(html, "cloud-hypervisor"), /Needed/);
  assert.match(stepHTML(html, "cloud-hypervisor"), /Download and install \(5 MB, v54\.0\)/);
  assert.match(stepHTML(html, "virtiofsd"), /Copy command/);
  assert.match(stepHTML(html, "enable"), /Turn on/);
  const never = stepHTML(html, "kvm-device");
  assert.match(never, /Blocked on this machine/);
  // A never step's only control is its help link.
  assert.deepEqual(never.match(/<button[^>]*>/g)?.length, 1);
  assert.match(never, /<button[^>]*data-help-id="glossary\.terminals_sandbox_setup_kvm"/);
  assert.match(never, /restart the computer/);
  // A sentence display is not shown as code.
  assert.doesNotMatch(never, /<code/);
});

// The operator's report: "Read how this step works" opened a GitHub page.
// Every card's help opens the dashboard's own help drawer (App.tsx's
// delegated data-help-id listener) and nothing links out of the dashboard.
test("every step's help opens the dashboard's help drawer, never a page outside it", () => {
  for (const html of [render(true), render(false)]) {
    assert.doesNotMatch(html, /github\.com/);
    assert.doesNotMatch(html, /target="_blank"/);
    for (const prereq of ["component", "cloud-hypervisor", "virtiofsd", "kvm-device", "e2fsprogs", "enable"]) {
      assert.match(stepHTML(html, prereq), /<button type="button" data-help-id="glossary\.terminals_sandbox_setup[a-z_]*"[^>]*>.*How this step works<\/button>/s, prereq);
    }
    assert.match(stepHTML(html, "cloud-hypervisor"), /data-help-id="glossary\.terminals_sandbox_setup_vm"/);
    assert.match(stepHTML(html, "component"), /data-help-id="glossary\.terminals_sandbox_setup_module"/);
    assert.match(stepHTML(html, "enable"), /data-help-id="glossary\.terminals_sandbox_setup_enable"/);
  }
});

// A hosted row (Daytona, the operator's case): the key step is a real
// field, never a "Turn on" that sends nothing; the consent step names the
// terminal it opens.
const hostedPlan = (keyOver: Partial<SandboxSetupPlan["steps"][number]> = {}): SandboxSetupPlan => ({
  backend: "daytona",
  label: "Daytona",
  next: 2,
  ready: false,
  checked: false,
  fingerprint: "fp-d",
  steps: [
    { prereq: "component", kind: "component", label: "The backend's module selected", state: "done", class: "auto", channel: "component_select", can_run: false, can_undo: true, docs: "sandboxed-terminals.md#the-isolation-engine-component-isolation" },
    { prereq: "hosted-account", kind: "account", label: "An account with the provider", state: "unknown", class: "never", channel: "none", display: "You need your own account with the provider; Observer never creates one.", can_run: false, can_undo: false, docs: "sandboxed-terminals.md#hosted-sandboxes-beta-e2b-modal-and-vercel-sandbox" },
    {
      prereq: "hosted-key",
      kind: "credential",
      label: "The provider's API key in this machine's keychain",
      state: "missing",
      class: "auto",
      channel: "hosted_connect",
      display: "Paste the provider's API key; it is kept in this machine's keychain and never logged.",
      fields: ["DAYTONA_API_KEY"],
      command: "observer sandbox hosted connect daytona",
      can_run: true,
      can_undo: false,
      docs: "sandboxed-terminals.md#hosted-sandboxes-beta-e2b-modal-and-vercel-sandbox",
      ...keyOver,
    },
    { prereq: "hosted-consent", kind: "consent", label: "Your consent for this provider", state: "missing", class: "auto", channel: "hosted_consent", display: "Read what leaves this machine and record your consent for this provider.", can_run: true, can_undo: false, docs: "sandboxed-terminals.md#hosted-sandboxes-beta-e2b-modal-and-vercel-sandbox" },
    { prereq: "enable", kind: "enable", label: "The backend enabled", state: "missing", class: "auto", channel: "sandbox_enable", display: "Add this backend to the end of the backends list.", can_run: true, can_undo: false, docs: "sandboxed-terminals.md#enabling-it" },
  ],
});

function renderHosted(plan: SandboxSetupPlan, compact = false): string {
  return renderToStaticMarkup(
    <MemoryRouter>
      <SandboxSetupPanel
        compact={compact}
        backend="daytona"
        initialSummaries={[{ backend: "daytona", label: "Daytona", ready: false, next: "The provider's API key in this machine's keychain" }]}
        initialPlan={plan}
        onTerminal={() => {}}
      />
    </MemoryRouter>,
  );
}

test("hosted: the key step is a masked field and a store button, never a bare Turn on", () => {
  for (const compact of [false, true]) {
    const key = stepHTML(renderHosted(hostedPlan(), compact), "hosted-key");
    assert.match(key, /<form[^>]*data-testid="sandbox-setup-key-form"/);
    assert.match(key, /<input type="password"[^>]*autoComplete="off"/i);
    assert.doesNotMatch(key, /value="[^"]+"/, "the field is never pre-filled");
    assert.match(key, /DAYTONA_API_KEY/);
    assert.match(key, /Store in this machine(&#x27;|')s keychain/);
    assert.doesNotMatch(key, /Turn on/);
    assert.match(key, /data-help-id="glossary\.terminals_sandbox_setup_hosted_key"/);
    // The CLI form is not offered beside a working field.
    assert.doesNotMatch(key, /observer sandbox hosted connect/);
  }
});

test("hosted: a provider with several values gets one field each, an ID as plain text", () => {
  const key = stepHTML(renderHosted(hostedPlan({ fields: ["VERCEL_TOKEN", "VERCEL_TEAM_ID", "VERCEL_PROJECT_ID"], command: "observer sandbox hosted connect vercel-sandbox" })), "hosted-key");
  assert.equal(key.match(/<input /g)?.length, 3);
  assert.match(key, /<input type="password"/);
  assert.equal(key.match(/<input type="text"/g)?.length, 2);
});

test("hosted: with guided installs off the key step shows the command to copy instead", () => {
  const key = stepHTML(
    renderHosted(hostedPlan({ class: "guide", channel: "none", reason: "Guided installs are turned off on this machine, so this is shown as steps to follow." })),
    "hosted-key",
  );
  assert.doesNotMatch(key, /<form/);
  assert.match(key, /<code[^>]*data-testid="sandbox-setup-command"[^>]*>observer sandbox hosted connect daytona<\/code>/);
  assert.match(key, /Copy command/);
  assert.match(key, /asks for DAYTONA_API_KEY and keeps it in this machine(&#x27;|')s keychain/);
});

test("hosted: a key step the organization does not allow shows no field", () => {
  const key = stepHTML(renderHosted(hostedPlan({ state: "not_allowed", can_run: false, reason: "Your organization does not allow this backend on this machine (allowed_backends)." })), "hosted-key");
  assert.match(key, /Not allowed by your organization/);
  assert.doesNotMatch(key, /<form/);
  assert.doesNotMatch(key, /<input/);
});

test("hosted: a stored key shows no field", () => {
  const key = stepHTML(renderHosted(hostedPlan({ state: "done", can_run: false })), "hosted-key");
  assert.match(key, /Done/);
  assert.doesNotMatch(key, /<form/);
});

test("org-hosted: the sign-in step names its terminal and opens the org gateway's help", () => {
  const plan: SandboxSetupPlan = {
    backend: "openshell-org",
    label: "OpenShell (org-hosted)",
    next: 1,
    ready: false,
    checked: false,
    fingerprint: "fp-o",
    steps: [
      { prereq: "component", kind: "component", label: "The backend's module selected", state: "done", class: "auto", channel: "component_select", can_run: false, can_undo: false },
      { prereq: "orgshell-login", kind: "account", label: "Signed in to your organization's OpenShell gateway", state: "missing", class: "auto", channel: "orgshell_login", display: "Sign in to your organization's OpenShell gateway with this machine.", can_run: true, can_undo: false, docs: "sandbox-openshell-org.md#turning-it-on" },
    ],
  };
  const login = stepHTML(renderHosted(plan), "orgshell-login");
  assert.match(login, /Sign in in terminal/);
  assert.doesNotMatch(login, /Turn on|<input/);
  assert.match(login, /data-help-id="glossary\.terminals_sandbox_setup_org_shell"/);
});

test("hosted: the consent and enable steps say what they do; the account step has only its help", () => {
  const html = renderHosted(hostedPlan());
  assert.match(stepHTML(html, "hosted-consent"), /Open the consent screen in terminal/);
  assert.doesNotMatch(stepHTML(html, "hosted-consent"), /Turn on/);
  assert.match(stepHTML(html, "hosted-consent"), /data-help-id="glossary\.terminals_sandbox_setup_hosted_consent"/);
  assert.match(stepHTML(html, "enable"), /Turn on/);
  const account = stepHTML(html, "hosted-account");
  assert.deepEqual(account.match(/<button[^>]*>/g)?.length, 1);
  assert.match(account, /data-help-id="glossary\.terminals_sandbox_setup_hosted_account"/);
});

test("hosted: the consent step asks for the folder first and cannot run without one", () => {
  const consent = stepHTML(renderHosted(hostedPlan()), "hosted-consent");
  assert.match(consent, /data-testid="sandbox-setup-consent-project"/);
  assert.match(consent, /Folder the consent is for/);
  assert.match(consent, /Defaults to the Observer workspace/);
  assert.match(consent, /<button[^>]*disabled[^>]*>(?:(?!<\/button>)[\s\S])*Open the consent screen in terminal/);
});

test("a download's consent line and a disclosure come before the button", () => {
  const html = render(true);
  const dl = stepHTML(html, "cloud-hypervisor");
  const consentAt = dl.indexOf("checked against sha256 0123456789ab");
  const buttonAt = dl.indexOf("Download and install");
  assert.ok(consentAt > 0 && consentAt < buttonAt, "consent before the button");
  const el = stepHTML(html, "e2fsprogs");
  assert.ok(el.indexOf("Before you run it: Installs a system package") < el.indexOf("Open the install terminal"));
});

test("a step in flight links its terminal and says it may be waiting for input", () => {
  const el = stepHTML(render(true), "e2fsprogs");
  assert.match(el, /In progress/);
  assert.match(el, /Open the install terminal/);
  assert.match(el, /may be waiting for input/);
  assert.match(el, /Installing from this dashboard/);
});

test("an elevated step degraded to a guide says how it becomes a button", () => {
  assert.match(stepHTML(render(true), "virtiofsd"), /allow_elevated = true/);
});

test("Manage mode offers Undo where the server allows it; the compact form does not", () => {
  assert.match(stepHTML(render(false), "component"), /Undo/);
  assert.doesNotMatch(stepHTML(render(true), "component"), /Undo/);
});

test("Manage mode offers Repair for a step this dashboard set up that no longer verifies", () => {
  const plan: SandboxSetupPlan = {
    ...setupPlan,
    steps: [
      {
        ...setupPlan.steps[1],
        state: "missing",
        reason: "the placed file no longer matches its checksum",
        record: { ...setupPlan.steps[4].record!, status: "installed", tool: "cloud-hypervisor", terminal_handle: undefined, maybe_waiting_for_input: false },
      },
    ],
  };
  const el = stepHTML(render(false, plan), "cloud-hypervisor");
  assert.match(el, /Repair/);
  // The step is not done now, so its record reads as history (D-R4-5).
  assert.match(el, /Last run from this dashboard on /);
});

test("a ready plan says so", () => {
  const ready: SandboxSetupPlan = { ...setupPlan, ready: true, next: -1, steps: [setupPlan.steps[0]] };
  assert.match(render(true, ready), /Cloud Hypervisor is set up and runs here\./);
});

test("the compact form links to the Backends setting; Settings' own form does not", () => {
  assert.match(render(true), /href="\/terminals#sandbox-backends"/);
  assert.doesNotMatch(render(false), /href="\/terminals#sandbox-backends"/);
});

test("no copy in the panel carries an em or en dash", () => {
  assert.doesNotMatch(render(false), /[\u2013\u2014]/);
  assert.doesNotMatch(render(true), /[\u2013\u2014]/);
});

// Settings > Terminals > Sandbox isolation: each backend gets "Set up" (not
// ready) or "Manage" (ready), opening this panel under the row; the
// Enabled checkboxes are unchanged.
const row = (over: Partial<SandboxBackendAvail>): SandboxBackendAvail => ({
  id: "bwrap",
  label: "Bubblewrap",
  class: "process",
  location: "local",
  maturity: "beta",
  available: true,
  beta: false,
  capture_by_tier: {},
  component: "terminals.sandbox",
  ...over,
});

const listRows = [
  row({}),
  row({ id: "cloud-hypervisor", label: "Cloud Hypervisor", class: "hw_vm", available: false, verdict: "backend_missing", reason: "cloud-hypervisor not found" }),
];

function settingsList(withSetup: boolean, open: string | null = null): string {
  return renderToStaticMarkup(
    <MemoryRouter>
      <SandboxBackendsList
        backends={listRows}
        order={["bwrap"]}
        egress="internet"
        writable
        onOrder={() => {}}
        {...(withSetup
          ? {
              onSetup: () => {},
              setupRows: {
                bwrap: { backend: "bwrap", label: "Bubblewrap", ready: true },
                "cloud-hypervisor": { backend: "cloud-hypervisor", label: "Cloud Hypervisor", ready: false, next: "x" },
              },
              setupOpen: open,
              setupPanel: (
                <SandboxSetupPanel backend="cloud-hypervisor" initialSummaries={setupSummaries} initialPlan={setupPlan} onTerminal={() => {}} />
              ),
            }
          : {})}
      />
    </MemoryRouter>,
  );
}

test("Settings: Set up for a row that is not ready, Manage for one that is", () => {
  const html = settingsList(true);
  assert.match(html, /aria-label="Manage Bubblewrap"[^>]*>Manage<\/button>/);
  assert.match(html, /aria-label="Set up Cloud Hypervisor"[^>]*>Set up<\/button>/);
  assert.match(html, /aria-label="Enable Bubblewrap"/);
  assert.doesNotMatch(html, /data-testid="sandbox-setup-panel"/);
});

test("Settings: the open row shows the full setup panel under it", () => {
  const html = settingsList(true, "cloud-hypervisor");
  assert.match(html, /data-testid="sandbox-setup-panel"/);
  // Full size (not compact): Manage actions show, the dialog's link does not.
  assert.match(html, /Undo/);
  assert.doesNotMatch(html, /Manage sandbox backends in Terminals settings/);
});

test("Settings: a row the setup summaries do not list (it does not run here) offers no Set up (D-4)", () => {
  const html = renderToStaticMarkup(
    <MemoryRouter>
      <SandboxBackendsList
        backends={listRows}
        order={["bwrap"]}
        egress="internet"
        writable
        onOrder={() => {}}
        onSetup={() => {}}
        setupRows={{ bwrap: { backend: "bwrap", label: "Bubblewrap", ready: false, unconfirmed: true } }}
      />
    </MemoryRouter>,
  );
  assert.match(html, /aria-label="Manage Bubblewrap"/);
  assert.doesNotMatch(html, /Set up Cloud Hypervisor/);
});

test("Settings: with the sandbox off the summaries still list Set up and Manage (D-3)", () => {
  const html = renderToStaticMarkup(
    <MemoryRouter>
      <SandboxSetupRowsList
        rows={[
          { backend: "bwrap", label: "Bubblewrap", ready: false, next: "Bubblewrap (bwrap) 0.4.0 or newer" },
          { backend: "process_lite", label: "Landlock only", ready: true },
        ]}
        onSetup={() => {}}
      />
    </MemoryRouter>,
  );
  assert.match(html, /data-testid="sandbox-setup-rows"/);
  assert.match(html, /aria-label="Set up Bubblewrap"[^>]*>Set up<\/button>/);
  assert.match(html, /aria-label="Manage Landlock only"[^>]*>Manage<\/button>/);
  assert.doesNotMatch(html, new RegExp(`[${String.fromCharCode(0x2013, 0x2014)}]`));
});

test("Settings: without the setup routes no Set up or Manage button shows", () => {
  const html = settingsList(false);
  assert.doesNotMatch(html, />Set up</);
  assert.doesNotMatch(html, />Manage</);
  assert.match(html, /aria-label="Enable Bubblewrap"/);
});

test("a beta row: the panel shows a Beta badge and the sentence, Settings reads (beta), the dialog line names it", () => {
  const sentence = "Setup on Windows 11 Pro is beta: it has not been checked on a live host yet.";
  const html = renderToStaticMarkup(
    <MemoryRouter>
      <SandboxSetupPanel
        backend="cloud-hypervisor"
        initialSummaries={setupSummaries.map((s) => (s.backend === "cloud-hypervisor" ? { ...s, beta: sentence } : s))}
        initialPlan={{ ...setupPlan, beta: sentence }}
        onTerminal={() => {}}
      />
    </MemoryRouter>,
  );
  assert.match(html, /data-testid="sandbox-setup-headline"[^>]*>[\s\S]*?>Beta<\/span>/);
  assert.match(html, new RegExp(`data-testid="sandbox-setup-beta"[^>]*>${sentence}</p>`));
  assert.match(html, /<option value="cloud-hypervisor" selected="">Cloud Hypervisor \(beta\) \(next: Cloud Hypervisor\)<\/option>/);
  assert.match(html, /<option value="bwrap">Bubblewrap \(set up\)<\/option>/);
  assert.doesNotMatch(render(true), /sandbox-setup-beta|>Beta</);

  const list = renderToStaticMarkup(
    <MemoryRouter>
      <SandboxBackendsList
        backends={listRows}
        order={["bwrap"]}
        egress="internet"
        writable
        onOrder={() => {}}
        onSetup={() => {}}
        setupRows={{
          bwrap: { backend: "bwrap", label: "Bubblewrap", ready: true },
          "cloud-hypervisor": { backend: "cloud-hypervisor", label: "Cloud Hypervisor", ready: false, next: "x", beta: sentence },
        }}
      />
    </MemoryRouter>,
  );
  assert.match(list, /aria-label="Set up Cloud Hypervisor"[^>]*>Set up \(beta\)<\/button>/);
  assert.match(list, /aria-label="Manage Bubblewrap"[^>]*>Manage<\/button>/);

  assert.equal(
    setupLine(2, ["Hyper-V isolated containers (HCS)"]),
    "Set up a sandbox backend (2 available to set up): Hyper-V isolated containers (HCS) (beta)",
  );
  assert.equal(setupLine(2), "Set up a sandbox backend (2 available to set up)");
});

// Fix round 4: a long unbroken token wraps (D-R4-4), the chooser follows a
// checked plan (D-R4-3), and a step not done reads its record as history
// (D-R4-5).
test("fix4: the chooser follows the checked plan, a needed step's record is history, long tokens wrap", () => {
  const digest = "ghcr.io/example/agent@sha256:" + "a".repeat(64);
  const summaries: SandboxSetupSummary[] = [{ backend: "apple-container", label: "Apple container", ready: false, unconfirmed: true }];
  const plan: SandboxSetupPlan = {
    backend: "apple-container",
    label: "Apple container",
    next: 0,
    ready: false,
    checked: true,
    fingerprint: "fp",
    steps: [
      {
        prereq: "apple-container-image",
        kind: "content",
        label: "The sandbox image",
        state: "missing",
        class: "auto",
        channel: "terminal_cmd",
        can_run: true,
        can_undo: false,
        reason: "The image " + digest + " is not present.",
        record: {
          id: 16,
          tool: "apple-container-image",
          channel: "terminal_cmd",
          command: "container image pull",
          status: "installed",
          installed_at: "2026-11-07T05:00:00Z",
          can_uninstall: false,
          can_forget: true,
        },
      },
    ],
  };
  const html = renderToStaticMarkup(
    <MemoryRouter>
      <SandboxSetupPanel backend="apple-container" compact onTerminal={() => {}} initialSummaries={summaries} initialPlan={plan} />
    </MemoryRouter>,
  );
  assert.match(html, /Apple container \(next: The sandbox image\)/);
  assert.doesNotMatch(html, /set up, not checked/);
  assert.match(html, /Last run from this dashboard on /);
  assert.doesNotMatch(html, /Installed from this dashboard/);
  assert.match(html, /data-testid="sandbox-setup-panel" class="[^"]*\[overflow-wrap:anywhere\]/);
});
