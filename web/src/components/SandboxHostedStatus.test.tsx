// Render tests of the Hosted sandboxes status view (lane SBX-P7, owed by its
// merge, plans decision log P-090), rendered with react-dom/server under
// node's test runner (scripts/test-components.mjs). The view takes the
// fetched answer as a prop, so no fetch runs here.

import { test } from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { SandboxHostedStatusView, type HostedStatusResponse, type SandboxHostedStatusViewProps } from "@/components/SandboxHostedStatus";

// React warns that a layout effect does nothing on the server; the chips use
// one, and the warning says nothing about these tests.
const consoleError = console.error;
console.error = (...args: unknown[]) => {
  if (typeof args[0] === "string" && args[0].includes("useLayoutEffect does nothing on the server")) return;
  consoleError(...args);
};

const answer: HostedStatusResponse = {
  confirm_token: "tok",
  providers: [
    {
      id: "e2b",
      name: "E2B",
      credential: "keystore",
      credential_env: ["E2B_API_KEY"],
      consent: { at: "2026-10-23T10:00:00Z" },
      consent_verdict: "consent_changed_cap",
      screen: {
        lines: [{ label: "Region", value: "us-west-1" }],
        excluded: [{ path: ".env.local", reason: "env_file" }],
        uploaded: ["main.go"],
        uploaded_more: 3,
      },
      unverified: ["resize"],
      endpoint_docs: null,
    },
    {
      id: "modal",
      name: "Modal",
      credential: "",
      credential_env: ["MODAL_TOKEN_ID", "MODAL_TOKEN_SECRET"],
      unverified: null,
      endpoint_docs: null,
    },
  ],
  leftovers: [
    {
      run_id: "r1",
      provider: "e2b",
      region: "us-west-1",
      vendor_id: "",
      state: "delete_unconfirmed",
      age_seconds: 3900,
      expires_in_seconds: 0,
      action: "find_and_delete",
      adoptable: false,
    },
  ],
  spend: [{ provider: "e2b", day: "2026-10-23", minutes: 12, estimate: { usd: 0.02, price: { date: "2026-10-01" } } }],
};

function view(over: Partial<SandboxHostedStatusViewProps> = {}): string {
  return renderToStaticMarkup(
    <SandboxHostedStatusView
      data={answer}
      selected={["e2b", "modal"]}
      workspace="/w"
      onWorkspace={() => {}}
      rootOptions={[{ id: "/w", label: "/w" }]}
      busy=""
      err={null}
      post={() => {}}
      today="2026-10-23"
      {...over}
    />,
  );
}

test("the hosted status names each selected provider's credential source, never a value", () => {
  const html = view();
  assert.match(html, /E2B/);
  assert.match(html, /connected \(stored in this machine&#x27;s keychain\)/);
  assert.match(html, /observer sandbox hosted connect modal/);
  assert.match(html, /MODAL_TOKEN_ID, MODAL_TOKEN_SECRET/);
});

test("the consent screen lists the uploaded and excluded files and names a changed fact", () => {
  const html = view();
  assert.match(html, /Region/);
  assert.match(html, /us-west-1/);
  assert.match(html, /main\.go/);
  assert.match(html, /and 3 more/);
  assert.match(html, /\.env\.local \(env file\)/);
  assert.match(html, /Agree again \(consent changed cap\)/);
  assert.match(html, /Withdraw agreement/);
});

test("today's box-minutes and a leftover whose create answer was lost", () => {
  const html = view();
  assert.match(html, /Today: 12 box-minutes/);
  assert.match(html, /\(create answer lost\)/);
  assert.match(html, /delete unconfirmed, started 1 h 5 min ago, past its timeout/);
});

test("a provider not selected is not shown, and no leftovers says so", () => {
  const html = view({ selected: ["modal"], data: { ...answer, leftovers: [] } });
  assert.doesNotMatch(html, />E2B</);
  assert.match(html, /None: every box this machine created was deleted and confirmed\./);
});

test("an error from a write is shown", () => {
  assert.match(view({ err: "consent refused" }), /consent refused/);
});
