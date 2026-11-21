// Component tests of Settings > Connected tools > Cloud agents (cloud-agents
// lane CA-B5), rendered with react-dom/server under node's test runner
// (scripts/test-components.mjs): the connector catalog shows coverage level
// and needs, the key field is a password field that never carries a value
// the server sent, enumerable parameters are pickers, accounts show state,
// errors by class and honest missing figures, and the user picker appears
// for any connector whose catalog row declares chooses_user.

import { test } from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import {
  AccountRow,
  CloudAgentsBody,
  ConnectForm,
  ConnectorSummary,
  UserPicker,
} from "@/pages/settings/CloudAgentsCard";
import type { CloudAgentAccount, CloudAgentConnector, CloudAgentsView } from "@/lib/cloudAgents";

const noop = () => undefined;

const signals = [
  { signal: "discovery", state: "verified", label: "Verified" },
  { signal: "tokens", state: "not_established", label: "Not established" },
];

const codex: CloudAgentConnector = {
  id: "codex-cloud",
  label: "Codex Cloud",
  provider: "openai",
  tool: "codex",
  kind: "cli",
  command: "codex",
  experimental: true,
  placeholder_project: "[codex-cloud]",
  placeholder_note: "repository not reported",
  signals,
  doc_ref: "",
  needs_key: false,
  params: [],
  grounding: "live_verified",
  grounding_label: "Live verified",
  grounding_rank: 0,
  grounding_meaning: "A live run against a signed-in account confirmed what this connector reads.",
  chooses_user: false,
};

const devin: CloudAgentConnector = {
  ...codex,
  id: "devin",
  label: "Devin",
  provider: "cognition",
  tool: "devin",
  kind: "api",
  command: undefined,
  experimental: false,
  needs_key: true,
  key_label: "Devin personal access token or service-user key",
  params: [{ name: "org_id", label: "Organization id", hint: "org-<32 hex>" }],
  hosts: ["api.devin.ai"],
  grounding: "documented",
  grounding_label: "Documented",
  grounding_meaning: "Built from the vendor's published documentation.",
  chooses_user: true,
  user_label: "Devin user",
};

const qoder: CloudAgentConnector = {
  ...devin,
  id: "qoder-cloud",
  label: "Qoder Cloud",
  chooses_user: false,
  user_label: undefined,
  params: [
    {
      name: "region",
      label: "Region",
      hint: "Where your Qoder account lives",
      choices: [
        { value: "global", label: "Global" },
        { value: "cn", label: "China" },
      ],
    },
  ],
};

// A connector another lane adds through the same routes (OpenHands): the
// picker must follow the capability, not the id.
const openhands: CloudAgentConnector = { ...devin, id: "openhands-cloud", label: "OpenHands Cloud", params: [], user_label: "OpenHands user" };

function account(over: Partial<CloudAgentAccount> = {}): CloudAgentAccount {
  return {
    id: 3,
    connector: "codex-cloud",
    label: "Codex Cloud",
    provider: "openai",
    account_id: "user-abc",
    coverage: "verified",
    gaps: [],
    activity_gaps: 0,
    open_tasks: 0,
    waiting: 0,
    owed: 0,
    signals,
    linked_at: "2026-11-01T00:00:00Z",
    ...over,
  };
}

test("a connector summary shows its coverage level, needs and hosts", () => {
  const cli = renderToStaticMarkup(<ConnectorSummary c={codex} />);
  assert.match(cli, /Live verified/);
  assert.match(cli, /Experimental/);
  assert.match(cli, /Needs your signed-in codex CLI\./);
  assert.match(cli, /Observer stores no credential/);
  const api = renderToStaticMarkup(<ConnectorSummary c={devin} />);
  assert.match(api, /Documented/);
  assert.match(api, /Needs an API key, organization id and choosing your Devin user\./);
  assert.match(api, /Calls api\.devin\.ai only/);
  assert.match(api, /Finds sessions/);
});

test("the connect form lists the catalog in a picker", () => {
  const html = renderToStaticMarkup(<ConnectForm connectors={[codex, devin, qoder]} onConnected={noop} />);
  assert.match(html, /<select/);
  assert.match(html, /<option value="codex-cloud">Codex Cloud \(experimental\)<\/option>/);
  assert.match(html, /<option value="devin">Devin<\/option>/);
  // Nothing chosen: no key field, buttons disabled with the reason.
  assert.doesNotMatch(html, /type="password"/);
  assert.match(html, /title="Choose a connector\."/);
});

test("an API connector takes its key in an empty password field", () => {
  const html = renderToStaticMarkup(<ConnectForm connectors={[devin]} onConnected={noop} initialConnector="devin" />);
  assert.match(html, /type="password"/);
  assert.match(html, /autoComplete="new-password"|autocomplete="new-password"/);
  // The field starts empty: a stored key is never sent to the page, so none is shown.
  assert.match(html, /type="password"[^>]*value=""|value=""[^>]*type="password"/);
  assert.match(html, /Organization id/);
  assert.match(html, /title="Paste the API key\."/);
});

test("a parameter with a closed list is a picker, not a text field", () => {
  const html = renderToStaticMarkup(<ConnectForm connectors={[qoder]} onConnected={noop} initialConnector="qoder-cloud" />);
  assert.match(html, /<option value="global">Global<\/option>/);
  assert.match(html, /<option value="cn">China<\/option>/);
  assert.match(html, /Choose the region/);
});

test("an account row shows state, the error class and an honest missing pass", () => {
  const html = renderToStaticMarkup(
    <AccountRow a={account({ coverage: "disconnected", last_error: "not_signed_in" })} c={codex} onChanged={noop} />,
  );
  assert.match(html, /Disconnected/);
  assert.match(html, /Not signed in/);
  assert.match(html, /No pass yet/);
  assert.doesNotMatch(html, />0 running/);
  assert.match(html, />Test</);
  assert.match(html, />Sync now</);
  assert.match(html, />Disconnect</);
});

test("an API account offers Replace key instead of a keyless test", () => {
  const html = renderToStaticMarkup(
    <AccountRow a={account({ connector: "devin", label: "Devin", account_id: "org-1", user_state: "vendor_user_chosen", vendor_user: "user-a" })} c={devin} onChanged={noop} />,
  );
  assert.match(html, /Replace key/);
  assert.doesNotMatch(html, />Test</);
});

test("an account from a newer build is shown, never synced", () => {
  const html = renderToStaticMarkup(<AccountRow a={account({ connector: "future", label: "future", signals: [] })} c={undefined} onChanged={noop} />);
  assert.match(html, /not known to this version/);
  assert.doesNotMatch(html, /Sync now/);
  assert.match(html, />Disconnect</);
});

test("a member-scoped account with no user says nothing is pulled", () => {
  const a = account({ connector: "openhands-cloud", label: "OpenHands Cloud", account_id: "keychain-key", user_state: "vendor_user_not_chosen" });
  const html = renderToStaticMarkup(<AccountRow a={a} c={openhands} onChanged={noop} />);
  assert.match(html, /No OpenHands user chosen: nothing is pulled/);
  assert.match(html, /Choose your OpenHands user/);
  // No connector without the capability gets a picker.
  assert.doesNotMatch(renderToStaticMarkup(<AccountRow a={account()} c={codex} onChanged={noop} />), /cloud-agent-user-picker/);
});

test("the user picker lists candidates with session counts and hints", () => {
  const a = account({ connector: "devin", label: "Devin", account_id: "org-1", user_state: "vendor_user_chosen", vendor_user: "user-a" });
  const html = renderToStaticMarkup(
    <UserPicker
      a={a}
      c={devin}
      onChanged={noop}
      initial={{
        account: 3,
        connector: "devin",
        user_label: "Devin user",
        chosen: "user-a",
        candidates: [
          { user_id: "user-a", username: "alice", sessions: 4 },
          { user_id: "user-b", sessions: 1 },
        ],
        more: true,
        service_user_sessions: 2,
        no_user_sessions: 0,
        message_reads: 2,
      }}
    />,
  );
  assert.match(html, /<option value="user-a" selected="">alice \(4 sessions on the first page\)<\/option>/);
  assert.match(html, /user-b \(1 session on the first page\)/);
  assert.match(html, /Only users with a session on the first page are listed/);
  assert.match(html, /started by a service user/);
  assert.match(html, /title="That user is already chosen\."/);
});

test("a refused user list shows its error class", () => {
  const a = account({ connector: "devin", label: "Devin", user_state: "vendor_user_not_chosen" });
  const html = renderToStaticMarkup(
    <UserPicker
      a={a}
      c={devin}
      onChanged={noop}
      initial={{
        account: 3,
        connector: "devin",
        user_label: "Devin user",
        candidates: [],
        more: false,
        service_user_sessions: 0,
        no_user_sessions: 0,
        message_reads: 0,
        error_class: "permission_denied",
      }}
    />,
  );
  assert.match(html, /Could not list users: Permission denied\./);
  assert.doesNotMatch(html, /Save and pull/);
});

test("the body with nothing linked says no vendor is called", () => {
  const view: CloudAgentsView = { generated_at: "2026-11-03T00:00:00Z", connectors: [codex], accounts: [] };
  const html = renderToStaticMarkup(<CloudAgentsBody view={view} onChanged={noop} />);
  assert.match(html, /No account connected/);
  assert.doesNotMatch(html, /Sync all/);
  const linked = renderToStaticMarkup(<CloudAgentsBody view={{ ...view, accounts: [account()] }} onChanged={noop} />);
  assert.match(linked, /1 connected account/);
  assert.match(linked, /Sync all/);
});

test("no rendered copy carries an em dash", () => {
  const view: CloudAgentsView = {
    generated_at: "2026-11-03T00:00:00Z",
    connectors: [codex, devin, qoder],
    accounts: [account({ last_error: "rate_limited" }), account({ id: 4, connector: "devin", label: "Devin", user_state: "vendor_user_not_chosen" })],
  };
  const html = renderToStaticMarkup(<CloudAgentsBody view={view} onChanged={noop} />);
  assert.ok(!html.includes("\u2014"), "em dash in the Cloud agents card");
});
