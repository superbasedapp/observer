// Component tests of the Getting started v2 surfaces, rendered with
// react-dom/server under node's test runner (scripts/test-components.mjs):
// the connected strip names where this machine is connected and never
// prints the online address (a personal dashboard's u-... host stays on the
// button), and the progress block shows the code while it waits.

import { test } from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router-dom";
import { ConnectedStrip } from "@/components/GetStarted";
import { ConnectProgressBlock } from "@/components/ConnectProgress";
import type { Account, ConnectProgress } from "@/lib/getStarted";
import type { ConnectFlow } from "@/lib/useConnectFlow";

function render(node: React.ReactNode): string {
  return renderToStaticMarkup(<MemoryRouter>{node}</MemoryRouter>);
}

const noop = async () => undefined;

function flowOf(progress: ConnectProgress | null, error: string | null = null): ConnectFlow {
  return {
    progress,
    active: !!progress?.running && ["starting", "waiting_approval", "approved", "attaching"].includes(progress.state),
    available: true,
    busy: false,
    error,
    start: noop,
    reconsent: noop,
    cancel: noop,
    openApproval: () => undefined,
    reload: () => undefined,
  };
}

const personal: Account = {
  signedIn: true,
  identityKnown: true,
  connected: true,
  locked: false,
  displayName: "Personal dashboard",
  email: "sam@example.com",
  lastSentAt: new Date(Date.now() - 5 * 60_000).toISOString(),
  onlineUrl: "https://u-abc123.superbased.app/",
  kind: "personal",
};

test("the connected strip names the dashboard and the account, never the address", () => {
  const html = render(<ConnectedStrip account={personal} />);
  assert.match(html, /Connected to/);
  assert.match(html, /Personal dashboard/);
  assert.match(html, /sam@example\.com/);
  assert.match(html, /Last sent \d+ min/);
  assert.match(html, /Open online dashboard/);
  // The address is the link's target, never its text.
  const text = html.replace(/<[^>]+>/g, " ");
  assert.doesNotMatch(text, /u-abc123/);
  assert.match(html, /href="https:\/\/u-abc123\.superbased\.app\/"/);
});

test("the connected strip says when nothing was sent yet, and hides the button without an address", () => {
  const html = render(<ConnectedStrip account={{ ...personal, lastSentAt: undefined, onlineUrl: null, email: undefined }} />);
  assert.match(html, /Nothing sent yet/);
  assert.doesNotMatch(html, /Open online dashboard/);
  assert.doesNotMatch(html, / as /);
});

test("the progress block shows the code while waiting, and how a flow ended", () => {
  const waiting = render(
    <ConnectProgressBlock
      flow={flowOf({
        state: "waiting_approval",
        running: true,
        user_code: "KTRW-4821",
        approve_url: "https://cloud.superbased.app/connect/r1",
        verify_url: "https://cloud.superbased.app/connect",
      })}
    />,
  );
  assert.match(waiting, /Waiting for approval in your browser/);
  assert.match(waiting, /KTRW-4821/);
  assert.match(waiting, /Open approval page/);
  assert.match(waiting, /Stop/);

  const declined = render(<ConnectProgressBlock flow={flowOf({ state: "error", running: false, message: "The request was declined." })} />);
  assert.match(declined, /The request was declined\./);
  assert.doesNotMatch(declined, /Stop/);

  assert.equal(render(<ConnectProgressBlock flow={flowOf({ state: "idle", running: false })} />), "");
  assert.match(render(<ConnectProgressBlock flow={flowOf(null, "This machine is already connected to Acme.")} />), /already connected to Acme/);
});
