// Component tests of the installer's hand-off (?connecting=1) and the "Two
// dashboards" note, rendered with react-dom/server under node's test runner
// (scripts/test-components.mjs): the waiting card says where to approve and
// offers nothing to start, the expired card says how to try again, and the
// note names what each dashboard holds without printing an address.

import { test } from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router-dom";
import { HandoffCard, TwoDashboardsNote } from "@/components/ConnectHandoff";
import type { Account } from "@/lib/getStarted";

function render(node: React.ReactNode): string {
  return renderToStaticMarkup(<MemoryRouter>{node}</MemoryRouter>);
}

const text = (html: string) => html.replace(/<[^>]+>/g, " ").replace(/&#x27;/g, "'").replace(/\s+/g, " ");

test("the waiting card says where to approve, and offers no second way to connect", () => {
  const html = render(<HandoffCard phase="waiting" handoff={{ team: "" }} />);
  assert.match(text(html), /Connecting this machine/);
  assert.match(
    text(html),
    /Approve this machine in the browser tab that just opened \(or enter the code shown in your terminal\)\. This page updates when it is connected\./,
  );
  assert.doesNotMatch(html, /Sign in and connect|Connect this machine<\/button>|<button/);
  assert.match(html, /data-phase="waiting"/);

  const team = render(<HandoffCard phase="waiting" handoff={{ team: "acme" }} />);
  assert.match(text(team), /Connecting to the team acme\./);
});

test("the expired card says how to try again", () => {
  const html = render(<HandoffCard phase="expired" handoff={{ team: "" }} />);
  assert.match(text(html), /Not connected yet/);
  assert.match(text(html), /observer connect/);
});

test("the card renders nothing outside a hand-off or once connected", () => {
  assert.equal(render(<HandoffCard phase="none" handoff={null} />), "");
  assert.equal(render(<HandoffCard phase="connected" handoff={{ team: "" }} />), "");
});

const personal: Account = {
  signedIn: true,
  identityKnown: true,
  connected: true,
  locked: false,
  displayName: "your personal dashboard",
  onlineUrl: "https://u-abc123.superbased.app/",
};

test("the two dashboards note names what each holds, never the address", () => {
  const html = render(<TwoDashboardsNote account={personal} onDismiss={() => undefined} />);
  const t = text(html);
  assert.match(t, /Two dashboards/);
  assert.match(t, /This local dashboard/);
  assert.match(t, /Everything Observer records on this computer, in full; it stays here\./);
  assert.match(t, /Your online dashboard/);
  assert.match(t, /A summary from each machine you connect\./);
  assert.match(t, /Open your online dashboard/);
  assert.match(t, /Got it/);
  assert.doesNotMatch(t, /u-abc123/);
  assert.match(html, /href="https:\/\/u-abc123\.superbased\.app\/"/);

  const team = text(render(<TwoDashboardsNote account={{ ...personal, displayName: "Acme", kind: "team", onlineUrl: null }} onDismiss={() => undefined} />));
  assert.match(team, /Team dashboard: Acme/);
  assert.match(team, /Full detail \(prompts, responses, file paths\); the team's admins can read it\./);
  assert.doesNotMatch(team, /Open the team dashboard/);
});
