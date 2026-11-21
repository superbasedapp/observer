// Component tests of the Privacy page's Package lookup card and the
// Scanners card's read-only posture row (lane RM-2, plan section 13.10),
// rendered with react-dom/server under node's test runner
// (scripts/test-components.mjs). The pure lines are pinned in
// src/lib/packageLookup.test.ts; these prove the card renders them: the
// first-run choice side by side on a fresh install, no control on a managed
// node, the remote controls only in a remote mode, and the database accept
// hidden on the Scanners card where the posture downloads nothing.

import { test } from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router-dom";
import { LookupPostureRow, PackageLookupView } from "@/components/security/PackageLookupCard";
import { ScannersCard, type SecurityScanners } from "@/components/security/ScannersCard";
import type { PackageLookupStatus } from "@/lib/packageLookup";

function st(over: Partial<PackageLookupStatus> = {}): PackageLookupStatus {
  return {
    mode: "",
    configured: "",
    via: "shards",
    via_choices: ["shards"],
    kinds: ["language", "actions"],
    kind_choices: ["language", "actions"],
    private: "withhold",
    private_sending: false,
    managed: false,
    download: { accepted: false, text: "download text" },
    remote: { accepted: false, text: "remote text" },
    remote_private: { accepted: false, text: "private text" },
    remote_hosts: ["superbased.app", "shards.superbased.app"],
    approx_mb: 300,
    cache_bytes: 0,
    drivers: [{ driver: "security.scan.osv", remote: false, note: "remote lookup: not available for osv-scanner in this build" }],
    ...over,
  };
}

const view = (s: PackageLookupStatus) => renderToStaticMarkup(<MemoryRouter><PackageLookupView st={s} onChanged={() => {}} /></MemoryRouter>);

test("a fresh install offers the download and the lookup side by side, and nothing else", () => {
  const html = view(st());
  assert.match(html, /package-lookup-first-run/);
  assert.match(html, /package-lookup-choose-local/);
  assert.match(html, /package-lookup-choose-remote/);
  assert.match(html, /never sends source code/);
  assert.doesNotMatch(html, /package-lookup-mode/);
  // The consent text is never shown as accepted, and no dialog is open.
  assert.doesNotMatch(html, /remote text/);
});

test("a managed node reads its organization's posture with no control", () => {
  const html = view(st({ managed: true }));
  assert.match(html, /package-lookup-managed/);
  assert.match(html, /Set by your organization/);
  assert.doesNotMatch(html, /<input/);
  assert.doesNotMatch(html, /package-lookup-choose/);
});

test("a managed node shows what its organization decided, with the policy version", () => {
  const html = view(st({ managed: true, mode: "both", org: { on: true, private: "send", kinds: ["language"], org_name: "Acme", version: 9, source: "org" } }));
  assert.match(html, /package-lookup-managed/);
  assert.match(html, /Acme/);
  assert.match(html, /looked up too/);
  assert.match(html, /Security policy version 9/);
  assert.doesNotMatch(html, /<input/);
  assert.doesNotMatch(html, /package-lookup-choose/);
});

test("the remote controls show only in a remote mode", () => {
  const local = view(st({ mode: "local", configured: "local", download: { accepted: true, text: "" } }));
  assert.match(local, /package-lookup-mode/);
  assert.doesNotMatch(local, /package-lookup-remote/);
  const remote = view(st({ mode: "remote", configured: "remote", remote: { accepted: true, accepted_at: "2026-11-04T10:00:00Z", accepted_on: "dashboard", text: "" } }));
  assert.match(remote, /package-lookup-remote/);
  assert.match(remote, /GitHub Actions/);
  assert.match(remote, /package-lookup-private/);
  assert.match(remote, /dependency confusion/);
  assert.match(remote, /not available for osv-scanner/);
  assert.match(remote, /package-lookup-withdraw/);
});

test("the Scanners card shows the posture read-only with a link, or the first-run choice", () => {
  const row = renderToStaticMarkup(<MemoryRouter><LookupPostureRow st={st({ mode: "remote", remote: { accepted: true, text: "" } })} onChanged={() => {}} /></MemoryRouter>);
  assert.match(row, /scanner-lookup/);
  assert.match(row, /href="\/privacy"/);
  assert.doesNotMatch(row, /<input/);
  const first = renderToStaticMarkup(<MemoryRouter><LookupPostureRow st={st()} onChanged={() => {}} /></MemoryRouter>);
  assert.match(first, /scanner-lookup-first-run/);
});

test("the Scanners card hides the database accept where the posture downloads nothing", () => {
  const data = (lookup: PackageLookupStatus): SecurityScanners => ({
    drivers: [],
    databases: [],
    attribution: "",
    db: { accepted: false, approx_mb: 300, source: "superbased.app", text: "", managed: false, installed: 0, lookup },
  });
  const render = (lookup: PackageLookupStatus) => renderToStaticMarkup(<MemoryRouter><ScannersCard data={data(lookup)} onChanged={() => {}} /></MemoryRouter>);
  assert.doesNotMatch(render(st({ mode: "remote", remote: { accepted: true, text: "" } })), /scanner-db-accept/);
  assert.doesNotMatch(render(st()), /scanner-db-accept"/);
  assert.match(render(st({ mode: "local" })), /scanner-db-accept/);
});
