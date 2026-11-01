import assert from "node:assert/strict";
import test from "node:test";

import {
  clearDrawerTab,
  drawerProcFromParams,
  DRAWER_MESSAGE_PARAM,
  drawerTabFromParams,
  hasDrawerState,
  migrateLegacyDrawerTab,
  writeDrawerProc,
  writeDrawerTab,
} from "./drawerTab.ts";

const IDS = ["overview", "messages", "cost", "cache", "tasks", "mcp", "system"] as const;
const P = (s: string) => new URLSearchParams(s);

test("drawerTabFromParams: dtab is the drawer's tab", () => {
  assert.equal(drawerTabFromParams(P("session=s1&dtab=messages"), IDS), "messages");
  assert.equal(drawerTabFromParams(P("session=s1&dtab=bogus"), IDS), null);
  assert.equal(drawerTabFromParams(P("session=s1"), IDS), null);
});

test("drawerTabFromParams: an old /sessions?session=..&tab=messages link still opens Messages", () => {
  assert.equal(drawerTabFromParams(P("session=s1&tab=messages"), IDS), "messages");
});

test("drawerTabFromParams: without a session param, tab belongs to the page", () => {
  // Cache page tab "events" / a page tab that shares a drawer id ("cache").
  assert.equal(drawerTabFromParams(P("tab=cache"), IDS), null);
  assert.equal(drawerTabFromParams(P("tab=events"), IDS), null);
});

test("drawerTabFromParams: dtab wins over a legacy tab", () => {
  assert.equal(drawerTabFromParams(P("session=s1&tab=messages&dtab=cost"), IDS), "cost");
});

test("migrateLegacyDrawerTab: maps once, then writes dtab only", () => {
  const m = migrateLegacyDrawerTab(P("session=s1&tab=messages"), IDS, "overview");
  assert.equal(m?.toString(), "session=s1&dtab=messages");
  // Already migrated: nothing to do.
  assert.equal(migrateLegacyDrawerTab(m!, IDS, "overview"), null);
  // The default tab is dtab's absence.
  assert.equal(migrateLegacyDrawerTab(P("session=s1&tab=overview"), IDS, "overview")?.toString(), "session=s1");
  // A page's own tab value that is not a drawer tab is left alone.
  assert.equal(migrateLegacyDrawerTab(P("session=s1&tab=events"), IDS, "overview"), null);
});

test("a page with page tabs and an open drawer keeps both", () => {
  // Switch the drawer while the page sits on its Events tab.
  const opened = writeDrawerTab(P("tab=events"), "messages", "overview");
  assert.equal(opened.toString(), "tab=events&dtab=messages");
  assert.equal(drawerTabFromParams(opened, IDS), "messages");
  assert.equal(opened.get("tab"), "events");
  // Back to the drawer's default: only dtab goes.
  assert.equal(writeDrawerTab(opened, "overview", "overview").toString(), "tab=events");
  // Closing the drawer drops dtab, never the page's tab.
  assert.equal(clearDrawerTab(opened)?.toString(), "tab=events");
  assert.equal(clearDrawerTab(P("tab=events")), null);
});

test("proc: the picked process rides in the URL and goes with the drawer", () => {
  const cases: Array<[string, string | null, string]> = [
    ["session=s1&dtab=system", "abc", "session=s1&dtab=system&proc=abc"],
    ["session=s1&dtab=system&proc=abc", "def", "session=s1&dtab=system&proc=def"],
    ["session=s1&dtab=system&proc=abc", null, "session=s1&dtab=system"],
    ["tab=events", null, "tab=events"],
  ];
  for (const [from, key, want] of cases) {
    const next = writeDrawerProc(P(from), key);
    assert.equal(next.toString(), want);
    assert.equal(drawerProcFromParams(next), key);
  }
  assert.equal(drawerProcFromParams(P("proc=")), null);
  // Closing the drawer drops dtab and proc, never the page's tab.
  assert.equal(clearDrawerTab(P("tab=events&dtab=system&proc=abc"))?.toString(), "tab=events");
  assert.equal(clearDrawerTab(P("tab=events&proc=abc"))?.toString(), "tab=events");
  assert.equal(hasDrawerState(P("tab=events")), false);
  assert.equal(hasDrawerState(P("proc=x")), true);
});

test("closing the drawer also drops a deep-linked message key (msg)", () => {
  assert.equal(DRAWER_MESSAGE_PARAM, "msg");
  assert.equal(clearDrawerTab(P("dtab=messages&msg=k1&tab=events"))?.toString(), "tab=events");
  assert.equal(clearDrawerTab(P("msg=k1"))?.toString(), "");
  // Switching the drawer's tab keeps the key, so the jump still lands.
  assert.equal(writeDrawerTab(P("session=s&msg=k1"), "messages", "overview").get("msg"), "k1");
});
