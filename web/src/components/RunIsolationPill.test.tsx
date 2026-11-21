// Render tests of the terminal run pill's seccomp part (OpenShell build lane
// FU4, audit FU4-A2): a key-on dashboard launch on a backend Observer's
// filter cannot reach says it is not filtered; a filtered run names the
// filter; a key-off run reads as before.

import { test } from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { RunIsolationPill, SECCOMP_NOT_FILTERED_TITLE } from "@/components/RunIsolationPill";

const base = { class: "container", backend: "seatbelt", capture_level: "full", capture_rule: "C2", verification: "live" };

test("a key-on run Observer's filter cannot reach says it is not filtered", () => {
  const html = renderToStaticMarkup(<RunIsolationPill isolation={{ ...base, seccomp: "not_applicable" }} />);
  assert.match(html, /seccomp not applicable: not filtered by Observer/);
  assert.match(html, /text-warn/);
  assert.match(html, /data-seccomp="not_applicable"/);
  assert.ok(html.includes(SECCOMP_NOT_FILTERED_TITLE.replaceAll("'", "&#x27;")));
});

test("a filtered run names the filter", () => {
  const html = renderToStaticMarkup(<RunIsolationPill isolation={{ ...base, backend: "bwrap", class: "process", seccomp: "observer_default" }} />);
  assert.match(html, /seccomp filter observer_default/);
  assert.doesNotMatch(html, /text-warn/);
});

test("key-off states and an older daemon read as before", () => {
  for (const seccomp of ["off", "none", "engine_default", undefined]) {
    const html = renderToStaticMarkup(<RunIsolationPill isolation={{ ...base, seccomp }} />);
    assert.doesNotMatch(html, /seccomp (filter|not applicable)/);
    assert.doesNotMatch(html, /text-warn/);
    assert.match(html, /seatbelt/);
  }
});

test("an unsandboxed run renders nothing", () => {
  assert.equal(renderToStaticMarkup(<RunIsolationPill isolation={{ class: "none" }} />), "");
  assert.equal(renderToStaticMarkup(<RunIsolationPill />), "");
});
