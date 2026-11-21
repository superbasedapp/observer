import { test } from "node:test";
import assert from "node:assert/strict";
import {
  iacEngineName,
  iacErrorText,
  iacInstallBody,
  iacMB,
  iacPinChanged,
  iacShownEngines,
  iacStage,
  iacStageLine,
  type IaCEngineRow,
} from "./codeSecurityIac.ts";

// The IaC scanners card's pure half (dashboard CLI parity plan B-CS2): which
// engines it lists, each one's install state and line, the POST body for the
// pin the dialog showed, a changed pin, and a refused POST's words.

function row(over: Partial<IaCEngineRow> = {}): IaCEngineRow {
  return {
    component: "security.scan.trivy",
    driver: "trivy",
    kind: "process",
    compiled: true,
    platform: "untested",
    beta: true,
    note: "Trivy: selected, not installed",
    labels: [],
    selected: true,
    installed: false,
    install_pin: "aa11",
    install_bytes: 42_000_000,
    install_consent: "Downloads Trivy 0.75.0 from GitHub",
    ...over,
  };
}

test("iacShownEngines lists the engines in this build that are selected", () => {
  const engines = [
    row(),
    row({ driver: "kics", component: "security.scan.kics", selected: false }),
    row({ driver: "other", compiled: false }),
  ];
  assert.deepEqual(
    iacShownEngines({ engines }).map((e) => e.driver),
    ["trivy"],
  );
  assert.deepEqual(iacShownEngines({ engines: null }), []);
  assert.deepEqual(iacShownEngines(null), []);
});

test("iacStage: installed, blocked, waiting for the accept, or unavailable", () => {
  const cases: { name: string; e: IaCEngineRow; want: string }[] = [
    { name: "installed wins", e: row({ installed: true, install_pin: "", install_blocked: "x" }), want: "installed" },
    { name: "blocked", e: row({ install_pin: "", install_blocked: "no vendor release for this platform" }), want: "blocked" },
    { name: "a pin to accept", e: row(), want: "waiting" },
    { name: "nothing to offer", e: row({ install_pin: "" }), want: "unavailable" },
  ];
  for (const c of cases) assert.equal(iacStage(c.e), c.want, c.name);
});

test("iacStageLine says the state in words, the size before the install", () => {
  assert.match(iacStageLine(row()), /Trivy is not installed: .*about 42 MB download/);
  assert.match(iacStageLine(row({ install_pin: "", install_blocked: "no vendor release" })), /cannot be installed here: no vendor release\./);
  assert.equal(iacStageLine(row({ installed: true, note: "Trivy: /usr/bin/trivy sha256 aa: verified" })), "Trivy: /usr/bin/trivy sha256 aa: verified");
  assert.match(iacStageLine(row({ driver: "kics", installed: true, note: "" })), /^KICS is installed\.$/);
});

test("iacInstallBody sends the pin the dialog showed, only while one is owed", () => {
  assert.deepEqual(iacInstallBody(row(), "aa11"), { engine: "trivy", sha256: "aa11" });
  assert.equal(iacInstallBody(row(), ""), null);
  assert.equal(iacInstallBody(row({ installed: true }), "aa11"), null);
  assert.equal(iacInstallBody(row({ install_pin: "", install_blocked: "x" }), "aa11"), null);
});

test("iacPinChanged compares the pin in force with the one shown", () => {
  assert.equal(iacPinChanged(row({ install_pin: "bb22" }), "aa11"), true);
  assert.equal(iacPinChanged(row(), "aa11"), false);
  assert.equal(iacPinChanged(undefined, "aa11"), false);
  assert.equal(iacPinChanged(row({ install_pin: "" }), "aa11"), false);
  assert.equal(iacPinChanged(row(), ""), false);
});

test("iacErrorText reads the route's detail, else the text, else the status", () => {
  assert.equal(iacErrorText('{"error":"install_refused","detail":"the trivy pin changed"}', 409), "the trivy pin changed");
  assert.equal(iacErrorText('{"error":"bad_request"}', 400), "bad_request");
  assert.equal(iacErrorText("plain words\n", 403), "plain words");
  assert.equal(iacErrorText("", 500), "HTTP 500");
});

test("iacEngineName and iacMB", () => {
  assert.equal(iacEngineName("trivy"), "Trivy");
  assert.equal(iacEngineName("kics"), "KICS");
  assert.equal(iacEngineName("other"), "other");
  assert.equal(iacMB(0), "an unknown amount");
  assert.equal(iacMB(500_000), "less than 1 MB");
  assert.equal(iacMB(42_400_000), "about 42 MB");
});
