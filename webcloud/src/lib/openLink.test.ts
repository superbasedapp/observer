// openLink.test.ts pins the hosted sign-in fix's link rule (lane A): every
// "Open your dashboard" button reads the server-built open_url
// (internal/cloudserver/api/tenantlink.go), and no console source composes a
// tenant dashboard address or reads the retired dashboard_url / online_url.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { ConnectHome } from "../api.ts";
import { homeMachineView } from "./connectModel.ts";

const src = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function walk(d: string): string[] {
  return readdirSync(d, { withFileTypes: true }).flatMap((e) =>
    e.isDirectory() ? walk(path.join(d, e.name)) : /\.(ts|tsx)$/.test(e.name) ? [path.join(d, e.name)] : [],
  );
}

// The dev mocks stand in for the server and so build what it would send;
// tests construct fixtures. Everything else is the console itself.
const consoleSources = walk(src).filter(
  (f) => !/\.test\.tsx?$/.test(f) && !/[\\/]devmock[^\\/]*\.ts$/.test(f),
);

test("the console reads open_url, never the retired dashboard_url or online_url", () => {
  for (const f of consoleSources) {
    const text = readFileSync(f, "utf8");
    assert.doesNotMatch(text, /\.(dashboard_url|online_url)\b/, path.relative(src, f));
    assert.doesNotMatch(text, /\bdashboardUrl\(/, path.relative(src, f));
  }
});

test("no console source composes a tenant address from a host", () => {
  for (const f of consoleSources) {
    const text = readFileSync(f, "utf8");
    // "https://" + host, `https://${host}`, new URL(...).origin + "/" (the
    // console's own window.location.origin is not a tenant address).
    assert.doesNotMatch(text, /["'`]https:\/\/["'`]\s*\+/, path.relative(src, f));
    assert.doesNotMatch(text, /`https:\/\/\$\{/, path.relative(src, f));
    assert.doesNotMatch(text, /(?<!window\.location)\.origin\s*\+\s*["'`]\//, path.relative(src, f));
  }
});

const machine = (open_url?: string): ConnectHome => ({
  devices: 1,
  recent: [{ request_id: "r", machine_name: "laptop", os: "linux", approved_at: "2026-11-17T00:00:00Z", target: null, open_url }],
});

test("the machine card opens the server's open_url, else the personal dashboard's", () => {
  assert.equal(homeMachineView(machine("https://acme.superbased.app/"), "https://u-1.superbased.app/").openUrl, "https://acme.superbased.app/");
  assert.equal(homeMachineView(machine(undefined), "https://u-1.superbased.app/").openUrl, "https://u-1.superbased.app/");
  assert.equal(homeMachineView(machine(undefined), null).openUrl, null);
});
