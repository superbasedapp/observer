// Guard: no shipped dashboard UI opens a native browser dialog
// (window.alert / confirm / prompt). They are unstyled, ignore the theme,
// block the whole page and cannot explain themselves; the operator report
// that started this (a daemon restart asking through window.confirm) is the
// regression this test exists to stop. Use the shared confirmDialog
// (shared/primitives/ConfirmDialog.tsx) for a question code must await, or
// the in-place ConfirmButton (with `reason` for a typed answer).
//
// The apps have no ESLint, so this is a source scan over every app surface
// and the shared design system. Comments are stripped first (they name the
// rule); test files and e2e specs are skipped (they may stub a dialog).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..");

const ROOTS = ["web/src", "web2/src", "webcloud/src", "shared", "web/index.html", "web2/index.html", "webcloud/index.html"];
const EXT = /\.(?:[cm]?[jt]sx?|html)$/;
const SKIP_FILE = /\.(?:test|spec)\.[cm]?[jt]sx?$/;
const SKIP_DIR = new Set(["node_modules", "dist", "e2e", "__fixtures__", "testdata"]);

const NAMES = ["alert", "confirm", "prompt"] as const;

function walk(p: string, out: string[]) {
  let st;
  try {
    st = statSync(p);
  } catch {
    return;
  }
  if (st.isDirectory()) {
    if (SKIP_DIR.has(path.basename(p))) return;
    for (const e of readdirSync(p)) walk(path.join(p, e), out);
    return;
  }
  if (EXT.test(p) && !SKIP_FILE.test(p)) out.push(p);
}

/** stripComments drops block comments and line comments (a `//` after a
 *  colon is kept: it is a URL inside a string). Lengths of lines are not
 *  preserved, but line breaks are, so reported line numbers stay right. */
export function stripComments(src: string): string {
  return src
    .replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, " "))
    .replace(/(^|[^:\\])\/\/.*$/gm, "$1");
}

/** nativeDialogCalls returns "line: text" for every native dialog call in a
 *  source file. Member forms (window./globalThis./self./top./parent., and
 *  window["confirm"]) always count; a bare alert( / confirm( / prompt(
 *  counts unless the file binds that name itself (`function confirm()`,
 *  `const prompt = ...`, a destructured or parameter `confirm`), the call is
 *  a method call, or the line is a method definition (`async confirm() {`). */
export function nativeDialogCalls(src: string): string[] {
  const code = stripComments(src);
  const hits: string[] = [];
  const lines = code.split("\n");
  const member = /\b(?:window|globalThis|self|top|parent)\s*(?:\??\.\s*(?:alert|confirm|prompt)\b|\[\s*["'`](?:alert|confirm|prompt)["'`]\s*\])\s*(?:\(|\)|,|;|$)/;
  const binds = (n: string) =>
    new RegExp(`\\b(?:function|const|let|var)\\s+${n}\\b|[{,]\\s*${n}\\s*[,}=]|\\(\\s*${n}\\s*[:?),=]`).test(code);
  const bare = NAMES.filter((n) => !binds(n)).map((n) => new RegExp(`(?<![\\w$.'"\`:/-])${n}\\(`));
  const methodDef = /^\s*(?:(?:async|static|public|private|protected|override)\s+)*(?:alert|confirm|prompt)\s*\([^)]*\)\s*(?::[^{;]*)?\{\s*$/;
  lines.forEach((line, i) => {
    if (member.test(line) || (!methodDef.test(line) && bare.some((re) => re.test(line)))) {
      hits.push(`${i + 1}: ${line.trim()}`);
    }
  });
  return hits;
}

test("nativeDialogCalls flags every native form and ignores look-alikes", () => {
  const flagged = [
    "if (!window.confirm(message)) return;",
    "const r = globalThis.prompt('why?');",
    "alert('done');",
    "x ? confirm(m) : null",
    "const ask = window.confirm;",
    "window['alert']('x')",
    "(m) => window.confirm(m)",
  ];
  for (const src of flagged) assert.equal(nativeDialogCalls(src).length, 1, src);
  const clean = [
    "// never window.confirm(...) here",
    "/* window.alert(1) */",
    "step.confirm();",
    "await ctl.confirm()",
    "async function confirm() {}\nconfirm();",
    "  async confirm(): Promise<void> {",
    "function run(prompt: string) {\n  prompt(1);\n}",
    "const { confirm } = props;\nconfirm();",
    'const href = "javascript:alert(1)";',
    "<p>Please confirm (twice)</p>",
    "deps.prompt({ section })",
    "await confirmDialog({ title })",
    'fetch("http://x//y")',
  ];
  for (const src of clean) assert.deepEqual(nativeDialogCalls(src), [], src);
});

test("no shipped app UI opens a native alert / confirm / prompt", () => {
  const files: string[] = [];
  for (const r of ROOTS) walk(path.join(repo, r), files);
  assert.ok(files.length > 100, `scanned only ${files.length} files: is the repo root right (${repo})?`);
  const offenders: string[] = [];
  for (const f of files) {
    for (const h of nativeDialogCalls(readFileSync(f, "utf8"))) {
      offenders.push(`${path.relative(repo, f).split(path.sep).join("/")}:${h}`);
    }
  }
  assert.deepEqual(
    offenders,
    [],
    "native dialog calls found; use confirmDialog or ConfirmButton from @shared/primitives instead",
  );
});
