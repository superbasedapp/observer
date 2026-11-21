// The CommonJS build loads through the package exports map.
const { test } = require("node:test");
const assert = require("node:assert/strict");

test("require('@superbased/sdk') resolves the CJS build", () => {
  const sb = require("@superbased/sdk");
  assert.equal(typeof sb.init, "function");
  assert.equal(typeof sb.admit, "function");
  assert.equal(typeof sb.observe, "function");
  assert.equal(sb.Kind.LLM, "LLM");
  assert.ok(require.resolve("@superbased/sdk").includes(require("node:path").join("dist", "cjs")));
});

const nodeMajor = Number(process.versions.node.split(".")[0]);
const openaiPkg = require("node:path").join(__dirname, "..", "node_modules", "openai", "package.json");
const openaiNeeds = Number((/^>=\s*(\d+)/.exec(JSON.parse(require("node:fs").readFileSync(openaiPkg, "utf8")).engines?.node ?? "") ?? [0, 0])[1]);

test("instrument() loads optional peers from the CJS build", { skip: nodeMajor < openaiNeeds && `openai needs Node ${openaiNeeds}+` }, () => {
  const sb = require("@superbased/sdk");
  sb.init({ exporter: { export(_s, cb) { cb({ code: 0 }); }, shutdown: async () => {}, forceFlush: async () => {} } });
  assert.deepEqual(sb.instrument(["openai"]), { openai: "instrumented" });
  sb.uninstrument();
  assert.deepEqual(sb.instrumented(), []);
});
