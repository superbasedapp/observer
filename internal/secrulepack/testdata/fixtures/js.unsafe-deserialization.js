const serialize = require("node-serialize");
const yaml = require("js-yaml");

function load(req) {
  // ruleid: js.unsafe-deserialization
  const a = serialize.unserialize(req.cookies.profile);
  // ruleid: js.unsafe-deserialization
  const b = yaml.load(req.body.doc, { schema: yaml.DEFAULT_FULL_SCHEMA });
  // ok: js.unsafe-deserialization
  const c = JSON.parse(req.cookies.profile);
  // ok: js.unsafe-deserialization
  const d = yaml.load(req.body.doc);
  // ok: js.unsafe-deserialization
  const e = serialize.serialize({ a: 1 });
  return [a, b, c, d, e];
}
