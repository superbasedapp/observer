const jwt = require("jsonwebtoken");
const jwtSimple = require("jwt-simple");

function auth(token, key) {
  // ruleid: js.jwt-verification-off
  const a = jwt.verify(token, key, { algorithms: ["HS256", "none"] });
  // ruleid: js.jwt-verification-off
  const b = jwt.verify(token, "");
  // ruleid: js.jwt-verification-off
  const c = jwtSimple.decode(token, key, true);
  // ok: js.jwt-verification-off
  const d = jwt.verify(token, key, { algorithms: ["RS256"] });
  // ok: js.jwt-verification-off
  const e = jwtSimple.decode(token, key);
  return [a, b, c, d, e];
}
