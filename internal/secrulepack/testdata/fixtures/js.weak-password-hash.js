const crypto = require("crypto");
const md5 = require("md5");

function store(user, password) {
  // ruleid: js.weak-password-hash
  const a = crypto.createHash("md5").update(password).digest("hex");
  // ruleid: js.weak-password-hash
  const b = crypto.createHash("sha256").update(user.password).digest("hex");
  // ruleid: js.weak-password-hash
  const c = md5(password);
  // ok: js.weak-password-hash
  const d = crypto.createHash("sha256").update(fileContents(user)).digest("hex");
  // ok: js.weak-password-hash
  const e = crypto.scryptSync(password, user.salt, 64);
  return [a, b, c, d, e];
}
