function issue(user) {
  // ruleid: js.insecure-token-randomness
  const resetToken = Math.random().toString(36).slice(2);
  // ruleid: js.insecure-token-randomness
  user.apiKey = "k_" + Math.floor(Math.random() * 1e16);
  // ruleid: js.insecure-token-randomness
  const creds = { clientSecret: Math.random().toString(16) };
  let password = "";
  for (let i = 0; i < 12; i++) {
    // ruleid: js.insecure-token-randomness
    password += "abcdefghjkmnpqrstuvwxyz23456789".charAt(Math.floor(Math.random() * 31));
  }
  // ok: js.insecure-token-randomness
  const jitter = Math.random() * 100;
  // ok: js.insecure-token-randomness
  const csrfToken = require("crypto").randomBytes(32).toString("hex");
  return [resetToken, creds, password, jitter, csrfToken];
}

// The false-positive shapes of the 1.1.0 rule: unique ids that are not
// secrets, and test code.
function ids() {
  // ok: js.insecure-token-randomness
  const token = `${process.pid}.${Date.now()}.${Math.random().toString(36).slice(2)}`;
  // ok: js.insecure-token-randomness
  const nonce = Math.random().toString(36).slice(2, 8);
  // ok: js.insecure-token-randomness
  const sessionId = "session-" + Math.random().toString(36).slice(2, 10);
  return [token, nonce, sessionId];
}

it("stores a secret", () => {
  // ok: js.insecure-token-randomness
  const secretValue = Math.floor(Math.random() * 100) + "";
  expect(secretValue).toBeTruthy();
});

// Lane SEC-G4 audit finding 3: Date.now() excuses a unique-id name only.
function mixed(user) {
  // ruleid: js.insecure-token-randomness
  password = Math.random().toString(36) + Date.now();
  // ok: js.insecure-token-randomness
  const resetTokenId = `${Date.now()}-${Math.random().toString(36).slice(2)}`;
  return [user, resetTokenId];
}
