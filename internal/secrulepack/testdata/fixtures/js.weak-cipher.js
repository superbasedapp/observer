const crypto = require("crypto");

function seal(key, iv, data) {
  // ruleid: js.weak-cipher
  const a = crypto.createCipheriv("des-ede3-cbc", key, iv);
  // ruleid: js.weak-cipher
  const b = crypto.createCipheriv("aes-128-ecb", key, null);
  // ruleid: js.weak-cipher
  const c = crypto.createCipher("aes192", key);
  // ok: js.weak-cipher
  const d = crypto.createCipheriv("aes-256-gcm", key, iv);
  // ok: js.weak-cipher
  const e = crypto.createDecipheriv("chacha20-poly1305", key, iv, { authTagLength: 16 });
  return [a, b, c, d, e, data];
}

// The false-positive shape of the 1.1.0 rule: test vectors.
describe("legacy cipher support", () => {
  it("decrypts a DES test vector", () => {
    // ok: js.weak-cipher
    const d = crypto.createDecipheriv("des-cbc", Buffer.alloc(8), Buffer.alloc(8));
    expect(d).toBeDefined();
  });
});
