const https = require("https");

// ruleid: js.tls-verify-off
const agent = new https.Agent({ rejectUnauthorized: false });
// ruleid: js.tls-verify-off
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
// ruleid: js.tls-verify-off
const opts = { host: "db.internal", rejectUnauthorized: false, port: 5432 };
// ok: js.tls-verify-off
const strict = new https.Agent({ rejectUnauthorized: true, ca: loadCA() });
// ok: js.tls-verify-off
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "1";

// The false-positive shapes of the 1.1.0 rule: an explicit opt-in flag
// and test code.
function proxyAgent(config) {
  if (config.insecure) {
    // ok: js.tls-verify-off
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
  }
  // ok: js.tls-verify-off
  return config.allowSelfSigned ? new https.Agent({ rejectUnauthorized: false }) : undefined;
}

describe("tls", () => {
  it("talks to a self-signed server", async () => {
    // ok: js.tls-verify-off
    await fetchJson({ rejectUnauthorized: false });
  });
});

test("http2 with a local certificate", async (t) => {
  // ok: js.tls-verify-off
  const client = connect({ rejectUnauthorized: false });
  t.after(() => client.close());
});

module.exports = { agent, opts, strict, proxyAgent };
