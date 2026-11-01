const axios = require("axios");
const https = require("https");

async function preview(req, res) {
  // ruleid: js.ssrf-request-url
  const a = await fetch(req.query.url);
  // ruleid: js.ssrf-request-url
  const b = await axios.get(req.body.callback);
  // ruleid: js.ssrf-request-url
  https.get(`https://${req.params.host}/status`, () => {});
  // ok: js.ssrf-request-url
  const c = await fetch("https://api.example.com/search?q=" + encodeURIComponent(req.query.q));
  // ok: js.ssrf-request-url
  const d = await axios.post("https://api.example.com/hook", { url: req.body.url });
  res.json([a.status, b.status, c.status, d.status]);
}

async function lookup(req) {
  // ok: js.ssrf-request-url
  return fetch("https://api.example.com/users/" + req.params.id);
}

// The false-positive shapes of the 1.1.0 rule: a host fixed by the
// program's configuration, and a request object that is not a web
// request's input.
async function show(req, res, config) {
  // ok: js.ssrf-request-url
  const a = await fetch(`${process.env.SHOWS_API}shows/${req.params.id}`);
  // ok: js.ssrf-request-url
  const b = await fetch(`${config.apiBase}/episodes/${req.params.id}`);
  res.json([a.status, b.status]);
}

function follow(request, location) {
  const headers = request.headers;
  // ok: js.ssrf-request-url
  return fetch(location, { headers });
}
