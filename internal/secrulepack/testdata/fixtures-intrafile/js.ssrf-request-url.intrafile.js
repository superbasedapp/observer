const axios = require("axios");

function fetchUrl(url) {
  // ruleid: js.ssrf-request-url
  return axios.get(url);
}

function preview(req, res) {
  res.send(fetchUrl(req.query.url));
}

function requestedUrl(req) {
  return req.body.url;
}

function previewReturned(req, res) {
  // ruleid: js.ssrf-request-url
  res.send(fetch(requestedUrl(req)));
}

// The sanitizer sits in the helper: the value is URI-encoded before the
// caller fetches it.
function encoded(value) {
  return encodeURIComponent(value);
}

function previewEncoded(req, res) {
  // ok: js.ssrf-request-url
  res.send(axios.get(encoded(req.query.url)));
}
