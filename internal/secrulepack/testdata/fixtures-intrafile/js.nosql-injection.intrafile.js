const User = require("./models/user");

// Cross-function taint in one file (--taint-intrafile): the value from the
// web request is handed to a helper that queries with it.
function byEmail(email) {
  // ruleid: js.nosql-injection
  return User.findOne({ email: email });
}

async function login(req, res) {
  res.json(await byEmail(req.body.email));
}

function requestedFilter(req) {
  return req.query.filter;
}

async function search(req, res) {
  // ruleid: js.nosql-injection
  res.json(await User.find(requestedFilter(req)));
}

// The sanitizer sits in the helper: the value is converted to a string
// before the caller queries with it.
function asText(value) {
  return String(value);
}

async function lookup(req, res) {
  // ok: js.nosql-injection
  res.json(await User.findOne({ name: asText(req.body.name) }));
}
