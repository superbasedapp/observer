const fs = require("fs");
const path = require("path");

function readByName(name) {
  // ruleid: js.path-traversal-request
  return fs.readFileSync(name, "utf8");
}

function download(req, res) {
  res.send(readByName(req.query.name));
}

function requestedPath(req) {
  return req.params.path;
}

function removeRequested(req) {
  // ruleid: js.path-traversal-request
  fs.unlinkSync(requestedPath(req));
}

// The sanitizer sits in the helper: the name is reduced to a base name
// before the caller reads it.
function cleanName(name) {
  return path.basename(name);
}

function readClean(req, res) {
  // ok: js.path-traversal-request
  res.send(fs.readFileSync(cleanName(req.query.name), "utf8"));
}
