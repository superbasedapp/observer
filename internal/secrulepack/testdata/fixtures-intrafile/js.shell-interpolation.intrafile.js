const { exec, execSync } = require("child_process");

function listDirectory(dir) {
  // ruleid: js.shell-interpolation
  return execSync("ls -l " + dir).toString();
}

function listing(req, res) {
  res.send(listDirectory(req.query.dir));
}

function archiveName(req) {
  return req.body.archive;
}

function archive(req) {
  // ruleid: js.shell-interpolation
  exec("tar tf " + archiveName(req));
}

// The sanitizer sits in the helper: the value is parsed to a number before
// the caller interpolates it.
function asCount(value) {
  return parseInt(value, 10);
}

function tail(req, res) {
  // ok: js.shell-interpolation
  res.send(execSync("tail -n " + asCount(req.query.lines) + " app.log").toString());
}
