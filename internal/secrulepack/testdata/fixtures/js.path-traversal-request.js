const fs = require("fs");
const path = require("path");

const BASE = "/srv/files";

function serve(req, res) {
  // ruleid: js.path-traversal-request
  const data = fs.readFileSync(path.join(BASE, req.query.file));
  // ruleid: js.path-traversal-request
  res.sendFile(BASE + "/" + req.params.name);
  // ruleid: js.path-traversal-request
  fs.unlink(req.body.path, () => {});
  // ok: js.path-traversal-request
  const safe = fs.readFileSync(path.join(BASE, path.basename(req.query.file)));
  // ok: js.path-traversal-request
  res.sendFile(req.params.name, { root: BASE });
  // ok: js.path-traversal-request
  const cfg = fs.readFileSync(path.join(BASE, "config.json"));
  return [data, safe, cfg];
}

// The false-positive shape of the 1.1.0 rule: a download confined by its
// root option.
function confined(req, res) {
  // ok: js.path-traversal-request
  res.download(req.params.file, { root: "/srv/files" });
}
