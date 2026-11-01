const cp = require("child_process");
const { exec, execSync } = require("child_process");
const path = require("path");

function convert(req, res) {
  // ruleid: js.shell-interpolation
  cp.exec("convert " + req.query.file + " out.png", () => {});
  const name = req.body.name;
  // ruleid: js.shell-interpolation
  execSync(`git log --author=${name}`);
  // ok: js.shell-interpolation
  cp.execFile("convert", [req.query.file, "out.png"], () => {});
  const n = Number(req.query.count);
  // ok: js.shell-interpolation
  exec("seq " + n, () => {});
  res.end();
}

// The false-positive shapes of the 1.1.0 rule: commands built from the
// program's own paths and flags.
function build(outDir, verbose) {
  const tool = path.join(__dirname, "bin", "build");
  // ok: js.shell-interpolation
  execSync(`${tool} --out ${outDir}${verbose ? " -v" : ""}`);
  // ok: js.shell-interpolation
  cp.exec("rm -rf " + path.join(outDir, "cache"), () => {});
}

module.exports = { convert, build };
