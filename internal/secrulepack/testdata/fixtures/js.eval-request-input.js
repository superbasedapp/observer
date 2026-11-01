const express = require("express");
const vm = require("vm");
const app = express();

app.get("/calc", (req, res) => {
  const expr = req.query.expr;
  // ruleid: js.eval-request-input
  res.send(String(eval(expr)));
});

app.post("/tpl", (req, res) => {
  // ruleid: js.eval-request-input
  const fn = new Function("data", req.body.template);
  // ruleid: js.eval-request-input
  vm.runInNewContext(req.body.script, {});
  res.send(fn({}));
});

app.get("/fixed", (req, res) => {
  const n = Number(req.query.n);
  // ok: js.eval-request-input
  res.send(String(eval("1 + 2")));
});

function local(cfg) {
  // ok: js.eval-request-input
  return new Function("x", cfg.body);
}
