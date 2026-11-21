// Cross-function taint in one file (--taint-intrafile): the value from the
// web request is handed to a helper that runs it.

function runExpression(expr) {
  // ruleid: js.eval-request-input
  return eval(expr);
}

function calculate(req, res) {
  res.send(String(runExpression(req.query.expr)));
}

function expressionFromRequest(req) {
  return req.body.expr;
}

function calculateReturned(req, res) {
  // ruleid: js.eval-request-input
  res.send(String(eval(expressionFromRequest(req))));
}

// The helper takes the request value but returns a fixed expression;
// nothing of the input reaches eval.
function fixedExpression(requested) {
  return "1 + 1";
}

function calculateFixed(req, res) {
  // ok: js.eval-request-input
  res.send(String(eval(fixedExpression(req.query.expr))));
}
