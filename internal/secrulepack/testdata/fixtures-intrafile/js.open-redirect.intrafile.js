// Cross-function taint in one file (--taint-intrafile): the value from the
// web request is handed to a helper that redirects to it.
function sendTo(res, target) {
  // ruleid: js.open-redirect
  res.redirect(target);
}

function done(req, res) {
  sendTo(res, req.query.next);
}

function returnTarget(req) {
  return req.body.returnTo;
}

function finish(req, res) {
  // ruleid: js.open-redirect
  res.redirect(returnTarget(req));
}

// The sanitizer sits in the helper: the value is encoded before the caller
// redirects to it.
function encoded(value) {
  return encodeURIComponent(value);
}

function bounce(req, res) {
  // ok: js.open-redirect
  res.redirect(encoded(req.query.next));
}
