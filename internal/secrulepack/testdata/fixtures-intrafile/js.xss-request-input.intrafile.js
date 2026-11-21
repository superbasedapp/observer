// Cross-function taint in one file (--taint-intrafile): the value from the
// web request is handed to a helper that writes it into the page.
function showBanner(el, text) {
  // ruleid: js.xss-request-input
  el.innerHTML = "<div class=banner>" + text + "</div>";
}

function banner(req, res) {
  showBanner(document.body, req.query.banner);
}

function requestedTitle(req) {
  return req.body.title;
}

function title(req) {
  // ruleid: js.xss-request-input
  document.getElementById("title").innerHTML = requestedTitle(req);
}

// The sanitizer sits in the helper: the value is cleaned before the caller
// writes it into the page.
function clean(value) {
  return DOMPurify.sanitize(value);
}

function bio(req) {
  // ok: js.xss-request-input
  document.getElementById("bio").innerHTML = clean(req.body.bio);
}
