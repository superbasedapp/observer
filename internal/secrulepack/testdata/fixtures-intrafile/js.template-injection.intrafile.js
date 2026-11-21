const ejs = require("ejs");

function renderPage(source) {
  // ruleid: js.template-injection
  return ejs.render(source, {});
}

function page(req, res) {
  res.send(renderPage(req.query.tpl));
}

function requestedTemplate(req) {
  return req.body.tpl;
}

function pageReturned(req, res) {
  // ruleid: js.template-injection
  res.send(ejs.render(requestedTemplate(req), {}));
}

// The helper takes the request value but returns a fixed template; nothing
// of the input becomes template source.
function fixedTemplate(requested) {
  return "<p><%= name %></p>";
}

function pageFixed(req, res) {
  // ok: js.template-injection
  res.send(ejs.render(fixedTemplate(req.query.tpl), { name: "x" }));
}
