const ejs = require("ejs");
const Handlebars = require("handlebars");
const _ = require("lodash");

function page(req, res) {
  // ruleid: js.template-injection
  const a = ejs.render(req.body.template, { user: req.user });
  // ruleid: js.template-injection
  const b = Handlebars.compile(req.query.tpl);
  // ruleid: js.template-injection
  const c = _.template("Hello " + req.params.name);
  // ok: js.template-injection
  const d = ejs.render("<p><%= name %></p>", { name: req.query.name });
  // ok: js.template-injection
  const e = Handlebars.compile("<p>{{name}}</p>")({ name: req.query.name });
  res.send(a + b() + c() + d + e);
}

// The false-positive shape of the 1.1.0 rule: a compile method of a
// library that is not a template engine.
function validator(req, ajv) {
  // ok: js.template-injection
  return ajv.compile(req.body.schema);
}
