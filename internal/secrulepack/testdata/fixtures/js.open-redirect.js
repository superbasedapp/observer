const express = require("express");
const app = express();

app.get("/login/done", (req, res) => {
  // ruleid: js.open-redirect
  res.redirect(req.query.next);
  // ruleid: js.open-redirect
  res.redirect(302, req.body.returnTo);
  // ruleid: js.open-redirect
  res.redirect("/" + req.query.path);
  // ok: js.open-redirect
  res.redirect("/login?next=" + encodeURIComponent(req.query.next));
  // ok: js.open-redirect
  res.redirect("/items/" + req.params.id);
  // ok: js.open-redirect
  res.redirect("https://accounts.example.com/" + req.query.page);
  // ok: js.open-redirect
  res.redirect("/");
});

app.get("/go", (req, res) => {
  // ruleid: js.open-redirect
  res.setHeader("Location", req.query.to);
  res.statusCode = 302;
  res.end();
});

function followReturn() {
  const params = new URLSearchParams(window.location.search);
  // ruleid: js.open-redirect
  window.location.href = params.get("returnTo");
  // ruleid: js.open-redirect
  location.assign(location.hash.slice(1));
  // ok: js.open-redirect
  window.location.href = "/dashboard";
}

// The program's own values, not request input.
function goTo(res, target) {
  // ok: js.open-redirect
  res.redirect(target);
}
