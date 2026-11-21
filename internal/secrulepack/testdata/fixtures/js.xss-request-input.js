const express = require("express");
const app = express();

app.get("/hello", (req, res) => {
  const page = document.getElementById("greeting");
  // ruleid: js.xss-request-input
  page.innerHTML = "<b>Hello " + req.query.name + "</b>";
  // ok: js.xss-request-input
  page.textContent = "Hello " + req.query.name;
  // ok: js.xss-request-input
  page.innerHTML = DOMPurify.sanitize(req.query.bio);
  // ok: js.xss-request-input
  page.innerHTML = "<b>Hello</b>";
});

function showFragment() {
  const target = document.querySelector("#out");
  // ruleid: js.xss-request-input
  target.innerHTML = decodeURIComponent(location.hash.slice(1));
  const params = new URLSearchParams(window.location.search);
  // ruleid: js.xss-request-input
  document.write("<p>" + params.get("msg") + "</p>");
  // ruleid: js.xss-request-input
  target.insertAdjacentHTML("beforeend", document.referrer);
  // ok: js.xss-request-input
  target.innerHTML = "<span>" + escapeHtml(params.get("msg")) + "</span>";
  // ok: js.xss-request-input
  target.innerHTML = "<span>page " + parseInt(params.get("page"), 10) + "</span>";
}

// The program's own values, not request input.
function render(el, html) {
  // ok: js.xss-request-input
  el.innerHTML = html;
  // ok: js.xss-request-input
  document.write(html);
}
