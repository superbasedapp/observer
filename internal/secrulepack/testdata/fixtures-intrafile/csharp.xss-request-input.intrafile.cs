using System.Net;
using Microsoft.AspNetCore.Html;
using Microsoft.AspNetCore.Mvc;

// Cross-function taint in one file (--taint-intrafile): the value from the
// web request is handed to a helper that marks it raw HTML.
class PagesController : Controller
{
    HtmlString Heading(string text)
    {
        // ruleid: csharp.xss-request-input
        return new HtmlString("<h1>" + text + "</h1>");
    }

    public IActionResult Show()
    {
        return View(Heading(Request.Query["title"]));
    }

    string RequestedNote()
    {
        return Request.Form["note"];
    }

    public IActionResult Note()
    {
        // ruleid: csharp.xss-request-input
        return Content("<p>" + RequestedNote() + "</p>", "text/html");
    }

    // The sanitizer sits in the helper: the value is encoded before the
    // caller marks it raw.
    string Encoded(string value)
    {
        return WebUtility.HtmlEncode(value);
    }

    public IActionResult Comment()
    {
        // ok: csharp.xss-request-input
        return View(new HtmlString("<p>" + Encoded(Request.Query["comment"]) + "</p>"));
    }
}
