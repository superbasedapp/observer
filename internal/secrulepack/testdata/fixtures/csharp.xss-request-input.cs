using System.Net;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Html;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;

class GreetingController : Controller
{
    public IActionResult Hello()
    {
        string name = Request.Query["name"];
        // ruleid: csharp.xss-request-input
        var banner = new HtmlString("<b>Hello " + name + "</b>");
        // ruleid: csharp.xss-request-input
        return Content("<h1>" + Request.Form["title"] + "</h1>", "text/html");
    }

    public IActionResult Plain([FromQuery] string text)
    {
        // ok: csharp.xss-request-input
        var a = Content(text, "text/plain");
        // ok: csharp.xss-request-input
        var b = new HtmlString("<p>" + HtmlEncoder.Default.Encode(text) + "</p>");
        // ok: csharp.xss-request-input
        var c = new HtmlString("<p>" + WebUtility.HtmlEncode(text) + "</p>");
        return a;
    }

    public async System.Threading.Tasks.Task Echo([FromQuery] string message)
    {
        // ruleid: csharp.xss-request-input
        await HttpContext.Response.WriteAsync("<p>" + message + "</p>");
    }
}

static class BadgeHelpers
{
    public static IHtmlContent Note(this IHtmlHelper html, HttpRequest request)
    {
        // ruleid: csharp.xss-request-input
        return html.Raw("<em>" + request.Query["note"] + "</em>");
    }

    // The program's own values, not request input.
    public static IHtmlContent Badge(this IHtmlHelper html, string label)
    {
        // ok: csharp.xss-request-input
        return html.Raw("<span class=badge>" + label + "</span>");
    }
}
