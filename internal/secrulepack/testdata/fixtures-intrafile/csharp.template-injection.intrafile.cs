using Microsoft.AspNetCore.Mvc;
using Scriban;

// Cross-function taint in one file (--taint-intrafile): the value from the
// web request is handed to a helper that parses it as a template.
class PagesController : Controller
{
    Template ParsePage(string source)
    {
        // ruleid: csharp.template-injection
        return Template.Parse(source);
    }

    public IActionResult Page()
    {
        return Ok(ParsePage(Request.Query["tpl"]).Render());
    }

    string RequestedTemplate()
    {
        return Request.Form["tpl"];
    }

    public IActionResult PageReturned()
    {
        // ruleid: csharp.template-injection
        return Ok(Template.Parse(RequestedTemplate()).Render());
    }

    // The helper takes the request value but returns a fixed template;
    // nothing of the input becomes template source.
    string FixedTemplate(string requested)
    {
        return "Hello {{ name }}";
    }

    public IActionResult PageFixed()
    {
        // ok: csharp.template-injection
        return Ok(Template.Parse(FixedTemplate(Request.Query["tpl"])).Render());
    }
}
