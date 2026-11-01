using Microsoft.AspNetCore.Mvc;
using Scriban;

class PagesController : Controller
{
    public string Render([FromQuery] string tpl)
    {
        // ruleid: csharp.template-injection
        var t = Template.Parse(tpl);
        // ok: csharp.template-injection
        var u = Template.Parse("Hello {{ name }}");
        return t.Render() + u.Render(new { name = tpl });
    }

    public string Mail()
    {
        // ruleid: csharp.template-injection
        var t = Template.Parse("<p>" + Request.Query["greeting"] + "</p>");
        return t.Render();
    }
}
