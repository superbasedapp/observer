using System;
using Microsoft.AspNetCore.Mvc;

class AccountController : Controller
{
    public IActionResult Done([FromQuery] string returnUrl)
    {
        // ruleid: csharp.open-redirect
        return Redirect(returnUrl);
    }

    public IActionResult DoneChecked([FromQuery] string returnUrl)
    {
        if (Url.IsLocalUrl(returnUrl))
        {
            // ok: csharp.open-redirect
            return Redirect(returnUrl);
        }
        // ok: csharp.open-redirect
        return LocalRedirect(returnUrl);
    }

    public IActionResult Go()
    {
        string to = Request.Query["to"];
        // ruleid: csharp.open-redirect
        Response.Redirect(to);
        // ok: csharp.open-redirect
        var a = Redirect(Url.Action("Index", "Home", new { tab = to }));
        // ok: csharp.open-redirect
        var b = Redirect("/items/" + to);
        // ruleid: csharp.open-redirect
        return new RedirectResult(Request.Form["next"]);
    }
}

// The program's own values, not request input.
class HomeController : Controller
{
    public IActionResult Go(string target)
    {
        // ok: csharp.open-redirect
        return Redirect(target);
    }
}
