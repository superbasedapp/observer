using System;
using Microsoft.AspNetCore.Mvc;

// Cross-function taint in one file (--taint-intrafile): the value from the
// web request is handed to a helper that redirects to it.
class LoginController : Controller
{
    IActionResult SendTo(string target)
    {
        // ruleid: csharp.open-redirect
        return Redirect(target);
    }

    public IActionResult Done()
    {
        return SendTo(Request.Query["next"]);
    }

    string ReturnTarget()
    {
        return Request.Form["returnUrl"];
    }

    public IActionResult Finish()
    {
        // ruleid: csharp.open-redirect
        return Redirect(ReturnTarget());
    }

    // The sanitizer sits in the helper: the value is escaped before the
    // caller redirects to it.
    string Escaped(string value)
    {
        return Uri.EscapeDataString(value);
    }

    public IActionResult Bounce()
    {
        // ok: csharp.open-redirect
        return Redirect(Escaped(Request.Query["next"]));
    }
}
