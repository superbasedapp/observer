using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;

// Cross-function taint in one file (--taint-intrafile): the value from the
// web request is handed to a helper that runs a shell.
class BackupController : Controller
{
    Process Archive(string name)
    {
        // ruleid: csharp.shell-interpolation
        return Process.Start("bash", "-c \"tar czf /backups/" + name + ".tgz /data\"");
    }

    public IActionResult Backup()
    {
        Archive(Request.Query["name"]);
        return Ok();
    }

    string RequestedHost()
    {
        return Request.Form["host"];
    }

    public IActionResult Ping()
    {
        // ruleid: csharp.shell-interpolation
        Process.Start("cmd.exe", "/c ping " + RequestedHost());
        return Ok();
    }

    // The sanitizer sits in the helper: the count is parsed to a number
    // before the caller builds the command line.
    int AsCount(string value)
    {
        return int.Parse(value);
    }

    public IActionResult Tail()
    {
        // ok: csharp.shell-interpolation
        Process.Start("bash", "-c \"tail -n " + AsCount(Request.Query["lines"]) + " app.log\"");
        return Ok();
    }
}
