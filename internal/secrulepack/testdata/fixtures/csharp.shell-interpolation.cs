using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;

class ToolsController : Controller
{
    public IActionResult Clean()
    {
        string dir = Request.Query["dir"];
        // ruleid: csharp.shell-interpolation
        Process.Start("cmd.exe", "/c rmdir /s /q " + dir);
        // ruleid: csharp.shell-interpolation
        var psi = new ProcessStartInfo { FileName = "bash", Arguments = $"-c \"rm -rf {dir}\"" };
        // ruleid: csharp.shell-interpolation
        var ps = new ProcessStartInfo("powershell", "-Command Get-ChildItem " + Request.Form["path"]);
        // ok: csharp.shell-interpolation
        var safe = new ProcessStartInfo("git") { ArgumentList = { "clean", "-fd", dir } };
        // ok: csharp.shell-interpolation
        Process.Start("cmd.exe", "/c dir");
        int lines = int.Parse(Request.Query["lines"]);
        // ok: csharp.shell-interpolation
        Process.Start("bash", $"-c \"tail -n {lines} app.log\"");
        return Ok();
    }

    public IActionResult Ping([FromQuery] string host, [FromQuery] int count)
    {
        // ruleid: csharp.shell-interpolation
        Process.Start("sh", "-c \"ping -c 1 " + host + "\"");
        // ok: csharp.shell-interpolation
        Process.Start("sh", $"-c \"ping -c {count} localhost\"");
        return Ok();
    }
}

// The program's own values, not request input.
class Cleaner
{
    void Clean(string dir)
    {
        // ok: csharp.shell-interpolation
        Process.Start("cmd.exe", "/c rmdir /s /q " + dir);
    }
}
