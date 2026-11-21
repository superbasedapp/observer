using System.IO;
using Microsoft.AspNetCore.Mvc;

// Cross-function taint in one file (--taint-intrafile): the value from the
// web request is handed to a helper that opens it.
class DownloadsController : Controller
{
    byte[] ReadNamed(string name)
    {
        // ruleid: csharp.path-traversal-request
        return File.ReadAllBytes(name);
    }

    public IActionResult Get()
    {
        return Ok(ReadNamed(Request.Query["name"]));
    }

    string RequestedPath()
    {
        return Request.Query["path"];
    }

    public IActionResult Remove()
    {
        // ruleid: csharp.path-traversal-request
        File.Delete(RequestedPath());
        return Ok();
    }

    // The sanitizer sits in the helper: the name is reduced to its file
    // name before the caller opens it.
    string PlainName(string name)
    {
        return Path.GetFileName(name);
    }

    public IActionResult GetPlain()
    {
        // ok: csharp.path-traversal-request
        return Ok(File.ReadAllBytes(PlainName(Request.Query["name"])));
    }
}
