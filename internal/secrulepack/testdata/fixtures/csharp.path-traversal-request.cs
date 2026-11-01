using System.IO;
using Microsoft.AspNetCore.Mvc;

class FilesController : Controller
{
    const string Base = "/srv/files";

    public IActionResult Get([FromQuery] string name)
    {
        // ruleid: csharp.path-traversal-request
        var bytes = File.ReadAllBytes(Path.Combine(Base, name));
        // ok: csharp.path-traversal-request
        var safe = File.ReadAllBytes(Path.Combine(Base, Path.GetFileName(name)));
        // ok: csharp.path-traversal-request
        var cfg = File.ReadAllText(Path.Combine(Base, "config.json"));
        return Ok(bytes.Length + safe.Length + cfg.Length);
    }

    public IActionResult Raw()
    {
        // ruleid: csharp.path-traversal-request
        return PhysicalFile(Base + "/" + Request.Query["f"], "application/octet-stream");
    }

    // Pack 1.3.1 near-misses, the shapes the SEC-G5 corpus reviewers named
    // (19 wrong matches, internal values and checked paths): an existence
    // check, a reader over the request body, a path the action looks up
    // by an id.
    public IActionResult Validate([FromBody] ValidatePathDto dto)
    {
        // ok: csharp.path-traversal-request
        if (!System.IO.File.Exists(dto.Path) && !Directory.Exists(dto.Path)) return NotFound();
        return Ok();
    }

    public async Task<IActionResult> Upload()
    {
        // ok: csharp.path-traversal-request
        using var reader = new StreamReader(Request.Body);
        return Ok(await reader.ReadToEndAsync());
    }

    public IActionResult Image([FromRoute] Guid itemId)
    {
        var path = _library.GetImagePath(itemId);
        // ok: csharp.path-traversal-request
        return PhysicalFile(path, "image/jpeg");
    }

    // Pack 1.3.1 positives: a stream and a listing over a route string.
    public IActionResult Download([FromRoute] string file)
    {
        // ruleid: csharp.path-traversal-request
        using var fs = new FileStream(Base + "/" + file, FileMode.Open);
        // ok: csharp.path-traversal-request
        var exists = Directory.Exists(Base + "/" + file);
        return Ok(fs.Length + (exists ? 1 : 0));
    }

    public IActionResult List([FromQuery] string dir)
    {
        // ruleid: csharp.path-traversal-request
        return Ok(Directory.GetFiles(Path.Combine(Base, dir)));
    }
}
