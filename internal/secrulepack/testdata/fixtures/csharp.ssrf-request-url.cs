using System;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;

class PreviewController : Controller
{
    static readonly HttpClient Client = new HttpClient();

    public async Task<string> Fetch([FromQuery] string url)
    {
        // ruleid: csharp.ssrf-request-url
        var a = await Client.GetStringAsync(url);
        // ok: csharp.ssrf-request-url
        var b = await Client.GetStringAsync("https://api.example.com/search?q=" + Uri.EscapeDataString(url));
        // ok: csharp.ssrf-request-url
        var c = await Client.GetStringAsync("https://api.example.com/users/" + url);
        return a + b + c;
    }

    public async Task<string> Hook()
    {
        // ruleid: csharp.ssrf-request-url
        var r = await Client.PostAsync(Request.Form["callback"], null);
        return r.ToString();
    }

    // Pack 1.3.1 near-misses, the shapes the SEC-G5 corpus reviewers named
    // (8 wrong matches): a command's or a service's DeleteAsync and
    // GetAsync, over an id.
    public async Task<IActionResult> Delete([FromRoute] Guid orgId)
    {
        // ok: csharp.ssrf-request-url
        var result = await deleteInviteCommand.DeleteAsync(orgId);
        return Ok(result);
    }

    public async Task<IActionResult> Remove([FromRoute] string id, [FromQuery] string token)
    {
        // ok: csharp.ssrf-request-url
        await _userService.DeleteAsync(id, token);
        // ok: csharp.ssrf-request-url
        var q = await _secretsQuery.GetAsync(id);
        return Ok(q);
    }

    // Pack 1.3.1 positive: an HTTP client field known by its name.
    private readonly HttpClient _httpClient;

    public async Task<string> Proxy([FromQuery] string target)
    {
        // ruleid: csharp.ssrf-request-url
        return await _httpClient.GetStringAsync(target);
    }
}
