using System;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;

// Cross-function taint in one file (--taint-intrafile): the value from the
// web request is handed to a helper that fetches it.
class PreviewController : Controller
{
    private readonly HttpClient _httpClient = new HttpClient();

    Task<string> FetchUrl(string target)
    {
        // ruleid: csharp.ssrf-request-url
        return _httpClient.GetStringAsync(target);
    }

    public async Task<IActionResult> Preview()
    {
        return Ok(await FetchUrl(Request.Query["url"]));
    }

    string RequestedUrl()
    {
        return Request.Form["callback"];
    }

    public async Task<IActionResult> Callback()
    {
        // ruleid: csharp.ssrf-request-url
        return Ok(await _httpClient.GetStringAsync(RequestedUrl()));
    }

    // The sanitizer sits in the helper: the value is URL-encoded before the
    // caller fetches it.
    string Encoded(string value)
    {
        return Uri.EscapeDataString(value);
    }

    public async Task<IActionResult> PreviewEncoded()
    {
        // ok: csharp.ssrf-request-url
        return Ok(await _httpClient.GetStringAsync(Encoded(Request.Query["url"])));
    }
}
