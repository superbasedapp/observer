using System.Net;
using System.Net.Http;

class Clients
{
    HttpClient Make(bool pinned)
    {
        var h = new HttpClientHandler();
        // ruleid: csharp.tls-verify-off
        h.ServerCertificateCustomValidationCallback = (msg, cert, chain, errors) => true;
        // ruleid: csharp.tls-verify-off
        var g = new HttpClientHandler { ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator };
        // ruleid: csharp.tls-verify-off
        ServicePointManager.ServerCertificateValidationCallback += (s, c, ch, e) => true;
        // ok: csharp.tls-verify-off
        h.ServerCertificateCustomValidationCallback = (msg, cert, chain, errors) => cert != null && cert.Thumbprint == "AB";
        return new HttpClient(h);
    }
}
