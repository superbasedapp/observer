using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

class Startup
{
    void Configure(IServiceCollection services)
    {
        services.AddCors(o => o.AddPolicy("open", p =>
            // ruleid: csharp.cors-credentials-any-origin
            p.SetIsOriginAllowed(origin => true).AllowAnyHeader().AllowCredentials()));
        services.AddCors(o => o.AddPolicy("known", p =>
            // ok: csharp.cors-credentials-any-origin
            p.WithOrigins("https://app.example.com").AllowCredentials()));
        services.AddCors(o => o.AddPolicy("public", p =>
            // ok: csharp.cors-credentials-any-origin
            p.SetIsOriginAllowed(origin => true).AllowAnyHeader()));
    }

    void Reflect(HttpContext context)
    {
        // ruleid: csharp.cors-credentials-any-origin
        context.Response.Headers["Access-Control-Allow-Origin"] = context.Request.Headers["Origin"];
        context.Response.Headers["Access-Control-Allow-Credentials"] = "true";
    }
}
