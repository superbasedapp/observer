using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;

class Auth
{
    TokenValidationParameters Params(SecurityKey key)
    {
        // ruleid: csharp.jwt-verification-off
        var a = new TokenValidationParameters { ValidateIssuer = true, RequireSignedTokens = false };
        // ruleid: csharp.jwt-verification-off
        var b = new TokenValidationParameters { SignatureValidator = (token, p) => new JwtSecurityToken(token) };
        // ok: csharp.jwt-verification-off
        var c = new TokenValidationParameters { ValidateIssuerSigningKey = true, IssuerSigningKey = key };
        // ruleid: csharp.jwt-verification-off
        c.RequireSignedTokens = false;
        return a ?? b ?? c;
    }
}
