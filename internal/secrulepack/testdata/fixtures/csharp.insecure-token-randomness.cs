using System;
using System.Security.Cryptography;

class Tokens
{
    static readonly Random Rng = new Random();

    string NewResetToken()
    {
        // ruleid: csharp.insecure-token-randomness
        return Rng.Next().ToString("x");
    }

    void Issue()
    {
        // ruleid: csharp.insecure-token-randomness
        var otpCode = new Random().Next(1000000);
        // ok: csharp.insecure-token-randomness
        var jitter = Rng.Next(100);
        // ok: csharp.insecure-token-randomness
        var sessionToken = RandomNumberGenerator.GetInt32(int.MaxValue);
    }
}
