using System.Security.Cryptography;
using System.Text;

class Accounts
{
    void Store(string password, string salt, byte[] body)
    {
        using var md5 = MD5.Create();
        // ruleid: csharp.weak-password-hash
        var a = md5.ComputeHash(Encoding.UTF8.GetBytes(password));
        // ruleid: csharp.weak-password-hash
        var b = SHA256.HashData(Encoding.UTF8.GetBytes(salt + password));
        // ok: csharp.weak-password-hash
        var c = SHA256.HashData(body);
        // ok: csharp.weak-password-hash
        var d = Rfc2898DeriveBytes.Pbkdf2(password, Encoding.UTF8.GetBytes(salt), 600000, HashAlgorithmName.SHA256, 32);
    }
}
