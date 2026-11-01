using System.Security.Cryptography;

class Seal
{
    void Ciphers(byte[] key)
    {
        // ruleid: csharp.weak-cipher
        var a = TripleDES.Create();
        var aes = Aes.Create();
        // ruleid: csharp.weak-cipher
        aes.Mode = CipherMode.ECB;
        // ok: csharp.weak-cipher
        aes.Mode = CipherMode.CBC;
        // ok: csharp.weak-cipher
        var g = new AesGcm(key, 16);
    }
}
