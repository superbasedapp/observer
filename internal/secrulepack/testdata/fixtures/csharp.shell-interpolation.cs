using System.Diagnostics;

class Cleaner
{
    void Clean(string dir)
    {
        // ruleid: csharp.shell-interpolation
        Process.Start("cmd.exe", "/c rmdir /s /q " + dir);
        // ruleid: csharp.shell-interpolation
        var psi = new ProcessStartInfo { FileName = "bash", Arguments = $"-c \"rm -rf {dir}\"" };
        // ok: csharp.shell-interpolation
        var safe = new ProcessStartInfo("git") { ArgumentList = { "clean", "-fd", dir } };
        // ok: csharp.shell-interpolation
        Process.Start("cmd.exe", "/c dir");
    }
}
