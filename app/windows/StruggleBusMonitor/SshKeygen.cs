using System.Diagnostics;
using System.IO;

namespace StruggleBusMonitor;

/// <summary>
/// Asks Windows' own <c>ssh-keygen</c> whether a signature verifies. It is started by its full
/// path under the Windows folder, never found through PATH, so a program of the same name placed
/// somewhere on PATH is never the one that answers.
/// </summary>
internal static class SshKeygen
{
    public static string DefaultPath => Path.Combine(Environment.SystemDirectory, "OpenSSH", "ssh-keygen.exe");

    /// <summary>
    /// Runs <c>ssh-keygen -Y verify</c> on exactly <paramref name="message"/>, against one signer
    /// line. The three inputs are written to a new folder that is removed afterwards.
    /// </summary>
    public static async Task<SshVerdict> VerifyAsync(string tool, byte[] message, string signature, string signerLine, string principal, string purpose)
    {
        if (!File.Exists(tool)) return SshVerdict.NoTool;
        var folder = Directory.CreateTempSubdirectory("strugglebus-verify-").FullName;
        try
        {
            var signers = Path.Combine(folder, "allowed_signers");
            var signed = Path.Combine(folder, "signature.sig");
            var document = Path.Combine(folder, "document");
            await File.WriteAllTextAsync(signers, signerLine + "\n");
            await File.WriteAllTextAsync(signed, signature);
            await File.WriteAllBytesAsync(document, message);
            return await RunAsync(tool, ["-Y", "verify", "-f", signers, "-I", principal, "-n", purpose, "-s", signed], document) == 0
                ? SshVerdict.Good
                : SshVerdict.Bad;
        }
        finally
        {
            Directory.Delete(folder, recursive: true);
        }
    }

    /// <summary>Runs the tool with the file's bytes as its input and returns its exit code.</summary>
    private static async Task<int> RunAsync(string tool, string[] arguments, string inputFile)
    {
        var start = new ProcessStartInfo(tool)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        foreach (var argument in arguments) start.ArgumentList.Add(argument);
        using var process = Process.Start(start) ?? throw new InvalidOperationException("ssh-keygen could not be started.");
        var output = process.StandardOutput.ReadToEndAsync();
        var errors = process.StandardError.ReadToEndAsync();
        await using (var input = File.OpenRead(inputFile))
        {
            await input.CopyToAsync(process.StandardInput.BaseStream);
        }
        process.StandardInput.Close();
        await Task.WhenAll(output, errors, process.WaitForExitAsync());
        return process.ExitCode;
    }
}
