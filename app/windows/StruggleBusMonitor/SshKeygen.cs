using System.Diagnostics;
using System.IO;

namespace StruggleBusMonitor;

/// <summary>
/// Asks Windows' own <c>ssh-keygen</c> whether a signature verifies. It is started by its full
/// path under the Windows folder, never found through PATH, so a program of the same name placed
/// somewhere on PATH is never the one that answers.
/// </summary>
/// <summary>ssh-keygen did not produce a signature. The message is what the tool said.</summary>
internal sealed class SshSigningException(string toolSaid) : Exception(toolSaid);

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
        if (!UpdateTrust.IsMicrosoft(CatalogSignature.OfProgram(tool))) return SshVerdict.UntrustedTool;
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

    /// <summary>
    /// The ssh-keygen used to ask a hardware key to sign: the first found, in OpenSSH's own
    /// folder under Program Files and then Windows' own, that is validly signed by Microsoft,
    /// in the file or through a Windows catalog. Never one found through PATH, and never one
    /// trusted for where it is. Null when there is none.
    /// </summary>
    public static string? SigningTool() => SigningTool(
        [Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "OpenSSH", "ssh-keygen.exe"), DefaultPath],
        File.Exists, CatalogSignature.OfProgram);

    internal static string? SigningTool(IEnumerable<string> candidates, Func<string, bool> exists, Func<string, FileSignature> signatureOf) =>
        candidates.FirstOrDefault(path => exists(path) && UpdateTrust.IsMicrosoft(signatureOf(path)));

    /// <summary>
    /// Asks the hardware key to sign exactly <paramref name="document"/> for
    /// <paramref name="purpose"/>. The bytes go into a new folder of the user's own, the tool
    /// signs that file, and the folder is removed whatever happens. Returns the signature text.
    /// Throws <see cref="SshSigningException"/> with what the tool said when it does not sign,
    /// and <see cref="InvalidDataException"/> when the file it signed is no longer those bytes.
    /// </summary>
    public static async Task<string> SignAsync(string tool, string keyFile, string purpose, byte[] document, TimeSpan patience)
    {
        RequireSignablePurpose(purpose);
        var folder = Directory.CreateTempSubdirectory("strugglebus-sign-").FullName;
        try
        {
            var file = Path.Combine(folder, "fleet.toml");
            await File.WriteAllBytesAsync(file, document);
            var (exit, said) = await RunToEndAsync(tool, ["-Y", "sign", "-n", purpose, "-f", keyFile, file], patience);
            var signature = file + ".sig";
            if (exit != 0 || !File.Exists(signature)) throw new SshSigningException(said);
            if (!(await File.ReadAllBytesAsync(file)).AsSpan().SequenceEqual(document)) throw new InvalidDataException();
            return await File.ReadAllTextAsync(signature);
        }
        finally
        {
            Directory.Delete(folder, recursive: true);
        }
    }

    /// <summary>
    /// The only namespaces this app may ever ask a hardware key to sign for: the site's own fleet
    /// and commands to its hosts. The same keys sign software releases under other namespaces, and
    /// this is the lowest place a signature can be asked for, so the refusal lives here: no screen
    /// built later can turn the app into a release signer by passing something else.
    /// </summary>
    public static readonly IReadOnlyList<string> SignablePurposes = ["strugglebus-fleet", "strugglebus-host-command"];

    internal static void RequireSignablePurpose(string purpose)
    {
        if (!SignablePurposes.Contains(purpose, StringComparer.Ordinal))
        {
            throw new InvalidOperationException($"This app never asks a hardware key to sign for \"{purpose}\". It signs only the site's fleet and commands to its hosts.");
        }
    }

    /// <summary>Runs the tool with no input and no window, and returns its exit code and what it wrote. A tool that outlasts <paramref name="patience"/> is stopped.</summary>
    private static async Task<(int Exit, string Said)> RunToEndAsync(string tool, string[] arguments, TimeSpan patience)
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
        using var process = Process.Start(start) ?? throw new SshSigningException("ssh-keygen could not be started.");
        process.StandardInput.Close();
        var output = process.StandardOutput.ReadToEndAsync();
        var errors = process.StandardError.ReadToEndAsync();
        using var limit = new CancellationTokenSource(patience);
        try
        {
            await process.WaitForExitAsync(limit.Token);
        }
        catch (OperationCanceledException)
        {
            process.Kill(entireProcessTree: true);
            throw new SshSigningException("It waited too long for the key and was stopped.");
        }

        return (process.ExitCode, (await errors + await output).Trim());
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
