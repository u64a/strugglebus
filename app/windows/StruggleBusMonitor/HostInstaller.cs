using System.IO;

namespace StruggleBusMonitor;

/// <summary>
/// The worker host's installer as Add a host hands it over: the bytes to save, whether they
/// carry the publisher's signature (and from which certificate), and a warning to show when a
/// signed copy was there but could not be trusted.
/// </summary>
internal sealed record HostInstaller(byte[] Bytes, string? Thumbprint = null, string? Warning = null)
{
    public bool Signed => Thumbprint is not null;
}

/// <summary>
/// Chooses between the two copies of the installer a release carries.
///
/// The unsigned one is built into the app, so it is covered by the app's own signature. The
/// signed one ships as a file beside the app, because only the owner's PC can sign and the app
/// is built elsewhere. A file beside the app is not trusted for being there: it is used only if
/// it is exactly the built-in installer followed by one signature block, and Windows says that
/// signature is valid and from this project's certificate.
/// </summary>
internal static class HostInstallerLogic
{
    public const string FailedCheck =
        "WARNING: the signed installer that came with this app failed its check, so the unsigned one was saved instead. "
        + "That should not happen with a genuine copy of the app. Reinstall the app from the releases page before adding more hosts.";

    private static ReadOnlySpan<byte> BlockStart => "\r\n# SIG # Begin signature block\r\n"u8;
    private static ReadOnlySpan<byte> BlockEnd => "# SIG # End signature block\r\n"u8;

    /// <summary>The signed copy's place: beside the running app.</summary>
    public static string SignedPath => Path.Combine(AppContext.BaseDirectory, AddHostLogic.BootstrapFileName);

    /// <summary>
    /// The signed copy if it passes; the built-in one otherwise. A copy that is simply not there
    /// (a development build, or a release from before installers were signed) is no cause for a
    /// warning. One that is there and fails is.
    /// </summary>
    public static HostInstaller Pick(byte[] builtIn, string signedPath, Func<string, FileSignature> read)
    {
        if (!File.Exists(signedPath)) return new HostInstaller(builtIn);
        var signed = File.ReadAllBytes(signedPath);
        var signature = IsBuiltInPlusOneBlock(builtIn, signed) ? read(signedPath) : FileSignature.None;
        return UpdateTrust.IsOurs(signature)
            ? new HostInstaller(signed, signature.Thumbprint)
            : new HostInstaller(builtIn, Warning: FailedCheck);
    }

    /// <summary>Exactly the built-in bytes, then one signature block, then nothing.</summary>
    internal static bool IsBuiltInPlusOneBlock(ReadOnlySpan<byte> builtIn, ReadOnlySpan<byte> signed)
    {
        if (!signed.StartsWith(builtIn)) return false;
        var rest = signed[builtIn.Length..];
        return rest.StartsWith(BlockStart) && rest.EndsWith(BlockEnd) && HasOneBlock(rest[BlockStart.Length..^BlockEnd.Length]);
    }

    /// <summary>Between the first block's start and the last block's end there must be no other start or end.</summary>
    private static bool HasOneBlock(ReadOnlySpan<byte> inside) =>
        inside.IndexOf("# SIG # Begin signature block"u8) < 0 && inside.IndexOf("# SIG # End signature block"u8) < 0;
}
