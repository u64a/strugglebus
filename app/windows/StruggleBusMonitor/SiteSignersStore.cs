using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace StruggleBusMonitor;

/// <summary>
/// Where the site's signer lines are kept on this PC. They are public keys, so nothing here is
/// secret; they are protected with DPAPI so that another program cannot quietly change which
/// keys this app accepts a fleet from by editing a settings file. (A program running as the same
/// Windows user could still rewrite it; the hosts' own pinned keys are what finally decide.)
/// </summary>
internal static class SiteSignersStore
{
    private static string StorePath => AppPaths.File("site-signers.bin");

    /// <summary>
    /// The stored lines. An unreadable or missing store is an empty set: the app then accepts no
    /// fleet until the operator adds the keys again. Lines an earlier version kept in the plain
    /// settings file are never taken from there unseen; see <see cref="SiteSignersLogic.Earlier"/>.
    /// </summary>
    public static string Load() => File.Exists(StorePath) ? Read() : string.Empty;

    private static string Read()
    {
        try
        {
            return Encoding.UTF8.GetString(ProtectedData.Unprotect(File.ReadAllBytes(StorePath), null, DataProtectionScope.CurrentUser));
        }
        catch (Exception error) when (error is CryptographicException or IOException)
        {
            return string.Empty;
        }
    }

    public static void Save(string lines)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(StorePath)!);
        File.WriteAllBytes(StorePath, ProtectedData.Protect(Encoding.UTF8.GetBytes(lines), null, DataProtectionScope.CurrentUser));
    }
}
