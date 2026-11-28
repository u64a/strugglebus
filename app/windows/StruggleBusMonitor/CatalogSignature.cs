using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32.SafeHandles;

namespace StruggleBusMonitor;

/// <summary>
/// A program's signature when it is not in the file but in a Windows catalog. The programs that
/// come with Windows are signed this way: Windows keeps signed lists (catalogs) of file hashes, and
/// a file is vouched for when its hash is in one. <see cref="Authenticode.Read"/> sees only a
/// signature inside the file, so it reports none for these.
///
/// What is checked: the file's SHA-256 is in a catalog Windows itself holds, Windows verifies that
/// catalog's signature for this file (WinVerifyTrust on the catalog member, no window, nothing
/// fetched), and the catalog's signer is read from the catalog. Whose signature it is, is for the
/// caller to decide, as with <see cref="UpdateTrust.IsMicrosoft"/>.
///
/// The catalog vouches for the file's contents, not where it is. A byte-for-byte copy elsewhere
/// has the same hash and the same answer; a file with one byte changed does not. Callers that
/// care where a program is must check that as well.
/// </summary>
internal static class CatalogSignature
{
    /// <summary>
    /// A program's signature wherever Windows keeps it: the one inside the file when it has a
    /// valid one, otherwise the catalog's.
    /// </summary>
    public static FileSignature OfProgram(string path)
    {
        var inFile = Authenticode.Read(path);
        return inFile.Valid ? inFile : Read(path);
    }

    /// <summary>The catalog signature covering the file, or <see cref="FileSignature.None"/> when no catalog does or it does not verify.</summary>
    public static FileSignature Read(string path)
    {
        try
        {
            using var file = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            return Read(path, file);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            return FileSignature.None;
        }
    }

    private static FileSignature Read(string path, SafeFileHandle file)
    {
        if (!CryptCATAdminAcquireContext2(out var admin, IntPtr.Zero, "SHA256", IntPtr.Zero, 0)) return FileSignature.None;
        try
        {
            return HashOf(admin, file) is { } hash ? InCatalog(path, file, hash, admin) : FileSignature.None;
        }
        finally
        {
            CryptCATAdminReleaseContext(admin, 0);
        }
    }

    /// <summary>The signer of the catalog that lists this hash, when there is one and it verifies for the file.</summary>
    private static FileSignature InCatalog(string path, SafeFileHandle file, byte[] hash, IntPtr admin)
    {
        var catalog = CryptCATAdminEnumCatalogFromHash(admin, hash, (uint)hash.Length, 0, IntPtr.Zero);
        if (catalog == IntPtr.Zero) return FileSignature.None;
        try
        {
            return CatalogPath(catalog) is { } catalogPath && Verifies(path, file, hash, catalogPath, admin)
                ? SignerOf(catalogPath)
                : FileSignature.None;
        }
        finally
        {
            CryptCATAdminReleaseCatalogContext(admin, catalog, 0);
        }
    }

    /// <summary>The file's hash as catalogs record it (for a program, over the parts a signature covers).</summary>
    private static byte[]? HashOf(IntPtr admin, SafeFileHandle file)
    {
        uint size = 0;
        CryptCATAdminCalcHashFromFileHandle2(admin, file, ref size, null, 0);
        if (size is 0 or > 64) return null;
        var hash = new byte[size];
        return CryptCATAdminCalcHashFromFileHandle2(admin, file, ref size, hash, 0) ? hash : null;
    }

    private static string? CatalogPath(IntPtr catalog)
    {
        var info = new CatalogInfo { Size = (uint)Marshal.SizeOf<CatalogInfo>() };
        return CryptCATCatalogInfoFromContext(catalog, ref info, 0) ? info.CatalogFile : null;
    }

    /// <summary>Asks Windows whether the catalog's signature is valid and trusted for this file. No window, nothing fetched.</summary>
    private static bool Verifies(string path, SafeFileHandle file, byte[] hash, string catalogPath, IntPtr admin)
    {
        var pinned = GCHandle.Alloc(hash, GCHandleType.Pinned);
        var member = new WinTrustCatalogInfo
        {
            Size = (uint)Marshal.SizeOf<WinTrustCatalogInfo>(),
            CatalogFilePath = catalogPath,
            MemberTag = Convert.ToHexString(hash),
            MemberFilePath = path,
            MemberFile = file.DangerousGetHandle(),
            CalculatedFileHash = pinned.AddrOfPinnedObject(),
            CalculatedFileHashSize = (uint)hash.Length,
            CatalogAdmin = admin
        };
        var memberPointer = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustCatalogInfo>());
        try
        {
            Marshal.StructureToPtr(member, memberPointer, fDeleteOld: false);
            var data = new WinTrustData
            {
                Size = (uint)Marshal.SizeOf<WinTrustData>(),
                UiChoice = 2,            // WTD_UI_NONE
                RevocationChecks = 0,    // WTD_REVOKE_NONE
                UnionChoice = 2,         // WTD_CHOICE_CATALOG
                Subject = memberPointer,
                StateAction = 0,         // WTD_STATEACTION_IGNORE
                ProviderFlags = 0x1010   // WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE
            };
            var action = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE"); // WINTRUST_ACTION_GENERIC_VERIFY_V2
            return WinVerifyTrust(IntPtr.Zero, ref action, ref data) == 0;
        }
        finally
        {
            Marshal.DestroyStructure<WinTrustCatalogInfo>(memberPointer);
            Marshal.FreeHGlobal(memberPointer);
            pinned.Free();
        }
    }

    /// <summary>Who signed the catalog, with the organisation read from its own field in the certificate.</summary>
    private static FileSignature SignerOf(string catalogPath)
    {
#pragma warning disable SYSLIB0057 // No replacement reads the signer out of a signed file; the format here is known.
        using var embedded = X509Certificate.CreateFromSignedFile(catalogPath);
#pragma warning restore SYSLIB0057
        using var signer = X509CertificateLoader.LoadCertificate(embedded.GetRawCertData());
        return new FileSignature(true, signer.Thumbprint, Authenticode.Organisation(signer.SubjectName), Authenticode.Organisation(signer.IssuerName));
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CatalogInfo
    {
        public uint Size;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string CatalogFile;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WinTrustCatalogInfo
    {
        public uint Size;
        public uint CatalogVersion;
        [MarshalAs(UnmanagedType.LPWStr)] public string CatalogFilePath;
        [MarshalAs(UnmanagedType.LPWStr)] public string MemberTag;
        [MarshalAs(UnmanagedType.LPWStr)] public string MemberFilePath;
        public IntPtr MemberFile;
        public IntPtr CalculatedFileHash;
        public uint CalculatedFileHashSize;
        public IntPtr CatalogContext;
        public IntPtr CatalogAdmin;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WinTrustData
    {
        public uint Size;
        public IntPtr PolicyCallbackData;
        public IntPtr SipClientData;
        public uint UiChoice;
        public uint RevocationChecks;
        public uint UnionChoice;
        public IntPtr Subject;
        public uint StateAction;
        public IntPtr StateData;
        public IntPtr UrlReference;
        public uint ProviderFlags;
        public uint UiContext;
        public IntPtr SignatureSettings;
    }

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminAcquireContext2(out IntPtr admin, IntPtr subsystem, string hashAlgorithm, IntPtr strongHashPolicy, uint flags);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminCalcHashFromFileHandle2(IntPtr admin, SafeFileHandle file, ref uint hashSize, byte[]? hash, uint flags);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    private static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr admin, byte[] hash, uint hashSize, uint flags, IntPtr previous);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATCatalogInfoFromContext(IntPtr catalog, ref CatalogInfo info, uint flags);

    [DllImport("wintrust.dll", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminReleaseCatalogContext(IntPtr admin, IntPtr catalog, uint flags);

    [DllImport("wintrust.dll", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminReleaseContext(IntPtr admin, uint flags);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = false)]
    private static extern int WinVerifyTrust(IntPtr window, ref Guid action, ref WinTrustData data);
}
