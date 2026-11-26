using System.IO;
using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace StruggleBusMonitor;

/// <summary>
/// What Windows says about a file's code signature. <see cref="Valid"/> means the signature
/// matches the file and chains to a trusted root; the other values name who signed it.
/// </summary>
internal sealed record FileSignature(bool Valid, string Thumbprint, string SubjectOrganisation, string IssuerOrganisation)
{
    public static readonly FileSignature None = new(false, string.Empty, string.Empty, string.Empty);
}

/// <summary>
/// Decides whether a downloaded update may be installed. The releases repository says what the
/// newest version is, but write access to a repository must not be enough to run code on every
/// PC: each program file in the update has to be signed by this project's certificate or, for the
/// .NET runtime that ships with the app, by Microsoft.
///
/// Limits, so nobody reads more into this than it gives: files that are not programs (settings,
/// text) are not signed and not checked, and an older release that was genuinely signed would
/// still pass.
/// </summary>
internal static class UpdateTrust
{
    /// <summary>
    /// The certificates this project signs with, by thumbprint. A name is not enough: someone
    /// else with the same name could hold their own certificate. Before the certificate is
    /// renewed, the next thumbprint must be added here and shipped in a release signed by the
    /// current one.
    /// </summary>
    public static readonly IReadOnlyList<string> Thumbprints =
    [
        "3FF059FA28ED74ACB229CBA2E670CEA565015238" // valid to 26 Nov 2027
    ];

    public const string MainProgram = "StruggleBusMonitor.exe";
    private const string Microsoft = "Microsoft Corporation";

    public static bool IsOurs(FileSignature signature) =>
        signature.Valid && Thumbprints.Contains(signature.Thumbprint, StringComparer.OrdinalIgnoreCase);

    /// <summary>Signed by Microsoft with a certificate from one of Microsoft's own authorities.</summary>
    public static bool IsMicrosoft(FileSignature signature) =>
        signature.Valid && signature.SubjectOrganisation == Microsoft && signature.IssuerOrganisation == Microsoft;

    /// <summary>
    /// Why the update package must not be installed, or null when every program file in it is
    /// acceptably signed. <paramref name="scratch"/> is an empty folder to unpack into.
    /// </summary>
    public static string? Problem(string packagePath, Func<string, FileSignature> read, string scratch)
    {
        using var package = ZipFile.OpenRead(packagePath);
        var mainIsOurs = false;
        foreach (var entry in package.Entries.Where(IsProgram))
        {
            var signature = SignatureOf(entry, read, scratch);
            if (IsOurs(signature)) mainIsOurs |= entry.Name == MainProgram;
            else if (!IsMicrosoft(signature)) return $"The update was not installed: {entry.Name} in it is not signed by this app's publisher.";
        }
        return mainIsOurs ? null : "The update was not installed: the app in it is not signed by this app's publisher.";
    }

    /// <summary>Unpacks one file, asks about its signature and removes the copy again.</summary>
    private static FileSignature SignatureOf(ZipArchiveEntry entry, Func<string, FileSignature> read, string scratch)
    {
        var copy = Path.Combine(scratch, $"{Guid.NewGuid():N}{Path.GetExtension(entry.Name)}");
        entry.ExtractToFile(copy);
        try { return read(copy); }
        finally { File.Delete(copy); }
    }

    /// <summary>A Windows program file, whatever it is named: they all start with the bytes 'MZ'.</summary>
    private static bool IsProgram(ZipArchiveEntry entry)
    {
        if (entry.Length < 2) return false;
        using var stream = entry.Open();
        return stream.ReadByte() == 'M' && stream.ReadByte() == 'Z';
    }

    /// <summary>The same check against the real signature reader, unpacking into a temporary folder.</summary>
    public static string? Problem(string packagePath)
    {
        var scratch = Directory.CreateTempSubdirectory("sbm-update-").FullName;
        try { return Problem(packagePath, Authenticode.Read, scratch); }
        finally { Directory.Delete(scratch, recursive: true); }
    }
}

/// <summary>Reads a file's code signature from Windows.</summary>
internal static class Authenticode
{
    private const string OrganisationOid = "2.5.4.10";

    public static FileSignature Read(string path)
    {
        if (!Verifies(path)) return FileSignature.None;
        // Marked obsolete along with the other loaders that guess a file's format. There is no
        // replacement for reading the signer out of a signed program, and the format here is known.
#pragma warning disable SYSLIB0057
        using var embedded = X509Certificate.CreateFromSignedFile(path);
#pragma warning restore SYSLIB0057
        using var signer = X509CertificateLoader.LoadCertificate(embedded.GetRawCertData());
        return new FileSignature(true, signer.Thumbprint, Organisation(signer.SubjectName), Organisation(signer.IssuerName));
    }

    /// <summary>
    /// The organisation in a certificate name, read from its own field. Matching text in the
    /// printed name instead would let a name such as CN="x, O=Microsoft Corporation" pass.
    /// </summary>
    internal static string Organisation(X500DistinguishedName name)
    {
        foreach (var part in name.EnumerateRelativeDistinguishedNames())
        {
            if (part.GetSingleElementType().Value == OrganisationOid) return part.GetSingleElementValue() ?? string.Empty;
        }
        return string.Empty;
    }

    /// <summary>
    /// Asks Windows whether the file's signature is valid and trusted. No window is shown and
    /// nothing is fetched from the network, so the answer is the same offline.
    /// </summary>
    private static bool Verifies(string path)
    {
        var file = new WinTrustFileInfo { Size = (uint)Marshal.SizeOf<WinTrustFileInfo>(), FilePath = path };
        var filePointer = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustFileInfo>());
        try
        {
            Marshal.StructureToPtr(file, filePointer, fDeleteOld: false);
            var data = new WinTrustData
            {
                Size = (uint)Marshal.SizeOf<WinTrustData>(),
                UiChoice = 2,            // WTD_UI_NONE
                RevocationChecks = 0,    // WTD_REVOKE_NONE
                UnionChoice = 1,         // WTD_CHOICE_FILE
                File = filePointer,
                StateAction = 0,         // WTD_STATEACTION_IGNORE
                ProviderFlags = 0x1010   // WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE
            };
            var action = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE"); // WINTRUST_ACTION_GENERIC_VERIFY_V2
            return WinVerifyTrust(IntPtr.Zero, ref action, ref data) == 0;
        }
        finally
        {
            Marshal.DestroyStructure<WinTrustFileInfo>(filePointer);
            Marshal.FreeHGlobal(filePointer);
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WinTrustFileInfo
    {
        public uint Size;
        [MarshalAs(UnmanagedType.LPWStr)] public string FilePath;
        public IntPtr FileHandle;
        public IntPtr KnownSubject;
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
        public IntPtr File;
        public uint StateAction;
        public IntPtr StateData;
        public IntPtr UrlReference;
        public uint ProviderFlags;
        public uint UiContext;
        public IntPtr SignatureSettings;
    }

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = false)]
    private static extern int WinVerifyTrust(IntPtr window, ref Guid action, ref WinTrustData data);
}
