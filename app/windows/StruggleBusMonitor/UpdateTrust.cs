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

/// <summary>What the check needs to ask Windows about a file. Tests answer for it.</summary>
internal sealed record FileReaders(Func<string, FileSignature> Signature, Func<string, Version?> ProgramVersion)
{
    public static readonly FileReaders Windows = new(Authenticode.Read, Authenticode.ProgramVersion);
}

/// <summary>
/// Decides whether a downloaded update may be installed. The releases repository says what the
/// newest version is, but write access to a repository must not be enough to run code on every
/// PC. So, before an update is installed:
///
/// 1. Every program file in it must be signed by this project's certificate. Microsoft's
///    signature is accepted too, but only on libraries (the .NET runtime), never on a program
///    that can be started.
/// 2. The app in it must be newer than the one running, going by the version inside the app's
///    own signed file. An old release that was genuinely signed cannot be served again as new.
/// 3. Every file beside the app, programs included, must match a list of hashes the publisher
///    signed for that version. That pins the package byte for byte: a text file that tells .NET
///    which libraries to load cannot be edited, and a library cannot be swapped for an older
///    one that Microsoft also signed.
///
/// Limits, so nobody reads more into this than it gives: revocation is not checked online. Two
/// things are not on the list. The package's own wrapping (its name and description files) and
/// the packaging tool's version file hold nothing that is loaded or run; at worst a change to
/// them confuses the updater about versions. And the two helper programs the packaging tool
/// adds after the list is made are covered by rule 1 alone.
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

    /// <summary>Where the app's files sit inside an update package.</summary>
    public const string AppFolder = "lib/app/";
    public const string MainProgram = "StruggleBusMonitor.exe";
    public const string FileList = "signed-files.psd1";

    /// <summary>
    /// What the packaging tool adds beside the app after the list is made, so the list cannot
    /// name them: its version file, and its updater and launcher, which rule 1 still requires
    /// to be signed by this project.
    /// </summary>
    private static readonly HashSet<string> AddedByPackager = new(StringComparer.OrdinalIgnoreCase)
    {
        "sq.version", "Squirrel.exe", "StruggleBus Monitor_ExecutionStub.exe"
    };
    private const string Microsoft = "Microsoft Corporation";
    private const string Refused = "The update was not installed: ";

    public static bool IsOurs(FileSignature signature) =>
        signature.Valid && Thumbprints.Contains(signature.Thumbprint, StringComparer.OrdinalIgnoreCase);

    /// <summary>Signed by Microsoft with a certificate from one of Microsoft's own authorities.</summary>
    public static bool IsMicrosoft(FileSignature signature) =>
        signature.Valid && signature.SubjectOrganisation == Microsoft && signature.IssuerOrganisation == Microsoft;

    /// <summary>
    /// Why the update package must not be installed, or null when it passes every rule above.
    /// <paramref name="scratch"/> is an empty folder to unpack into; <paramref name="running"/>
    /// is this app's own version.
    /// </summary>
    public static string? Problem(string packagePath, FileReaders readers, string scratch, Version running)
    {
        using var zip = ZipFile.OpenRead(packagePath);
        var package = new UpdatePackageFiles(zip, scratch);
        return ProgramsProblem(package, readers) ?? VersionAndListProblem(package, readers, running);
    }

    private static string? ProgramsProblem(UpdatePackageFiles package, FileReaders readers)
    {
        foreach (var entry in package.Programs)
        {
            var signature = package.Read(entry, readers.Signature);
            var accepted = IsOurs(signature) || (IsMicrosoft(signature) && ProgramFile.IsLibrary(entry));
            if (!accepted) return $"{Refused}{entry.Name} in it is not signed by this app's publisher.";
        }
        return null;
    }

    private static string? VersionAndListProblem(UpdatePackageFiles package, FileReaders readers, Version running)
    {
        // Every program has passed by now, so the app, if it is there at all, is the publisher's.
        if (package.Find(MainProgram) is not { } app) return $"{Refused}the app is missing from it.";
        var version = ThreeParts(package.Read(app, readers.ProgramVersion));
        return NotNewerProblem(version, ThreeParts(running)!) ?? ListProblem(package, readers, version!);
    }

    private static string? NotNewerProblem(Version? version, Version running)
    {
        if (version is not null && version > running) return null;
        return $"{Refused}it is version {version?.ToString() ?? "unknown"}, which is not newer than this one ({running}).";
    }

    private static string? ListProblem(UpdatePackageFiles package, FileReaders readers, Version version)
    {
        if (package.Find(FileList) is not { } entry) return $"{Refused}its signed list of files is missing.";
        var (signature, lines) = package.Read(entry, path => (readers.Signature(path), File.ReadAllLines(path)));
        return IsOurs(signature)
            ? ContentsProblem(package, SignedFileList.Parse(lines), version)
            : $"{Refused}its list of files is not signed by this app's publisher.";
    }

    private static string? ContentsProblem(UpdatePackageFiles package, SignedFileList list, Version version)
    {
        if (list.Version != version) return $"{Refused}its signed list of files is for another version.";
        var problem = list.Problem(package.AppFiles.Where(IsOnTheList).ToList());
        return problem is null ? null : Refused + problem;
    }

    /// <summary>Every file beside the app is on the list except the list itself and what the packaging tool adds.</summary>
    private static bool IsOnTheList((string Name, ZipArchiveEntry Entry) file) =>
        file.Name != FileList && !AddedByPackager.Contains(file.Name);

    private static Version? ThreeParts(Version? version) =>
        version is null ? null : new Version(version.Major, version.Minor, Math.Max(version.Build, 0));

    /// <summary>The same check with Windows answering, unpacking into a temporary folder.</summary>
    public static string? Problem(string packagePath)
    {
        var scratch = Directory.CreateTempSubdirectory("sbm-update-").FullName;
        try { return Problem(packagePath, FileReaders.Windows, scratch, typeof(UpdateTrust).Assembly.GetName().Version!); }
        finally { Directory.Delete(scratch, recursive: true); }
    }
}

/// <summary>The files of an update package, and a way to look at one on disk without leaving it there.</summary>
internal sealed class UpdatePackageFiles(ZipArchive zip, string scratch)
{
    /// <summary>Every program file anywhere in the package.</summary>
    public IEnumerable<ZipArchiveEntry> Programs => zip.Entries.Where(ProgramFile.IsProgram);

    /// <summary>Every file beside the app, programs included, with its path inside the app's folder.</summary>
    public IEnumerable<(string Name, ZipArchiveEntry Entry)> AppFiles =>
        from entry in zip.Entries
        where entry.FullName.StartsWith(UpdateTrust.AppFolder, StringComparison.Ordinal) && entry.Name.Length > 0
        select (entry.FullName[UpdateTrust.AppFolder.Length..], entry);

    /// <summary>A file directly in the app's folder, by name.</summary>
    public ZipArchiveEntry? Find(string name) => zip.GetEntry(UpdateTrust.AppFolder + name);

    /// <summary>Unpacks one file, hands it to <paramref name="use"/> and removes the copy again.</summary>
    public T Read<T>(ZipArchiveEntry entry, Func<string, T> use)
    {
        var copy = Path.Combine(scratch, $"{Guid.NewGuid():N}{Path.GetExtension(entry.Name)}");
        entry.ExtractToFile(copy);
        try { return use(copy); }
        finally { File.Delete(copy); }
    }
}

/// <summary>Telling Windows program files apart by their content, never by their name.</summary>
internal static class ProgramFile
{
    private const int HeaderOffsetAt = 0x3C;
    private const int CharacteristicsAfterHeader = 22;
    private const int LibraryFlag = 0x2000;

    /// <summary>A Windows program file, whatever it is named: they all start with the bytes 'MZ'.</summary>
    public static bool IsProgram(ZipArchiveEntry entry) => Start(entry, 2) is [(byte)'M', (byte)'Z'];

    /// <summary>
    /// A library (a .dll) as opposed to a program that can be started, read from the flag in
    /// the file's own header. A file whose header cannot be read is not called a library.
    /// </summary>
    public static bool IsLibrary(ZipArchiveEntry entry)
    {
        var start = Start(entry, 4096);
        if (start.Length < HeaderOffsetAt + 4) return false;
        var header = BitConverter.ToInt32(start, HeaderOffsetAt);
        var inRange = header > 0 && header + CharacteristicsAfterHeader + 2 <= start.Length;
        return inRange && start.AsSpan(header, 4).SequenceEqual("PE\0\0"u8)
            && (BitConverter.ToUInt16(start, header + CharacteristicsAfterHeader) & LibraryFlag) != 0;
    }

    private static byte[] Start(ZipArchiveEntry entry, int length)
    {
        using var stream = entry.Open();
        var buffer = new byte[Math.Min(length, entry.Length)];
        stream.ReadExactly(buffer);
        return buffer;
    }
}

/// <summary>
/// The publisher's list of the files that ship beside the app, programs included: one version
/// and one SHA-256 per file. It travels as a PowerShell data file only because Windows can sign and check those;
/// it is read as text and never run.
/// </summary>
internal sealed record SignedFileList(Version? Version, IReadOnlyDictionary<string, string> Hashes)
{
    private const string VersionPrefix = "# version ";
    private const string HashPrefix = "# sha256 ";
    private const string SignatureStart = "# SIG # Begin signature block";

    public static SignedFileList Parse(IEnumerable<string> lines)
    {
        Version? version = null;
        var hashes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var line in lines.TakeWhile(line => !line.StartsWith(SignatureStart, StringComparison.Ordinal)))
        {
            if (line.StartsWith(VersionPrefix, StringComparison.Ordinal)) System.Version.TryParse(line[VersionPrefix.Length..].Trim(), out version);
            else if (line.StartsWith(HashPrefix, StringComparison.Ordinal)) AddHash(hashes, line[HashPrefix.Length..]);
        }
        return new SignedFileList(version, hashes);
    }

    private static void AddHash(Dictionary<string, string> hashes, string rest)
    {
        var parts = rest.Split("  ", 2);
        if (parts.Length == 2) hashes[parts[1].Trim()] = parts[0].Trim();
    }

    /// <summary>What is wrong with the files next to this list, or null: none changed, added or missing.</summary>
    public string? Problem(IReadOnlyList<(string Name, ZipArchiveEntry Entry)> files)
    {
        foreach (var (name, entry) in files)
        {
            if (!Hashes.TryGetValue(name, out var expected)) return $"{name} in it is not on the publisher's signed list.";
            if (!string.Equals(expected, Hash(entry), StringComparison.OrdinalIgnoreCase)) return $"{name} in it is not what the publisher signed.";
        }
        var present = files.Select(file => file.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);
        return Hashes.Keys.FirstOrDefault(name => !present.Contains(name)) is { } missing ? $"{missing} is missing from it." : null;
    }

    private static string Hash(ZipArchiveEntry entry)
    {
        using var stream = entry.Open();
        return Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(stream));
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

    /// <summary>The version stamped inside a program file, which its signature covers. Null if it has none.</summary>
    public static Version? ProgramVersion(string path)
    {
        var info = System.Diagnostics.FileVersionInfo.GetVersionInfo(path);
        return info.FileVersion is null ? null : new Version(info.FileMajorPart, info.FileMinorPart, info.FileBuildPart);
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
