using System.IO.Compression;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace StruggleBusMonitor.Tests;

public sealed class UpdateTrustTests : IDisposable
{
    private const string Ours = "3FF059FA28ED74ACB229CBA2E670CEA565015238";
    private const string Refused = "The update was not installed: ";
    private static readonly FileSignature OurSignature = new(true, Ours, "Open Source Developer", "Asseco Data Systems S.A.");
    private static readonly FileSignature MicrosoftSignature = new(true, "AA", "Microsoft Corporation", "Microsoft Corporation");
    private static readonly Version Running = new(1, 7, 2, 0);
    private static readonly Version Next = new(1, 7, 3);

    private readonly string folder = Directory.CreateTempSubdirectory("sbm-trust-test-").FullName;

    public void Dispose() => Directory.Delete(folder, recursive: true);

    /// <summary>
    /// The start of a real program file: 'MZ', the offset of the header, the header's 'PE' mark
    /// and its flags. <paramref name="signer"/> follows it, for the fake reader to answer by.
    /// </summary>
    private static byte[] Program(string signer, bool library = false)
    {
        var bytes = new byte[0x40 + 24];
        bytes[0] = (byte)'M';
        bytes[1] = (byte)'Z';
        BitConverter.GetBytes(0x40).CopyTo(bytes, 0x3C);
        "PE\0\0"u8.CopyTo(bytes.AsSpan(0x40));
        BitConverter.GetBytes((ushort)(library ? 0x2022 : 0x0022)).CopyTo(bytes, 0x40 + 22);
        return [.. bytes, .. Encoding.ASCII.GetBytes(signer)];
    }

    private static byte[] Library(string signer) => Program(signer, library: true);

    private static byte[] Text(string text) => Encoding.UTF8.GetBytes(text);

    private static FileSignature Signer(string marker) => marker switch
    {
        "ours" => OurSignature,
        "microsoft" => MicrosoftSignature,
        "stranger" => new FileSignature(true, "BB", "Someone Else", "Some Authority"),
        "same-name" => new FileSignature(true, "CC", "Open Source Developer", "Asseco Data Systems S.A."),
        "microsoft-customer" => new FileSignature(true, "DD", "Someone Else", "Microsoft Corporation"),
        _ => FileSignature.None
    };

    /// <summary>Answers for a program by the marker after its header, and for the list as told.</summary>
    private static FileReaders Readers(string listSigner = "ours", Version? appVersion = null, bool noVersion = false) => new(
        path => Signer(path.EndsWith(".psd1", StringComparison.Ordinal) ? listSigner : Marker(File.ReadAllBytes(path))),
        _ => noVersion ? null : appVersion ?? new Version(1, 7, 3, 0));

    private static string ListOf(string version, params (string Name, byte[] Content)[] files) =>
        "# StruggleBus Monitor signed file list. Data only; never run.\n"
        + $"# version {version}\n"
        + string.Concat(files.Select(file => $"# sha256 {Convert.ToHexString(SHA256.HashData(file.Content)).ToLowerInvariant()}  {file.Name}\n"))
        + "@{}\n\r\n# SIG # Begin signature block\r\n# sha256 00  smuggled.json\r\n# SIG # End signature block\r\n";

    private static readonly (string Name, byte[] Content) Deps = ("StruggleBusMonitor.deps.json", Text("""{"deps":1}"""));
    private static readonly (string Name, byte[] Content) Config = ("StruggleBusMonitor.runtimeconfig.json", Text("""{"config":1}"""));
    private static readonly (string Name, byte[] Content) Culture = ("de/Resources.txt", Text("hallo"));

    /// <summary>A package as the release script makes one, which the changes below then spoil.</summary>
    private static Dictionary<string, byte[]> Good() => new()
    {
        ["lib/app/StruggleBusMonitor.exe"] = Program("ours"),
        ["lib/app/StruggleBusMonitor.dll"] = Library("ours"),
        ["lib/app/Squirrel.exe"] = Program("ours"),
        ["lib/app/coreclr.dll"] = Library("microsoft"),
        ["lib/app/" + Deps.Name] = Deps.Content,
        ["lib/app/" + Config.Name] = Config.Content,
        ["lib/app/" + Culture.Name] = Culture.Content,
        ["lib/app/sq.version"] = Text("1.7.3"),
        ["lib/app/signed-files.psd1"] = Text(ListOf("1.7.3", Deps, Config, Culture)),
        ["lib/app/"] = [],
        ["NZCypher819.StruggleBusMonitor.nuspec"] = Text("<package/>"),
        ["[Content_Types].xml"] = Text("<Types/>")
    };

    /// <summary>The signer written after a program's header. A stub too short to hold one counts as Microsoft's.</summary>
    private static string Marker(byte[] program) =>
        program.Length > 0x40 + 24 ? Encoding.ASCII.GetString(program[(0x40 + 24)..]) : "microsoft";

    private string? Problem(Dictionary<string, byte[]> files, FileReaders? readers = null)
    {
        var path = Path.Combine(folder, $"{Guid.NewGuid():N}.nupkg");
        using (var zip = ZipFile.Open(path, ZipArchiveMode.Create))
        {
            foreach (var (name, content) in files)
            {
                using var stream = zip.CreateEntry(name).Open();
                stream.Write(content);
            }
        }
        var scratch = Directory.CreateDirectory(Path.Combine(folder, Guid.NewGuid().ToString("N"))).FullName;
        var problem = UpdateTrust.Problem(path, readers ?? Readers(), scratch, Running);
        Assert.Empty(Directory.GetFiles(scratch));
        return problem;
    }

    private string? Changed(Action<Dictionary<string, byte[]>> change, FileReaders? readers = null)
    {
        var files = Good();
        change(files);
        return Problem(files, readers);
    }

    [Fact]
    public void APackageAsTheReleaseScriptMakesItIsAccepted() => Assert.Null(Problem(Good()));

    public static TheoryData<string, string> BadPrograms() => new()
    {
        { "unsigned", "helper.dll" },
        { "stranger", "helper.dll" },
        // The same name on the certificate is not the same certificate.
        { "same-name", "helper.dll" },
        // A certificate Microsoft's signing service issued to someone else is not Microsoft's own.
        { "microsoft-customer", "helper.dll" },
        // A program file is recognised by its content, not its name, wherever it sits in the package.
        { "unsigned", "notes.txt" }
    };

    [Theory]
    [MemberData(nameof(BadPrograms))]
    public void OneBadProgramFileRefusesTheWholePackage(string signer, string name)
    {
        Assert.Equal($"{Refused}{name} in it is not signed by this app's publisher.", Changed(files => files["lib/app/" + name] = Library(signer)));
        Assert.Equal($"{Refused}{name} in it is not signed by this app's publisher.", Changed(files => files["elsewhere/" + name] = Library(signer)));
    }

    [Fact]
    public void MicrosoftsSignatureIsAcceptedOnALibraryButNotOnAProgramThatCanBeStarted()
    {
        Assert.Null(Changed(files => files["lib/app/hostfxr.dll"] = Library("microsoft")));
        Assert.Equal($"{Refused}tool.exe in it is not signed by this app's publisher.", Changed(files => files["lib/app/tool.exe"] = Program("microsoft")));
        // Named like a library, but its own header says it is a program.
        Assert.Equal($"{Refused}tool.dll in it is not signed by this app's publisher.", Changed(files => files["lib/app/tool.dll"] = Program("microsoft")));
        Assert.Equal($"{Refused}StruggleBusMonitor.exe in it is not signed by this app's publisher.",
            Changed(files => files["lib/app/StruggleBusMonitor.exe"] = Program("microsoft")));
    }

    [Theory]
    [InlineData(2)]
    [InlineData(0x3F)]
    public void AProgramFileTooShortToHaveAHeaderIsNotCalledALibrary(int length)
    {
        var stub = Program("microsoft")[..length];

        Assert.Equal($"{Refused}stub.dll in it is not signed by this app's publisher.",
            Changed(files => files["lib/app/stub.dll"] = stub));
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(4000)]
    [InlineData(0x30)]
    public void AHeaderThatPointsNowhereIsNotCalledALibrary(int offset)
    {
        var broken = Library("microsoft");
        BitConverter.GetBytes(offset).CopyTo(broken, 0x3C);

        Assert.Equal($"{Refused}broken.dll in it is not signed by this app's publisher.",
            Changed(files => files["lib/app/broken.dll"] = broken));
    }

    [Fact]
    public void TheAppMustBeInThePackage() =>
        Assert.Equal($"{Refused}the app is missing from it.", Changed(files => files.Remove("lib/app/StruggleBusMonitor.exe")));

    [Fact]
    public void AnOlderOrEqualVersionCannotBeServedAsNew()
    {
        Assert.Equal($"{Refused}it is version 1.7.2, which is not newer than this one (1.7.2).", Problem(Good(), Readers(appVersion: new Version(1, 7, 2, 0))));
        Assert.Equal($"{Refused}it is version 1.6.0, which is not newer than this one (1.7.2).", Problem(Good(), Readers(appVersion: new Version(1, 6, 0, 9))));
        Assert.Equal($"{Refused}it is version unknown, which is not newer than this one (1.7.2).", Problem(Good(), Readers(noVersion: true)));
    }

    [Fact]
    public void TheSignedListMustBeThereSignedAndForThisVersion()
    {
        Assert.Equal($"{Refused}its signed list of files is missing.", Changed(files => files.Remove("lib/app/signed-files.psd1")));
        Assert.Equal($"{Refused}its list of files is not signed by this app's publisher.", Problem(Good(), Readers(listSigner: "stranger")));
        Assert.Equal($"{Refused}its list of files is not signed by this app's publisher.", Problem(Good(), Readers(listSigner: "unsigned")));
        // A genuine list from another release cannot vouch for this one's files.
        Assert.Equal($"{Refused}its signed list of files is for another version.",
            Changed(files => files["lib/app/signed-files.psd1"] = Text(ListOf("1.7.2", Deps, Config, Culture))));
        Assert.Equal($"{Refused}its signed list of files is for another version.",
            Changed(files => files["lib/app/signed-files.psd1"] = Text("@{}\n")));
    }

    [Fact]
    public void AFileBesideTheAppThatWasChangedAddedOrRemovedRefusesThePackage()
    {
        // The files that tell .NET which libraries to load are the reason the list exists.
        Assert.Equal($"{Refused}StruggleBusMonitor.deps.json in it is not what the publisher signed.",
            Changed(files => files["lib/app/StruggleBusMonitor.deps.json"] = Text("""{"deps":"elsewhere"}""")));
        Assert.Equal($"{Refused}extra.config in it is not on the publisher's signed list.", Changed(files => files["lib/app/extra.config"] = Text("x")));
        Assert.Equal($"{Refused}sub/extra.json in it is not on the publisher's signed list.", Changed(files => files["lib/app/sub/extra.json"] = Text("x")));
        Assert.Equal($"{Refused}StruggleBusMonitor.runtimeconfig.json is missing from it.",
            Changed(files => files.Remove("lib/app/StruggleBusMonitor.runtimeconfig.json")));
        // A line after the signature block is not part of what was signed.
        Assert.Equal($"{Refused}smuggled.json in it is not on the publisher's signed list.", Changed(files => files["lib/app/smuggled.json"] = Text("x")));
    }

    [Fact]
    public void TheListIsReadForgivingOfCaseAndStrictAboutShape()
    {
        var list = SignedFileList.Parse(["# version 2.0.1", "# sha256 AB  Folder/File.json", "# sha256 malformed", "# a comment", "@{}"]);

        Assert.Equal(new Version(2, 0, 1), list.Version);
        Assert.Equal("AB", list.Hashes["folder/file.json"]);
        Assert.Single(list.Hashes);
        Assert.Null(SignedFileList.Parse(["# version next"]).Version);
    }

    [Fact]
    public void ThumbprintsAreComparedWithoutRegardToCase()
    {
        Assert.True(UpdateTrust.IsOurs(OurSignature with { Thumbprint = Ours.ToLowerInvariant() }));
        Assert.False(UpdateTrust.IsOurs(OurSignature with { Valid = false }));
        Assert.False(UpdateTrust.IsMicrosoft(MicrosoftSignature with { Valid = false }));
    }

    private static string RuntimeFile(string name) => Path.Combine(Path.GetDirectoryName(typeof(object).Assembly.Location)!, name);

    [Fact]
    public void WindowsIsAskedAboutRealFiles()
    {
        // The .NET runtime's own files are signed by Microsoft; this test assembly is not signed.
        var signed = Authenticode.Read(RuntimeFile("coreclr.dll"));
        var unsigned = Authenticode.Read(typeof(UpdateTrustTests).Assembly.Location);

        Assert.True(UpdateTrust.IsMicrosoft(signed), signed.ToString());
        Assert.False(UpdateTrust.IsOurs(signed));
        Assert.NotEmpty(signed.Thumbprint);
        Assert.Equal(FileSignature.None, unsigned);
        Assert.True(Authenticode.ProgramVersion(RuntimeFile("coreclr.dll")) > new Version(8, 0, 0));
        Assert.Null(Authenticode.ProgramVersion(Path.Combine(AppContext.BaseDirectory, "Contracts", "app-update", "signed-files.psd1")));
    }

    [Fact]
    public void ARealSignedListIsThePublishersAndAChangedCopyIsNot()
    {
        // A list signed with the project's real certificate, kept as a fixture. Its signature is
        // timestamped, so it stays valid after that certificate expires.
        var real = Path.Combine(AppContext.BaseDirectory, "Contracts", "app-update", "signed-files.psd1");
        var changed = Path.Combine(folder, "changed.psd1");
        File.WriteAllText(changed, File.ReadAllText(real).Replace("# version 1.7.3", "# version 9.9.9"));

        Assert.True(UpdateTrust.IsOurs(Authenticode.Read(real)));
        Assert.Equal(new Version(1, 7, 3), SignedFileList.Parse(File.ReadAllLines(real)).Version);
        Assert.Equal(FileSignature.None, Authenticode.Read(changed));
    }

    [Fact]
    public void ARealPackageIsUnpackedCheckedAndCleanedUp()
    {
        var package = Path.Combine(folder, "real.nupkg");
        using (var zip = ZipFile.Open(package, ZipArchiveMode.Create)) zip.CreateEntryFromFile(RuntimeFile("coreclr.dll"), "lib/app/coreclr.dll");
        var before = Directory.GetDirectories(Path.GetTempPath(), "sbm-update-*").Length;

        // Microsoft's library passes; the package is refused only because the app is not in it.
        Assert.Equal($"{Refused}the app is missing from it.", UpdateTrust.Problem(package));
        Assert.Equal(before, Directory.GetDirectories(Path.GetTempPath(), "sbm-update-*").Length);
    }

    [Fact]
    public void TheOrganisationIsReadFromItsOwnField()
    {
        var name = new X500DistinguishedName("CN=\"x, O=Microsoft Corporation\", O=Someone Else, C=AU");

        Assert.Equal("Someone Else", Authenticode.Organisation(name));
        Assert.Equal(string.Empty, Authenticode.Organisation(new X500DistinguishedName("CN=nobody")));
    }

    [Fact]
    public void AMissingPackageIsRefused()
    {
        var present = Path.Combine(folder, "present.nupkg");
        File.WriteAllBytes(present, [1]);

        Assert.Contains("could not be found", VelopackEngine.PackageProblem(null, _ => null));
        Assert.Contains("could not be found", VelopackEngine.PackageProblem(Path.Combine(folder, "missing.nupkg"), _ => null));
        Assert.Null(VelopackEngine.PackageProblem(present, _ => null));
        Assert.Equal("refused", VelopackEngine.PackageProblem(present, _ => "refused"));
    }
}
