using System.IO.Compression;
using System.Security.Cryptography.X509Certificates;

namespace StruggleBusMonitor.Tests;

public sealed class UpdateTrustTests : IDisposable
{
    private const string Ours = "3FF059FA28ED74ACB229CBA2E670CEA565015238";
    private static readonly FileSignature OurSignature = new(true, Ours, "Open Source Developer", "Asseco Data Systems S.A.");
    private static readonly FileSignature MicrosoftSignature = new(true, "AA", "Microsoft Corporation", "Microsoft Corporation");

    private readonly string folder = Directory.CreateTempSubdirectory("sbm-trust-test-").FullName;

    public void Dispose() => Directory.Delete(folder, recursive: true);

    private static byte[] Program(string marker) => [(byte)'M', (byte)'Z', .. System.Text.Encoding.ASCII.GetBytes(marker)];

    /// <summary>A package holding the named files. A file's content is what the fake reader keys on.</summary>
    private string Package(params (string Path, byte[] Content)[] files)
    {
        var path = Path.Combine(folder, $"{Guid.NewGuid():N}.nupkg");
        using var zip = ZipFile.Open(path, ZipArchiveMode.Create);
        foreach (var (name, content) in files)
        {
            using var stream = zip.CreateEntry(name).Open();
            stream.Write(content);
        }
        return path;
    }

    /// <summary>Reads the marker after 'MZ' and answers as that signer would.</summary>
    private static FileSignature Fake(string path)
    {
        var marker = System.Text.Encoding.ASCII.GetString(File.ReadAllBytes(path)[2..]);
        return marker switch
        {
            "ours" => OurSignature,
            "microsoft" => MicrosoftSignature,
            "stranger" => new FileSignature(true, "BB", "Someone Else", "Some Authority"),
            "same-name" => new FileSignature(true, "CC", "Open Source Developer", "Asseco Data Systems S.A."),
            "microsoft-customer" => new FileSignature(true, "DD", "Someone Else", "Microsoft Corporation"),
            _ => FileSignature.None
        };
    }

    private string? Problem(params (string Path, byte[] Content)[] files)
    {
        var scratch = Directory.CreateDirectory(Path.Combine(folder, Guid.NewGuid().ToString("N"))).FullName;
        var problem = UpdateTrust.Problem(Package(files), Fake, scratch);
        Assert.Empty(Directory.GetFiles(scratch));
        return problem;
    }

    [Fact]
    public void APackageSignedByThePublisherAndMicrosoftIsAccepted() =>
        Assert.Null(Problem(
            ("lib/app/StruggleBusMonitor.exe", Program("ours")),
            ("lib/app/StruggleBusMonitor.dll", Program("ours")),
            ("lib/app/coreclr.dll", Program("microsoft")),
            ("lib/app/settings.json", "{}"u8.ToArray()),
            ("lib/app/empty.txt", [])));

    public static TheoryData<string, string> Refused() => new()
    {
        { "unsigned", "helper.dll" },
        { "stranger", "helper.dll" },
        // The same name on the certificate is not the same certificate.
        { "same-name", "helper.dll" },
        // A certificate Microsoft's signing service issued to someone else is not Microsoft's own.
        { "microsoft-customer", "helper.dll" },
        // A program file is recognised by its content, not its name.
        { "unsigned", "notes.txt" }
    };

    [Theory]
    [MemberData(nameof(Refused))]
    public void OneBadProgramFileRefusesTheWholePackage(string signer, string name)
    {
        var problem = Problem(
            ("lib/app/StruggleBusMonitor.exe", Program("ours")),
            ($"lib/app/{name}", Program(signer)));

        Assert.Equal($"The update was not installed: {name} in it is not signed by this app's publisher.", problem);
    }

    [Theory]
    [InlineData("microsoft")]
    [InlineData(null)]
    public void TheAppItselfMustBeSignedByThePublisher(string? appSigner)
    {
        var files = new List<(string, byte[])> { ("lib/app/coreclr.dll", Program("microsoft")) };
        if (appSigner is not null) files.Add(("lib/app/StruggleBusMonitor.exe", Program(appSigner)));

        Assert.Equal("The update was not installed: the app in it is not signed by this app's publisher.", Problem([.. files]));
    }

    [Fact]
    public void ThumbprintsAreComparedWithoutRegardToCase()
    {
        Assert.True(UpdateTrust.IsOurs(OurSignature with { Thumbprint = Ours.ToLowerInvariant() }));
        Assert.False(UpdateTrust.IsOurs(OurSignature with { Valid = false }));
        Assert.False(UpdateTrust.IsMicrosoft(MicrosoftSignature with { Valid = false }));
    }

    [Fact]
    public void WindowsIsAskedAboutRealFiles()
    {
        // The .NET runtime's own files are signed by Microsoft; this test assembly is not signed.
        var runtime = Path.Combine(Path.GetDirectoryName(typeof(object).Assembly.Location)!, "coreclr.dll");
        var signed = Authenticode.Read(runtime);
        var unsigned = Authenticode.Read(typeof(UpdateTrustTests).Assembly.Location);

        Assert.True(UpdateTrust.IsMicrosoft(signed), $"{runtime}: {signed}");
        Assert.False(UpdateTrust.IsOurs(signed));
        Assert.NotEmpty(signed.Thumbprint);
        Assert.Equal(FileSignature.None, unsigned);
    }

    [Fact]
    public void ARealPackageIsUnpackedCheckedAndCleanedUp()
    {
        var runtime = Path.Combine(Path.GetDirectoryName(typeof(object).Assembly.Location)!, "coreclr.dll");
        var package = Package(("lib/app/coreclr.dll", File.ReadAllBytes(runtime)));
        var before = Directory.GetDirectories(Path.GetTempPath(), "sbm-update-*").Length;

        // Microsoft's file passes; the package is refused only because the app is not in it.
        Assert.Equal("The update was not installed: the app in it is not signed by this app's publisher.", UpdateTrust.Problem(package));
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
        var present = Package(("a.txt", [1]));

        Assert.Contains("could not be found", VelopackEngine.PackageProblem(null, _ => null));
        Assert.Contains("could not be found", VelopackEngine.PackageProblem(Path.Combine(folder, "missing.nupkg"), _ => null));
        Assert.Null(VelopackEngine.PackageProblem(present, _ => null));
        Assert.Equal("refused", VelopackEngine.PackageProblem(present, _ => "refused"));
    }
}
