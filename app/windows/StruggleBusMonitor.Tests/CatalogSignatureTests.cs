using System.IO;

namespace StruggleBusMonitor.Tests;

/// <summary>Reading a catalog signature, against the programs Windows itself ships.</summary>
public sealed class CatalogSignatureTests
{
    private static readonly string Windows = Environment.SystemDirectory;

    /// <summary>A program that ships with every Windows and is signed through a catalog, not in the file.</summary>
    private static string CatalogSigned()
    {
        string[] candidates = [Path.Combine(Windows, "OpenSSH", "ssh-keygen.exe"), Path.Combine(Windows, "whoami.exe"), Path.Combine(Windows, "find.exe")];
        return candidates.First(path => File.Exists(path) && !Authenticode.Read(path).Valid);
    }

    [Fact]
    public void AProgramWindowsShipsIsVouchedForByACatalogSignedByMicrosoft()
    {
        var program = CatalogSigned();

        var signature = CatalogSignature.Read(program);

        Assert.True(signature.Valid, program);
        Assert.True(UpdateTrust.IsMicrosoft(signature), $"{program}: {signature.SubjectOrganisation} / {signature.IssuerOrganisation}");
        Assert.False(Authenticode.Read(program).Valid);
    }

    [Fact]
    public void AnExactCopyHasTheSameAnswerAndACopyWithOneByteChangedHasNone()
    {
        var folder = Directory.CreateTempSubdirectory("catalog-test-").FullName;
        try
        {
            var copy = Path.Combine(folder, "copy.exe");
            File.Copy(CatalogSigned(), copy);
            Assert.True(UpdateTrust.IsMicrosoft(CatalogSignature.Read(copy)));

            var bytes = File.ReadAllBytes(copy);
            bytes[^1] ^= 0x01;
            var changed = Path.Combine(folder, "changed.exe");
            File.WriteAllBytes(changed, bytes);

            Assert.Equal(FileSignature.None, CatalogSignature.Read(changed));
        }
        finally
        {
            Directory.Delete(folder, recursive: true);
        }
    }

    [Fact]
    public void AFileNoCatalogKnowsAndAFileThatIsNotThereHaveNoSignature()
    {
        var folder = Directory.CreateTempSubdirectory("catalog-test-").FullName;
        try
        {
            var mine = Path.Combine(folder, "mine.exe");
            File.WriteAllBytes(mine, [0x4D, 0x5A, 1, 2, 3, 4, 5, 6]);

            Assert.Equal(FileSignature.None, CatalogSignature.Read(mine));
            Assert.Equal(FileSignature.None, CatalogSignature.Read(Path.Combine(folder, "missing.exe")));
            Assert.Equal(FileSignature.None, CatalogSignature.Read(folder));
        }
        finally
        {
            Directory.Delete(folder, recursive: true);
        }
    }
}
