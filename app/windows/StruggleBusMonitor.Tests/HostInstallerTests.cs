using System.Text;

namespace StruggleBusMonitor.Tests;

public sealed class HostInstallerTests : IDisposable
{
    private const string Ours = "3FF059FA28ED74ACB229CBA2E670CEA565015238";
    private const string Start = "\r\n# SIG # Begin signature block\r\n";
    private const string End = "# SIG # End signature block\r\n";
    private static readonly FileSignature OurSignature = new(true, Ours, "Open Source Developer", "Asseco Data Systems S.A.");
    private static readonly byte[] BuiltIn = Encoding.ASCII.GetBytes("Write-Output 'install'\n");

    private readonly string folder = Directory.CreateTempSubdirectory("sbm-installer-test-").FullName;

    public void Dispose() => Directory.Delete(folder, recursive: true);

    private static byte[] With(string after) => [.. BuiltIn, .. Encoding.ASCII.GetBytes(after)];

    private string Saved(byte[] bytes)
    {
        var path = Path.Combine(folder, $"{Guid.NewGuid():N}.ps1");
        File.WriteAllBytes(path, bytes);
        return path;
    }

    [Fact]
    public void WithNoSignedCopyTheBuiltInInstallerIsUsedWithoutFuss()
    {
        var installer = HostInstallerLogic.Pick(BuiltIn, Path.Combine(folder, "absent.ps1"), _ => throw new InvalidOperationException("nothing to read"));

        Assert.Same(BuiltIn, installer.Bytes);
        Assert.False(installer.Signed);
        Assert.Null(installer.Warning);
    }

    [Fact]
    public void ASignedCopyThatPassesIsUsed()
    {
        var signed = With(Start + "# MIIabc\r\n" + End);

        var installer = HostInstallerLogic.Pick(BuiltIn, Saved(signed), _ => OurSignature);

        Assert.Equal(signed, installer.Bytes);
        Assert.True(installer.Signed);
        Assert.Equal(Ours, installer.Thumbprint);
        Assert.Null(installer.Warning);
    }

    public static TheoryData<string, string> NotOneBlockAfterTheBuiltIn() => new()
    {
        { "no block at all", "" },
        { "something between the installer and the block", "Remove-Item C:\\ -Recurse" + Start + "# x\r\n" + End },
        { "something after the block", Start + "# x\r\n" + End + "Remove-Item C:\\ -Recurse\r\n" },
        { "two blocks", Start + "# x\r\n" + End + Start + "# y\r\n" + End },
        { "a second start inside", Start + "# SIG # Begin signature block\r\n" + End },
        { "a block that never ends", Start + "# x\r\n" }
    };

    [Theory]
    [MemberData(nameof(NotOneBlockAfterTheBuiltIn))]
    public void ACopyThatIsNotTheBuiltInInstallerPlusOneBlockIsRefusedLoudly(string why, string after)
    {
        // Windows is not even asked: the shape is wrong whatever the signature says.
        var installer = HostInstallerLogic.Pick(BuiltIn, Saved(With(after)), _ => throw new InvalidOperationException(why));

        Assert.Same(BuiltIn, installer.Bytes);
        Assert.False(installer.Signed);
        Assert.Equal(HostInstallerLogic.FailedCheck, installer.Warning);
    }

    [Fact]
    public void ACopyOfADifferentInstallerIsRefusedEvenIfItIsSigned()
    {
        var other = Encoding.ASCII.GetBytes("Write-Output 'something else'\n" + Start + "# x\r\n" + End);

        var installer = HostInstallerLogic.Pick(BuiltIn, Saved(other), _ => OurSignature);

        Assert.Same(BuiltIn, installer.Bytes);
        Assert.Equal(HostInstallerLogic.FailedCheck, installer.Warning);
    }

    [Fact]
    public void ARightlyShapedCopySignedBySomeoneElseOrNotValidlyIsRefused()
    {
        var path = Saved(With(Start + "# x\r\n" + End));

        Assert.Equal(HostInstallerLogic.FailedCheck, HostInstallerLogic.Pick(BuiltIn, path, _ => FileSignature.None).Warning);
        Assert.Equal(HostInstallerLogic.FailedCheck,
            HostInstallerLogic.Pick(BuiltIn, path, _ => new FileSignature(true, "BB", "Open Source Developer", "Asseco Data Systems S.A.")).Warning);
    }

    [Fact]
    public void ARealSignedInstallerPassesAgainstItsOwnUnsignedBytesAndFailsOnceChanged()
    {
        // The worker host's installer, signed with the project's real certificate by
        // worker-host/tools/sign-bootstrap.ps1 and kept as a fixture. Its unsigned bytes are
        // whatever comes before the signature block.
        var real = Path.Combine(AppContext.BaseDirectory, "Contracts", "app-update", "bootstrap-signed.ps1");
        var signed = File.ReadAllBytes(real);
        var unsigned = signed[..signed.AsSpan().IndexOf(Encoding.ASCII.GetBytes(Start))];
        var changed = (byte[])signed.Clone();
        changed[10] ^= 1;

        var good = HostInstallerLogic.Pick(unsigned, real, Authenticode.Read);
        var tampered = HostInstallerLogic.Pick(changed[..unsigned.Length], Saved(changed), Authenticode.Read);

        Assert.True(good.Signed);
        Assert.Equal(Ours, good.Thumbprint);
        Assert.Equal(signed, good.Bytes);
        Assert.Equal(HostInstallerLogic.FailedCheck, tampered.Warning);
    }

    [Fact]
    public void TheCheckToRunOnTheNewPcMatchesTheInstallerHandedOver()
    {
        var unsigned = AddHostLogic.InstallerCheck(new HostInstaller(BuiltIn));
        var signed = AddHostLogic.InstallerCheck(new HostInstaller(BuiltIn, Ours));

        Assert.Contains("Get-FileHash -Algorithm SHA256", unsigned[0]);
        Assert.Contains(HostEnrolFile.Sha256(BuiltIn), unsigned[1]);
        Assert.Contains($"$s.Status -eq 'Valid' -and $s.SignerCertificate.Thumbprint -eq '{Ours}'", signed[0]);
        Assert.DoesNotContain("Get-FileHash", signed[0]);
        Assert.Contains("True", signed[1]);
    }

    [Fact]
    public void TheSignedCopyIsLookedForBesideTheApp() =>
        Assert.Equal(Path.Combine(AppContext.BaseDirectory, "bootstrap.ps1"), HostInstallerLogic.SignedPath);
}
