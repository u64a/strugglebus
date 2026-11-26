using Xunit;

namespace StruggleBusMonitor.Tests;

public class AddHostLogicTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 24, 4, 2, 0, TimeSpan.Zero);
    private const string Key = "AAAAC3NzaC1lZDI1NTE5AAAAIGtleWtleWtleWtleWtleWtleWtleWtleWtleWtleWtleWtleWtl";
    private const string Namespaces = "namespaces=\"strugglebus-fleet,strugglebus-host-command\"";
    private static readonly string TwoSigners = $"owner {Namespaces} ssh-ed25519 {Key} key-a\r\n\r\n  backup {Namespaces} ssh-ed25519 {Key} key-b  \n";
    private static readonly Session Bus = new("https://bus.example.lan/", "credential", [1, 2, 3], "device-1", "office-laptop");

    private static AddHostForm Form(string name = "Office1") =>
        new(name, Claude: true, Copilot: true, Dedicated: true, TwoSigners, "https://github.com/acme/\n", "bus", "new worker host");

    [Theory]
    [InlineData("Office1", "host-office1")]
    [InlineData("  Lab PC 2 ", "host-lab-pc-2")]
    [InlineData("host-devbox", "host-devbox")]
    [InlineData("dev_box", "host-dev-box")]
    public void TheHostIsNamedFromThePc(string typed, string prefix) =>
        Assert.Equal(prefix, AddHostLogic.Prefix(typed));

    [Fact]
    public void TheNameBoxSaysWhatTheHostWillBeCalledOrWhatIsWrong()
    {
        Assert.Equal(NameFeedback.None, AddHostLogic.NameFeedback("  "));
        Assert.Equal(new NameFeedback("It will join the bus as host-office1", false), AddHostLogic.NameFeedback("Office1"));
        Assert.True(AddHostLogic.NameFeedback("office.1").IsProblem);
        var tooLong = AddHostLogic.NameFeedback(new string('a', 27));
        Assert.True(tooLong.IsProblem);
        Assert.Contains("32 characters and the limit is 31", tooLong.Text);
        Assert.False(AddHostLogic.NameFeedback(new string('a', 26)).IsProblem);
    }

    [Fact]
    public void LinesAndEnginesAreReadFromTheForm()
    {
        Assert.Equal(2, AddHostLogic.Lines(TwoSigners).Count);
        Assert.All(AddHostLogic.Lines(TwoSigners), line => Assert.Equal(line.Trim(), line));
        Assert.Empty(AddHostLogic.Lines(" \r\n \n"));
        Assert.Equal(["claude", "ghcp"], AddHostLogic.Engines(true, true));
        Assert.Equal(["ghcp"], AddHostLogic.Engines(false, true));
        Assert.Equal(["claude"], AddHostLogic.Engines(true, false));
        Assert.Empty(AddHostLogic.Engines(false, false));
    }

    [Fact]
    public void TheDataComesFromTheFormAndThisPcsEnrollment()
    {
        var data = AddHostLogic.Data(Form(), Bus, "CODE", Now);

        Assert.Equal(("office-laptop", "https://bus.example.lan", "host-office1", "CODE", true, "bus"),
            (data.Device, data.BusUrl, data.HostPrefix, data.EnrolCode, data.Dedicated, data.FleetSource));
        Assert.Equal(Bus.CaDer, data.CaDer);
        Assert.Equal(["https://github.com/acme/"], data.Remotes);
        Assert.Equal(2, data.Signers.Count);
        Assert.Equal(Now, data.WrittenAt);
    }

    [Fact]
    public void ACompleteFormHasNoProblem()
    {
        Assert.Null(AddHostLogic.Problem(Form(), Bus, hasGrant: true, Now));
        Assert.Null(HostEnrolFile.Problem(AddHostLogic.Data(Form(), Bus, AddHostLogic.PlaceholderCode, Now)));
    }

    public static TheoryData<string, AddHostForm, bool> Refused() => new()
    {
        { "Enter the PC's name.", Form("  "), true },
        { "lowercase letters, digits and hyphens", Form("office.1"), true },
        { "too long", Form(new string('a', 30)), true },
        { "Choose GitHub Copilot, Claude Code or both.", Form() with { Claude = false, Copilot = false }, true },
        { "two signers", Form() with { Signers = TwoSigners.Split('\n')[0] }, true },
        { "signer line", Form() with { Signers = "not a signer\nalso not" }, true },
        { "repository location", Form() with { Remotes = "" }, true },
        { "repository location", Form() with { Remotes = "https://github.com/acme" }, true },
        { "fleet source", Form() with { FleetSource = "ftp" }, true },
        { "Enter an audit reason.", Form() with { Reason = " " }, true },
        { "Save operator access", Form(), false }
    };

    [Theory]
    [MemberData(nameof(Refused))]
    public void WhatIsWrongIsSaidBeforeACodeIsAskedFor(string mentions, AddHostForm form, bool hasGrant) =>
        Assert.Contains(mentions, AddHostLogic.Problem(form, Bus, hasGrant, Now));

    [Fact]
    public void TheInstallerInTheAppIsTheWorkerHostsOwnFileByteForByte()
    {
        var source = File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "WorkerHost", "bootstrap.ps1"));

        var shipped = AddHostLogic.Bootstrap();

        Assert.Equal(source, shipped);
        Assert.NotEmpty(shipped);
        // It is stored with line feeds only; a checkout that changed that would change its hash.
        Assert.DoesNotContain((byte)'\r', shipped);
        Assert.Contains("-DataFile", System.Text.Encoding.ASCII.GetString(shipped));
    }

    [Fact]
    public void TheResultSaysWhatToCompareAndWhatToDoNext()
    {
        var data = AddHostLogic.Data(Form(), Bus, AddHostLogic.PlaceholderCode, Now);
        var file = HostEnrolFile.Render(data);

        var bootstrap = AddHostLogic.Bootstrap();
        var text = AddHostLogic.ResultText("sbhost-enrol.json", data, file, new HostInstaller(bootstrap), Now.AddMinutes(15), Now);

        Assert.StartsWith("Saved sbhost-enrol.json and bootstrap.ps1 for host-office1. Move both to the new PC.", text);
        Assert.Contains(@"Get-FileHash -Algorithm SHA256 .\bootstrap.ps1", text);
        Assert.Contains($"It must print:   {HostEnrolFile.Sha256(bootstrap)}", text);
        Assert.True(text.IndexOf("Get-FileHash", StringComparison.Ordinal) < text.IndexOf("powershell -ExecutionPolicy", StringComparison.Ordinal));
        Assert.Contains($"Data file digest:  {HostEnrolFile.Digest(file)}", text);
        Assert.Equal(2, text.Split("Signer:            SHA256:").Length - 1);
        Assert.Contains(@"powershell -ExecutionPolicy Bypass -File .\bootstrap.ps1 -DataFile .\sbhost-enrol.json", text);
        Assert.Contains("works once", text);
        Assert.DoesNotContain(AddHostLogic.PlaceholderCode, text);
        Assert.Equal("Create a one-time code for worker host host-office1", AddHostLogic.HelloPrompt("host-office1"));
    }

    [Fact]
    public void AFailedInstallerCheckIsTheFirstThingTheResultSays()
    {
        var data = AddHostLogic.Data(Form(), Bus, AddHostLogic.PlaceholderCode, Now);
        var file = HostEnrolFile.Render(data);
        var installer = new HostInstaller(AddHostLogic.Bootstrap(), Warning: HostInstallerLogic.FailedCheck);

        var text = AddHostLogic.ResultText("sbhost-enrol.json", data, file, installer, Now.AddMinutes(15), Now);

        Assert.StartsWith(HostInstallerLogic.FailedCheck, text);
        Assert.Contains("Saved sbhost-enrol.json and bootstrap.ps1", text);
        // The unsigned installer was saved, so its hash is what to check.
        Assert.Contains(HostEnrolFile.Sha256(installer.Bytes), text);
    }

    [Fact]
    public void ASignedInstallerIsCheckedByItsSignatureNotItsHash()
    {
        var data = AddHostLogic.Data(Form(), Bus, AddHostLogic.PlaceholderCode, Now);
        var installer = new HostInstaller(AddHostLogic.Bootstrap(), "3FF059FA28ED74ACB229CBA2E670CEA565015238");

        var text = AddHostLogic.ResultText("sbhost-enrol.json", data, HostEnrolFile.Render(data), installer, Now.AddMinutes(15), Now);

        Assert.StartsWith("Saved sbhost-enrol.json and bootstrap.ps1", text);
        Assert.Contains("Get-AuthenticodeSignature", text);
        Assert.Contains("3FF059FA28ED74ACB229CBA2E670CEA565015238", text);
        Assert.DoesNotContain("Get-FileHash", text);
    }
}
