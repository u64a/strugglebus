using System.IO;
using System.Text;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;

namespace StruggleBusMonitor.Tests;

/// <summary>The rules for asking a hardware key to sign a fleet from inside the app.</summary>
public sealed class FleetSignLogicTests
{
    private static readonly byte[] Key = SshSignatureMaker.Key();
    private static readonly IReadOnlyList<SiteSigner> Held =
        FleetPublishLogic.Signers(SshSignatureMaker.SignerLine(Key) + "\n" + SshSignatureMaker.SignerLine(SshSignatureMaker.Key(seed: 2)));

    private static byte[] Bytes(string text) => new UTF8Encoding(false).GetBytes(text);

    [Fact]
    public void TheAppOnlyEverSignsForTheFleetNamespace()
    {
        Assert.Equal("strugglebus-fleet", FleetSignLogic.Namespace);
        Assert.Same(FleetPublishLogic.Namespace, FleetSignLogic.Namespace);
    }

    [Fact]
    public void AFleetDocumentPassesAndGivesItsSerial() =>
        Assert.Equal(7, FleetSignLogic.RequireFleet(Bytes("serial = 7\nowner = \"Alex\"\n\n[[host]]\nagent_name = \"host-a-host\"\nagent_id = \"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa\"\n")));

    [Fact]
    public void AWorkerHostReleaseFileIsRefusedBeforeAnyKeyIsAsked()
    {
        var release = Bytes("serial = 13\nversion = \"2026.11.28.3\"\ntree_sha256 = \"a475f578\"\ninstaller_sha256 = \"30213d63\"\nbootstrap_sha256 = \"aec825a9\"\n");

        Assert.Equal(FleetRefusal.UnknownKey, Assert.Throws<FleetRefusedException>(() => FleetSignLogic.RequireFleet(release)).Reason);
    }

    [Fact]
    public void ABusReleaseStatementIsRefusedBeforeAnyKeyIsAsked()
    {
        var statement = Bytes("strugglebus-bus-release 1\nversion 0.2.74\n2f4fc12cc9b9de7adb91dffc95f753f3b34bd1cd964fad45dd564fc82fb38f10  SHA256SUMS\n");

        Assert.Equal(FleetRefusal.SerialLine, Assert.Throws<FleetRefusedException>(() => FleetSignLogic.RequireFleet(statement)).Reason);
    }

    [Theory]
    [InlineData("")]
    [InlineData("\uFEFFserial = 1\n")]
    [InlineData("serial = 1\r\n")]
    public void BytesHostsWouldRefuseAreNotSigned(string text) =>
        Assert.EndsWith("so it is not signed.", Assert.Throws<InvalidOperationException>(() => FleetSignLogic.RequireFleet(Bytes(text))).Message);

    [Theory]
    [InlineData("strugglebus-release")]
    [InlineData("strugglebus-bus-release")]
    [InlineData("strugglebus-host-command")]
    public void ASignatureMadeForAnyOtherNamespaceIsNeverAccepted(string purpose)
    {
        var body = Bytes("serial = 7\n");

        var error = Assert.Throws<InvalidOperationException>(() => FleetPublishLogic.Check(body, SshSignatureMaker.File(Key, purpose: purpose), Held));

        Assert.Equal(FleetPublishLogic.WrongPurpose, error.Message);
    }

    [Fact]
    public void TheKeyFileIsTheOneBesideThePublicFile()
    {
        Assert.Equal(@"C:\k\id_sk_a", FleetSignLogic.KeyFileBeside(@"C:\k\id_sk_a.pub", _ => true));
        Assert.Equal(@"C:\k\id_sk_a", FleetSignLogic.KeyFileBeside(@"C:\k\id_sk_a.PUB", _ => true));
        Assert.Null(FleetSignLogic.KeyFileBeside(@"C:\k\id_sk_a.pub", _ => false));
        Assert.Null(FleetSignLogic.KeyFileBeside(@"C:\k\id_sk_a.txt", _ => true));
    }

    [Fact]
    public void TheKeyToSignWithIsTheChosenOneOrTheFirstWhoseFileIsHere()
    {
        var files = new Dictionary<string, string> { [Held[0].KeyBase64] = "a", [Held[1].KeyBase64] = "b" };

        Assert.Equal("a", FleetSignLogic.KeyToUse(Held, files, null, _ => true)!.KeyFile);
        Assert.Equal("b", FleetSignLogic.KeyToUse(Held, files, Held[1].KeyBase64, _ => true)!.KeyFile);
        Assert.Equal("a", FleetSignLogic.KeyToUse(Held, files, Held[1].KeyBase64, file => file == "a")!.KeyFile);
        Assert.Equal("a", FleetSignLogic.KeyToUse(Held, files, "a key that is not held", _ => true)!.KeyFile);
        Assert.Null(FleetSignLogic.KeyToUse(Held, files, null, _ => false));
        Assert.Null(FleetSignLogic.KeyToUse(Held, new Dictionary<string, string>(), null, _ => true));
        Assert.Null(FleetSignLogic.KeyToUse([], files, null, _ => true));
    }

    [Fact]
    public void WhatIsReadBeforeTheTouchNamesTheSerialTheChangeAndAHashOfTheExactBytes()
    {
        var document = Bytes("serial = 7\n");
        var key = new SigningKey(Held[0], @"C:\k\id_sk_a");

        var text = FleetSignLogic.TouchText(7, FleetSignLogic.AddsHost("host-office2-host"), document, key);

        Assert.StartsWith("Sign fleet serial 7 with your hardware key?", text);
        Assert.Contains("Change:   adds worker host host-office2-host", text);
        Assert.Contains($"SHA-256:  {FleetSignLogic.ShortHash(document)} ...  (11 bytes)", text);
        Assert.Contains($"Key:      {Held[0].Fingerprint}", text);
        Assert.Contains("never a software release", text);
        Assert.Matches("^[0-9a-f]{4} [0-9a-f]{4} [0-9a-f]{4} [0-9a-f]{4}$", FleetSignLogic.ShortHash(document));
        Assert.NotEqual(FleetSignLogic.ShortHash(document), FleetSignLogic.ShortHash(Bytes("serial = 8\n")));
    }

    [Fact]
    public void AFailedSigningSaysWhichKeyWasAskedForAndWhatTheToolSaid()
    {
        var key = new SigningKey(Held[0], @"C:\k\id_sk_a");

        Assert.Equal($"{FleetSignLogic.NotSigned} {Held[0].Fingerprint} (id_sk_a).", FleetSignLogic.NotSignedText(key, "  "));
        Assert.EndsWith("ssh-keygen said: device not found", FleetSignLogic.NotSignedText(key, "device not found\r\n"));
        Assert.True(FleetSignLogic.NotSignedText(key, new string('x', 2000)).Length < 800);
        Assert.Equal(256, FleetSignLogic.SignedReason(7, new string('x', 500)).Length);
        Assert.Equal("Signed and published in the Windows app: fleet serial 7, adds worker host a", FleetSignLogic.SignedReason(7, FleetSignLogic.AddsHost("a")));
    }
}

/// <summary>Finding and running ssh-keygen for signing.</summary>
public sealed class SshKeygenSigningTests
{
    private static readonly FileSignature Microsoft = new(true, "T", "Microsoft Corporation", "Microsoft Corporation");

    [Fact]
    public void TheToolIsTheFirstMicrosoftSignedOneAndNeverAnythingElse()
    {
        string[] candidates = ["first", "second"];

        Assert.Equal("first", SshKeygen.SigningTool(candidates, _ => true, _ => Microsoft));
        Assert.Equal("second", SshKeygen.SigningTool(candidates, path => path == "second", _ => Microsoft));
        Assert.Equal("second", SshKeygen.SigningTool(candidates, _ => true, path => path == "first" ? new FileSignature(true, "T", "Someone Else", "Microsoft Corporation") : Microsoft));
        Assert.Null(SshKeygen.SigningTool(candidates, _ => true, _ => FileSignature.None));
        Assert.Null(SshKeygen.SigningTool(candidates, _ => false, _ => Microsoft));
    }

    [Fact]
    public void ThisPcsToolIsUnderProgramFilesOrWindowsAndSignedByMicrosoft()
    {
        var tool = SshKeygen.SigningTool();

        Assert.NotNull(tool);
        Assert.True(Path.IsPathFullyQualified(tool));
        Assert.EndsWith(@"OpenSSH\ssh-keygen.exe", tool);
        Assert.True(UpdateTrust.IsMicrosoft(Authenticode.Read(tool)));
    }

    [Theory]
    [InlineData("strugglebus-release")]
    [InlineData("strugglebus-bus-release")]
    [InlineData("strugglebus-baseline")]
    [InlineData("strugglebus-fleet ")]
    [InlineData("STRUGGLEBUS-FLEET")]
    [InlineData("file")]
    [InlineData("")]
    public async Task TheLowestLayerRefusesToAskAKeyToSignForAnythingButTheFleetAndHostCommands(string purpose)
    {
        var before = Directory.GetDirectories(Path.GetTempPath(), "strugglebus-sign-*").Length;

        // The tool path does not exist: the refusal comes before anything is started or written.
        var error = await Assert.ThrowsAsync<InvalidOperationException>(
            () => SshKeygen.SignAsync(@"C:\no\such\ssh-keygen.exe", @"C:\no\such\key", purpose, "serial = 1\n"u8.ToArray(), TimeSpan.FromSeconds(5)));

        Assert.Contains("never asks a hardware key to sign for", error.Message);
        Assert.Equal(before, Directory.GetDirectories(Path.GetTempPath(), "strugglebus-sign-*").Length);
    }

    [Fact]
    public void OnlyTheFleetAndHostCommandNamespacesCanBeSigned()
    {
        Assert.Equal(["strugglebus-fleet", "strugglebus-host-command"], SshKeygen.SignablePurposes);
        Assert.Contains(FleetSignLogic.Namespace, SshKeygen.SignablePurposes);
        SshKeygen.RequireSignablePurpose("strugglebus-fleet");
        SshKeygen.RequireSignablePurpose("strugglebus-host-command");
    }

    [Fact]
    public async Task AToolThatDoesNotSignIsAFailureWithWhatItSaidAndLeavesNothingBehind()
    {
        var before = Directory.GetDirectories(Path.GetTempPath(), "strugglebus-sign-*").Length;
        var missingKey = Path.Combine(Path.GetTempPath(), "no-such-key-" + Guid.NewGuid().ToString("N"));

        var error = await Assert.ThrowsAsync<SshSigningException>(
            () => SshKeygen.SignAsync(SshKeygen.DefaultPath, missingKey, FleetSignLogic.Namespace, "serial = 1\n"u8.ToArray(), TimeSpan.FromSeconds(30)));

        Assert.NotEqual(string.Empty, error.Message);
        Assert.Equal(before, Directory.GetDirectories(Path.GetTempPath(), "strugglebus-sign-*").Length);
    }
}

/// <summary>Adding a host with the app asking the hardware key to sign: one journey to a published fleet.</summary>
[Collection(StaWindowAdminCollection.Name)]
public sealed class FleetSignWindowTests(StaWindowAdminFixture sta)
{
    private const string AgentId = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
    private const string FleetRoute = "GET /api/mobile/site-documents/fleet";
    private const string PublishRoute = "POST /api/mobile/site-documents/fleet";
    private const string KeyFile = @"C:\keys\id_ed25519_sk_test";
    private static readonly byte[] Key = SshSignatureMaker.Key();
    private static readonly string KeyText = Convert.ToBase64String(Key);
    private static readonly string Vectors = Path.Combine(AppContext.BaseDirectory, "Contracts", "fleet", "compose");
    private static readonly byte[] After = File.ReadAllBytes(Path.Combine(Vectors, "after.toml"));

    private static readonly string Agents =
        $$"""[{"id":"{{AgentId}}","name":"host-office2-host","description":"","host":"office2","last_seen_at":null}]""";

    private const string Principals =
        """[{"id":"sp1","name":"host-office2","agent_name_prefix":"host-office2","status":"enabled","version":3,"actions":[],"host_redeem_request_id":"11111111-2222-4333-8444-555555555555","host_redeemed_from":"192.168.1.20"}]""";

    private static string Stored(byte[] body, long serial) => JsonSerializer.Serialize(new
    {
        name = "fleet", serial, body = Convert.ToBase64String(body), signature = SshSignatureMaker.File(Key), signer_fingerprint = "SHA256:x", stored_at = "2030-01-02T03:04:05Z"
    });

    /// <summary>Admin, Worker hosts, with a host waiting, a fleet on the bus, and a signer whose key file is on this PC.</summary>
    private static StaWindowAdminScene Open(bool keyFileHere = true)
    {
        var scene = new StaWindowAdminScene().WithSettings(settings => settings.SignerKeyFiles[KeyText] = KeyFile).Enroll();
        try
        {
            var bus = scene.Bus;
            bus.AgentsJson = Agents;
            bus.On("GET /api/mobile/admin/agents", _ => StaWindowAdminBus.Ok("[]"));
            bus.On("GET /api/mobile/admin/devices", _ => StaWindowAdminBus.Ok("[]"));
            bus.On("GET /api/mobile/admin/service-principals", _ => StaWindowAdminBus.Ok(Principals));
            bus.On(FleetRoute, _ => StaWindowAdminBus.Ok(Stored(File.ReadAllBytes(Path.Combine(Vectors, "before.toml")), 5)));
            bus.On(PublishRoute, _ => StaWindowAdminBus.Ok(Stored(After, 6)));
            if (keyFileHere) scene.Platform.KeyFiles.Add(KeyFile);
            scene.Platform.HardwareKey = _ => SshSignatureMaker.File(Key);
            scene.Open();
            scene.Window.HostSigners.Text = SshSignatureMaker.SignerLine(Key);
            scene.Window.AdminNav.IsChecked = true;
            scene.Window.AdminTabHosts.IsChecked = true;
            StaWindowAdminScene.Until(() => scene.Window.AdminHostsSummary.Text.Length > 0, "the worker hosts");
            return scene;
        }
        catch
        {
            scene.Dispose();
            throw;
        }
    }

    private static void Press(StaWindowAdminScene scene)
    {
        var window = scene.Window;
        window.FleetResultPanel.Visibility = Visibility.Collapsed;
        var row = ((IEnumerable<HostRow>)window.AdminHostList.ItemsSource).Single();
        window.HostJoin_Click(new Button { Tag = row }, new RoutedEventArgs());
        StaWindowAdminScene.Until(() => window.FleetResultPanel.Visibility == Visibility.Visible || scene.Notice.Length > 0, "the outcome");
    }

    [Fact]
    public void CompareThenTouchThenWindowsHelloPublishesTheNewFleet() => sta.Run(() =>
    {
        using var scene = Open();

        Press(scene);

        Assert.Equal([FleetJoinLogic.CompareCaption, "Sign the fleet"], scene.Platform.Confirmations.Select(asked => asked.Item2));
        var touch = scene.Platform.Confirmations[1].Item1;
        Assert.Contains("Sign fleet serial 6 with your hardware key?", touch);
        Assert.Contains("Change:   adds worker host host-office2-host", touch);
        Assert.Contains(FleetSignLogic.ShortHash(After), touch);

        var signed = Assert.Single(scene.Platform.Signed);
        Assert.Equal((scene.Platform.HardwareSigningTool, KeyFile, "strugglebus-fleet"), (signed.Tool, signed.KeyFile, signed.Purpose));
        Assert.Equal(After, signed.Document);

        var sent = JsonDocument.Parse(Assert.Single(scene.Bus.RequestsTo(PublishRoute)).Body).RootElement;
        Assert.Equal(6, sent.GetProperty("serial").GetInt64());
        Assert.Equal(Convert.ToBase64String(After), sent.GetProperty("body").GetString());
        Assert.Equal(SshSignatureMaker.File(Key), sent.GetProperty("signature").GetString());
        Assert.Equal("Signed and published in the Windows app: fleet serial 6, adds worker host host-office2-host", sent.GetProperty("reason").GetString());
        Assert.Contains(FleetPublishLogic.HelloPrompt(6), scene.Platform.HelloPrompts);
        Assert.Equal(2, scene.Platform.Verified.Count);
        Assert.StartsWith("Published fleet serial 6 at ", scene.Window.FleetResult.Text);
        Assert.Contains("adds worker host host-office2-host. Signed in this app with SHA256:", scene.Window.FleetResult.Text);
        Assert.Equal(string.Empty, scene.Notice);
    });

    [Fact]
    public void SayingNoBeforeTheTouchAsksTheKeyForNothing() => sta.Run(() =>
    {
        using var scene = Open();
        scene.Platform.ConfirmAnswers.Enqueue(true);
        scene.Platform.ConfirmAnswers.Enqueue(false);

        Press(scene);

        Assert.Empty(scene.Platform.Signed);
        Assert.Empty(scene.Bus.RequestsTo(PublishRoute));
        Assert.Equal(FleetJoinLogic.NothingChanged, scene.Window.FleetResult.Text);
    });

    [Fact]
    public void AKeyThatDoesNotSignOrAFileThatChangedPublishesNothing() => sta.Run(() =>
    {
        using (var scene = Open())
        {
            scene.Platform.SigningFailure = new SshSigningException("device not found");
            Press(scene);
            Assert.StartsWith(FleetSignLogic.NotSigned, scene.Notice);
            Assert.EndsWith("ssh-keygen said: device not found", scene.Notice);
            Assert.Empty(scene.Bus.RequestsTo(PublishRoute));
        }

        using var changed = Open();
        changed.Platform.SigningFailure = new InvalidDataException();
        Press(changed);
        Assert.Equal(FleetSignLogic.Changed, changed.Notice);
        Assert.Empty(changed.Bus.RequestsTo(PublishRoute));
    });

    [Fact]
    public void ASignatureWithoutThePinOrThatDoesNotVerifyIsNotPublished() => sta.Run(() =>
    {
        using (var scene = Open())
        {
            scene.Platform.HardwareKey = _ => SshSignatureMaker.File(Key, flags: 0x01);
            Press(scene);
            Assert.Equal(FleetPublishLogic.NoTouchAndPin, scene.Notice);
            Assert.Empty(scene.Bus.RequestsTo(PublishRoute));
            Assert.DoesNotContain(FleetPublishLogic.HelloPrompt(6), scene.Platform.HelloPrompts);
        }

        using var forged = Open();
        forged.Platform.HardwareKey = _ =>
        {
            forged.Platform.Verdict = SshVerdict.Bad;
            return SshSignatureMaker.File(Key);
        };
        Press(forged);
        Assert.Equal(FleetPublishLogic.BadSignature, forged.Notice);
        Assert.Empty(forged.Bus.RequestsTo(PublishRoute));
    });

    [Fact]
    public void WithoutAMicrosoftSignedSshKeygenTheKeyIsNotAsked() => sta.Run(() =>
    {
        using var scene = Open();
        scene.Platform.HardwareSigningTool = null;

        Press(scene);

        Assert.Equal(FleetSignLogic.NoTool, scene.Notice);
        Assert.Empty(scene.Platform.Signed);
    });

    [Fact]
    public void WithNoKeyFileOnThisPcTheDocumentIsSavedForSigningElsewhereAsBefore() => sta.Run(() =>
    {
        var folder = Directory.CreateTempSubdirectory("fleet-sign-test-").FullName;
        try
        {
            using var scene = Open(keyFileHere: false);
            scene.Platform.FleetSavePath = Path.Combine(folder, "fleet.toml");

            Press(scene);

            Assert.Empty(scene.Platform.Signed);
            Assert.Equal(After, File.ReadAllBytes(scene.Platform.FleetSavePath));
            Assert.StartsWith("The app cannot sign on this PC yet", scene.Window.SigningKeyText.Text);
        }
        finally
        {
            Directory.Delete(folder, recursive: true);
        }
    });

    [Fact]
    public void AddingAKeyRemembersItsKeyFileAndTheOperatorCanChooseWhichKeySigns() => sta.Run(() =>
    {
        var folder = Directory.CreateTempSubdirectory("fleet-sign-test-").FullName;
        try
        {
            using var scene = new StaWindowAdminScene().Enroll().Open();
            var window = scene.Window;
            foreach (var seed in new byte[] { 1, 2 })
            {
                var name = Path.Combine(folder, $"id_sk_{seed}");
                File.WriteAllText(name, "a key handle");
                File.WriteAllText(name + ".pub", $"sk-ssh-ed25519@openssh.com {Convert.ToBase64String(SshSignatureMaker.Key(seed: seed))}\n");
                scene.Platform.PublicKeyPath = name + ".pub";
                StaWindowAdminScene.ClickAndWait(window.SignerAddButton);
            }

            var signers = ((IEnumerable<SiteSigner>)window.SignersList.ItemsSource).ToList();
            Assert.Equal(Path.Combine(folder, "id_sk_1"), AppSettings.Load().SignerKeyFiles[signers[0].KeyBase64]);
            Assert.Contains($"signs the fleet with {signers[0].Fingerprint} (id_sk_1)", window.SigningKeyText.Text);

            window.SignerUse_Click(new Button { Tag = "not a signer" }, new RoutedEventArgs());
            window.SignerUse_Click(new Button { Tag = signers[1] }, new RoutedEventArgs());

            Assert.Equal(signers[1].KeyBase64, AppSettings.Load().SigningKey);
            Assert.Contains($"signs the fleet with {signers[1].Fingerprint} (id_sk_2)", window.SigningKeyText.Text);
        }
        finally
        {
            Directory.Delete(folder, recursive: true);
        }
    });
}
