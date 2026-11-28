using System.IO;
using System.Text;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;

namespace StruggleBusMonitor.Tests;

/// <summary>Setting up a new key on a security key: what the tool is asked, and what is refused before it is asked anything.</summary>
public sealed class NewKeyTests
{
    [Theory]
    [InlineData("A")]
    [InlineData("spare")]
    [InlineData("desk-2")]
    [InlineData("abcdefghijklmnopqrstuvwx")]
    public void AShortPlainNameIsAccepted(string name) => Assert.Null(NewKeyLogic.NameProblem(name));

    [Theory]
    [InlineData("")]
    [InlineData("-a")]
    [InlineData("two words")]
    [InlineData("a/b")]
    [InlineData(@"..\x")]
    [InlineData("a.pub")]
    [InlineData("abcdefghijklmnopqrstuvwxy")]
    [InlineData("a\n")]
    public void ANameThatCouldBeAPathOrAnOptionIsRefused(string name) => Assert.Equal(NewKeyLogic.NameNeeded, NewKeyLogic.NameProblem(name));

    /// <summary>The exact command agreed with security: on the key, resident, PIN every time, the project's application, no passphrase.</summary>
    [Fact]
    public void TheToolIsAskedForAResidentKeyThatNeedsItsPinEveryTime()
    {
        Assert.Equal(
            ["-t", "ed25519-sk", "-O", "resident", "-O", "verify-required", "-O", "application=ssh:strugglebus-signing", "-O", "user=spare", "-N", "", "-C", "strugglebus-spare", "-f", @"C:\u\.ssh\id_ed25519_sk_strugglebus_spare"],
            NewKeyLogic.Arguments("spare", @"C:\u\.ssh\id_ed25519_sk_strugglebus_spare"));
    }

    [Fact]
    public async Task AKeyIsMadeInTheFolderUnderTheAppsOwnNameAndItsPublicFileComesBack()
    {
        var folder = Path.Combine(Path.GetTempPath(), "new-key-test-" + Guid.NewGuid().ToString("N"), ".ssh");
        try
        {
            string[]? asked = null;
            var made = await SshKeygen.CreateKeyAsync(folder, "spare", arguments =>
            {
                asked = arguments;
                File.WriteAllText(arguments[^1] + ".pub", "sk-ssh-ed25519@openssh.com AAAA\n");
                return Task.FromResult((0, string.Empty));
            });

            Assert.Equal(Path.Combine(folder, "id_ed25519_sk_strugglebus_spare.pub"), made);
            Assert.Equal(NewKeyLogic.Arguments("spare", Path.Combine(folder, "id_ed25519_sk_strugglebus_spare")), asked);
        }
        finally
        {
            Directory.Delete(Path.GetDirectoryName(folder)!, recursive: true);
        }
    }

    [Theory]
    [InlineData("id_ed25519_sk_strugglebus_spare")]
    [InlineData("id_ed25519_sk_strugglebus_spare.pub")]
    public async Task AnExistingKeyFileIsNeverOverwrittenAndTheToolIsNotStarted(string existing)
    {
        var folder = Directory.CreateTempSubdirectory("new-key-test-").FullName;
        try
        {
            File.WriteAllText(Path.Combine(folder, existing), "mine");
            var started = false;

            var error = await Assert.ThrowsAsync<InvalidOperationException>(() => SshKeygen.CreateKeyAsync(folder, "spare", _ =>
            {
                started = true;
                return Task.FromResult((0, string.Empty));
            }));

            Assert.Equal(NewKeyLogic.Exists("id_ed25519_sk_strugglebus_spare"), error.Message);
            Assert.False(started);
            Assert.Equal("mine", File.ReadAllText(Path.Combine(folder, existing)));
        }
        finally
        {
            Directory.Delete(folder, recursive: true);
        }
    }

    [Fact]
    public async Task ABadNameNeverReachesTheTool()
    {
        var error = await Assert.ThrowsAsync<InvalidOperationException>(
            () => SshKeygen.CreateKeyAsync(Path.GetTempPath(), @"..\x", _ => throw new InvalidOperationException("started")));

        Assert.Equal(NewKeyLogic.NameNeeded, error.Message);
    }

    [Theory]
    [InlineData(1, "Key enrollment failed: invalid format", false)]
    [InlineData(0, "", false)]
    public async Task AToolThatMakesNoKeyIsAFailureWithWhatItSaid(int exit, string said, bool writes)
    {
        var folder = Directory.CreateTempSubdirectory("new-key-test-").FullName;
        try
        {
            var error = await Assert.ThrowsAsync<SshSigningException>(() => SshKeygen.CreateKeyAsync(folder, "spare", arguments =>
            {
                if (writes) File.WriteAllText(arguments[^1] + ".pub", "x");
                return Task.FromResult((exit, said));
            }));

            Assert.Equal(said, error.Message);
            Assert.Contains(said.Length == 0 ? "stopped without saying why" : "ssh-keygen said: " + said, NewKeyLogic.Failed(error.Message));
            Assert.Contains("has no PIN yet", NewKeyLogic.Failed(error.Message));
        }
        finally
        {
            Directory.Delete(folder, recursive: true);
        }
    }

    [Fact]
    public async Task TheRealToolIsNeverStartedForANameAlreadyTaken()
    {
        var folder = Directory.CreateTempSubdirectory("new-key-test-").FullName;
        try
        {
            File.WriteAllText(Path.Combine(folder, "id_ed25519_sk_strugglebus_A"), "mine");

            await Assert.ThrowsAsync<InvalidOperationException>(() => SshKeygen.CreateKeyAsync(@"C:\no\such\ssh-keygen.exe", folder, "A", TimeSpan.FromSeconds(5)));
        }
        finally
        {
            Directory.Delete(folder, recursive: true);
        }
    }
}

/// <summary>The checklist: each step done or not from what the app already knows.</summary>
public sealed class SetupChecklistTests
{
    private static IReadOnlyList<SetupItem> Items(int signers = 0, bool remotes = false, bool fleet = false, int hosts = 0, int agents = 0) =>
        SetupChecklistLogic.Items(new SetupFacts(signers, remotes, fleet, hosts, agents));

    [Fact]
    public void ANewlyEnrolledPcHasOneStepDoneAndIsPointedAtItsKeys()
    {
        var items = Items();

        Assert.Equal([true, false, false, false, false, false], items.Select(item => item.Done));
        Assert.Equal(["", "security", "addhost", "fleet", "addhost", "fleet"], items.Select(item => item.Tab));
        Assert.Equal("1 of 6 done. Next: register two hardware keys. This card goes away when every step is done.", SetupChecklistLogic.Summary(items));
        Assert.False(SetupChecklistLogic.AllDone(items));
        Assert.Equal(Visibility.Collapsed, items[0].ActionVisibility);
        Assert.Equal(Visibility.Visible, items[1].ActionVisibility);
        Assert.Equal("✓", items[0].Mark);
        Assert.Equal("○", items[1].Mark);
        Assert.Equal("Go there", items[1].Action);
    }

    [Fact]
    public void OneKeyIsNotEnoughAndTwoAre()
    {
        Assert.False(Items(signers: 1)[1].Done);
        Assert.StartsWith("One is registered. Add a second", Items(signers: 1)[1].Detail);
        Assert.True(Items(signers: 2)[1].Done);
        Assert.Equal("3 are registered.", Items(signers: 3)[1].Detail);
    }

    [Fact]
    public void EachStepIsDoneFromItsOwnFact()
    {
        var items = Items(signers: 2, remotes: true, fleet: true, hosts: 1, agents: 2);

        Assert.True(SetupChecklistLogic.AllDone(items));
        Assert.All(items, item => Assert.Equal(Visibility.Collapsed, item.ActionVisibility));
        Assert.Equal("The fleet lists 1 worker host.", items[4].Detail);
        Assert.Equal("2 agents may task the hosts.", items[5].Detail);
        Assert.Equal("The fleet lists 2 worker hosts.", Items(hosts: 2)[4].Detail);
        Assert.Equal("1 agent may task the hosts.", Items(agents: 1)[5].Detail);
        Assert.Equal("2 of 6 done. Next: say where the site's repositories are. This card goes away when every step is done.", SetupChecklistLogic.Summary(Items(signers: 2)));
    }
}

[Collection(StaWindowAdminCollection.Name)]
public sealed class NewKeyAndSetupWindowTests(StaWindowAdminFixture sta)
{
    private const string FleetRoute = "GET /api/mobile/site-documents/fleet";
    private static readonly byte[] Key = SshSignatureMaker.Key();
    private static readonly string KeyA = Convert.ToBase64String(Key);
    private static readonly string LineA = SiteSignersLogic.LineFor("sk-ssh-ed25519@openssh.com " + Convert.ToBase64String(Key));
    private static readonly string Vectors = Path.Combine(AppContext.BaseDirectory, "Contracts", "fleet", "compose");

    private static List<SetupItem> Checklist(MainWindow window) => ((IEnumerable<SetupItem>)window.SetupList.ItemsSource).ToList();

    private static StaWindowAdminScene Open(byte[]? fleet, Action<StaWindowAdminScene>? before = null)
    {
        var scene = new StaWindowAdminScene().Enroll();
        try
        {
            scene.Bus.On(FleetRoute, _ => fleet is null
                ? StaWindowAdminBus.Fail(404, "Not found.")
                : StaWindowAdminBus.Ok(JsonSerializer.Serialize(new
                {
                    name = "fleet", serial = 7, body = Convert.ToBase64String(fleet), signature = SshSignatureMaker.File(Key), signer_fingerprint = "SHA256:x", stored_at = "2030-01-02T03:04:05Z"
                })));
            before?.Invoke(scene);
            scene.Open();
            scene.Window.AdminNav.IsChecked = true;
            return scene;
        }
        catch
        {
            scene.Dispose();
            throw;
        }
    }

    [Fact]
    public void ANewSiteSeesTheChecklistAndEachButtonOpensItsTab() => sta.Run(() =>
    {
        using var scene = Open(fleet: null);
        var window = scene.Window;
        StaWindowAdminScene.Until(() => window.SetupPanel.Visibility == Visibility.Visible, "the checklist");

        var items = Checklist(window);
        Assert.Equal([true, false, false, false, false, false], items.Select(item => item.Done));
        Assert.StartsWith("1 of 6 done. Next: register two hardware keys.", window.SetupText.Text);

        window.SetupGo_Click(new Button { Tag = "not a step" }, new RoutedEventArgs());
        Assert.True(window.AdminTabAgents.IsChecked);
        window.SetupGo_Click(new Button { Tag = items[1] }, new RoutedEventArgs());
        Assert.True(window.AdminTabSecurity.IsChecked);
        window.SetupGo_Click(new Button { Tag = items[2] }, new RoutedEventArgs());
        Assert.True(window.AdminTabAddHost.IsChecked);
        window.SetupGo_Click(new Button { Tag = items[3] }, new RoutedEventArgs());
        Assert.True(window.AdminTabFleet.IsChecked);

        // Entering the repository locations ticks that step at once, with nothing fetched.
        window.HostRemotes.Text = "https://github.com/acme/";
        window.HostRemotes_LostFocus(window.HostRemotes, new RoutedEventArgs());
        Assert.True(Checklist(window)[2].Done);
    });

    [Fact]
    public void ASiteThatIsSetUpNeverSeesTheChecklist() => sta.Run(() =>
    {
        var fleet = File.ReadAllBytes(Path.Combine(Vectors, "before.toml"));
        var rows = FleetAccessLogic.Rows(FleetCompose.Agents(Encoding.UTF8.GetString(fleet)));
        Assert.Contains(rows, row => row.Kind == "host");
        Assert.Contains(rows, row => row.Kind == "coordinator");
        var two = LineA + "\n" + SshSignatureMaker.SignerLine(SshSignatureMaker.Key(seed: 2));

        using var scene = Open(fleet, scene => scene.WithSettings(settings => settings.HostRemotes = "https://github.com/acme/"));
        var window = scene.Window;
        StaWindowAdminScene.Until(() => scene.Bus.RequestsTo(FleetRoute).Count > 0 && window.SetupList.ItemsSource is not null, "the fleet to be read");
        Assert.Equal(Visibility.Visible, window.SetupPanel.Visibility);
        Assert.StartsWith("5 of 6 done. Next: register two hardware keys.", window.SetupText.Text);

        window.HostSigners.Text = two;

        Assert.Equal(Visibility.Collapsed, window.SetupPanel.Visibility);
        Assert.Equal(string.Empty, window.SetupText.Text);
    });

    [Fact]
    public void AFleetTheAppCannotReadShowsNoChecklist() => sta.Run(() =>
    {
        using var scene = Open("not a fleet\n"u8.ToArray());
        var window = scene.Window;
        StaWindowAdminScene.Until(() => scene.Bus.RequestsTo(FleetRoute).Count > 0, "the fleet to be asked for");
        window.AdminTabFleet.IsChecked = true;
        StaWindowAdminScene.Until(() => window.FleetAccessSummary.Text.Length > 0, "the fleet card");

        Assert.Equal(Visibility.Collapsed, window.SetupPanel.Visibility);
    });

    [Fact]
    public void ANewKeyIsMadeThenAddedWithItsFingerprintAndWindowsHello() => sta.Run(() =>
    {
        var folder = Directory.CreateTempSubdirectory("new-key-window-").FullName;
        try
        {
            using var scene = Open(fleet: null);
            var window = scene.Window;
            window.AdminTabSecurity.IsChecked = true;
            scene.Platform.NewKey = name =>
            {
                Assert.Equal(NewKeyLogic.TouchText, window.NewKeyText.Text);
                File.WriteAllText(Path.Combine(folder, NewKeyLogic.FileName(name)), "a key handle");
                var publicFile = Path.Combine(folder, NewKeyLogic.FileName(name) + ".pub");
                File.WriteAllText(publicFile, $"sk-ssh-ed25519@openssh.com {KeyA} strugglebus-{name}\n");
                return publicFile;
            };

            window.NewKeyName.Text = " spare ";
            StaWindowAdminScene.ClickAndWait(window.NewKeyButton);

            Assert.Equal(LineA, window.HostSigners.Text);
            Assert.Equal((scene.Platform.HardwareSigningTool!, "spare"), Assert.Single(scene.Platform.KeysAsked));
            var asked = Assert.Single(scene.Platform.Confirmations).Item1;
            Assert.StartsWith("A new key was made on your security key.", asked);
            Assert.Contains($"Fingerprint:  {FleetPublishLogic.Signers(LineA)[0].Fingerprint}", asked);
            Assert.Contains("File:         id_ed25519_sk_strugglebus_spare.pub", asked);
            Assert.Contains("Write the fingerprint down or photograph it now.", asked);
            Assert.Contains(SiteSignersLogic.AddHelloPrompt(FleetPublishLogic.Signers(LineA)[0]), scene.Platform.HelloPrompts);
            Assert.Equal(Path.Combine(folder, "id_ed25519_sk_strugglebus_spare"), AppSettings.Load().SignerKeyFiles[KeyA]);
            Assert.Equal(string.Empty, window.NewKeyName.Text);
            Assert.Equal(string.Empty, window.NewKeyText.Text);
            Assert.Equal(string.Empty, scene.Notice);
        }
        finally
        {
            Directory.Delete(folder, recursive: true);
        }
    });

    [Fact]
    public void ANewKeyTheOperatorDeclinesIsMadeButIsNotASigner() => sta.Run(() =>
    {
        var folder = Directory.CreateTempSubdirectory("new-key-window-").FullName;
        try
        {
            using var scene = Open(fleet: null);
            var window = scene.Window;
            scene.Platform.ConfirmAnswer = false;
            scene.Platform.NewKey = name =>
            {
                var publicFile = Path.Combine(folder, NewKeyLogic.FileName(name) + ".pub");
                File.WriteAllText(publicFile, $"sk-ssh-ed25519@openssh.com {KeyA}\n");
                scene.Platform.PublicKeys.Add((publicFile, File.ReadAllText(publicFile)));
                return publicFile;
            };

            window.NewKeyName.Text = "A";
            StaWindowAdminScene.ClickAndWait(window.NewKeyButton);

            Assert.Equal(string.Empty, window.HostSigners.Text);
            Assert.Empty(scene.Platform.HelloPrompts);
            Assert.Equal("id_ed25519_sk_strugglebus_A.pub", Assert.Single((IEnumerable<FoundKey>)window.FoundKeysList.ItemsSource).FileName);
        }
        finally
        {
            Directory.Delete(folder, recursive: true);
        }
    });

    [Fact]
    public void NoNameNoToolAndAToolThatMakesNoKeyEachSayWhyAndAddNothing() => sta.Run(() =>
    {
        using var scene = Open(fleet: null);
        var window = scene.Window;

        StaWindowAdminScene.ClickAndWait(window.NewKeyButton);
        Assert.Equal(NewKeyLogic.NameNeeded, scene.Notice);
        Assert.Empty(scene.Platform.KeysAsked);

        window.NewKeyName.Text = "spare";
        var tool = scene.Platform.HardwareSigningTool;
        scene.Platform.HardwareSigningTool = null;
        StaWindowAdminScene.ClickAndWait(window.NewKeyButton);
        Assert.Equal(NewKeyLogic.NoTool, scene.Notice);
        Assert.Empty(scene.Platform.KeysAsked);

        scene.Platform.HardwareSigningTool = tool;
        StaWindowAdminScene.ClickAndWait(window.NewKeyButton);
        Assert.Equal(NewKeyLogic.Failed("Key enrollment failed: invalid format"), scene.Notice);
        Assert.Equal("spare", window.NewKeyName.Text);
        Assert.Equal(string.Empty, window.NewKeyText.Text);
        Assert.Equal(string.Empty, window.HostSigners.Text);
        Assert.Empty(scene.Platform.Confirmations);
    });
}
