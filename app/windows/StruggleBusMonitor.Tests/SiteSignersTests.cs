using System.IO;

namespace StruggleBusMonitor.Tests;

/// <summary>Setting up the site's signers from a hardware key's public file.</summary>
public sealed class SiteSignersLogicTests
{
    private static readonly string KeyA = Convert.ToBase64String(SshSignatureMaker.Key());
    private static readonly string KeyB = Convert.ToBase64String(SshSignatureMaker.Key(seed: 2));

    private static string PublicFile(string key, string type = SshSignatureMaker.HardwareKey, string comment = " chris@pc") => $"{type} {key}{comment}\n";

    [Fact]
    public void AHardwareKeysPublicFileBecomesASignerLineHostsAccept()
    {
        var line = SiteSignersLogic.LineFor(PublicFile(KeyA));

        Assert.Equal($"owner namespaces=\"strugglebus-fleet,strugglebus-host-command\" sk-ssh-ed25519@openssh.com {KeyA}", line);
        Assert.True(HostEnrolFile.IsSignerLine(line));
        Assert.Equal(line, SiteSignersLogic.LineFor(PublicFile(KeyA, comment: string.Empty).Replace("\n", "\r\n")));
        Assert.Equal(line, SshSignatureMaker.SignerLine(SshSignatureMaker.Key(), principal: "owner"));
    }

    [Theory]
    [InlineData("", SiteSignersLogic.NotAPublicKey)]
    [InlineData("hello there", SiteSignersLogic.NotAPublicKey)]
    [InlineData("sk-ssh-ed25519@openssh.com AAAA a\nsk-ssh-ed25519@openssh.com BBBB b", SiteSignersLogic.NotAPublicKey)]
    [InlineData("-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----", SiteSignersLogic.PrivateKeyChosen)]
    [InlineData("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA me", SiteSignersLogic.NotAHardwareKey)]
    [InlineData("ssh-rsa AAAAB3NzaC1yc2E me", SiteSignersLogic.NotAHardwareKey)]
    public void AnythingElseIsRefusedInWords(string file, string expected) =>
        Assert.Equal(expected, Assert.Throws<InvalidOperationException>(() => SiteSignersLogic.LineFor(file)).Message);

    [Fact]
    public void KeysAreAddedOncePerKeyAndTheSetIsSummarised()
    {
        var first = SiteSignersLogic.Add("", SiteSignersLogic.LineFor(PublicFile(KeyA)));
        var both = SiteSignersLogic.Add(first + "\r\n", SiteSignersLogic.LineFor(PublicFile(KeyB)));

        Assert.Equal(2, FleetPublishLogic.Signers(both).Count);
        Assert.DoesNotContain('\r', both);
        Assert.Equal(SiteSignersLogic.AlreadyHeld, Assert.Throws<InvalidOperationException>(() => SiteSignersLogic.Add(both, SiteSignersLogic.LineFor(PublicFile(KeyA)))).Message);

        Assert.StartsWith("No site signers yet.", SiteSignersLogic.Summary(""));
        Assert.StartsWith("1 site signer, 1 on a hardware key:  SHA256:", SiteSignersLogic.Summary(first));
        Assert.EndsWith("A site needs two before a host can be added.", SiteSignersLogic.Summary(first));
        Assert.StartsWith("2 site signers, 2 on a hardware key:  SHA256:", SiteSignersLogic.Summary(both));
        Assert.DoesNotContain("needs two", SiteSignersLogic.Summary(both));
    }

    [Fact]
    public void AKeyCanBeRemovedOnlyWhileTwoRemain()
    {
        var lines = new[] { KeyA, KeyB, Convert.ToBase64String(SshSignatureMaker.Key(seed: 3)) }.Select(key => SiteSignersLogic.LineFor(PublicFile(key))).ToList();
        var three = string.Join("\n", lines);

        var two = SiteSignersLogic.Remove(three, KeyA);
        Assert.Equal(string.Join("\n", lines[1], lines[2]), two);
        Assert.Equal(SiteSignersLogic.TwoNeeded, Assert.Throws<InvalidOperationException>(() => SiteSignersLogic.Remove(two, KeyB)).Message);
    }

    [Fact]
    public void TheQuestionsShowTheFingerprintAndSayWhatASignerCanDo()
    {
        var signer = FleetPublishLogic.Signers(SiteSignersLogic.LineFor(PublicFile(KeyA)))[0];

        var add = SiteSignersLogic.AddReview(signer, "a.pub");
        Assert.Contains($"Fingerprint:  {signer.Fingerprint}", add);
        Assert.Contains("ssh-keygen -lf", add);
        Assert.Contains("which agents may task every worker host", add);
        Assert.Contains("keep trusting it until it is removed on each host", SiteSignersLogic.RemoveReview(signer));
        Assert.Equal($"Add site signer {signer.Fingerprint}", SiteSignersLogic.AddHelloPrompt(signer));
    }
}

/// <summary>Adding and removing a hardware key from the real window.</summary>
[Collection(StaWindowAdminCollection.Name)]
public sealed class SiteSignersWindowTests(StaWindowAdminFixture sta)
{
    private static readonly string KeyA = Convert.ToBase64String(SshSignatureMaker.Key());
    private static readonly string LineA = SiteSignersLogic.LineFor($"sk-ssh-ed25519@openssh.com {KeyA}");
    private static readonly string LineB = SiteSignersLogic.LineFor($"sk-ssh-ed25519@openssh.com {Convert.ToBase64String(SshSignatureMaker.Key(seed: 2))}");
    private static readonly string LineC = SiteSignersLogic.LineFor($"sk-ssh-ed25519@openssh.com {Convert.ToBase64String(SshSignatureMaker.Key(seed: 3))}");

    private static string WritePublicFile(string folder, string name, string text)
    {
        var path = Path.Combine(folder, name);
        File.WriteAllText(path, text);
        return path;
    }

    private static List<SiteSigner> Listed(MainWindow window) => ((IEnumerable<SiteSigner>)window.SignersList.ItemsSource).ToList();

    [Fact]
    public void AddingAHardwareKeyShowsItsFingerprintAsksWindowsHelloAndKeepsItProtected() => sta.Run(() =>
    {
        var folder = Directory.CreateTempSubdirectory("signers-test-").FullName;
        try
        {
            using var scene = new StaWindowAdminScene().Enroll().Open();
            var window = scene.Window;
            Assert.StartsWith("No site signers yet.", window.SignersSummary.Text);
            Assert.True(window.HostSigners.IsReadOnly);

            scene.Platform.PublicKeyPath = WritePublicFile(folder, "id_ed25519_sk_a.pub", $"sk-ssh-ed25519@openssh.com {KeyA} me@pc\n");
            StaWindowAdminScene.ClickAndWait(window.SignerAddButton);

            var signer = Assert.Single(Listed(window));
            Assert.Equal(LineA, window.HostSigners.Text);
            Assert.Equal(LineA, SiteSignersStore.Load(new AppSettings()));
            Assert.DoesNotContain(KeyA, File.ReadAllText(AppPaths.File("site-signers.bin")));
            Assert.Equal(string.Empty, AppSettings.Load().HostSigners);
            var asked = Assert.Single(scene.Platform.Confirmations);
            Assert.Contains($"Fingerprint:  {signer.Fingerprint}", asked.Item1);
            Assert.Contains("From file:    id_ed25519_sk_a.pub", asked.Item1);
            Assert.Contains(SiteSignersLogic.AddHelloPrompt(signer), scene.Platform.HelloPrompts);
            Assert.StartsWith("1 site signer, 1 on a hardware key:", window.SignersSummary.Text);
            Assert.Equal(string.Empty, scene.Notice);

            // The same key again, a key that is not a hardware key, an oversized file, and no file chosen: nothing changes.
            StaWindowAdminScene.ClickAndWait(window.SignerAddButton);
            Assert.Equal(SiteSignersLogic.AlreadyHeld, scene.Notice);
            scene.Platform.PublicKeyPath = WritePublicFile(folder, "id_ed25519.pub", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA me\n");
            StaWindowAdminScene.ClickAndWait(window.SignerAddButton);
            Assert.Equal(SiteSignersLogic.NotAHardwareKey, scene.Notice);
            scene.Platform.PublicKeyPath = WritePublicFile(folder, "huge.pub", new string('A', SshSignature.MaxLength + 1));
            StaWindowAdminScene.ClickAndWait(window.SignerAddButton);
            Assert.Equal(SiteSignersLogic.NotAPublicKey, scene.Notice);
            scene.Platform.PublicKeyPath = null;
            StaWindowAdminScene.ClickAndWait(window.SignerAddButton);
            Assert.Equal(LineA, window.HostSigners.Text);
            Assert.Single(scene.Platform.Confirmations);
        }
        finally
        {
            Directory.Delete(folder, recursive: true);
        }
    });

    [Fact]
    public void SayingNoToTheFingerprintAddsNothing() => sta.Run(() =>
    {
        var folder = Directory.CreateTempSubdirectory("signers-test-").FullName;
        try
        {
            using var scene = new StaWindowAdminScene().Enroll().Open();
            scene.Platform.ConfirmAnswer = false;
            scene.Platform.PublicKeyPath = WritePublicFile(folder, "a.pub", $"sk-ssh-ed25519@openssh.com {KeyA}\n");

            StaWindowAdminScene.ClickAndWait(scene.Window.SignerAddButton);

            Assert.Equal(string.Empty, scene.Window.HostSigners.Text);
            Assert.Empty(scene.Platform.HelloPrompts);
            Assert.False(File.Exists(AppPaths.File("site-signers.bin")));
        }
        finally
        {
            Directory.Delete(folder, recursive: true);
        }
    });

    [Fact]
    public void AKeyIsRemovedOnlyWithWindowsHelloAndNeverBelowTwo() => sta.Run(() =>
    {
        using var scene = new StaWindowAdminScene().Enroll().Open();
        var window = scene.Window;
        window.HostSigners.Text = string.Join("\n", LineA, LineB, LineC);
        var first = Listed(window)[0];

        window.SignerRemove_Click(new System.Windows.Controls.Button { Tag = "not a signer" }, new System.Windows.RoutedEventArgs());
        window.SignerRemove_Click(new System.Windows.Controls.Button { Tag = first }, new System.Windows.RoutedEventArgs());
        StaWindowAdminScene.Until(() => Listed(window).Count == 2, "the key to be removed");

        Assert.Equal(string.Join("\n", LineB, LineC), window.HostSigners.Text);
        Assert.Equal(window.HostSigners.Text, SiteSignersStore.Load(new AppSettings()));
        Assert.Contains($"Fingerprint:  {first.Fingerprint}", Assert.Single(scene.Platform.Confirmations).Item1);
        Assert.Contains(SiteSignersLogic.RemoveHelloPrompt(first), scene.Platform.HelloPrompts);

        window.SignerRemove_Click(new System.Windows.Controls.Button { Tag = Listed(window)[0] }, new System.Windows.RoutedEventArgs());
        StaWindowAdminScene.Until(() => scene.Notice.Length > 0, "the refusal");
        Assert.Equal(SiteSignersLogic.TwoNeeded, scene.Notice);
        Assert.Equal(2, Listed(window).Count);
    });

    [Fact]
    public void LinesKeptInThePlainSettingsFileAreMovedToTheProtectedStoreOnce() => sta.Run(() =>
    {
        using var scene = new StaWindowAdminScene().WithSettings(settings => settings.HostSigners = LineA + "\n" + LineB);

        var window = scene.Open().Window;

        Assert.Equal(2, Listed(window).Count);
        Assert.Equal(string.Empty, AppSettings.Load().HostSigners);
        Assert.Equal(LineA + "\n" + LineB, SiteSignersStore.Load(new AppSettings()));

        File.WriteAllText(AppPaths.File("site-signers.bin"), "not protected data");
        Assert.Equal(string.Empty, SiteSignersStore.Load(new AppSettings()));
    });

    [Fact]
    public void TheFormSaysThatTwoFilesAreSaved() => sta.Run(() =>
    {
        using var scene = new StaWindowAdminScene().Open();

        Assert.Equal("Create code and save the installer and data file", scene.Window.HostCreateButton.Content);
        Assert.Contains("installer script is saved beside it", WindowPlatform.HostFileDialog("x.json").Title);
        Assert.EndsWith(".ssh", WindowPlatform.PublicKeyDialog().InitialDirectory);
    });
}
