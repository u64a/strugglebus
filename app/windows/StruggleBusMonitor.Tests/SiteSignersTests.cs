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
    public void EarlierLinesYieldOnlyHardwareKeysRebuiltAndNotAlreadyHeld()
    {
        var lineA = SiteSignersLogic.LineFor(PublicFile(KeyA));
        var lineB = SiteSignersLogic.LineFor(PublicFile(KeyB));
        var earlier = string.Join("\r\n", lineA.Replace("strugglebus-host-command", "strugglebus-release"), lineB + " key-name", "junk", "x namespaces=\"a\" ssh-rsa AAAA");

        Assert.Equal([lineA, lineB], SiteSignersLogic.Earlier(earlier, "").Select(signer => signer.Line));
        Assert.Equal([lineB], SiteSignersLogic.Earlier(earlier, lineA).Select(signer => signer.Line));
        Assert.Empty(SiteSignersLogic.Earlier("", ""));

        var both = SiteSignersLogic.Earlier(earlier, "");
        Assert.Equal(lineA + "\n" + lineB, SiteSignersLogic.With("", both));
        Assert.Contains("kept 2 site signer keys", SiteSignersLogic.EarlierReview(both));
        Assert.Contains("kept 1 site signer key in", SiteSignersLogic.EarlierReview([both[0]]));
        Assert.Equal("Keep 1 earlier site signer key", SiteSignersLogic.EarlierHelloPrompt(1));
        Assert.Equal("Confirm 1 signer key from an earlier version", SiteSignersLogic.EarlierButton(1));
    }

    [Fact]
    public void HardwareKeysFoundOnThePcAreListedOnceEachAndNotWhenAlreadySigners()
    {
        var lineA = SiteSignersLogic.LineFor(PublicFile(KeyA));
        (string Path, string Text)[] files =
        [
            (@"C:\u\.ssh\id_sk_b.pub", PublicFile(KeyB)),
            (@"C:\u\.ssh\id_sk_a.pub", PublicFile(KeyA)),
            (@"C:\u\.ssh\copy_of_b.pub", PublicFile(KeyB, comment: " again")),
            (@"C:\u\.ssh\id_ed25519.pub", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA me"),
            (@"C:\u\.ssh\notes.pub", "not a key at all")
        ];

        var none = SiteSignersLogic.Found(files, "");
        Assert.Equal(["copy_of_b.pub", "id_sk_a.pub"], none.Select(key => key.FileName));
        Assert.Equal(FleetPublishLogic.Signers(lineA)[0].Fingerprint, none[1].Fingerprint);
        Assert.Equal(@"C:\u\.ssh\id_sk_a.pub", none[1].Path);

        Assert.Equal(["copy_of_b.pub"], SiteSignersLogic.Found(files, lineA).Select(key => key.FileName));
        Assert.Empty(SiteSignersLogic.Found([], lineA));

        Assert.StartsWith("Found on this PC (2), not yet site signers.", SiteSignersLogic.FoundText(2, 0));
        Assert.StartsWith("No hardware key's public file was found", SiteSignersLogic.FoundText(0, 0));
        Assert.Equal("Every hardware key found in your .ssh folder is already a site signer.", SiteSignersLogic.FoundText(0, 3));
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
            Assert.Equal(LineA, SiteSignersStore.Load());
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
    public void AKeyFoundOnThePcIsAddedWithItsButtonAndNoFileIsChosen() => sta.Run(() =>
    {
        var folder = Directory.CreateTempSubdirectory("signers-test-").FullName;
        try
        {
            var publicFile = WritePublicFile(folder, "id_ed25519_sk_a.pub", $"sk-ssh-ed25519@openssh.com {KeyA} me@pc\n");
            File.WriteAllText(Path.Combine(folder, "id_ed25519_sk_a"), "a key handle");
            File.WriteAllText(Path.Combine(folder, "other.pub"), "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA me\n");
            using var scene = new StaWindowAdminScene().Enroll();
            scene.Platform.PublicKeys.AddRange(WindowPlatform.PublicKeyFilesIn(folder));
            var window = scene.Open().Window;
            window.AdminNav.IsChecked = true;
            window.AdminTabSecurity.IsChecked = true;

            var found = Assert.Single((IEnumerable<FoundKey>)window.FoundKeysList.ItemsSource);
            Assert.Equal("id_ed25519_sk_a.pub", found.FileName);
            Assert.StartsWith("Found on this PC (1), not yet site signers.", window.FoundKeysText.Text);

            window.FoundKeyAdd_Click(new System.Windows.Controls.Button { Tag = "not a key" }, new System.Windows.RoutedEventArgs());
            window.FoundKeyAdd_Click(new System.Windows.Controls.Button { Tag = found }, new System.Windows.RoutedEventArgs());
            StaWindowAdminScene.Until(() => Listed(window).Count == 1, "the key to be added");

            Assert.Equal(LineA, window.HostSigners.Text);
            Assert.Contains($"Fingerprint:  {found.Fingerprint}", Assert.Single(scene.Platform.Confirmations).Item1);
            Assert.Contains(SiteSignersLogic.AddHelloPrompt(Listed(window)[0]), scene.Platform.HelloPrompts);
            Assert.Equal(Path.Combine(folder, "id_ed25519_sk_a"), AppSettings.Load().SignerKeyFiles[KeyA]);
            Assert.Empty((IEnumerable<FoundKey>)window.FoundKeysList.ItemsSource);
            Assert.Equal("Every hardware key found in your .ssh folder is already a site signer.", window.FoundKeysText.Text);
        }
        finally
        {
            Directory.Delete(folder, recursive: true);
        }
    });

    [Fact]
    public void AFolderThatIsNotThereHoldsNoKeys() =>
        Assert.Empty(WindowPlatform.PublicKeyFilesIn(Path.Combine(Path.GetTempPath(), "no-such-folder-" + Guid.NewGuid().ToString("N"))));

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
        Assert.Equal(window.HostSigners.Text, SiteSignersStore.Load());
        Assert.Contains($"Fingerprint:  {first.Fingerprint}", Assert.Single(scene.Platform.Confirmations).Item1);
        Assert.Contains(SiteSignersLogic.RemoveHelloPrompt(first), scene.Platform.HelloPrompts);

        window.SignerRemove_Click(new System.Windows.Controls.Button { Tag = Listed(window)[0] }, new System.Windows.RoutedEventArgs());
        StaWindowAdminScene.Until(() => scene.Notice.Length > 0, "the refusal");
        Assert.Equal(SiteSignersLogic.TwoNeeded, scene.Notice);
        Assert.Equal(2, Listed(window).Count);
    });

    private static readonly string EarlierLines = string.Join("\n",
    [
        LineA.Replace("owner namespaces=\"strugglebus-fleet,strugglebus-host-command\"", "chris namespaces=\"strugglebus-fleet,strugglebus-release\"") + " a-comment",
        LineB,
        LineB,
        "someone namespaces=\"strugglebus-fleet\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA",
        "not a line at all"
    ]);

    [Fact]
    public void LinesAnEarlierVersionKeptUnprotectedAreNeverUsedUntilTheOperatorConfirmsThem() => sta.Run(() =>
    {
        using var scene = new StaWindowAdminScene().WithSettings(settings => settings.HostSigners = EarlierLines).Enroll();
        var window = scene.Open().Window;

        Assert.Empty(Listed(window));
        Assert.Equal(string.Empty, window.HostSigners.Text);
        Assert.Equal(System.Windows.Visibility.Visible, window.SignersEarlierButton.Visibility);
        Assert.Equal("Confirm 2 signer keys from an earlier version", window.SignersEarlierButton.Content);

        // No keeps nothing and leaves the offer standing.
        scene.Platform.ConfirmAnswer = false;
        StaWindowAdminScene.ClickAndWait(window.SignersEarlierButton);
        Assert.Empty(Listed(window));
        Assert.Empty(scene.Platform.HelloPrompts);
        Assert.False(File.Exists(AppPaths.File("site-signers.bin")));

        // Yes and Windows Hello keep only the hardware keys, each rebuilt with the app's own name and namespaces.
        scene.Platform.ConfirmAnswer = true;
        StaWindowAdminScene.ClickAndWait(window.SignersEarlierButton);
        Assert.Equal(LineA + "\n" + LineB, window.HostSigners.Text);
        Assert.DoesNotContain("strugglebus-release", window.HostSigners.Text);
        Assert.Equal(window.HostSigners.Text, SiteSignersStore.Load());
        Assert.Equal(string.Empty, AppSettings.Load().HostSigners);
        Assert.Contains("Keep 2 earlier site signer keys", scene.Platform.HelloPrompts);
        Assert.Contains(scene.Platform.Confirmations, asked => Listed(window).All(signer => asked.Item1.Contains(signer.Fingerprint)));
        Assert.Equal(System.Windows.Visibility.Collapsed, window.SignersEarlierButton.Visibility);
    });

    [Fact]
    public void AStoreThatCannotBeReadIsAnEmptySet() => sta.Run(() =>
    {
        using var scene = new StaWindowAdminScene().Enroll();
        Directory.CreateDirectory(Path.GetDirectoryName(AppPaths.File("site-signers.bin"))!);
        File.WriteAllText(AppPaths.File("site-signers.bin"), "not protected data");

        Assert.Equal(string.Empty, SiteSignersStore.Load());
        Assert.Empty(Listed(scene.Open().Window));
        Assert.Equal(System.Windows.Visibility.Collapsed, scene.Window.SignersEarlierButton.Visibility);
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
