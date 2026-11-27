using System.Windows;
using System.Windows.Controls;

namespace StruggleBusMonitor.Tests;

/// <summary>What the About card says and which addresses it may open.</summary>
public sealed class AboutLogicTests
{
    [Fact]
    public void TheCardSaysWhoseItIsAndWhatTheLicenceAllows()
    {
        Assert.Contains("u64a", AboutLogic.Owner);
        Assert.Contains("Copyright © 2026 NZCypher819", AboutLogic.Owner);
        Assert.StartsWith("MIT licence", AboutLogic.Licence);
        Assert.Contains("no warranty", AboutLogic.Licence);
    }

    [Fact]
    public void EveryLinkIsASecureAddressInTheProjectsRepository()
    {
        Assert.Equal(
            ["Project and source", "Manual", "Releases", "Licence", "Privacy policy", "Security policy", "Report a problem"],
            AboutLogic.Links.Select(link => link.Label));
        Assert.All(AboutLogic.Links, link => Assert.True(
            link.Url == AboutLogic.ProjectUrl || link.Url.StartsWith(AboutLogic.ProjectUrl + "/", StringComparison.Ordinal), link.Url));
        Assert.Equal("https://github.com/u64a/strugglebus", AboutLogic.ProjectUrl);
    }

    [Theory]
    [InlineData("https://github.com/u64a/strugglebus", true)]
    [InlineData("https://github.com/u64a/strugglebus/issues", true)]
    [InlineData("https://github.com/u64a/strugglebus/issues/new", false)]
    [InlineData("https://example.com", false)]
    [InlineData(@"C:\Windows\System32\calc.exe", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public void OnlyAnAddressOnTheCardMayBeOpened(string? url, bool allowed) => Assert.Equal(allowed, AboutLogic.MayOpen(url));
}

/// <summary>The About card in the real window.</summary>
[Collection(StaWindowAdminCollection.Name)]
public sealed class AboutWindowTests(StaWindowAdminFixture sta)
{
    [Fact]
    public void SettingsEndsWithAnAboutCardAndItsLinksOpenInTheBrowser() => sta.Run(() =>
    {
        using var scene = new StaWindowAdminScene().Open();
        var window = scene.Window;

        Assert.Equal(AboutLogic.What, window.AboutWhatText.Text);
        Assert.Equal(AboutLogic.Owner, window.AboutOwnerText.Text);
        Assert.Equal(AboutLogic.Licence, window.AboutLicenceText.Text);
        Assert.Equal(AboutLogic.LinksNote, window.AboutLinksNote.Text);
        Assert.Same(AboutLogic.Links, window.AboutLinks.ItemsSource);

        var licence = AboutLogic.Links.Single(link => link.Label == "Licence");
        window.AboutLink_Click(new Button { Tag = licence }, new RoutedEventArgs());

        Assert.Equal([licence.Url], scene.Platform.OpenedLinks);
    });

    [Fact]
    public void AnAddressThatIsNotOnTheCardIsNeverOpened() => sta.Run(() =>
    {
        using var scene = new StaWindowAdminScene().Open();

        scene.Window.AboutLink_Click(new Button { Tag = new AboutLink("Elsewhere", "https://example.com") }, new RoutedEventArgs());
        scene.Window.AboutLink_Click(new Button { Tag = "https://github.com/u64a/strugglebus" }, new RoutedEventArgs());

        Assert.Empty(scene.Platform.OpenedLinks);
        Assert.Equal(string.Empty, scene.Notice);
    });

    [Fact]
    public void WhenNoBrowserOpensTheAddressIsShownInstead() => sta.Run(() =>
    {
        using var scene = new StaWindowAdminScene().Open();
        scene.Platform.BrowserFails = true;

        scene.Window.AboutLink_Click(new Button { Tag = AboutLogic.Links[0] }, new RoutedEventArgs());

        Assert.Equal($"Windows could not open a browser. The address is {AboutLogic.ProjectUrl}", scene.Notice);
    });
}
