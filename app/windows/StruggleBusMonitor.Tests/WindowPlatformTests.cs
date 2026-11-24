using System.Windows;

namespace StruggleBusMonitor.Tests;

/// <summary>
/// The real platform, as far as it can be exercised without prompting anyone: its dialogs, Windows
/// Hello, the clipboard and the registry read are deliberately left alone.
/// </summary>
[Collection(StaWindowAdminCollection.Name)]
public class WindowPlatformTests(StaWindowAdminFixture sta)
{
    [Fact]
    public void TheVirtualScreenIsTheWholeDesktop() => sta.Run(() =>
    {
        var screen = new WindowPlatform().VirtualScreen;

        Assert.Equal(new Rect(SystemParameters.VirtualScreenLeft, SystemParameters.VirtualScreenTop, SystemParameters.VirtualScreenWidth, SystemParameters.VirtualScreenHeight), screen);
        Assert.True(screen.Width > 0 && screen.Height > 0);
    });

    [Fact]
    public void TheExportDialogAsksForACsvFileAndWarnsBeforeOverwriting() => sta.Run(() =>
    {
        var dialog = WindowPlatform.ExportDialog("strugglebus-messages-20261117-120509.csv");

        Assert.Equal("strugglebus-messages-20261117-120509.csv", dialog.FileName);
        Assert.Equal("CSV files (*.csv)|*.csv|All files (*.*)|*.*", dialog.Filter);
        Assert.Equal("csv", dialog.DefaultExt);
        Assert.True(dialog.AddExtension);
        Assert.True(dialog.OverwritePrompt);
        Assert.Equal("Export retained StruggleBus activity", dialog.Title);
    });

    [Fact]
    public async Task ACopyRunFromABuildFolderCannotUpdateAndSaysSoWithoutLookingOnline()
    {
        var platform = new WindowPlatform();

        Assert.False(platform.CanUpdate);
        Assert.False(string.IsNullOrWhiteSpace(platform.CurrentVersion));
        Assert.Equal(new UpdateStatus(UpdateState.NotInstalled), await platform.CheckForUpdatesAsync(null, download: true));
    }

    [Fact]
    public void TheWindowsThemeAnswerIsLightOnlyForANonZeroNumber()
    {
        Assert.True(WindowPlatform.IsLightPreference(() => 1));
        Assert.False(WindowPlatform.IsLightPreference(() => 0));
        Assert.False(WindowPlatform.IsLightPreference(() => null));
        Assert.False(WindowPlatform.IsLightPreference(() => "1"));
        Assert.False(WindowPlatform.IsLightPreference(() => throw new System.Security.SecurityException("Registry access is not allowed.")));
    }

    [Fact]
    public async Task WaitingIsAnOrdinaryDelay()
    {
        var wait = new WindowPlatform().Delay(TimeSpan.Zero);

        await wait;
        Assert.True(wait.IsCompletedSuccessfully);
    }
}
