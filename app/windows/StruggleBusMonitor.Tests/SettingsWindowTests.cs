using System.IO;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace StruggleBusMonitor.Tests;

/// <summary>The Settings page of the real window: themes, updates, this PC and the logs.</summary>
[Collection(StaWindowAdminCollection.Name)]
public class SettingsWindowTests(StaWindowAdminFixture sta)
{
    private const string BusLogJson = """
        {"version":"0.2.65","started_at":"2026-11-16T10:00:00Z","entries":[
          {"ts":"2026-11-17T08:00:00Z","source":"audit","level":"info","event":"agent.block","subject":"prox-manager","actor":"human:operator","status":null,"remote_address":null,"detail":"blocked"},
          {"ts":"2026-11-17T07:00:00Z","source":"request","level":"warning","event":"POST /api/mobile/actions","subject":null,"actor":null,"status":500,"remote_address":"10.0.0.5","detail":"HTTP 500"}]}
        """;

    private static Color AppBackground => ((SolidColorBrush)Application.Current.Resources["Bg"]).Color;

    private static List<T> Items<T>(ItemsControl list) => ((IEnumerable<T>)list.ItemsSource).ToList();

    private static StaWindowAdminScene Installed(bool autoUpdate = true)
    {
        var scene = new StaWindowAdminScene().WithSettings(settings => settings.AutoUpdate = autoUpdate);
        scene.Platform.Installed = true;
        return scene;
    }

    /// <summary>An enrolled window showing the Logs tab with the bus log loaded.</summary>
    private static StaWindowAdminScene OpenLogs(Func<BusRequest, BusReply>? logs = null)
    {
        var scene = new StaWindowAdminScene().Enroll();
        try
        {
            scene.Bus.On("GET /api/mobile/admin/logs", logs ?? (_ => StaWindowAdminBus.Ok(BusLogJson)));
            scene.Open();
            scene.Window.SettingsNav.IsChecked = true;
            scene.Window.SettingsTabLogs.IsChecked = true;
            StaWindowAdminScene.Until(() => scene.Window.BusLogStatus.Text.Length > 0, "the bus log");
            return scene;
        }
        catch
        {
            scene.Dispose();
            throw;
        }
    }

    // ---- General -----------------------------------------------------------------------------

    [Fact]
    public void ACopyThatWasNotInstalledSaysItCannotUpdateItself() => sta.Run(() =>
    {
        using var scene = new StaWindowAdminScene().Open();
        var window = scene.Window;
        var architecture = RuntimeInformation.ProcessArchitecture.ToString().ToLowerInvariant();

        Assert.Equal($"Version 9.9.9 · {architecture}", window.VersionText.Text);
        Assert.Equal($"Updates are downloaded from {AppUpdater.ReleasesUrl}", window.UpdateSourceText.Text);
        Assert.Equal(SettingsLogic.NotInstalledText, window.UpdateStatusText.Text);
        Assert.False(window.UpdateCheckButton.IsEnabled);
        Assert.False(window.AutoUpdateCheck.IsEnabled);
        Assert.True(window.AutoUpdateCheck.IsChecked);
        Assert.Equal(Visibility.Collapsed, window.UpdateRestartButton.Visibility);
        Assert.Equal(Visibility.Collapsed, window.UpdateButton.Visibility);
        Assert.True(window.ModeDark.IsChecked);
        Assert.Empty(scene.Platform.Delays);
    });

    [Fact]
    public void TheGeneralAndLogsTabsSwapPanels() => sta.Run(() =>
    {
        using var scene = new StaWindowAdminScene().Open();
        var window = scene.Window;

        window.SettingsTabLogs.IsChecked = true;
        Assert.Equal(Visibility.Visible, window.SettingsLogsPanel.Visibility);
        Assert.Equal(Visibility.Collapsed, window.SettingsGeneralPanel.Visibility);
        Assert.Equal("Enroll this PC to read the bus log.", window.BusLogEmpty.Text);
        Assert.Equal(Visibility.Visible, window.BusLogEmpty.Visibility);
        Assert.Equal(Visibility.Visible, window.ConnectionLogEmpty.Visibility);

        window.SettingsTabGeneral.IsChecked = true;
        Assert.Equal(Visibility.Collapsed, window.SettingsLogsPanel.Visibility);
        Assert.Equal(Visibility.Visible, window.SettingsGeneralPanel.Visibility);
        Assert.Empty(scene.Bus.Requests);
    });

    // ---- Themes ------------------------------------------------------------------------------

    [Fact]
    public void PickingALightThemeShowsItAndSwitchesToLightMode() => sta.Run(() =>
    {
        using var scene = new StaWindowAdminScene().Open();
        var window = scene.Window;
        var card = Items<ThemeCard>(window.LightThemeList).Single(theme => theme.Palette.Id == "rose-pine");

        window.ThemeCard_Click(new Button { DataContext = card }, new RoutedEventArgs());

        Assert.True(card.IsSelected);
        Assert.True(window.ModeLight.IsChecked);
        Assert.Equal(Themes.Parse("#faf4ed"), AppBackground);
        var saved = AppSettings.Load();
        Assert.Equal((AppThemeMode.Light, "rose-pine", Themes.DefaultDark), (saved.Mode, saved.LightTheme, saved.DarkTheme));
        Assert.Single(Items<ThemeCard>(window.LightThemeList), theme => theme.IsSelected);
    });

    [Fact]
    public void PickingADarkThemeSwitchesBackToDarkMode() => sta.Run(() =>
    {
        using var scene = new StaWindowAdminScene().WithSettings(settings => settings.Mode = AppThemeMode.Light).Open();
        var window = scene.Window;
        var card = Items<ThemeCard>(window.DarkThemeList).Single(theme => theme.Palette.Id == "nord");

        window.ThemeCard_Click(new Button { DataContext = card }, new RoutedEventArgs());

        Assert.True(card.IsSelected);
        Assert.True(window.ModeDark.IsChecked);
        Assert.Equal(Themes.Parse("#2e3440"), AppBackground);
        var saved = AppSettings.Load();
        Assert.Equal((AppThemeMode.Dark, "nord"), (saved.Mode, saved.DarkTheme));
    });

    [Fact]
    public void AClickThatCarriesNoThemeChangesNothing() => sta.Run(() =>
    {
        using var scene = new StaWindowAdminScene().Open();

        scene.Window.ThemeCard_Click(new Button { DataContext = "not a theme" }, new RoutedEventArgs());
        scene.Window.ThemeCard_Click(new object(), new RoutedEventArgs());

        Assert.Equal(Themes.Parse("#05182e"), AppBackground);
        Assert.False(File.Exists(AppPaths.File("settings.json")));
    });

    [Fact]
    public void TheModeButtonsChooseBetweenDarkLightAndMatchingWindows() => sta.Run(() =>
    {
        using var scene = new StaWindowAdminScene().Open();
        var window = scene.Window;
        scene.Platform.PrefersLight = true;

        window.ModeSystem.IsChecked = true;
        Assert.Equal(AppThemeMode.System, AppSettings.Load().Mode);
        Assert.Equal(Themes.Parse("#eff1f5"), AppBackground);

        window.ModeDark.IsChecked = true;
        Assert.Equal(AppThemeMode.Dark, AppSettings.Load().Mode);
        Assert.Equal(Themes.Parse("#05182e"), AppBackground);

        window.ModeLight.IsChecked = true;
        Assert.Equal(AppThemeMode.Light, AppSettings.Load().Mode);
        Assert.Equal(Themes.Parse("#eff1f5"), AppBackground);
    });

    // ---- Updates -----------------------------------------------------------------------------

    [Fact]
    public void AnInstalledCopyChecksShortlyAfterStartupAndThenEveryFewHours() => sta.Run(() =>
    {
        using var scene = Installed();
        scene.Platform.UpdateResult = new UpdateStatus(UpdateState.ReadyToRestart, "1.9.0");
        scene.Open();
        var window = scene.Window;

        Assert.True(window.UpdateCheckButton.IsEnabled);
        Assert.True(window.AutoUpdateCheck.IsEnabled);
        Assert.Equal("Updates are checked at startup and every few hours, then downloaded in the background.", window.UpdateStatusText.Text);
        Assert.Equal([TimeSpan.FromSeconds(8)], scene.Platform.Delays);
        Assert.Empty(scene.Platform.UpdateChecks);

        scene.Platform.EndDelay(0);
        StaWindowAdminFixture.Drain();

        Assert.Equal([true], scene.Platform.UpdateChecks);
        Assert.Equal([TimeSpan.FromSeconds(8), TimeSpan.FromHours(4)], scene.Platform.Delays);
        Assert.Equal(Visibility.Visible, window.UpdateButton.Visibility);
        Assert.Equal("Update 1.9.0 ready · Restart", window.UpdateButton.Content);
        Assert.Equal(Visibility.Visible, window.UpdateRestartButton.Visibility);
        Assert.Equal("Restart to update", window.UpdateRestartButton.Content);
        Assert.Equal("Version 1.9.0 is downloaded. It installs when you restart, or the next time you close the app.", window.UpdateStatusText.Text);
    });

    [Fact]
    public void WithAutomaticUpdatesOffTheBackgroundLoopChecksNothing() => sta.Run(() =>
    {
        using var scene = Installed(autoUpdate: false).Open();

        Assert.Equal("Automatic updates are off. Nothing is checked, downloaded or installed until you press Check for updates.", scene.Window.UpdateStatusText.Text);
        scene.Platform.EndDelay(0);
        StaWindowAdminFixture.Drain();

        Assert.Empty(scene.Platform.UpdateChecks);
        Assert.Equal(2, scene.Platform.Delays.Count);
    });

    [Fact]
    public void TheBackgroundLoopEndsWhenTheWindowCloses() => sta.Run(() =>
    {
        using var scene = Installed().Open();

        scene.Close();
        scene.Platform.EndDelay(0);
        StaWindowAdminFixture.Drain();

        Assert.Empty(scene.Platform.UpdateChecks);
        Assert.Single(scene.Platform.Delays);
    });

    [Fact]
    public void AManualCheckWithAutomaticUpdatesOffOnlyLooksThenDownloadsWhenAsked() => sta.Run(() =>
    {
        using var scene = Installed(autoUpdate: false).Open();
        var window = scene.Window;
        scene.Platform.UpdateResult = new UpdateStatus(UpdateState.Available, "1.9.0");

        StaWindowAdminScene.ClickAndWait(window.UpdateCheckButton);

        Assert.Equal([false], scene.Platform.UpdateChecks);
        Assert.Equal("Version 1.9.0 is available. Download it, then restart to install it.", window.UpdateStatusText.Text);
        Assert.Equal(Visibility.Visible, window.UpdateRestartButton.Visibility);
        Assert.Equal("Download version 1.9.0", window.UpdateRestartButton.Content);
        Assert.Equal(Visibility.Collapsed, window.UpdateButton.Visibility);

        scene.Platform.UpdateResult = new UpdateStatus(UpdateState.ReadyToRestart, "1.9.0");
        StaWindowAdminScene.ClickAndWait(window.UpdateRestartButton);

        Assert.Equal([false, true], scene.Platform.UpdateChecks);
        Assert.Equal(0, scene.Platform.Restarts);
        Assert.Equal("Restart to update", window.UpdateRestartButton.Content);
        Assert.Equal("Version 1.9.0 is downloaded. It installs when you press Restart to update.", window.UpdateStatusText.Text);

        (window.Left, window.Top) = (300, 200);
        StaWindowAdminScene.Click(window.UpdateRestartButton);
        StaWindowAdminScene.Until(() => scene.Platform.Restarts == 1, "the restart into the update");

        Assert.Equal((300d, 200d), (AppSettings.Load().WindowLeft, AppSettings.Load().WindowTop));
        Assert.Equal([false, true], scene.Platform.UpdateChecks);
    });

    [Fact]
    public void AManualCheckShowsTheDownloadWhileItRunsAndReportsWhenUpToDate() => sta.Run(() =>
    {
        using var scene = Installed().Open();
        var window = scene.Window;
        scene.Platform.UpdateProgress = new UpdateStatus(UpdateState.Downloading, "1.9.0");
        scene.Platform.UpdateGate = new TaskCompletionSource();

        StaWindowAdminScene.Click(window.UpdateCheckButton);
        StaWindowAdminFixture.Drain();

        Assert.Equal("Downloading version 1.9.0…", window.UpdateStatusText.Text);
        Assert.Equal(Visibility.Collapsed, window.UpdateRestartButton.Visibility);

        scene.Platform.UpdateGate.SetResult();
        StaWindowAdminScene.Until(() => window.UpdateStatusText.Text != "Downloading version 1.9.0…", "the check to finish");

        Assert.Equal([true], scene.Platform.UpdateChecks);
        Assert.StartsWith("You are on the latest version. Checked ", window.UpdateStatusText.Text);
    });

    [Fact]
    public void AFailedManualCheckSaysWhy() => sta.Run(() =>
    {
        using var scene = Installed().Open();
        scene.Platform.UpdateResult = new UpdateStatus(UpdateState.Failed, Detail: "GitHub could not be reached.");

        StaWindowAdminScene.ClickAndWait(scene.Window.UpdateCheckButton);

        Assert.Equal("The update check failed: GitHub could not be reached.", scene.Window.UpdateStatusText.Text);
    });

    [Fact]
    public void SwitchingAutomaticUpdatesIsSavedAndTurningThemOnChecksAtOnce() => sta.Run(() =>
    {
        using var scene = Installed().Open();
        var window = scene.Window;

        window.AutoUpdateCheck.IsChecked = false;
        Assert.False(AppSettings.Load().AutoUpdate);
        Assert.Equal("Automatic updates are off. Nothing is checked, downloaded or installed until you press Check for updates.", window.UpdateStatusText.Text);
        Assert.Empty(scene.Platform.UpdateChecks);

        scene.Platform.UpdateResult = new UpdateStatus(UpdateState.ReadyToRestart, "1.9.0");
        window.AutoUpdateCheck.IsChecked = true;
        StaWindowAdminFixture.Drain();

        Assert.True(AppSettings.Load().AutoUpdate);
        Assert.Equal([true], scene.Platform.UpdateChecks);
        Assert.Equal("Version 1.9.0 is downloaded. It installs when you restart, or the next time you close the app.", window.UpdateStatusText.Text);
    });

    [Fact]
    public void SwitchingAutomaticUpdatesOnACopyThatCannotUpdateChecksNothing() => sta.Run(() =>
    {
        using var scene = new StaWindowAdminScene().WithSettings(settings => settings.AutoUpdate = false).Open();
        var window = scene.Window;
        Assert.False(window.AutoUpdateCheck.IsChecked);

        window.AutoUpdateCheck.IsChecked = true;
        StaWindowAdminFixture.Drain();

        Assert.True(AppSettings.Load().AutoUpdate);
        Assert.Empty(scene.Platform.UpdateChecks);
        Assert.Equal(SettingsLogic.NotInstalledText, window.UpdateStatusText.Text);
    });

    // ---- This PC -----------------------------------------------------------------------------

    [Fact]
    public void ForgettingThisPcIsOnlyDoneOnceConfirmed() => sta.Run(() =>
    {
        using var scene = new StaWindowAdminScene().Enroll().Open();
        var window = scene.Window;

        scene.Platform.ConfirmAnswer = false;
        window.ForgetDevice_Click(window, new RoutedEventArgs());
        StaWindowAdminFixture.Drain();

        Assert.Equal("Forget this PC", scene.Platform.Confirmations.Single().Caption);
        Assert.StartsWith("Remove the saved enrollment and operator access from this PC?", scene.Platform.Confirmations.Single().Message);
        Assert.Equal("LIVE", window.StatusText.Text);
        Assert.True(File.Exists(AppPaths.File("session.bin")));
    });

    [Fact]
    public void ForgettingThisPcClearsWhatItKnewAndReturnsToEnrollment() => sta.Run(() =>
    {
        using var scene = new StaWindowAdminScene().Enroll();
        scene.Bus.On("GET /api/mobile/admin/logs", _ => StaWindowAdminBus.Ok(BusLogJson));
        scene.Bus.AgentsJson = """[{"id":"a1","name":"prox-manager","description":"","host":"pve1","last_seen_at":null}]""";
        scene.Open();
        var window = scene.Window;
        window.SettingsNav.IsChecked = true;
        window.SettingsTabLogs.IsChecked = true;
        StaWindowAdminScene.Until(() => window.BusLogStatus.Text.Length > 0, "the bus log");
        Assert.Equal("1", window.AgentCountText.Text);

        window.ForgetDevice_Click(window, new RoutedEventArgs());
        StaWindowAdminScene.Until(() => window.StatusText.Text == "NOT ENROLLED", "the PC to be forgotten");

        Assert.False(File.Exists(AppPaths.File("session.bin")));
        Assert.False(File.Exists(AppPaths.File("operator-grant.bin")));
        Assert.Equal(Visibility.Collapsed, window.ThisPcCard.Visibility);
        Assert.Equal(string.Empty, window.DeviceLabelText.Text);
        Assert.Equal(string.Empty, window.BusLogStatus.Text);
        Assert.Empty(Items<BusLogEntry>(window.BusLogList));
        Assert.Equal("Enroll this PC to read the bus log.", window.BusLogEmpty.Text);
        Assert.Empty(window.ChannelFilter.Items);
        Assert.Empty(window.AgentList.Items);
        Assert.True(window.MonitorNav.IsChecked);
        Assert.Equal(Visibility.Visible, window.EnrollmentPanel.Visibility);
        Assert.False(window.AdminNav.IsEnabled);
    });

    // ---- Logs --------------------------------------------------------------------------------

    [Fact]
    public void TheLogsTabLoadsTheBusLog() => sta.Run(() =>
    {
        using var scene = OpenLogs();
        var window = scene.Window;

        Assert.StartsWith("StruggleBus 0.2.65, running since ", window.BusLogStatus.Text);
        Assert.Contains(". Loaded ", window.BusLogStatus.Text);
        Assert.Equal(["agent.block", "POST /api/mobile/actions"], Items<BusLogEntry>(window.BusLogList).Select(entry => entry.Event));
        Assert.Equal(Visibility.Collapsed, window.BusLogEmpty.Visibility);
        Assert.Contains("limit=500", scene.Bus.RequestsTo("GET /api/mobile/admin/logs").Select(request => request.Query));
    });

    [Fact]
    public void TheBusLogCanBeNarrowedToProblemsOrByText() => sta.Run(() =>
    {
        using var scene = OpenLogs();
        var window = scene.Window;

        window.BusLogProblems.IsChecked = true;
        Assert.Equal(["POST /api/mobile/actions"], Items<BusLogEntry>(window.BusLogList).Select(entry => entry.Event));

        window.BusLogAll.IsChecked = true;
        window.BusLogFilter.Text = "prox";
        Assert.Equal(["agent.block"], Items<BusLogEntry>(window.BusLogList).Select(entry => entry.Event));

        window.BusLogFilter.Text = "nothing like this";
        Assert.Empty(Items<BusLogEntry>(window.BusLogList));
        Assert.Equal(Visibility.Visible, window.BusLogEmpty.Visibility);
        Assert.Equal("Nothing matches.", window.BusLogEmpty.Text);
    });

    [Fact]
    public void CopyingTheBusLogCopiesTheLinesThatAreShown() => sta.Run(() =>
    {
        using var scene = OpenLogs();
        var window = scene.Window;
        window.BusLogFilter.Text = "prox";

        window.BusLogCopy_Click(window, new RoutedEventArgs());

        var line = Assert.Single(scene.Platform.Clipboard);
        Assert.Equal(Items<BusLogEntry>(window.BusLogList).Single().ToLine(), line);
        Assert.Contains("agent.block", line);

        window.BusLogFilter.Text = "nothing like this";
        window.BusLogCopy_Click(window, new RoutedEventArgs());
        Assert.Single(scene.Platform.Clipboard);
    });

    [Fact]
    public void RefreshLoadsTheBusLogAgain() => sta.Run(() =>
    {
        using var scene = OpenLogs();
        var window = scene.Window;
        scene.Bus.On("GET /api/mobile/admin/logs", _ => StaWindowAdminBus.Ok("""{"version":"0.2.66","started_at":null,"entries":[]}"""));
        var button = new Button();

        window.BusLogRefresh_Click(button, new RoutedEventArgs());
        StaWindowAdminScene.WaitFor(button);

        Assert.StartsWith("StruggleBus 0.2.66. Loaded ", window.BusLogStatus.Text);
        Assert.Equal("The bus has nothing logged.", window.BusLogEmpty.Text);
        Assert.Equal(Visibility.Visible, window.BusLogEmpty.Visibility);
    });

    [Fact]
    public void ABusTooOldToServeItsLogSaysSo() => sta.Run(() =>
    {
        using var scene = OpenLogs(_ => StaWindowAdminBus.Fail(404, "Not found."));

        Assert.Equal(SettingsLogic.BusLogUnsupported, scene.Window.BusLogStatus.Text);
        Assert.Equal("Nothing loaded.", scene.Window.BusLogEmpty.Text);
    });

    [Fact]
    public void ABusLogThatCannotBeLoadedSaysWhy() => sta.Run(() =>
    {
        using var scene = OpenLogs(_ => StaWindowAdminBus.Fail(500, "Log store is locked."));

        Assert.Equal("Could not load the bus log: StruggleBus said: Log store is locked.", scene.Window.BusLogStatus.Text);
    });

    [Fact]
    public void TheConnectionLogRecordsTheFirstContactAndCanBeCopiedAndCleared() => sta.Run(() =>
    {
        using var scene = new StaWindowAdminScene().Enroll().Open();
        var window = scene.Window;

        Assert.Equal(["Connected to the bus."], Items<ConnectionEvent>(window.ConnectionLogList).Select(entry => entry.Text));
        Assert.Equal(Visibility.Collapsed, window.ConnectionLogEmpty.Visibility);

        window.ConnectionLogCopy_Click(window, new RoutedEventArgs());
        Assert.EndsWith("  Connected to the bus.", Assert.Single(scene.Platform.Clipboard));

        window.ConnectionLogClear_Click(window, new RoutedEventArgs());
        Assert.Empty(Items<ConnectionEvent>(window.ConnectionLogList));
        Assert.Equal(Visibility.Visible, window.ConnectionLogEmpty.Visibility);

        window.ConnectionLogCopy_Click(window, new RoutedEventArgs());
        Assert.Single(scene.Platform.Clipboard);
    });

    [Fact]
    public void AMaintenanceNoticeOnTheBoardIsWrittenToTheConnectionLogOnce() => sta.Run(() =>
    {
        using var scene = new StaWindowAdminScene().Enroll();
        var notice = "Strugglebus maintenance: release 0.2.66 is scheduled for installation at 2099-01-01T00:00:00Z. Expect a short disconnect.";
        scene.Bus.MessagesJson = $"[{StaWindowAdminBus.MessageJson(5, "general", "bus", notice, DateTimeOffset.Now)}]";
        scene.Bus.On("GET /api/mobile/admin/logs", _ => StaWindowAdminBus.Ok(BusLogJson));
        scene.Open();
        var window = scene.Window;
        StaWindowAdminScene.Until(() => scene.Bus.RequestsTo("GET /api/mobile/admin/logs").Count == 1, "the bus version check");

        var log = Items<ConnectionEvent>(window.ConnectionLogList).Select(entry => entry.Text).ToList();
        Assert.Equal(2, log.Count);
        Assert.StartsWith("Maintenance announced: release 0.2.66 installs at ", log[0]);
        Assert.Equal("Connected to the bus.", log[1]);
        Assert.Equal("limit=1", scene.Bus.RequestsTo("GET /api/mobile/admin/logs").Single().Query);
    });
}
