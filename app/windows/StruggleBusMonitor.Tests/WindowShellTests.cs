using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Media;
using Microsoft.Win32;

namespace StruggleBusMonitor.Tests;

/// <summary>The window shell: startup, enrollment, navigation, notices, placement and shutdown.</summary>
[Collection(StaWindowAdminCollection.Name)]
public class WindowShellTests(StaWindowAdminFixture sta)
{
    private static Color AppBackground => ((SolidColorBrush)Application.Current.Resources["Bg"]).Color;

    private static bool SessionSaved => File.Exists(AppPaths.File("session.bin"));

    // ---- Startup -----------------------------------------------------------------------------

    [Fact]
    public void AnUnenrolledPcSeesTheEnrollmentPanelAndCannotReachTheWorkspace() => sta.Run(() =>
    {
        using var scene = new StaWindowAdminScene().Open();
        var window = scene.Window;

        Assert.Equal("NOT ENROLLED", window.StatusText.Text);
        Assert.Equal(Visibility.Collapsed, window.StatusDetailText.Visibility);
        Assert.Equal(Visibility.Visible, window.EnrollmentPanel.Visibility);
        Assert.Equal(Visibility.Collapsed, window.WorkspacePanel.Visibility);
        Assert.False(window.HumansNav.IsEnabled);
        Assert.False(window.AdminNav.IsEnabled);
        Assert.False(window.QuickFindButton.IsEnabled);
        Assert.Equal(Visibility.Collapsed, window.ThisPcCard.Visibility);
        Assert.Empty(scene.Bus.Requests);
    });

    [Fact]
    public void AnEnrolledPcLoadsTheWorkspaceFromTheBus() => sta.Run(() =>
    {
        using var scene = new StaWindowAdminScene().Enroll().Open();
        var window = scene.Window;

        Assert.Equal("LIVE", window.StatusText.Text);
        Assert.Equal(Visibility.Visible, window.StatusDetailText.Visibility);
        Assert.Equal(Visibility.Visible, window.WorkspacePanel.Visibility);
        Assert.Equal(Visibility.Collapsed, window.EnrollmentPanel.Visibility);
        Assert.Equal(Visibility.Visible, window.MonitorPage.Visibility);
        Assert.True(window.AdminNav.IsEnabled);
        Assert.True(window.HumansNav.IsEnabled);
        Assert.True(window.QuickFindButton.IsEnabled);
        Assert.Equal(StaWindowAdminBus.DeviceLabel, window.DeviceLabelText.Text);
        Assert.Equal(Visibility.Visible, window.ThisPcCard.Visibility);
        Assert.Equal($"{StaWindowAdminBus.DeviceLabel}\n{scene.Bus.BaseUrl}", window.ThisPcText.Text);
        Assert.Equal(string.Empty, scene.Notice);
    });

    [Fact]
    public void AFrozenBusIsShownAsFrozen() => sta.Run(() =>
    {
        using var scene = new StaWindowAdminScene().Enroll();
        scene.Bus.State = "frozen";
        scene.Open();

        Assert.Equal("FROZEN", scene.Window.StatusText.Text);
    });

    [Fact]
    public void AnUnreadableSavedEnrollmentIsReportedAndThePcStartsUnenrolled() => sta.Run(() =>
    {
        using var scene = new StaWindowAdminScene();
        File.WriteAllText(AppPaths.File("session.bin"), "not a protected session");
        scene.Open();

        Assert.Equal("The saved Windows enrollment could not be read and was quarantined. Enroll this PC again.", scene.Notice);
        Assert.Equal(Visibility.Collapsed, scene.Window.NoticeActionButton.Visibility);
        Assert.Equal("NOT ENROLLED", scene.Window.StatusText.Text);
    });

    [Fact]
    public void ABusThatIsAwayAtStartupIsRetriedUntilItAnswers() => sta.Run(() =>
    {
        using var scene = new StaWindowAdminScene().Enroll();
        scene.Bus.On("GET /api/mobile/status", _ => StaWindowAdminBus.Fail(503, "Starting up."));
        scene.Open(waitForLive: false);
        var window = scene.Window;

        StaWindowAdminScene.Until(() => scene.Platform.Delays.Count == 1, "the first retry wait");
        Assert.Equal("RECONNECTING", window.StatusText.Text);
        Assert.Equal("StruggleBus said: Starting up.", window.StatusDetailText.Text);
        Assert.Equal(TimeSpan.FromSeconds(2), scene.Platform.Delays[0]);
        Assert.Equal(string.Empty, scene.Notice);

        scene.Platform.EndDelay(0);
        StaWindowAdminScene.Until(() => scene.Platform.Delays.Count == 2, "the second retry wait");
        Assert.Equal(TimeSpan.FromSeconds(4), scene.Platform.Delays[1]);

        scene.Bus.On("GET /api/mobile/status", _ => StaWindowAdminBus.Ok("""{"api_version":1,"state":"open"}"""));
        scene.Platform.EndDelay(1);
        StaWindowAdminScene.Until(() => window.StatusText.Text == "LIVE", "the bus to answer");

        var log = ((IEnumerable<ConnectionEvent>)window.ConnectionLogList.ItemsSource).Select(entry => entry.Text).ToList();
        Assert.Equal(2, log.Count);
        Assert.StartsWith("Reconnected. Offline for", log[0]);
        Assert.Equal("Bus not reachable. Trying again automatically. (StruggleBus said: Starting up.)", log[1]);
    });

    [Fact]
    public void RetryingStopsOnceTheWindowIsClosing() => sta.Run(() =>
    {
        using var scene = new StaWindowAdminScene().Enroll();
        scene.Bus.On("GET /api/mobile/status", _ => StaWindowAdminBus.Fail(503, "Starting up."));
        scene.Open(waitForLive: false);
        StaWindowAdminScene.Until(() => scene.Platform.Delays.Count == 1, "the first retry wait");

        scene.Close();
        var before = scene.Bus.Requests.Count;
        scene.Platform.EndDelay(0);
        StaWindowAdminFixture.Drain();

        Assert.Single(scene.Platform.Delays);
        Assert.Equal(before, scene.Bus.Requests.Count);
    });

    [Fact]
    public void ARevokedCredentialAtStartupOffersToEnrollAgain() => sta.Run(() =>
    {
        using var scene = new StaWindowAdminScene().Enroll();
        scene.Bus.On("GET /api/mobile/snapshot", _ => StaWindowAdminBus.Fail(401, "Credential is not active."));
        scene.Open(waitForLive: false);
        var window = scene.Window;
        StaWindowAdminScene.Until(() => window.StatusText.Text == "REVOKED", "the revocation to be shown");

        Assert.Equal(BusErrors.CredentialInactive + " Enroll this PC again to continue.", scene.Notice);
        Assert.Equal(Visibility.Visible, window.NoticeActionButton.Visibility);
        Assert.Equal("Enroll again", window.NoticeActionButton.Content);
        Assert.Empty(scene.Platform.Delays);

        StaWindowAdminScene.Click(window.NoticeActionButton);
        StaWindowAdminScene.Until(() => window.StatusText.Text == "NOT ENROLLED", "the PC to be forgotten");

        Assert.Equal(string.Empty, scene.Notice);
        Assert.False(SessionSaved);
        Assert.Equal(Visibility.Visible, window.EnrollmentPanel.Visibility);
    });

    [Fact]
    public void AnyOtherStartupFailureIsReportedOnceAndNotRetried() => sta.Run(() =>
    {
        using var scene = new StaWindowAdminScene().Enroll();
        scene.Bus.On("GET /api/mobile/snapshot", _ => StaWindowAdminBus.Fail(403, "Device is not allowed."));
        scene.Open(waitForLive: false);
        StaWindowAdminScene.Until(() => scene.Notice.Length > 0, "the failure notice");

        Assert.Equal("StruggleBus said: Device is not allowed.", scene.Notice);
        Assert.Equal("CONNECTING", scene.Window.StatusText.Text);
        Assert.Empty(scene.Platform.Delays);
    });

    // ---- Enrollment --------------------------------------------------------------------------

    [Fact]
    public void PastingAnEnrollmentEnrollsThePcAndOpensTheWorkspace() => sta.Run(() =>
    {
        using var scene = new StaWindowAdminScene().Open();
        var window = scene.Window;
        scene.Bus.On("POST /api/mobile/enrollments/redeem", _ => StaWindowAdminBus.Ok(
            """{"device_id":"device-9","device_label":"new-pc","credential_secret":"fresh-credential"}"""));
        window.EnrollmentBox.Text = scene.Bus.EnrollmentPayload();

        StaWindowAdminScene.ClickAndWait(window.EnrollButton);

        Assert.Equal(string.Empty, scene.Notice);
        Assert.Equal("LIVE", window.StatusText.Text);
        Assert.Equal("new-pc", window.DeviceLabelText.Text);
        Assert.Equal(string.Empty, window.EnrollmentBox.Text);
        Assert.Equal(Visibility.Visible, window.WorkspacePanel.Visibility);
        Assert.Equal(Visibility.Collapsed, window.EnrollmentPanel.Visibility);
        Assert.True(SessionSaved);
    });

    [Fact]
    public void ABadEnrollmentIsExplainedInTheNoticeBarAndCanBeDismissed() => sta.Run(() =>
    {
        using var scene = new StaWindowAdminScene().Open();
        var window = scene.Window;
        window.EnrollmentBox.Text = "{ not json";

        StaWindowAdminScene.ClickAndWait(window.EnrollButton);

        Assert.Equal(BusApi.IncompleteEnrollment, scene.Notice);
        Assert.True(window.EnrollButton.IsEnabled);
        Assert.Equal("{ not json", window.EnrollmentBox.Text);
        Assert.Equal("NOT ENROLLED", window.StatusText.Text);

        window.NoticeDismiss_Click(window, new RoutedEventArgs());
        Assert.Equal(Visibility.Collapsed, window.NoticeBar.Visibility);
    });

    [Fact]
    public void AButtonThatIsAlreadyWorkingCannotBeFiredTwice() => sta.Run(() =>
    {
        using var scene = new StaWindowAdminScene().Open();
        var window = scene.Window;
        window.EnrollmentBox.Text = "{ not json";
        window.EnrollButton.IsEnabled = false;

        StaWindowAdminScene.Click(window.EnrollButton);

        Assert.Equal(string.Empty, scene.Notice);
        Assert.False(window.EnrollButton.IsEnabled);
    });

    // ---- Navigation --------------------------------------------------------------------------

    [Fact]
    public void EachNavigationItemShowsItsOwnPage() => sta.Run(() =>
    {
        using var scene = new StaWindowAdminScene().Enroll().Open();
        var window = scene.Window;

        window.HumansNav.IsChecked = true;
        Assert.Equal(Visibility.Visible, window.HumansPage.Visibility);
        Assert.Equal(Visibility.Collapsed, window.MonitorPage.Visibility);
        Assert.Equal(Visibility.Visible, window.WorkspacePanel.Visibility);

        window.AdminNav.IsChecked = true;
        Assert.Equal(Visibility.Visible, window.AdminPage.Visibility);
        Assert.Equal(Visibility.Collapsed, window.HumansPage.Visibility);
        StaWindowAdminScene.Until(() => window.AdminDevicesSummary.Text.Length > 0, "the Admin lists");

        window.SettingsNav.IsChecked = true;
        Assert.Equal(Visibility.Visible, window.SettingsPage.Visibility);
        Assert.Equal(Visibility.Collapsed, window.WorkspacePanel.Visibility);
        Assert.Equal(Visibility.Collapsed, window.AdminPage.Visibility);

        window.MonitorNav.IsChecked = true;
        Assert.Equal(Visibility.Collapsed, window.SettingsPage.Visibility);
        Assert.Equal(Visibility.Visible, window.WorkspacePanel.Visibility);
        Assert.Equal(Visibility.Visible, window.MonitorPage.Visibility);
    });

    [Fact]
    public void SettingsReplacesTheEnrollmentPanelOnAnUnenrolledPc() => sta.Run(() =>
    {
        using var scene = new StaWindowAdminScene().Open();
        var window = scene.Window;

        window.SettingsNav.IsChecked = true;
        Assert.Equal(Visibility.Visible, window.SettingsPage.Visibility);
        Assert.Equal(Visibility.Collapsed, window.EnrollmentPanel.Visibility);

        window.MonitorNav.IsChecked = true;
        Assert.Equal(Visibility.Visible, window.EnrollmentPanel.Visibility);
        Assert.Equal(Visibility.Collapsed, window.WorkspacePanel.Visibility);
    });

    [Fact]
    public void TheQuickFindShortcutsOpenAndCloseTheOverlay() => sta.Run(() =>
    {
        using var scene = new StaWindowAdminScene().Enroll().Open();
        var window = scene.Window;

        Assert.False(window.RunShortcut(ShortcutAction.None));
        Assert.Equal(Visibility.Collapsed, window.QuickFindOverlay.Visibility);

        Assert.True(window.RunShortcut(ShortcutAction.OpenQuickFind));
        Assert.Equal(Visibility.Visible, window.QuickFindOverlay.Visibility);

        Assert.True(window.RunShortcut(ShortcutAction.CloseQuickFind));
        Assert.Equal(Visibility.Collapsed, window.QuickFindOverlay.Visibility);
    });

    [Fact]
    public void EscapeClosesQuickFindAndIsOtherwiseLeftAlone() => sta.Run(() =>
    {
        using var scene = new StaWindowAdminScene().Enroll().Open();
        var window = scene.Window;
        var source = HwndSource.FromHwnd(new WindowInteropHelper(window).EnsureHandle());
        KeyEventArgs Press(Key key)
        {
            var press = new KeyEventArgs(Keyboard.PrimaryDevice, source, 0, key) { RoutedEvent = Keyboard.PreviewKeyDownEvent };
            window.RaiseEvent(press);
            return press;
        }

        Assert.False(Press(Key.Escape).Handled);

        window.RunShortcut(ShortcutAction.OpenQuickFind);
        Assert.False(Press(Key.A).Handled);
        Assert.Equal(Visibility.Visible, window.QuickFindOverlay.Visibility);

        Assert.True(Press(Key.Escape).Handled);
        Assert.Equal(Visibility.Collapsed, window.QuickFindOverlay.Visibility);
    });

    // ---- Helpers shared with the other pages -------------------------------------------------

    [Fact]
    public void TheFirstScrollViewerInATreeIsFoundHoweverDeep() => sta.Run(() =>
    {
        var direct = new ScrollViewer();
        var nested = new ScrollViewer();
        var deep = new Grid();
        deep.Children.Add(new TextBlock());
        deep.Children.Add(new Border { Child = new Border { Child = nested } });

        Assert.Same(direct, MainWindow.FindScrollViewer(new Border { Child = direct }));
        Assert.Same(nested, MainWindow.FindScrollViewer(deep));
        Assert.Null(MainWindow.FindScrollViewer(new Border { Child = new TextBlock() }));
    });

    [Fact]
    public void ABusyClipboardIsReportedInsteadOfFailing() => sta.Run(() =>
    {
        using var scene = new StaWindowAdminScene().Open();
        var window = scene.Window;
        window.EnrollResultSecret.Text = "one-time-secret";

        window.EnrollCopy_Click(window, new RoutedEventArgs());
        Assert.Equal(["one-time-secret"], scene.Platform.Clipboard);
        Assert.Equal(string.Empty, scene.Notice);

        scene.Platform.ClipboardBusy = true;
        window.EnrollCopy_Click(window, new RoutedEventArgs());
        Assert.Equal("The clipboard is busy. Try copying again.", scene.Notice);
        Assert.Single(scene.Platform.Clipboard);
    });

    [Fact]
    public void FlashingTheTaskbarLeavesAWindowInTheBackgroundAlone() => sta.Run(() =>
    {
        using var scene = new StaWindowAdminScene().Open();
        var window = scene.Window;

        window.FlashTaskbar();
        _ = new WindowInteropHelper(window).EnsureHandle();
        window.FlashTaskbar();

        Assert.False(window.IsActive);
        Assert.False(window.IsVisible);
    });

    [Fact]
    public void AFailureTheBackgroundLoopsWillRetryShowsAsReconnectingAndIsLoggedOnce() => sta.Run(() =>
    {
        using var scene = new StaWindowAdminScene().Enroll().Open();
        var window = scene.Window;

        StaWindowAdminFixture.Await(window.ShowDegradedStateAsync("Snapshot check failed: timed out"), "the degraded state");
        StaWindowAdminFixture.Await(window.ShowDegradedStateAsync("Snapshot check failed: still down"), "the degraded state");

        Assert.Equal("RECONNECTING", window.StatusText.Text);
        Assert.Equal("Snapshot check failed: still down", window.StatusDetailText.Text);
        var log = ((IEnumerable<ConnectionEvent>)window.ConnectionLogList.ItemsSource).Select(entry => entry.Text).ToList();
        Assert.Equal(
            ["Bus not reachable. Trying again automatically. (Snapshot check failed: timed out)", "Connected to the bus."],
            log);
    });

    // ---- Theme -------------------------------------------------------------------------------

    [Fact]
    public void TheSavedThemeIsAppliedAtStartup() => sta.Run(() =>
    {
        using var scene = new StaWindowAdminScene()
            .WithSettings(settings => (settings.Mode, settings.LightTheme) = (AppThemeMode.Light, "rose-pine"))
            .Open();
        new WindowInteropHelper(scene.Window).EnsureHandle();

        Assert.Equal(Themes.Parse("#faf4ed"), AppBackground);
        Assert.True(scene.Window.ModeLight.IsChecked);
    });

    [Fact]
    public void MatchWindowsFollowsTheWindowsPreferenceWhenItChanges() => sta.Run(() =>
    {
        using var scene = new StaWindowAdminScene().WithSettings(settings => settings.Mode = AppThemeMode.System).Open();
        var window = scene.Window;
        Assert.True(window.ModeSystem.IsChecked);
        Assert.Equal(Themes.Parse("#05182e"), AppBackground);

        scene.Platform.PrefersLight = true;
        window.OnWindowsPreferenceChanged(this, new UserPreferenceChangedEventArgs(UserPreferenceCategory.Color));
        StaWindowAdminFixture.Drain();
        Assert.Equal(Themes.Parse("#05182e"), AppBackground);

        window.OnWindowsPreferenceChanged(this, new UserPreferenceChangedEventArgs(UserPreferenceCategory.General));
        StaWindowAdminFixture.Drain();
        Assert.Equal(Themes.Parse("#eff1f5"), AppBackground);
    });

    [Fact]
    public void AFixedThemeIgnoresTheWindowsPreference() => sta.Run(() =>
    {
        using var scene = new StaWindowAdminScene().Open();

        scene.Platform.PrefersLight = true;
        scene.Window.OnWindowsPreferenceChanged(this, new UserPreferenceChangedEventArgs(UserPreferenceCategory.General));
        StaWindowAdminFixture.Drain();

        Assert.Equal(Themes.Parse("#05182e"), AppBackground);
    });

    // ---- Placement and shutdown --------------------------------------------------------------

    [Fact]
    public void TheSavedPlacementIsRestoredWhenItIsStillOnAScreen() => sta.Run(() =>
    {
        using var scene = new StaWindowAdminScene()
            .WithSettings(settings => (settings.WindowLeft, settings.WindowTop, settings.WindowWidth, settings.WindowHeight) = (120, 60, 1000, 700))
            .Open();
        var window = scene.Window;

        Assert.Equal(WindowStartupLocation.Manual, window.WindowStartupLocation);
        Assert.Equal((120d, 60d, 1000d, 700d), (window.Left, window.Top, window.Width, window.Height));
        Assert.Equal(WindowState.Normal, window.WindowState);
    });

    [Fact]
    public void APlacementOnAScreenThatIsGoneIsNotRestored() => sta.Run(() =>
    {
        using var scene = new StaWindowAdminScene()
            .WithSettings(settings => (settings.WindowLeft, settings.WindowTop, settings.WindowWidth, settings.WindowHeight) = (2500, 60, 1000, 700))
            .Open();
        var window = scene.Window;

        Assert.Equal(WindowStartupLocation.CenterScreen, window.WindowStartupLocation);
        Assert.Equal((1280d, 820d), (window.Width, window.Height));
        Assert.NotEqual(2500, window.Left);
    });

    [Fact]
    public void AMaximizedWindowComesBackMaximizedAndKeepsItsRestoredSize() => sta.Run(() =>
    {
        using var scene = new StaWindowAdminScene()
            .WithSettings(settings =>
            {
                (settings.WindowLeft, settings.WindowTop, settings.WindowWidth, settings.WindowHeight) = (120, 60, 1000, 700);
                settings.WindowMaximized = true;
            })
            .Open();

        Assert.Equal(WindowState.Maximized, scene.Window.WindowState);

        // Never shown, so Windows has no restore bounds for it: nothing is saved over the old ones.
        scene.Close();
        var saved = AppSettings.Load();
        Assert.Equal((120d, 60d, 1000d, 700d), (saved.WindowLeft, saved.WindowTop, saved.WindowWidth, saved.WindowHeight));
        Assert.True(saved.WindowMaximized);
    });

    [Fact]
    public void ClosingSavesThePlacementAndInstallsADownloadedUpdate() => sta.Run(() =>
    {
        using var scene = new StaWindowAdminScene().Open();
        (scene.Window.Left, scene.Window.Top, scene.Window.Width, scene.Window.Height) = (200, 150, 1100, 720);

        scene.Close();

        var saved = AppSettings.Load();
        Assert.Equal((200d, 150d, 1100d, 720d), (saved.WindowLeft, saved.WindowTop, saved.WindowWidth, saved.WindowHeight));
        Assert.False(saved.WindowMaximized);
        Assert.Equal(1, scene.Platform.AppliedOnExit);
    });

    [Fact]
    public void ClosingWithAutomaticUpdatesOffInstallsNothing() => sta.Run(() =>
    {
        using var scene = new StaWindowAdminScene().WithSettings(settings => settings.AutoUpdate = false).Open();

        scene.Close();

        Assert.Equal(0, scene.Platform.AppliedOnExit);
    });

    [Fact]
    public void ClosingAnEnrolledWindowStopsTheLiveLoopsFirstAndIgnoresASecondClose() => sta.Run(() =>
    {
        using var scene = new StaWindowAdminScene().Enroll().Open();
        var window = scene.Window;
        var closed = 0;
        window.Closed += (_, _) => closed++;

        window.Close();
        Assert.Equal(0, closed);
        window.Close();
        Assert.Equal(0, closed);
        StaWindowAdminScene.Until(() => closed > 0, "the window to close");
        StaWindowAdminFixture.Drain();

        Assert.Equal(1, closed);
        Assert.Equal(1, scene.Platform.AppliedOnExit);
    });
}
