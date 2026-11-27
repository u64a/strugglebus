using System.Windows;

namespace StruggleBusMonitor.Tests;

public sealed class TrayLogicTests
{
    [Fact]
    public void ClosingHidesOnlyWithTheOptionOnAndNotWhenReallyQuitting()
    {
        Assert.True(TrayLogic.HidesOnClose(keepInTray: true, quitting: false));
        Assert.False(TrayLogic.HidesOnClose(keepInTray: true, quitting: true));
        Assert.False(TrayLogic.HidesOnClose(keepInTray: false, quitting: false));
    }

    [Fact]
    public void TheAppStartsHiddenOnlyWhenToldToAndTheOptionIsStillOn()
    {
        Assert.True(TrayLogic.StartsHidden(["app.exe", "--tray"], keepInTray: true));
        Assert.True(TrayLogic.StartsHidden(["--TRAY"], keepInTray: true));
        Assert.False(TrayLogic.StartsHidden(["app.exe"], keepInTray: true));
        // The option was turned off after Windows was told to start the app this way.
        Assert.False(TrayLogic.StartsHidden(["--tray"], keepInTray: false));
    }

    [Fact]
    public void TheTooltipSaysTheStateAndHowManyAreWaitingAndNothingElse()
    {
        Assert.Equal("StruggleBus Monitor: LIVE", TrayLogic.Tooltip("LIVE", 0));
        Assert.Equal("StruggleBus Monitor: OFFLINE, 3 waiting on you", TrayLogic.Tooltip(" OFFLINE ", 3));
        Assert.Equal("StruggleBus Monitor: starting", TrayLogic.Tooltip("", 0));
        Assert.Equal(120, TrayLogic.Tooltip(new string('x', 300), 2).Length);
    }

    [Fact]
    public void WindowsIsToldToStartThisCopyInTheTray() =>
        Assert.Equal("\"C:\\Users\\a b\\app\\StruggleBusMonitor.exe\" --tray", TrayLogic.RunCommand(@"C:\Users\a b\app\StruggleBusMonitor.exe"));

    [Fact]
    public void StartingAtSignInNeedsTheTrayOptionAndAnInstalledCopy()
    {
        Assert.True(TrayLogic.CanStartAtSignIn(keepInTray: true, installed: true));
        Assert.False(TrayLogic.CanStartAtSignIn(keepInTray: false, installed: true));
        Assert.False(TrayLogic.CanStartAtSignIn(keepInTray: true, installed: false));
    }

    [Fact]
    public void AHiddenAppRestartsForADownloadedUpdateOnlyWithAutomaticUpdatesOn()
    {
        Assert.True(TrayLogic.RestartsForUpdate(hiddenInTray: true, automatic: true, UpdateState.ReadyToRestart));
        Assert.False(TrayLogic.RestartsForUpdate(hiddenInTray: false, automatic: true, UpdateState.ReadyToRestart));
        Assert.False(TrayLogic.RestartsForUpdate(hiddenInTray: true, automatic: false, UpdateState.ReadyToRestart));
        Assert.False(TrayLogic.RestartsForUpdate(hiddenInTray: true, automatic: true, UpdateState.Downloading));
    }

    [Fact]
    public void AnAppStartedInTheTrayComesBackInTheTrayAfterUpdating()
    {
        Assert.Equal(["--tray"], App.TrayArguments(["x", "--Tray"]));
        Assert.Empty(App.TrayArguments(["x"]));
    }
}

/// <summary>The tray option on the real window.</summary>
[Collection(StaWindowAdminCollection.Name)]
public class TrayWindowTests(StaWindowAdminFixture sta)
{
    private static StaWindowAdminScene InTray(bool installed = true, Action<AppSettings>? more = null)
    {
        var scene = new StaWindowAdminScene().WithSettings(settings =>
        {
            settings.KeepInTray = true;
            more?.Invoke(settings);
        });
        scene.Platform.Installed = installed;
        return scene;
    }

    [Fact]
    public void ByDefaultThereIsNoTrayIconAndClosingExits() => sta.Run(() =>
    {
        using var scene = new StaWindowAdminScene().Open();
        var window = scene.Window;
        var closed = false;
        window.Closed += (_, _) => closed = true;

        Assert.False(window.KeepInTrayCheck.IsChecked);
        Assert.False(window.StartAtSignInCheck.IsEnabled);
        Assert.Empty(scene.Platform.TrayIcons);

        window.Close();
        StaWindowAdminScene.Until(() => closed, "the window to close");
    });

    [Fact]
    public void TurningTheOptionOnShowsTheIconAndTurningItOffRemovesItAndTheSignInStart() => sta.Run(() =>
    {
        using var scene = new StaWindowAdminScene();
        scene.Platform.Installed = true;
        var window = scene.Open().Window;

        window.KeepInTrayCheck.IsChecked = true;

        var icon = Assert.Single(scene.Platform.TrayIcons);
        Assert.True(AppSettings.Load().KeepInTray);
        Assert.True(window.StartAtSignInCheck.IsEnabled);
        Assert.False(window.StartAtSignInCheck.IsChecked);
        Assert.StartsWith("StruggleBus Monitor: ", icon.Tooltip);

        window.StartAtSignInCheck.IsChecked = true;
        Assert.True(scene.Platform.StartsAtSignIn);
        window.StartAtSignInCheck.IsChecked = false;
        Assert.False(scene.Platform.StartsAtSignIn);
        window.StartAtSignInCheck.IsChecked = true;

        window.KeepInTrayCheck.IsChecked = false;

        Assert.True(icon.Disposed);
        Assert.False(AppSettings.Load().KeepInTray);
        Assert.False(scene.Platform.StartsAtSignIn);
        Assert.False(window.StartAtSignInCheck.IsEnabled);
        Assert.False(window.StartAtSignInCheck.IsChecked);
    });

    [Fact]
    public void ACopyThatWasNotInstalledCannotStartAtSignIn() => sta.Run(() =>
    {
        using var scene = InTray(installed: false).Open();

        Assert.True(scene.Window.KeepInTrayCheck.IsChecked);
        Assert.False(scene.Window.StartAtSignInCheck.IsEnabled);
        Assert.Single(scene.Platform.TrayIcons);
    });

    [Fact]
    public void ClosingHidesTheWindowSaysSoOnceAndTheIconBringsItBack() => sta.Run(() =>
    {
        using var scene = InTray().Open();
        var window = scene.Window;
        var icon = Assert.Single(scene.Platform.TrayIcons);
        var closed = false;
        window.Closed += (_, _) => closed = true;

        window.Close();
        StaWindowAdminFixture.Drain();

        Assert.False(closed);
        Assert.Equal(Visibility.Hidden, window.Visibility);
        Assert.Equal([TrayLogic.StillRunning], icon.Notices);
        Assert.True(AppSettings.Load().TrayNoticeShown);
        Assert.False(icon.Disposed);

        icon.Open();
        Assert.Equal(Visibility.Visible, window.Visibility);
        Assert.True(window.ShowInTaskbar);

        window.Close();
        StaWindowAdminFixture.Drain();

        Assert.Equal(Visibility.Hidden, window.Visibility);
        Assert.Single(icon.Notices);
    });

    [Fact]
    public void QuitFromTheIconReallyExitsAndRemovesIt() => sta.Run(() =>
    {
        using var scene = InTray().Open();
        var icon = Assert.Single(scene.Platform.TrayIcons);
        var closed = false;
        scene.Window.Closed += (_, _) => closed = true;

        icon.Quit();
        StaWindowAdminScene.Until(() => closed, "the window to close");

        Assert.True(icon.Disposed);
    });

    [Fact]
    public void StartedInTheTrayTheWindowIsKeptOffScreenUntilOpened() => sta.Run(() =>
    {
        using var scene = InTray();
        scene.Platform.StartArgumentList.Add("--tray");
        var window = scene.Open().Window;

        Assert.False(window.ShowInTaskbar);
        Assert.False(window.ShowActivated);
        Assert.Equal(WindowState.Minimized, window.WindowState);

        scene.Platform.TrayIcons[0].Open();

        Assert.Equal(Visibility.Visible, window.Visibility);
        Assert.True(window.ShowInTaskbar);
        Assert.Equal(WindowState.Normal, window.WindowState);
    });

    [Fact]
    public void TheStartArgumentIsIgnoredOnceTheOptionIsOff() => sta.Run(() =>
    {
        using var scene = new StaWindowAdminScene();
        scene.Platform.StartArgumentList.Add("--tray");
        var window = scene.Open().Window;

        Assert.True(window.ShowInTaskbar);
        Assert.Empty(scene.Platform.TrayIcons);
    });

    [Fact]
    public void AHiddenAppInstallsADownloadedUpdateAtOnceAndComesBackInTheTray() => sta.Run(() =>
    {
        using var scene = InTray();
        scene.Platform.UpdateResult = new UpdateStatus(UpdateState.ReadyToRestart, "1.9.0");
        var window = scene.Open().Window;
        window.Close();
        StaWindowAdminFixture.Drain();

        scene.Platform.EndDelay(0);
        StaWindowAdminScene.Until(() => scene.Platform.Restarts == 1, "the restart for the update");

        Assert.Equal(["--tray"], Assert.Single(scene.Platform.RestartArguments));
        Assert.Equal("1.9.0", AppSettings.Load().StartupUpdateAttempt);
        Assert.True(scene.Platform.TrayIcons[0].Disposed);
    });

    [Fact]
    public void AnUpdateThatAlreadyFailedThisWayIsNotTriedAgainInALoop() => sta.Run(() =>
    {
        using var scene = InTray(more: settings => settings.StartupUpdateAttempt = "1.9.0");
        scene.Platform.UpdateResult = new UpdateStatus(UpdateState.ReadyToRestart, "1.9.0");
        var window = scene.Open().Window;
        window.Close();
        StaWindowAdminFixture.Drain();

        scene.Platform.EndDelay(0);
        StaWindowAdminScene.Until(() => scene.Platform.UpdateChecks.Count == 1, "the update check");
        StaWindowAdminFixture.Drain();

        Assert.Equal(0, scene.Platform.Restarts);
    });

    [Fact]
    public void AnOpenWindowIsNeverRestartedUnderTheOperator() => sta.Run(() =>
    {
        using var scene = InTray();
        scene.Platform.UpdateResult = new UpdateStatus(UpdateState.ReadyToRestart, "1.9.0");
        scene.Open();

        scene.Platform.EndDelay(0);
        StaWindowAdminScene.Until(() => scene.Platform.UpdateChecks.Count == 1, "the update check");
        StaWindowAdminFixture.Drain();

        Assert.Equal(0, scene.Platform.Restarts);
    });

    [Fact]
    public void AppearanceHasItsOwnTabAndGeneralKeepsTheBehaviourOptions() => sta.Run(() =>
    {
        using var scene = new StaWindowAdminScene().Open();
        var window = scene.Window;

        Assert.Equal(Visibility.Visible, window.SettingsGeneralPanel.Visibility);
        Assert.Equal(Visibility.Collapsed, window.SettingsAppearancePanel.Visibility);

        window.SettingsTabAppearance.IsChecked = true;

        Assert.Equal(Visibility.Visible, window.SettingsAppearancePanel.Visibility);
        Assert.Equal(Visibility.Collapsed, window.SettingsGeneralPanel.Visibility);
        Assert.Equal(Visibility.Collapsed, window.SettingsLogsPanel.Visibility);
        Assert.True(IsInside(window.DarkThemeList, window.SettingsAppearancePanel));
        Assert.True(IsInside(window.LightThemeList, window.SettingsAppearancePanel));
        Assert.True(IsInside(window.ModeDark, window.SettingsAppearancePanel));
        Assert.True(IsInside(window.KeepInTrayCheck, window.SettingsGeneralPanel));
        Assert.True(IsInside(window.AutoUpdateCheck, window.SettingsGeneralPanel));
        Assert.False(IsInside(window.DarkThemeList, window.SettingsGeneralPanel));
    });

    /// <summary>Whether a control sits somewhere inside a panel, going by how the page is written.</summary>
    private static bool IsInside(DependencyObject control, DependencyObject panel)
    {
        for (var parent = LogicalTreeHelper.GetParent(control); parent is not null; parent = LogicalTreeHelper.GetParent(parent))
        {
            if (ReferenceEquals(parent, panel)) return true;
        }
        return false;
    }
}
