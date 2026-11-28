using System.Windows;

namespace StruggleBusMonitor;

/// <summary>
/// Running in the system tray: with the option on, closing the window hides it and the app keeps
/// watching the bus. The tray icon opens it again or quits. See <see cref="TrayLogic"/>.
/// </summary>
public partial class MainWindow
{
    private ITrayIcon? _tray;
    private bool _quitting;
    private bool _hiddenInTray;
    private bool _showingTrayOptions;
    private WindowState _stateBeforeHide = WindowState.Normal;

    private void InitializeTray()
    {
        ShowTrayOptions();
        if (Application.Current is { } app) app.SessionEnding += (_, _) => _quitting = true;
        if (!_settings.KeepInTray) return;
        _tray = _platform.ShowTrayIcon(RestoreFromTray, QuitFromTray);
        if (TrayLogic.StartsHidden(_platform.StartArguments, _settings.KeepInTray)) StartHidden();
    }

    /// <summary>
    /// Started by Windows at sign-in, or by itself after an update while hidden: the window is
    /// never put on screen. It is shown minimised and off the taskbar for an instant, which WPF
    /// needs to finish loading it, and hidden as soon as that is done.
    /// </summary>
    private void StartHidden()
    {
        _stateBeforeHide = WindowState;
        _hiddenInTray = true;
        ShowInTaskbar = false;
        ShowActivated = false;
        WindowState = WindowState.Minimized;
        Loaded += (_, _) => HideOnceLoaded();
    }

    /// <summary>Only while still hidden: by the time it loads, the operator may already have opened it.</summary>
    private void HideOnceLoaded()
    {
        if (_hiddenInTray) Hide();
    }

    private void ShowTrayOptions()
    {
        _showingTrayOptions = true;
        KeepInTrayCheck.IsChecked = _settings.KeepInTray;
        FlashWhenAddressedCheck.IsChecked = _settings.FlashWhenAddressed;
        var canStart = TrayLogic.CanStartAtSignIn(_settings.KeepInTray, _platform.CanUpdate);
        StartAtSignInCheck.IsEnabled = canStart;
        StartAtSignInCheck.IsChecked = canStart && _platform.StartsAtSignIn;
        _showingTrayOptions = false;
    }

    internal void FlashWhenAddressed_Changed(object sender, RoutedEventArgs e)
    {
        if (!_ready || _showingTrayOptions) return;
        _settings.FlashWhenAddressed = FlashWhenAddressedCheck.IsChecked == true;
        _settings.Save();
    }

    private void KeepInTray_Changed(object sender, RoutedEventArgs e)
    {
        if (!_ready || _showingTrayOptions) return;
        _settings.KeepInTray = KeepInTrayCheck.IsChecked == true;
        _settings.Save();
        if (_settings.KeepInTray) _tray ??= _platform.ShowTrayIcon(RestoreFromTray, QuitFromTray);
        else RemoveTray();
        ShowTrayOptions();
        UpdateTrayTooltip();
    }

    /// <summary>Without the tray the app cannot start hidden, so it no longer starts at sign-in either.</summary>
    private void RemoveTray()
    {
        _tray?.Dispose();
        _tray = null;
        _platform.StartsAtSignIn = false;
    }

    private void StartAtSignIn_Changed(object sender, RoutedEventArgs e)
    {
        if (!_ready || _showingTrayOptions) return;
        _platform.StartsAtSignIn = StartAtSignInCheck.IsChecked == true;
    }

    /// <summary>True when closing the window should hide it instead; the caller then cancels the close.</summary>
    private bool HidesInsteadOfClosing() =>
        _tray is not null && !_shutdownStarted && TrayLogic.HidesOnClose(_settings.KeepInTray, _quitting);

    private void HideToTray()
    {
        _stateBeforeHide = WindowState == WindowState.Minimized ? WindowState.Normal : WindowState;
        SaveWindowPlacement();
        Hide();
        _hiddenInTray = true;
        if (_settings.TrayNoticeShown) return;
        _tray!.Notify(TrayLogic.StillRunning);
        _settings.TrayNoticeShown = true;
        _settings.Save();
    }

    internal void RestoreFromTray()
    {
        _hiddenInTray = false;
        ShowInTaskbar = true;
        ShowActivated = true;
        Show();
        WindowState = _stateBeforeHide;
        Activate();
    }

    /// <summary>Quit from the tray menu really exits, whatever the option says.</summary>
    internal void QuitFromTray()
    {
        _quitting = true;
        Close();
    }

    /// <summary>Connection state and the number waiting, and never any message text.</summary>
    private void UpdateTrayTooltip()
    {
        if (_tray is not null) _tray.Tooltip = TrayLogic.Tooltip(StatusText.Text, _waiting.Count);
    }

    /// <summary>
    /// A window nobody has open must not hold an update back. Each version is tried this way
    /// once, so an install that fails and comes back to this version does not loop.
    /// </summary>
    private async Task RestartForUpdateWhileHiddenAsync(UpdateStatus status)
    {
        if (!TrayLogic.RestartsForUpdate(_hiddenInTray, _settings.AutoUpdate, status.State) || status.Version == _settings.StartupUpdateAttempt) return;
        _settings.StartupUpdateAttempt = status.Version;
        _settings.Save();
        await StopMonitorAsync();
        _tray?.Dispose();
        _platform.RestartIntoUpdate(TrayLogic.StartArgument);
    }
}
