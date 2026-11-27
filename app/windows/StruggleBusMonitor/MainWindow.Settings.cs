using System.Windows;
using System.Windows.Controls;

namespace StruggleBusMonitor;

/// <summary>Settings page: themes, updates, forgetting this PC's enrollment, and the logs.</summary>
public partial class MainWindow
{
    private static readonly TimeSpan UpdateCheckInterval = TimeSpan.FromHours(4);
    private const int BusLogLimit = 500;
    private List<ThemeCard> _themeCards = [];
    private BusLog? _busLog;
    private UpdateStatus _updateStatus = new(UpdateState.UpToDate);

    private void InitializeSettings()
    {
        _themeCards = Themes.All.Select(palette => new ThemeCard(palette)).ToList();
        DarkThemeList.ItemsSource = _themeCards.Where(card => !card.Palette.IsLight).ToList();
        LightThemeList.ItemsSource = _themeCards.Where(card => card.Palette.IsLight).ToList();
        (_settings.Mode switch
        {
            AppThemeMode.Light => ModeLight,
            AppThemeMode.System => ModeSystem,
            _ => ModeDark
        }).IsChecked = true;
        UpdateThemeSelection();

        var architecture = System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture.ToString().ToLowerInvariant();
        VersionText.Text = $"Version {_platform.CurrentVersion} · {architecture}";
        UpdateSourceText.Text = $"Updates are downloaded from {AppUpdater.ReleasesUrl}";
        AutoUpdateCheck.IsChecked = _settings.AutoUpdate;
        AutoUpdateCheck.IsEnabled = _platform.CanUpdate;
        ShowUpdateStatus(SettingsLogic.InitialStatus(_platform.CanUpdate), checkedNow: false);
        ShowConnectionLog();
        ShowBusLog();
    }

    // ---- Logs --------------------------------------------------------------------------------

    private void SettingsTab_Checked(object sender, RoutedEventArgs e)
    {
        if (!_ready) return;
        SettingsGeneralPanel.Visibility = VisibleWhen(SettingsTabGeneral.IsChecked == true);
        SettingsAppearancePanel.Visibility = VisibleWhen(SettingsTabAppearance.IsChecked == true);
        SettingsLogsPanel.Visibility = VisibleWhen(SettingsTabLogs.IsChecked == true);
        OnSettingsPageShown();
    }

    private void OnSettingsPageShown()
    {
        if (!BusLogShowing) return;
        _ = LoadBusLogAsync();
        _ = KeepBusLogFreshAsync();
    }

    private bool BusLogShowing =>
        !_shutdownStarted && IsEnrolled && SettingsTabLogs.IsChecked == true && SettingsPage.Visibility == Visibility.Visible;

    /// <summary>
    /// Reloads the bus log every half minute for as long as the Logs tab is what is showing, so a
    /// problem appears without anyone pressing Refresh. It stops by itself when the tab is left.
    /// </summary>
    private async Task KeepBusLogFreshAsync()
    {
        if (_busLogRefreshing) return;
        _busLogRefreshing = true;
        await WindowLogic.RepeatAsync(
            _platform.Delay, SettingsLogic.BusLogRefreshEvery, SettingsLogic.BusLogRefreshEvery, () => !BusLogShowing, LoadBusLogAsync);
        _busLogRefreshing = false;
    }

    private bool _busLogRefreshing;

    /// <summary>Writes a connection event to the log and the Logs tab. Returns false for null or a repeat.</summary>
    private bool NoteConnection(ConnectionEvent? entry)
    {
        if (!_connectionLog.Add(entry)) return false;
        ShowConnectionLog();
        return true;
    }

    /// <summary>The bus answered. After an outage, or on first contact, also see which version came back.</summary>
    private void NoteConnected()
    {
        if (NoteConnection(_tracker.ReportUp(DateTimeOffset.Now))) _ = NoteBusVersionAsync();
    }

    private void NoteMaintenance(BusMessage message)
    {
        // A notice already written before this app was restarted is not written twice.
        var entry = _tracker.ReportMessage(message, DateTimeOffset.Now);
        if (SettingsLogic.IsNewNotice(entry, _connectionLog.Events)) NoteConnection(entry);
    }

    private async Task NoteBusVersionAsync()
    {
        try
        {
            var log = await _api.GetBusLogAsync(1, CancellationToken.None);
            NoteConnection(_tracker.ReportBus(log.Version, log.StartedAt, DateTimeOffset.Now));
        }
        catch (Exception)
        {
            // A bus older than 0.2.65 cannot say; the connection events are still logged.
        }
    }

    private void ShowConnectionLog()
    {
        ConnectionLogList.ItemsSource = _connectionLog.Events.ToList();
        ConnectionLogEmpty.Visibility = VisibleWhen(_connectionLog.Events.Count == 0);
    }

    internal void ConnectionLogCopy_Click(object sender, RoutedEventArgs e)
    {
        if (_connectionLog.Events.Count > 0) CopyToClipboard(_connectionLog.ToText());
    }

    internal void ConnectionLogClear_Click(object sender, RoutedEventArgs e)
    {
        _connectionLog.Clear();
        ShowConnectionLog();
    }

    internal async void BusLogRefresh_Click(object sender, RoutedEventArgs e) => await RunBusy(LoadBusLogAsync, sender);

    /// <summary>
    /// The whole log when this PC holds operator access and the bus offers it: that adds what worker
    /// hosts reported and the bus's security events. Otherwise the log any enrolled device may read.
    /// </summary>
    private async Task<BusLog> ReadBusLogAsync()
    {
        if (_api.HasOperatorGrant())
        {
            try
            {
                return await _api.GetFullBusLogAsync(BusLogLimit, CancellationToken.None);
            }
            catch (BusApiException error) when (SettingsLogic.FullLogUnavailable(error.StatusCode) || AdminFlow.IsLegacyBus(error))
            {
                // An older bus, or operator access that is no longer good: the ordinary log still is.
            }
        }
        return await _api.GetBusLogAsync(BusLogLimit, CancellationToken.None);
    }

    private async Task LoadBusLogAsync()
    {
        if (!IsEnrolled) return;
        try
        {
            _busLog = await ReadBusLogAsync();
            BusLogStatus.Text = SettingsLogic.BusLogStatus(_busLog, DateTime.Now);
        }
        catch (BusApiException error) when (AdminFlow.IsLegacyBus(error))
        {
            _busLog = null;
            BusLogStatus.Text = SettingsLogic.BusLogUnsupported;
        }
        catch (Exception error)
        {
            BusLogStatus.Text = $"Could not load the bus log: {error.Message}";
        }
        ShowBusLog();
    }

    private IReadOnlyList<BusLogEntry> ShownBusLog() =>
        BusLog.Filter(_busLog?.Entries ?? [], BusLogProblems.IsChecked == true, BusLogFilter.Text);

    private void ShowBusLog()
    {
        var shown = ShownBusLog();
        BusLogList.ItemsSource = shown;
        BusLogEmpty.Visibility = VisibleWhen(shown.Count == 0);
        BusLogEmpty.Text = SettingsLogic.BusLogEmptyText(IsEnrolled, _busLog);
    }

    private void BusLogFilter_Changed(object sender, RoutedEventArgs e)
    {
        if (_ready) ShowBusLog();
    }

    internal void BusLogCopy_Click(object sender, RoutedEventArgs e)
    {
        var shown = ShownBusLog();
        if (shown.Count > 0) CopyToClipboard(string.Join(Environment.NewLine, shown.Select(entry => entry.ToLine())));
    }

    // ---- Themes ------------------------------------------------------------------------------

    private void UpdateThemeSelection()
    {
        foreach (var card in _themeCards)
            card.IsSelected = card.Palette.Id == (card.Palette.IsLight ? _settings.LightTheme : _settings.DarkTheme);
    }

    internal void ThemeCard_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.DataContext is ThemeCard card) PickTheme(card.Palette);
    }

    private void PickTheme(ThemePalette palette)
    {
        if (palette.IsLight) _settings.LightTheme = palette.Id;
        else _settings.DarkTheme = palette.Id;

        // Picking a theme shows it, so the mode follows the kind of theme that was picked.
        _settings.Mode = SettingsLogic.ModeFor(palette.IsLight, system: false);
        (palette.IsLight ? ModeLight : ModeDark).IsChecked = true;
        UpdateThemeSelection();
        _settings.Save();
        ApplyTheme();
    }

    private void ThemeMode_Checked(object sender, RoutedEventArgs e)
    {
        if (!_ready) return;
        _settings.Mode = SettingsLogic.ModeFor(sender == ModeLight, sender == ModeSystem);
        _settings.Save();
        ApplyTheme();
    }

    // ---- Updates -----------------------------------------------------------------------------

    private Task MaintainUpdatesAsync() => _platform.CanUpdate
        ? WindowLogic.RepeatAsync(_platform.Delay, TimeSpan.FromSeconds(8), UpdateCheckInterval, () => _shutdownStarted, CheckAutomaticallyAsync)
        : Task.CompletedTask;

    /// <summary>The setting is read each round, so switching automatic updates on or off needs no restart.</summary>
    private Task CheckAutomaticallyAsync() =>
        _settings.AutoUpdate ? CheckForUpdatesAsync(checkedNow: false) : Task.CompletedTask;

    private async Task CheckForUpdatesAsync(bool checkedNow, bool download = true)
    {
        var progress = new Progress<UpdateStatus>(status => ShowUpdateStatus(status, checkedNow));
        var result = await _platform.CheckForUpdatesAsync(progress, download);
        ShowUpdateStatus(result, checkedNow);
    }

    /// <summary>The manual check. With automatic updates off it only looks, and the download waits to be asked for.</summary>
    private async void UpdateCheck_Click(object sender, RoutedEventArgs e) =>
        await RunBusy(() => CheckForUpdatesAsync(checkedNow: true, download: _settings.AutoUpdate), sender);

    private async void AutoUpdate_Changed(object sender, RoutedEventArgs e)
    {
        if (!_ready) return;
        _settings.AutoUpdate = AutoUpdateCheck.IsChecked == true;
        _settings.Save();
        ShowUpdateStatus(_updateStatus, checkedNow: false);
        if (_settings.AutoUpdate && _platform.CanUpdate) await RunBusy(() => CheckForUpdatesAsync(checkedNow: false));
    }

    private void ShowUpdateStatus(UpdateStatus status, bool checkedNow)
    {
        _updateStatus = status;
        var view = SettingsLogic.View(status, checkedNow, _settings.AutoUpdate, DateTime.Now);
        UpdateRestartButton.Visibility = VisibleWhen(view.ShowAction);
        UpdateRestartButton.Content = view.ActionLabel;
        UpdateButton.Visibility = VisibleWhen(view.ShowTitleBarButton);
        UpdateButton.Content = view.TitleBarLabel;
        UpdateCheckButton.IsEnabled = view.CanCheck;
        UpdateStatusText.Text = view.Text;
        _ = RestartForUpdateWhileHiddenAsync(status);
    }

    private async void UpdateRestart_Click(object sender, RoutedEventArgs e)
    {
        if (_updateStatus.State == UpdateState.Available)
        {
            await RunBusy(() => CheckForUpdatesAsync(checkedNow: true), sender);
            return;
        }
        SaveWindowPlacement();
        await StopMonitorAsync();
        _platform.RestartIntoUpdate();
    }

    // ---- This PC -----------------------------------------------------------------------------

    private void UpdateThisPcCard()
    {
        ThisPcCard.Visibility = VisibleWhen(_api.Session is not null);
        if (_api.Session is { } session)
            ThisPcText.Text = $"{session.DeviceLabel}\n{session.Endpoint}";
    }

    internal void ForgetDevice_Click(object sender, RoutedEventArgs e)
    {
        var confirmed = _platform.Confirm(this,
            "Remove the saved enrollment and operator access from this PC?\n\nYou will need a new enrollment from the StruggleBus device console to connect again. The device stays valid on the bus until it is revoked there.",
            "Forget this PC");
        if (confirmed) ForgetAndShowEnrollment();
    }

    private async void ForgetAndShowEnrollment()
    {
        await StopMonitorAsync();
        _api.ForgetSession();

        _pendingActivity.Clear();
        _knownActivitySequences.Clear();
        _activity.Clear();
        _agents.Clear();
        _agentModels = [];
        _selectedAgent = null;
        _selectedChannel = null;
        ChannelFilter.Items.Clear();
        AgentChip.Visibility = Visibility.Collapsed;
        UpdateHoldBar();
        ResetHumans();
        _busLog = null;
        BusLogStatus.Text = string.Empty;
        ShowBusLog();
        ClearEnrollmentResult();
        CloseQuickFind();
        ShowEnrollment();
    }
}
