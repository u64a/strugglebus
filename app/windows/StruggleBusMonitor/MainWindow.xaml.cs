using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Shapes;
using Microsoft.Win32;

namespace StruggleBusMonitor;

/// <summary>
/// Shell: theme, navigation, notices, window placement and shutdown. Each page's behaviour lives in
/// its own MainWindow.*.cs partial.
/// </summary>
public partial class MainWindow : Window
{
    private readonly BusApi _api;
    private readonly IWindowPlatform _platform;
    private readonly AppSettings _settings = AppSettings.Load();
    private readonly MonitorLifecycle _monitorLifecycle = new();
    private readonly ConnectionLog _connectionLog = ConnectionLog.Load();
    private readonly ConnectionTracker _tracker = new();
    private readonly bool _ready;
    private Action? _noticeAction;
    private bool _isFrozen;
    private bool _shutdownStarted;
    private bool _shutdownComplete;

    public MainWindow() : this(new WindowPlatform(), new BusApi())
    {
    }

    /// <summary>
    /// Tests pass a platform that answers the dialogs and Windows Hello itself, and an API whose
    /// requests go to a stand-in bus instead of the network.
    /// </summary>
    internal MainWindow(IWindowPlatform platform, BusApi api)
    {
        _platform = platform;
        _api = api;
        ApplyTheme();
        InitializeComponent();
        RestoreWindowPlacement();
        InitializeMonitor();
        InitializeHumans();
        InitializeAdmin();
        InitializeHosts();
        InitializeChannels();
        InitializeSettings();
        InitializeTray();
        _ready = true;

        SourceInitialized += (_, _) => ApplyTitleBarTheme();
        SystemEvents.UserPreferenceChanged += OnWindowsPreferenceChanged;

        if (_api.StartupWarning is { } warning) ShowNotice(warning);
        if (_api.Session is { } session)
        {
            ShowWorkspace(session);
            _ = ConnectAsync();
        }
        else
        {
            ShowEnrollment();
        }
        _ = MaintainUpdatesAsync();
    }

    private bool IsEnrolled => _api.Session is not null;

    /// <summary>
    /// Loads the workspace at startup. If the bus cannot be reached (maintenance, an update, the
    /// network not up yet) it keeps trying on its own instead of waiting for Refresh to be clicked.
    /// </summary>
    private async Task ConnectAsync()
    {
        for (var failures = 1; await TryConnectAsync(); failures++)
        {
            await _platform.Delay(MonitorLogic.RetryDelay(failures));
            if (ConnectAbandoned) return;
        }
    }

    /// <summary>Stop if the app is closing, the PC was forgotten, or a manual Refresh already connected.</summary>
    private bool ConnectAbandoned => _shutdownStarted || _api.Session is null || _monitorLifecycle.ActiveTaskCount > 0;

    /// <summary>One attempt. True when it failed in a way that waiting can fix.</summary>
    private async Task<bool> TryConnectAsync()
    {
        try
        {
            await RefreshAsync();
            return false;
        }
        catch (Exception error)
        {
            return ShowConnectFailure(error);
        }
    }

    private bool ShowConnectFailure(Exception error)
    {
        switch (WindowLogic.ClassifyConnectFailure(error))
        {
            case ConnectFailure.Retry:
                NoteConnection(_tracker.ReportDown(DateTimeOffset.Now, error.Message));
                SetConnectionState("RECONNECTING", error.Message, "Warn");
                return true;
            case ConnectFailure.Revoked:
                ShowRevoked(BusErrors.CredentialInactive);
                return false;
            default:
                ShowNotice(error.Message);
                return false;
        }
    }

    // ---- Theme -------------------------------------------------------------------------------

    private ThemePalette CurrentTheme => _settings.ResolveTheme(_platform.WindowsPrefersLight());

    private void ApplyTheme()
    {
        Themes.Apply(Application.Current.Resources, CurrentTheme);
        ApplyTitleBarTheme();
    }

    private void ApplyTitleBarTheme()
    {
        var handle = new WindowInteropHelper(this).Handle;
        if (handle == IntPtr.Zero) return;
        var dark = CurrentTheme.IsLight ? 0 : 1;
        _ = DwmSetWindowAttribute(handle, 20 /* DWMWA_USE_IMMERSIVE_DARK_MODE */, ref dark, sizeof(int));
    }

    internal void OnWindowsPreferenceChanged(object sender, UserPreferenceChangedEventArgs e)
    {
        if (e.Category == UserPreferenceCategory.General && _settings.Mode == AppThemeMode.System)
            Dispatcher.BeginInvoke(ApplyTheme);
    }

    // ---- Enrollment and navigation -----------------------------------------------------------

    private async void Enroll_Click(object sender, RoutedEventArgs e) => await RunBusy(EnrollAsync, sender);

    private async Task EnrollAsync()
    {
        var session = await _api.EnrollAsync(EnrollmentBox.Text, CancellationToken.None);
        EnrollmentBox.Clear();
        HideNotice();
        ShowWorkspace(session);
        await RefreshAsync();
    }

    private void ShowWorkspace(Session session)
    {
        // A different enrollment is a different bus or device: nothing kept from the last one applies.
        _adminLoadedAt = null;
        _hostsLoadedAt = null;
        _channelsLoadedAt = null;
        HumansNav.IsEnabled = true;
        ChannelsNav.IsEnabled = true;
        HostsNav.IsEnabled = true;
        AdminNav.IsEnabled = true;
        QuickFindButton.IsEnabled = true;
        DeviceLabelText.Text = session.DeviceLabel;
        SetConnectionState("CONNECTING", string.Empty, "Warn");
        UpdateThisPcCard();
        UpdateGrantStatus();
        if (MonitorNav.IsChecked == true) ShowPage(MonitorNav);
        else MonitorNav.IsChecked = true;
    }

    private void ShowEnrollment()
    {
        HumansNav.IsEnabled = false;
        ChannelsNav.IsEnabled = false;
        HostsNav.IsEnabled = false;
        AdminNav.IsEnabled = false;
        QuickFindButton.IsEnabled = false;
        DeviceLabelText.Text = string.Empty;
        SetConnectionState("NOT ENROLLED", string.Empty, "Warn");
        UpdateThisPcCard();
        if (MonitorNav.IsChecked == true) ShowPage(MonitorNav);
        else MonitorNav.IsChecked = true;
    }

    private void Nav_Checked(object sender, RoutedEventArgs e)
    {
        if (_ready) ShowPage((RadioButton)sender);
    }

    private static Visibility VisibleWhen(bool shown) => shown ? Visibility.Visible : Visibility.Collapsed;

    /// <summary>Which page each navigation item opens. Anything else opens Monitor.</summary>
    private NavPage PageOf(RadioButton nav)
    {
        (RadioButton Nav, NavPage Page)[] pages =
        [
            (SettingsNav, NavPage.Settings), (HumansNav, NavPage.Humans), (HostsNav, NavPage.Hosts),
            (ChannelsNav, NavPage.Channels), (AdminNav, NavPage.Admin)
        ];
        return pages.FirstOrDefault(entry => entry.Nav == nav).Page;
    }

    private void ShowPage(RadioButton nav)
    {
        var page = PageOf(nav);
        var layout = NavigationLogic.Layout(page, IsEnrolled);
        SettingsPage.Visibility = VisibleWhen(layout.Settings);
        EnrollmentPanel.Visibility = VisibleWhen(layout.Enrollment);
        WorkspacePanel.Visibility = VisibleWhen(layout.Workspace);
        MonitorPage.Visibility = VisibleWhen(layout.Monitor);
        HumansPage.Visibility = VisibleWhen(layout.Humans);
        AdminPage.Visibility = VisibleWhen(layout.Admin);
        HostsPage.Visibility = VisibleWhen(layout.Hosts);
        ChannelsPage.Visibility = VisibleWhen(layout.Channels);
        CloseMentionPopup();
        OnPageShown(page);
    }

    private void OnPageShown(NavPage page)
    {
        if (page != NavPage.Humans) UpdateHumansBadge();
        var shown = new Dictionary<NavPage, Action>
        {
            [NavPage.Humans] = OnHumansPageShown,
            [NavPage.Admin] = OnAdminPageShown,
            [NavPage.Hosts] = OnHostsPageShown,
            [NavPage.Channels] = OnChannelsPageShown,
            [NavPage.Settings] = OnSettingsPageShown
        };
        if (shown.TryGetValue(page, out var load)) load();
    }

    private void Window_PreviewKeyDown(object sender, KeyEventArgs e)
    {
        var quickFindOpen = QuickFindOverlay.Visibility == Visibility.Visible;
        if (RunShortcut(NavigationLogic.Shortcut(e.Key, Keyboard.Modifiers, IsEnrolled, quickFindOpen))) e.Handled = true;
    }

    /// <summary>Carries out a keyboard shortcut. False when there was nothing to do, so the key is left alone.</summary>
    internal bool RunShortcut(ShortcutAction action)
    {
        if (action == ShortcutAction.None) return false;
        if (action == ShortcutAction.OpenQuickFind) OpenQuickFind();
        else CloseQuickFind();
        return true;
    }

    // ---- Status, notices and busy handling ---------------------------------------------------

    private void SetConnectionState(string state, string detail, string colorKey)
    {
        StatusText.Text = state;
        StatusDetailText.Text = detail;
        StatusDetailText.Visibility = VisibleWhen(!string.IsNullOrEmpty(detail));
        StatusDot.SetResourceReference(Shape.FillProperty, colorKey);
        UpdateTrayTooltip();
    }

    /// <summary>Something failed that the background loops will retry; the first failure of an outage is logged.</summary>
    internal Task ShowDegradedStateAsync(string detail) =>
        Dispatcher.InvokeAsync(() =>
        {
            NoteConnection(_tracker.ReportDown(DateTimeOffset.Now, detail));
            SetConnectionState("RECONNECTING", detail, "Warn");
        }).Task;

    private void ShowNotice(string message, string? actionLabel = null, Action? action = null)
    {
        NoticeText.Text = message;
        _noticeAction = action;
        NoticeActionButton.Content = actionLabel;
        NoticeActionButton.Visibility = VisibleWhen(action is not null);
        NoticeBar.Visibility = Visibility.Visible;
    }

    private void HideNotice()
    {
        NoticeBar.Visibility = Visibility.Collapsed;
        _noticeAction = null;
    }

    internal void NoticeDismiss_Click(object sender, RoutedEventArgs e) => HideNotice();

    private void NoticeAction_Click(object sender, RoutedEventArgs e)
    {
        var action = _noticeAction;
        HideNotice();
        action?.Invoke();
    }

    /// <summary>
    /// Runs an operation, keeps the button that started it disabled so it cannot be fired twice, and
    /// reports a failure in the notice bar instead of a blocking dialog.
    /// </summary>
    private async Task RunBusy(Func<Task> operation, object? source = null)
    {
        var button = source as Button;
        if (button is { IsEnabled: false }) return;
        SetEnabled(button, false);
        try { await operation(); }
        catch (Exception error) { ShowNotice(WindowLogic.FailureText(error)); }
        finally { SetEnabled(button, true); }
    }

    private static void SetEnabled(Button? button, bool enabled)
    {
        if (button is not null) button.IsEnabled = enabled;
    }

    internal static ScrollViewer? FindScrollViewer(DependencyObject root)
    {
        for (var index = 0; index < VisualTreeHelper.GetChildrenCount(root); index++)
        {
            var child = VisualTreeHelper.GetChild(root, index);
            if (child is ScrollViewer viewer) return viewer;
            if (FindScrollViewer(child) is { } nested) return nested;
        }
        return null;
    }

    private void CopyToClipboard(string text)
    {
        try { _platform.SetClipboardText(text); }
        catch (COMException) { ShowNotice("The clipboard is busy. Try copying again."); }
    }

    internal void FlashTaskbar()
    {
        if (IsActive) return;
        var handle = new WindowInteropHelper(this).Handle;
        if (handle == IntPtr.Zero) return;
        var info = new FLASHWINFO
        {
            cbSize = (uint)Marshal.SizeOf<FLASHWINFO>(),
            hwnd = handle,
            dwFlags = 0x00000002 /* FLASHW_TRAY */ | 0x0000000C /* FLASHW_TIMERNOFG */,
            uCount = 3
        };
        FlashWindowEx(ref info);
    }

    // ---- Window placement and shutdown -------------------------------------------------------

    private void RestoreWindowPlacement()
    {
        var saved = WindowLogic.RestoredBounds(_settings.WindowLeft, _settings.WindowTop, _settings.WindowWidth, _settings.WindowHeight,
            _platform.VirtualScreen, MinWidth, MinHeight);
        if (saved is not { } bounds) return;
        WindowStartupLocation = WindowStartupLocation.Manual;
        (Left, Top, Width, Height) = (bounds.Left, bounds.Top, bounds.Width, bounds.Height);
        if (_settings.WindowMaximized) WindowState = WindowState.Maximized;
    }

    private void SaveWindowPlacement()
    {
        var bounds = WindowState == WindowState.Normal ? new Rect(Left, Top, Width, Height) : RestoreBounds;
        if (bounds.IsEmpty) return;
        (_settings.WindowLeft, _settings.WindowTop, _settings.WindowWidth, _settings.WindowHeight) = (bounds.Left, bounds.Top, bounds.Width, bounds.Height);
        _settings.WindowMaximized = WindowState == WindowState.Maximized;
        _settings.Save();
    }

    protected override async void OnClosing(CancelEventArgs e)
    {
        if (_shutdownComplete)
        {
            base.OnClosing(e);
            return;
        }

        e.Cancel = true;
        if (HidesInsteadOfClosing()) HideToTray();
        else if (!_shutdownStarted) await ShutDownAsync();
    }

    /// <summary>Stops the background work, then closes the window for real.</summary>
    private async Task ShutDownAsync()
    {
        _shutdownStarted = true;
        SaveWindowPlacement();
        SystemEvents.UserPreferenceChanged -= OnWindowsPreferenceChanged;
        await StopMonitorAsync();
        if (_settings.AutoUpdate) _platform.ApplyUpdateOnExit();
        _tray?.Dispose();
        _shutdownComplete = true;
        // Close() is refused while the OnClosing call is still on the stack, which is the case
        // whenever nothing above had to wait (for example when the PC is not enrolled).
        _ = Dispatcher.BeginInvoke(Close);
    }

    [DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attribute, ref int value, int size);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool FlashWindowEx(ref FLASHWINFO info);

    [StructLayout(LayoutKind.Sequential)]
    private struct FLASHWINFO
    {
        public uint cbSize;
        public IntPtr hwnd;
        public uint dwFlags;
        public uint uCount;
        public uint dwTimeout;
    }
}
