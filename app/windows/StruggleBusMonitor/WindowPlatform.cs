using System.Windows;
using Microsoft.Win32;

namespace StruggleBusMonitor;

/// <summary>
/// Everything the window asks of Windows itself rather than of the bus: blocking dialogs, Windows
/// Hello, the clipboard, the Windows theme preference, waiting, and the updater. Kept behind an
/// interface so the window can be driven in tests without prompting anyone or leaving the process.
/// </summary>
internal interface IWindowPlatform
{
    bool WindowsPrefersLight();
    Rect VirtualScreen { get; }

    /// <summary>A Yes/No warning dialog that defaults to No. True only for Yes.</summary>
    bool Confirm(Window owner, string message, string caption);

    /// <summary>Asks where to save the CSV export. Null when the operator cancels.</summary>
    string? PickExportPath(Window owner, string suggestedName);

    /// <summary>Asks where to save a worker host's enrolment data file. Null when the operator cancels.</summary>
    string? PickHostFilePath(Window owner, string suggestedName);

    /// <summary>Where a release puts the signed copy of the worker host's installer: beside the app.</summary>
    string SignedInstallerPath { get; }

    /// <summary>What the app was started with; <see cref="TrayLogic.StartArgument"/> means start hidden.</summary>
    IReadOnlyList<string> StartArguments { get; }

    /// <summary>Puts the app's icon in the system tray. Disposing the result removes it.</summary>
    ITrayIcon ShowTrayIcon(Action open, Action quit);

    /// <summary>Whether Windows starts this app when this user signs in.</summary>
    bool StartsAtSignIn { get; set; }
    void SetClipboardText(string text);
    Task<bool> VerifyHelloAsync(string message);
    Task Delay(TimeSpan time);

    bool CanUpdate { get; }
    string CurrentVersion { get; }
    Task<UpdateStatus> CheckForUpdatesAsync(IProgress<UpdateStatus>? progress, bool download);
    void RestartIntoUpdate(params string[] arguments);
    void ApplyUpdateOnExit();
}

/// <summary>The real thing: message boxes, Windows Hello, the registry, the clipboard and Velopack.</summary>
internal sealed class WindowPlatform : IWindowPlatform
{
    private readonly WindowsHello _hello = new();
    private readonly AppUpdater _updater = new();

    public bool WindowsPrefersLight() => IsLightPreference(ReadAppsUseLightTheme);

    /// <summary>Windows stores the choice as a number, 0 for dark. Anything else, or no answer, counts as dark.</summary>
    internal static bool IsLightPreference(Func<object?> read)
    {
        try { return read() is int value && value != 0; }
        catch (Exception) { return false; }
    }

    private static object? ReadAppsUseLightTheme()
    {
        using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
        return key?.GetValue("AppsUseLightTheme");
    }

    public Rect VirtualScreen => new(
        SystemParameters.VirtualScreenLeft, SystemParameters.VirtualScreenTop,
        SystemParameters.VirtualScreenWidth, SystemParameters.VirtualScreenHeight);

    public bool Confirm(Window owner, string message, string caption) =>
        MessageBox.Show(owner, message, caption, MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No) == MessageBoxResult.Yes;

    public string? PickExportPath(Window owner, string suggestedName)
    {
        var dialog = ExportDialog(suggestedName);
        return dialog.ShowDialog(owner) == true ? dialog.FileName : null;
    }

    public string SignedInstallerPath => HostInstallerLogic.SignedPath;

    public IReadOnlyList<string> StartArguments => Environment.GetCommandLineArgs();

    public ITrayIcon ShowTrayIcon(Action open, Action quit) => new TrayIcon(open, quit);

    public bool StartsAtSignIn
    {
        get => SignInStart.IsOn;
        set => SignInStart.Set(value);
    }

    public string? PickHostFilePath(Window owner, string suggestedName)
    {
        var dialog = HostFileDialog(suggestedName);
        return dialog.ShowDialog(owner) == true ? dialog.FileName : null;
    }

    internal static SaveFileDialog HostFileDialog(string suggestedName) => new()
    {
        Filter = "Enrolment data (*.json)|*.json|All files (*.*)|*.*",
        FileName = suggestedName,
        DefaultExt = ".json",
        AddExtension = true,
        OverwritePrompt = true,
        Title = "Save the worker host's enrolment data"
    };

    internal static SaveFileDialog ExportDialog(string suggestedName) => new()
    {
        Filter = "CSV files (*.csv)|*.csv|All files (*.*)|*.*",
        FileName = suggestedName,
        DefaultExt = ".csv",
        AddExtension = true,
        OverwritePrompt = true,
        Title = "Export retained StruggleBus activity"
    };

    public void SetClipboardText(string text) => Clipboard.SetText(text);

    public Task<bool> VerifyHelloAsync(string message) => _hello.VerifyAsync(message);

    public Task Delay(TimeSpan time) => Task.Delay(time);

    public bool CanUpdate => _updater.CanUpdate;

    public string CurrentVersion => _updater.CurrentVersion;

    public Task<UpdateStatus> CheckForUpdatesAsync(IProgress<UpdateStatus>? progress, bool download) =>
        _updater.CheckAndDownloadAsync(progress, CancellationToken.None, download);

    public void RestartIntoUpdate(params string[] arguments) => _updater.RestartIntoUpdate(arguments);

    public void ApplyUpdateOnExit() => _updater.ApplyOnExit();
}
