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

    /// <summary>A Microsoft-signed ssh-keygen that can ask a hardware key to sign, by full path. Null when this PC has none.</summary>
    string? HardwareSigningTool { get; }

    /// <summary>
    /// Asks the hardware key behind <paramref name="keyFile"/> to sign exactly these bytes for
    /// <paramref name="purpose"/>. Windows prompts for the PIN and a touch. See <see cref="SshKeygen.SignAsync"/>.
    /// </summary>
    Task<string> SignWithHardwareKeyAsync(string tool, string keyFile, string purpose, byte[] document);

    /// <summary>Whether a file is on this PC.</summary>
    bool FileExists(string path);

    /// <summary>The public key files in the operator's .ssh folder, with their text. Only small files directly in that folder.</summary>
    IReadOnlyList<(string Path, string Text)> PublicKeyFiles();

    /// <summary>Asks for a hardware key's public file. Null when the operator cancels.</summary>
    string? PickPublicKeyFile(Window owner);

    /// <summary>Asks where to save a composed fleet document for signing. Null when the operator cancels.</summary>
    string? PickFleetSavePath(Window owner);

    /// <summary>Asks which signed fleet document to publish. Null when the operator cancels.</summary>
    string? PickFleetFile(Window owner);

    /// <summary>Asks Windows' own ssh-keygen whether the signature verifies for exactly these bytes, against one signer line.</summary>
    Task<SshVerdict> VerifySshSignatureAsync(byte[] message, string signature, string signerLine, string principal, string purpose);

    /// <summary>Where a release puts the signed copy of the worker host's installer: beside the app.</summary>
    string SignedInstallerPath { get; }

    /// <summary>What the app was started with; <see cref="TrayLogic.StartArgument"/> means start hidden.</summary>
    IReadOnlyList<string> StartArguments { get; }

    /// <summary>Puts the app's icon in the system tray. Disposing the result removes it.</summary>
    ITrayIcon ShowTrayIcon(Action open, Action quit);

    /// <summary>Whether Windows starts this app when this user signs in.</summary>
    bool StartsAtSignIn { get; set; }
    void SetClipboardText(string text);

    /// <summary>Opens a web address in the operator's browser.</summary>
    void OpenLink(string url);
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

    public string? HardwareSigningTool => SshKeygen.SigningTool();

    public Task<string> SignWithHardwareKeyAsync(string tool, string keyFile, string purpose, byte[] document) =>
        SshKeygen.SignAsync(tool, keyFile, purpose, document, TimeSpan.FromMinutes(3));

    public bool FileExists(string path) => System.IO.File.Exists(path);

    public IReadOnlyList<(string Path, string Text)> PublicKeyFiles() =>
        PublicKeyFilesIn(System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".ssh"));

    /// <summary>At most 200 files named *.pub directly in the folder, each small enough to be a key; none when the folder is missing or unreadable.</summary>
    internal static IReadOnlyList<(string Path, string Text)> PublicKeyFilesIn(string folder)
    {
        try
        {
            return System.IO.Directory.EnumerateFiles(folder, "*.pub", System.IO.SearchOption.TopDirectoryOnly)
                .Take(200)
                .Where(path => new System.IO.FileInfo(path).Length <= SshSignature.MaxLength)
                .Select(path => (path, System.IO.File.ReadAllText(path)))
                .ToList();
        }
        catch (Exception error) when (error is System.IO.IOException or UnauthorizedAccessException)
        {
            return [];
        }
    }

    public string? PickPublicKeyFile(Window owner)
    {
        var dialog = PublicKeyDialog();
        return dialog.ShowDialog(owner) == true ? dialog.FileName : null;
    }

    internal static OpenFileDialog PublicKeyDialog() => new()
    {
        Filter = "Public key (*.pub)|*.pub|All files (*.*)|*.*",
        InitialDirectory = System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".ssh"),
        CheckFileExists = true,
        Title = "Choose the hardware key's public file (.pub)"
    };

    public string? PickFleetSavePath(Window owner)
    {
        var dialog = FleetSaveDialog();
        return dialog.ShowDialog(owner) == true ? dialog.FileName : null;
    }

    internal static SaveFileDialog FleetSaveDialog() => new()
    {
        Filter = "Fleet document (*.toml)|*.toml|All files (*.*)|*.*",
        FileName = "fleet.toml",
        DefaultExt = ".toml",
        AddExtension = true,
        OverwritePrompt = true,
        Title = "Save the new fleet document for signing"
    };

    public string? PickFleetFile(Window owner)
    {
        var dialog = FleetFileDialog();
        return dialog.ShowDialog(owner) == true ? dialog.FileName : null;
    }

    internal static OpenFileDialog FleetFileDialog() => new()
    {
        Filter = "Fleet document (*.toml)|*.toml|All files (*.*)|*.*",
        FileName = "fleet.toml",
        CheckFileExists = true,
        Title = "Choose the signed fleet document (its .sig must be beside it)"
    };

    public Task<SshVerdict> VerifySshSignatureAsync(byte[] message, string signature, string signerLine, string principal, string purpose) =>
        SshKeygen.VerifyAsync(SshKeygen.DefaultPath, message, signature, signerLine, principal, purpose);

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
        Title = "Save the worker host's data file (the installer script is saved beside it)"
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

    public void OpenLink(string url) =>
        System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(url) { UseShellExecute = true })?.Dispose();

    public Task<bool> VerifyHelloAsync(string message) => _hello.VerifyAsync(message);

    public Task Delay(TimeSpan time) => Task.Delay(time);

    public bool CanUpdate => _updater.CanUpdate;

    public string CurrentVersion => _updater.CurrentVersion;

    public Task<UpdateStatus> CheckForUpdatesAsync(IProgress<UpdateStatus>? progress, bool download) =>
        _updater.CheckAndDownloadAsync(progress, CancellationToken.None, download);

    public void RestartIntoUpdate(params string[] arguments) => _updater.RestartIntoUpdate(arguments);

    public void ApplyUpdateOnExit() => _updater.ApplyOnExit();
}
