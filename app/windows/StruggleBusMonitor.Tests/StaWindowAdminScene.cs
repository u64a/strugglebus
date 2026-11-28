using System.IO;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;

namespace StruggleBusMonitor.Tests;

/// <summary>
/// Stands in for Windows: answers the review dialogs, Windows Hello and the save dialog from
/// values a test sets, records what it was asked, and never shows anything.
/// </summary>
/// <summary>A tray icon that only remembers what it was told and lets a test click it.</summary>
internal sealed class FakeTrayIcon(Action open, Action quit) : ITrayIcon
{
    public string Tooltip { get; set; } = string.Empty;
    public List<string> Notices { get; } = [];
    public bool Disposed { get; private set; }
    public void Notify(string text) => Notices.Add(text);
    public void Dispose() => Disposed = true;
    public void Open() => open();
    public void Quit() => quit();
}

internal sealed class StaWindowAdminPlatform : IWindowPlatform
{
    private readonly List<TaskCompletionSource> _delays = [];

    public bool PrefersLight { get; set; }
    public Rect Screen { get; set; } = new(0, 0, 1920, 1080);
    public bool ConfirmAnswer { get; set; } = true;

    /// <summary>Answers to the next questions, in order; after them every question gets <see cref="ConfirmAnswer"/>.</summary>
    public Queue<bool> ConfirmAnswers { get; } = [];
    public bool HelloAnswer { get; set; } = true;
    public string? ExportPath { get; set; }
    public bool ClipboardBusy { get; set; }
    public bool Installed { get; set; }
    public UpdateStatus UpdateResult { get; set; } = new(UpdateState.UpToDate);
    public UpdateStatus? UpdateProgress { get; set; }

    public List<(string Message, string Caption)> Confirmations { get; } = [];
    public List<string> HelloPrompts { get; } = [];
    public List<string> SuggestedExportNames { get; } = [];
    public List<string> Clipboard { get; } = [];
    public List<TimeSpan> Delays { get; } = [];
    public List<bool> UpdateChecks { get; } = [];
    public int Restarts { get; private set; }
    public int AppliedOnExit { get; private set; }

    public bool WindowsPrefersLight() => PrefersLight;
    public Rect VirtualScreen => Screen;

    public bool Confirm(Window owner, string message, string caption)
    {
        Confirmations.Add((message, caption));
        return ConfirmAnswers.Count > 0 ? ConfirmAnswers.Dequeue() : ConfirmAnswer;
    }

    public string? PickExportPath(Window owner, string suggestedName)
    {
        SuggestedExportNames.Add(suggestedName);
        return ExportPath;
    }

    public string? HostFilePath { get; set; }

    /// <summary>No signed installer unless a test puts one here.</summary>
    public string SignedInstallerPath { get; set; } = Path.Combine(Path.GetTempPath(), $"no-signed-installer-{Guid.NewGuid():N}.ps1");
    public List<string> SuggestedHostFileNames { get; } = [];

    public string? FleetFilePath { get; set; }
    public SshVerdict Verdict { get; set; } = SshVerdict.Good;
    public List<(string Signer, string Principal, string Purpose, int Bytes)> Verified { get; } = [];

    public string? PickFleetFile(Window owner) => FleetFilePath;

    public string? HardwareSigningTool { get; set; } = @"C:\Program Files\OpenSSH\ssh-keygen.exe";

    /// <summary>What the hardware key "signs": given the bytes, the signature text. Null means the key did not sign.</summary>
    public Func<byte[], string>? HardwareKey { get; set; }
    public Exception? SigningFailure { get; set; }
    public List<(string Tool, string KeyFile, string Purpose, byte[] Document)> Signed { get; } = [];

    public Task<string> SignWithHardwareKeyAsync(string tool, string keyFile, string purpose, byte[] document)
    {
        Signed.Add((tool, keyFile, purpose, document));
        if (SigningFailure is not null) return Task.FromException<string>(SigningFailure);
        return Task.FromResult(HardwareKey!(document));
    }

    /// <summary>What "making a key" does: given the name, the new public file's path. Null means the tool made none.</summary>
    public Func<string, string>? NewKey { get; set; }
    public List<(string Tool, string Name)> KeysAsked { get; } = [];

    public Task<string> CreateHardwareKeyAsync(string tool, string name)
    {
        KeysAsked.Add((tool, name));
        return NewKey is null ? Task.FromException<string>(new SshSigningException("Key enrollment failed: invalid format")) : Task.FromResult(NewKey(name));
    }

    /// <summary>Key files "on this PC" beyond the real ones.</summary>
    public HashSet<string> KeyFiles { get; } = new(StringComparer.OrdinalIgnoreCase);

    public bool FileExists(string path) => KeyFiles.Contains(path) || System.IO.File.Exists(path);

    public List<(string Path, string Text)> PublicKeys { get; } = [];

    public IReadOnlyList<(string Path, string Text)> PublicKeyFiles() => PublicKeys;

    public string? PublicKeyPath { get; set; }

    public string? PickPublicKeyFile(Window owner) => PublicKeyPath;

    public string? FleetSavePath { get; set; }

    public string? PickFleetSavePath(Window owner) => FleetSavePath;

    public Task<SshVerdict> VerifySshSignatureAsync(byte[] message, string signature, string signerLine, string principal, string purpose)
    {
        Verified.Add((signerLine, principal, purpose, message.Length));
        return Task.FromResult(Verdict);
    }

    public string? PickHostFilePath(Window owner, string suggestedName)
    {
        SuggestedHostFileNames.Add(suggestedName);
        return HostFilePath;
    }

    public List<string> OpenedLinks { get; } = [];
    public bool BrowserFails { get; set; }

    public void OpenLink(string url)
    {
        if (BrowserFails) throw new System.ComponentModel.Win32Exception("no browser");
        OpenedLinks.Add(url);
    }

    public void SetClipboardText(string text)
    {
        if (ClipboardBusy) throw new COMException("CLIPBRD_E_CANT_OPEN");
        Clipboard.Add(text);
    }

    public Task<bool> VerifyHelloAsync(string message)
    {
        HelloPrompts.Add(message);
        return Task.FromResult(HelloAnswer);
    }

    /// <summary>A wait that lasts until the test ends it with <see cref="EndDelay"/>, so no test sleeps.</summary>
    public Task Delay(TimeSpan time)
    {
        Delays.Add(time);
        var pending = new TaskCompletionSource();
        _delays.Add(pending);
        return pending.Task;
    }

    public void EndDelay(int index) => _delays[index].SetResult();

    public bool CanUpdate => Installed;
    public string CurrentVersion => "9.9.9";

    /// <summary>When set, a check reports its progress and then waits here, as a download would.</summary>
    public TaskCompletionSource? UpdateGate { get; set; }

    public async Task<UpdateStatus> CheckForUpdatesAsync(IProgress<UpdateStatus>? progress, bool download)
    {
        UpdateChecks.Add(download);
        if (UpdateProgress is { } status) progress?.Report(status);
        if (UpdateGate is { } gate) await gate.Task;
        return UpdateResult;
    }

    public List<string[]> RestartArguments { get; } = [];

    public void RestartIntoUpdate(params string[] arguments)
    {
        Restarts++;
        RestartArguments.Add(arguments);
    }

    public List<string> StartArgumentList { get; } = [];
    public IReadOnlyList<string> StartArguments => StartArgumentList;
    public bool StartsAtSignIn { get; set; }
    public List<FakeTrayIcon> TrayIcons { get; } = [];

    public ITrayIcon ShowTrayIcon(Action open, Action quit)
    {
        var icon = new FakeTrayIcon(open, quit);
        TrayIcons.Add(icon);
        return icon;
    }
    public void ApplyUpdateOnExit() => AppliedOnExit++;
}

/// <summary>
/// One test's world: an emptied data folder, a loopback bus, a fake Windows and the real window,
/// built but never shown. Create and dispose it inside <see cref="StaWindowAdminFixture.Run"/>.
/// </summary>
internal sealed class StaWindowAdminScene : IDisposable
{
    private bool _closed;
    private MainWindow? _window;

    public StaWindowAdminScene()
    {
        TestDataDirectory.Reset();
    }

    public StaWindowAdminBus Bus { get; } = new();
    public StaWindowAdminPlatform Platform { get; } = new();
    public MainWindow Window => _window ?? throw new InvalidOperationException("Open the window first.");

    /// <summary>Saves this bus as the PC's enrollment, as a previous run of the app would have.</summary>
    public StaWindowAdminScene Enroll(bool withGrant = true)
    {
        BusApi.SessionStore.Save(Bus.Session);
        if (withGrant) BusApi.GrantStore.Save(StaWindowAdminBus.DeviceId, "grant-secret");
        return this;
    }

    public StaWindowAdminScene WithSettings(Action<AppSettings> change)
    {
        var settings = new AppSettings();
        change(settings);
        settings.Save();
        return this;
    }

    /// <summary>Builds the window. When enrolled it waits until the first load from the bus is done.</summary>
    public StaWindowAdminScene Open(bool waitForLive = true)
    {
        _window = new MainWindow(Platform, new BusApi());
        _window.Closed += (_, _) => _closed = true;
        // Windows only gives a window its position when it is shown, and this one never is.
        if (double.IsNaN(_window.Left)) (_window.Left, _window.Top) = (40, 40);
        // The live stream is the last thing the first load starts, so its request marks the end of it.
        if (waitForLive && File.Exists(AppPaths.File("session.bin")))
            StaWindowAdminFixture.PumpUntil(
                () => Window.StatusText.Text is "LIVE" or "FROZEN" && Bus.RequestsTo("GET /api/mobile/stream").Count > 0,
                "the first load from the bus");
        return this;
    }

    public static void Click(ButtonBase button) => button.RaiseEvent(new RoutedEventArgs(ButtonBase.ClickEvent));

    /// <summary>Clicks a button whose handler disables it while it works, and waits for it to finish.</summary>
    public static void ClickAndWait(Button button)
    {
        Click(button);
        WaitFor(button);
    }

    /// <summary>Waits for a handler that was started with <paramref name="button"/> as its sender.</summary>
    public static void WaitFor(Button button) =>
        StaWindowAdminFixture.PumpUntil(() => button.IsEnabled, "the operation behind a button");

    public static void Until(Func<bool> condition, string waitingFor) => StaWindowAdminFixture.PumpUntil(condition, waitingFor);

    public string Notice => Window.NoticeBar.Visibility == Visibility.Visible ? Window.NoticeText.Text : string.Empty;

    public void Close()
    {
        if (_window is null || _closed) return;
        // Quit, not Close: with the tray option on, closing only hides the window.
        _window.QuitFromTray();
        StaWindowAdminFixture.PumpUntil(() => _closed, "the window to close");
    }

    public void Dispose()
    {
        try { Close(); }
        finally { Bus.Dispose(); }
    }
}
