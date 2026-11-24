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
internal sealed class StaWindowAdminPlatform : IWindowPlatform
{
    private readonly List<TaskCompletionSource> _delays = [];

    public bool PrefersLight { get; set; }
    public Rect Screen { get; set; } = new(0, 0, 1920, 1080);
    public bool ConfirmAnswer { get; set; } = true;
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
        return ConfirmAnswer;
    }

    public string? PickExportPath(Window owner, string suggestedName)
    {
        SuggestedExportNames.Add(suggestedName);
        return ExportPath;
    }

    public string? HostFilePath { get; set; }
    public List<string> SuggestedHostFileNames { get; } = [];

    public string? PickHostFilePath(Window owner, string suggestedName)
    {
        SuggestedHostFileNames.Add(suggestedName);
        return HostFilePath;
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

    public void RestartIntoUpdate() => Restarts++;
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
        _window.Close();
        StaWindowAdminFixture.PumpUntil(() => _closed, "the window to close");
    }

    public void Dispose()
    {
        try { Close(); }
        finally { Bus.Dispose(); }
    }
}
