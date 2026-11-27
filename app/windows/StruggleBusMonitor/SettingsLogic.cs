namespace StruggleBusMonitor;

/// <summary>What the Settings page and the title bar show for an update state.</summary>
internal sealed record UpdateView(bool ShowAction, string ActionLabel, bool ShowTitleBarButton, string TitleBarLabel, bool CanCheck, string Text);

/// <summary>Pure helpers for the Settings page, kept apart from the window so they can be tested.</summary>
internal static class SettingsLogic
{
    /// <summary>
    /// Whether the bus's refusal of the whole log means "use the ordinary one": a bus too old to
    /// have it (not found, not allowed), or operator access it no longer accepts.
    /// </summary>
    public static bool FullLogUnavailable(int statusCode) => statusCode is 401 or 404 or 405;

    public const string NotInstalledText =
        "This copy was not installed with the setup program, so it cannot update itself. Install it once with the Setup download from the releases page and later versions will arrive on their own.";

    public const string BusLogUnsupported = "This bus does not serve its log yet. It needs StruggleBus 0.2.65 or newer.";

    public static AppThemeMode ModeFor(bool light, bool system)
    {
        if (light) return AppThemeMode.Light;
        return system ? AppThemeMode.System : AppThemeMode.Dark;
    }

    /// <summary>The state shown before any check has run.</summary>
    public static UpdateStatus InitialStatus(bool canUpdate) =>
        new(canUpdate ? UpdateState.UpToDate : UpdateState.NotInstalled);

    public static UpdateView View(UpdateStatus status, bool checkedNow, bool autoUpdate, DateTime now)
    {
        var ready = status.State == UpdateState.ReadyToRestart;
        var available = status.State == UpdateState.Available;
        return new UpdateView(
            ShowAction: ready || available,
            ActionLabel: available ? $"Download version {status.Version}" : "Restart to update",
            ShowTitleBarButton: ready,
            TitleBarLabel: $"Update {status.Version} ready · Restart",
            CanCheck: status.State is not (UpdateState.NotInstalled or UpdateState.Downloading),
            Text: StatusText(status, checkedNow, autoUpdate, now));
    }

    public static string StatusText(UpdateStatus status, bool checkedNow, bool autoUpdate, DateTime now) => status.State switch
    {
        UpdateState.NotInstalled => NotInstalledText,
        UpdateState.Available => $"Version {status.Version} is available. Download it, then restart to install it.",
        UpdateState.Downloading => $"Downloading version {status.Version}…",
        UpdateState.ReadyToRestart => ReadyText(status, autoUpdate),
        UpdateState.Failed => FailedText(status, checkedNow),
        _ => UpToDateText(checkedNow, autoUpdate, now)
    };

    private static string ReadyText(UpdateStatus status, bool autoUpdate) => autoUpdate
        ? $"Version {status.Version} is downloaded. It installs when you restart, or the next time you close the app."
        : $"Version {status.Version} is downloaded. It installs when you press Restart to update.";

    private static string FailedText(UpdateStatus status, bool checkedNow) => checkedNow
        ? $"The update check failed: {status.Detail}"
        : "The last automatic update check failed. It will be tried again.";

    private static string UpToDateText(bool checkedNow, bool autoUpdate, DateTime now)
    {
        if (checkedNow) return $"You are on the latest version. Checked {now:HH:mm}.";
        return autoUpdate
            ? "Updates are checked at startup and every few hours, then downloaded in the background."
            : "Automatic updates are off. Nothing is checked, downloaded or installed until you press Check for updates.";
    }

    // ---- Logs --------------------------------------------------------------------------------

    public static string BusLogStatus(BusLog log, DateTime now) =>
        $"StruggleBus {log.Version}" +
        (log.StartedAt is { } started ? $", running since {started.ToLocalTime():ddd d MMM HH:mm}" : string.Empty) +
        $". Loaded {now:HH:mm:ss}.";

    /// <summary>Why the bus log list is empty, for the text shown in its place.</summary>
    public static string BusLogEmptyText(bool enrolled, BusLog? log)
    {
        if (!enrolled) return "Enroll this PC to read the bus log.";
        if (log is null) return "Nothing loaded.";
        return log.Entries.Count == 0 ? "The bus has nothing logged." : "Nothing matches.";
    }

    /// <summary>A notice already written before this app was restarted is not written twice.</summary>
    public static bool IsNewNotice(ConnectionEvent? entry, IEnumerable<ConnectionEvent> known) =>
        entry is not null && known.All(existing => existing.Text != entry.Text);
}
