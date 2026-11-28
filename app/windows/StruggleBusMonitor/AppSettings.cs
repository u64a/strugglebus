using System.IO;
using System.Text.Json;

namespace StruggleBusMonitor;

public static class AppPaths
{
    /// <summary>
    /// Per-user data folder. STRUGGLEBUS_MONITOR_DATA_DIR overrides it so a development copy pointed
    /// at the mock server never touches the real enrollment.
    /// </summary>
    public static string DataDirectory { get; } =
        ResolveDataDirectory(Environment.GetEnvironmentVariable("STRUGGLEBUS_MONITOR_DATA_DIR"));

    internal static string ResolveDataDirectory(string? custom) =>
        string.IsNullOrEmpty(custom)
            ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "StruggleBusMonitor")
            : custom;

    public static string File(string name) => Path.Combine(DataDirectory, name);
}

public enum AppThemeMode { Dark, Light, System }

/// <summary>Non-secret preferences. Stored as plain JSON next to the protected session.</summary>
public sealed class AppSettings
{
    public AppThemeMode Mode { get; set; } = AppThemeMode.Dark;
    public string DarkTheme { get; set; } = Themes.DefaultDark;
    public string LightTheme { get; set; } = Themes.DefaultLight;
    public double? WindowLeft { get; set; }
    public double? WindowTop { get; set; }
    public double? WindowWidth { get; set; }
    public double? WindowHeight { get; set; }
    public bool WindowMaximized { get; set; }

    /// <summary>Check for, download and install updates without being asked. Off leaves only the manual check.</summary>
    public bool AutoUpdate { get; set; } = true;

    /// <summary>Sequence numbers of #humans questions cleared from the waiting list, newest kept.</summary>
    public List<long> ClearedWaiting { get; set; } = [];

    public const int MaximumClearedWaiting = 500;

    /// <summary>The update version last installed at startup, so one that fails is not retried in a loop.</summary>
    public string? StartupUpdateAttempt { get; set; }

    /// <summary>Closing the window hides it to the system tray and the app keeps running. Off unless chosen.</summary>
    public bool KeepInTray { get; set; }

    /// <summary>
    /// Flash the taskbar button when an agent addresses the operator in #humans while the app is
    /// not the window in use. On unless turned off.
    /// </summary>
    public bool FlashWhenAddressed { get; set; } = true;

    /// <summary>
    /// For each site signer added from a public file on this PC, where its key file is, by the
    /// key's own text. A key file is a handle that only works with the hardware key plugged in;
    /// the path is not secret. Used to ask that key to sign a fleet.
    /// </summary>
    public Dictionary<string, string> SignerKeyFiles { get; set; } = [];

    /// <summary>The site signer the operator chose to sign with, by the key's own text. Empty means the first that can.</summary>
    public string SigningKey { get; set; } = string.Empty;

    /// <summary>The "still running in the tray" notice has been shown once, so it is not shown again.</summary>
    public bool TrayNoticeShown { get; set; }

    /// <summary>
    /// The site's signer lines, repository locations and fleet source, as last used to add a
    /// worker host. Public values only: an allowed_signers line holds a public key.
    /// </summary>
    /// <summary>
    /// Where the signer lines used to be kept. They are now in <see cref="SiteSignersStore"/>,
    /// protected for this Windows account. A value found here is offered to the operator to
    /// confirm, key by key, and is never used as it stands.
    /// </summary>
    public string HostSigners { get; set; } = string.Empty;
    public string HostRemotes { get; set; } = string.Empty;
    public string HostFleetSource { get; set; } = AddHostLogic.DefaultFleetSource;

    public void ClearWaiting(IEnumerable<long> sequences) =>
        ClearedWaiting = ClearedWaiting.Concat(sequences).Distinct().Order().TakeLast(MaximumClearedWaiting).ToList();

    private static readonly JsonSerializerOptions Options = new() { WriteIndented = true };

    public static AppSettings Load() => LoadFromPath(AppPaths.File("settings.json"));

    internal static AppSettings LoadFromPath(string path)
    {
        try
        {
            return System.IO.File.Exists(path)
                ? JsonSerializer.Deserialize<AppSettings>(System.IO.File.ReadAllText(path), Options) ?? new AppSettings()
                : new AppSettings();
        }
        catch (Exception error) when (error is JsonException or IOException or UnauthorizedAccessException)
        {
            return new AppSettings();
        }
    }

    public void Save() => SaveToPath(AppPaths.File("settings.json"));

    internal void SaveToPath(string path)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            System.IO.File.WriteAllText(path, JsonSerializer.Serialize(this, Options));
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            // Preferences are a convenience; failing to save them must never break the monitor.
        }
    }

    public ThemePalette ResolveTheme(bool windowsPrefersLight)
    {
        var light = Mode == AppThemeMode.Light || (Mode == AppThemeMode.System && windowsPrefersLight);
        return Themes.Find(light ? LightTheme : DarkTheme, light);
    }
}
