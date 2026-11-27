namespace StruggleBusMonitor;

/// <summary>The icon the app keeps in the system tray while its window is hidden.</summary>
internal interface ITrayIcon : IDisposable
{
    /// <summary>The text shown when the pointer rests on the icon.</summary>
    string Tooltip { set; }

    /// <summary>Shows a short notice beside the icon.</summary>
    void Notify(string text);
}

/// <summary>
/// Decisions for running in the system tray, kept apart from the window so they can be tested.
/// Nothing here ever puts message text in a tooltip or a notice: messages are untrusted and may
/// be sensitive, and the tray is visible to anyone who can see the screen.
/// </summary>
internal static class TrayLogic
{
    /// <summary>Given to the app when Windows starts it at sign-in, or when it restarts itself for an update while hidden.</summary>
    public const string StartArgument = "--tray";

    public const string StillRunning = "StruggleBus Monitor is still running in the tray. Right-click its icon to quit.";

    /// <summary>The name of this app's entry among the programs Windows starts at sign-in.</summary>
    public const string RunEntryName = "StruggleBusMonitor";

    private const int LongestTooltip = 120;

    /// <summary>Closing the window hides it when the option is on, unless the app is really being quit.</summary>
    public static bool HidesOnClose(bool keepInTray, bool quitting) => keepInTray && !quitting;

    /// <summary>The app starts hidden only when told to and only while the tray option is still on.</summary>
    public static bool StartsHidden(IEnumerable<string> arguments, bool keepInTray) =>
        keepInTray && arguments.Contains(StartArgument, StringComparer.OrdinalIgnoreCase);

    /// <summary>Connection state and how many questions are waiting. Never any message text.</summary>
    public static string Tooltip(string state, int waiting)
    {
        var status = string.IsNullOrWhiteSpace(state) ? "starting" : state.Trim();
        var text = waiting > 0 ? $"StruggleBus Monitor: {status}, {waiting} waiting on you" : $"StruggleBus Monitor: {status}";
        return text.Length <= LongestTooltip ? text : text[..LongestTooltip];
    }

    /// <summary>What Windows runs at sign-in: this copy of the app, starting in the tray.</summary>
    public static string RunCommand(string programPath) => $"\"{programPath}\" {StartArgument}";

    /// <summary>
    /// Starting at sign-in needs the tray option (the app starts hidden) and an installed copy,
    /// whose program stays at the same path from one update to the next.
    /// </summary>
    public static bool CanStartAtSignIn(bool keepInTray, bool installed) => keepInTray && installed;

    /// <summary>
    /// A hidden window must not hold an update back for ever. With automatic updates on, a
    /// downloaded update is installed straight away when nobody has the window open.
    /// </summary>
    public static bool RestartsForUpdate(bool hiddenInTray, bool automatic, UpdateState state) =>
        hiddenInTray && automatic && state == UpdateState.ReadyToRestart;
}
