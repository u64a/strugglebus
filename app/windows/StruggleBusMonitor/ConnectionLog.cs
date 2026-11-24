using System.IO;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace StruggleBusMonitor;

/// <summary>One line of this app's own connection history. Tone is "Ok", "Warn" or "Bad".</summary>
public sealed record ConnectionEvent(DateTimeOffset At, string Tone, string Text)
{
    public string TimeLabel => At.ToLocalTime().ToString("ddd d MMM HH:mm:ss");
}

/// <summary>
/// Turns what the background loops see into the few moments worth writing down: the bus going
/// away, coming back, announcing a restart, freezing. Repeated failures during one outage produce
/// one line, not one per retry.
/// </summary>
public sealed partial class ConnectionTracker
{
    private bool? _up;
    private bool _frozen;
    private bool _stopAnnounced;
    private DateTimeOffset _downSince;
    private (string Version, DateTimeOffset At)? _maintenance;
    private string? _busVersion;
    private DateTimeOffset? _busStartedAt;

    public bool IsDown => _up == false;

    public ConnectionEvent? ReportUp(DateTimeOffset now)
    {
        var was = _up;
        _up = true;
        if (was == true) return null;
        if (was is null) return new ConnectionEvent(now, "Ok", "Connected to the bus.");
        return new ConnectionEvent(now, "Ok", $"Reconnected{TakeOutageCause()}. Offline for {Duration(now - _downSince)}.");
    }

    /// <summary>Why the outage that just ended happened, if the bus said so; the answer is used once.</summary>
    private string TakeOutageCause()
    {
        var announced = _stopAnnounced;
        _stopAnnounced = false;
        if (_maintenance is { } planned && _downSince >= planned.At - MaintenanceLead)
        {
            _maintenance = null;
            return $" after scheduled maintenance (release {planned.Version})";
        }
        return announced ? " after the bus restarted" : string.Empty;
    }

    public ConnectionEvent? ReportDown(DateTimeOffset now, string reason)
    {
        if (_up == false) return null;
        _up = false;
        _downSince = now;
        return new ConnectionEvent(now, "Bad", $"Bus not reachable. Trying again automatically. ({Trim(reason)})");
    }

    /// <summary>The bus said it is stopping, which is how every restart, update and maintenance run begins.</summary>
    public ConnectionEvent? ReportStopping(DateTimeOffset now)
    {
        if (_up == false) return null;
        _up = false;
        _downSince = now;
        _stopAnnounced = true;
        return new ConnectionEvent(now, "Warn", "The bus announced it is stopping for a restart or update. Reconnecting when it is back.");
    }

    public ConnectionEvent? ReportFrozen(DateTimeOffset now, bool frozen)
    {
        if (frozen == _frozen) return null;
        _frozen = frozen;
        return frozen
            ? new ConnectionEvent(now, "Bad", "Agent access is frozen on the bus.")
            : new ConnectionEvent(now, "Ok", "The freeze on agent access was cleared.");
    }

    /// <summary>The bus posts a fixed notice before installing a release; remembering it names the outage that follows.</summary>
    public ConnectionEvent? ReportMessage(BusMessage message, DateTimeOffset now)
    {
        if (ReadMaintenanceNotice(message.Body) is not { } notice) return null;
        if (notice.At < now - MaintenanceLead || IsKnownMaintenance(notice)) return null;
        _maintenance = notice;
        return new ConnectionEvent(now, "Warn",
            $"Maintenance announced: release {notice.Version} installs at {notice.At.ToLocalTime():HH:mm} on {notice.At.ToLocalTime():ddd d MMM}. The bus will disconnect briefly.");
    }

    private static (string Version, DateTimeOffset At)? ReadMaintenanceNotice(string body)
    {
        var match = MaintenanceNotice().Match(body);
        if (!match.Success || !DateTimeOffset.TryParse(match.Groups[2].Value, out var at)) return null;
        return (match.Groups[1].Value, at);
    }

    private bool IsKnownMaintenance((string Version, DateTimeOffset At) notice) =>
        _maintenance is { } known && known == notice;

    /// <summary>Notes a bus that came back as a different version, or that restarted without this app seeing it go.</summary>
    public ConnectionEvent? ReportBus(string version, DateTimeOffset? startedAt, DateTimeOffset now)
    {
        var (oldVersion, oldStart) = (_busVersion, _busStartedAt);
        (_busVersion, _busStartedAt) = (version, startedAt);
        if (oldVersion is null) return null;
        if (oldVersion != version)
            return new ConnectionEvent(now, "Ok", $"The bus is now on version {version} (was {oldVersion}).");
        return StartedAfter(startedAt, oldStart) is { } started
            ? new ConnectionEvent(now, "Warn", $"The bus restarted at {started.ToLocalTime():HH:mm:ss}, still on version {version}.")
            : null;
    }

    /// <summary>The new start time when both are known and it is the later one.</summary>
    private static DateTimeOffset? StartedAfter(DateTimeOffset? startedAt, DateTimeOffset? before) =>
        startedAt > before ? startedAt : null;

    private static readonly TimeSpan MaintenanceLead = TimeSpan.FromMinutes(30);

    internal static string Duration(TimeSpan span) => span.TotalSeconds < 60
        ? $"{Math.Max(1, (int)span.TotalSeconds)}s"
        : span.TotalHours < 1
            ? $"{(int)span.TotalMinutes}m {span.Seconds}s"
            : $"{(int)span.TotalHours}h {span.Minutes}m";

    private static string Trim(string reason)
    {
        var line = reason.ReplaceLineEndings(" ").Trim();
        return line.Length <= 160 ? line : line[..160] + "…";
    }

    [GeneratedRegex(@"^Strugglebus maintenance: release (\d+\.\d+\.\d+) is scheduled for installation at (\S+?)\. ")]
    private static partial Regex MaintenanceNotice();
}

/// <summary>This app's connection history, newest first, kept across restarts as plain JSON. Nothing secret is written.</summary>
public sealed class ConnectionLog
{
    public const int Maximum = 400;
    private static readonly JsonSerializerOptions Options = new() { WriteIndented = false };
    private readonly string? _path;
    private readonly List<ConnectionEvent> _events;

    private ConnectionLog(string? path, List<ConnectionEvent> events) => (_path, _events) = (path, events);

    public IReadOnlyList<ConnectionEvent> Events => _events;

    public static ConnectionLog Load() => LoadFromPath(AppPaths.File("connection-log.json"));

    internal static ConnectionLog LoadFromPath(string? path)
    {
        try
        {
            if (path is not null && File.Exists(path))
                return new ConnectionLog(path, JsonSerializer.Deserialize<List<ConnectionEvent>>(File.ReadAllText(path), Options) ?? []);
        }
        catch (Exception error) when (error is JsonException or IOException or UnauthorizedAccessException)
        {
            // A damaged history is not worth an error; start a new one.
        }
        return new ConnectionLog(path, []);
    }

    /// <summary>Adds the event unless it is null or repeats the newest line, and saves.</summary>
    public bool Add(ConnectionEvent? entry)
    {
        if (entry is null || RepeatsNewest(entry)) return false;
        _events.Insert(0, entry);
        if (_events.Count > Maximum) _events.RemoveRange(Maximum, _events.Count - Maximum);
        Save();
        return true;
    }

    private bool RepeatsNewest(ConnectionEvent entry) =>
        _events.Count > 0 && _events[0].Text == entry.Text && _events[0].At > entry.At.AddMinutes(-1);

    public void Clear()
    {
        _events.Clear();
        Save();
    }

    public string ToText() => string.Join(Environment.NewLine, _events.Select(entry => $"{entry.At.ToLocalTime():yyyy-MM-dd HH:mm:ss}  {entry.Text}"));

    private void Save()
    {
        if (_path is null) return;
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
            File.WriteAllText(_path, JsonSerializer.Serialize(_events, Options));
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            // History is a convenience; failing to save it must never break the monitor.
        }
    }
}

/// <summary>One line of the bus's own log, as served to an enrolled device.</summary>
public sealed record BusLogEntry(DateTimeOffset At, string Source, string Level, string Event, string? Subject, string? Actor, int? Status, string? RemoteAddress, string Detail)
{
    public string TimeLabel => At.ToLocalTime().ToString("ddd d MMM HH:mm:ss");
    public string SourceLabel => Source.ToUpperInvariant();
    public bool IsProblem => Level is "warning" or "error";
    public string Tone => Level switch { "error" => "Bad", "warning" => "Warn", _ => "Muted" };

    public string Summary
    {
        get
        {
            string?[] parts =
            [
                Labelled("HTTP ", Status?.ToString()),
                Subject,
                Labelled("by ", Actor),
                Labelled("from ", RemoteAddress),
                // A request line's detail only repeats the status; other sources say something new.
                Source != "request" ? Detail : null
            ];
            return string.Join("  ·  ", parts.Where(part => !string.IsNullOrWhiteSpace(part)));
        }
    }

    private static string? Labelled(string label, string? value) => string.IsNullOrWhiteSpace(value) ? null : label + value;

    public string ToLine() => $"{At.ToLocalTime():yyyy-MM-dd HH:mm:ss}  {Source,-7}  {Level,-7}  {Event}  {Summary}";
}

public sealed record BusLog(string Version, DateTimeOffset? StartedAt, IReadOnlyList<BusLogEntry> Entries)
{
    public static IReadOnlyList<BusLogEntry> Filter(IEnumerable<BusLogEntry> entries, bool problemsOnly, string? text)
    {
        var words = (text ?? string.Empty).Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        return entries
            .Where(entry => !problemsOnly || entry.IsProblem)
            .Where(entry => words.All(word =>
                entry.Event.Contains(word, StringComparison.OrdinalIgnoreCase) ||
                entry.Summary.Contains(word, StringComparison.OrdinalIgnoreCase) ||
                entry.Source.Contains(word, StringComparison.OrdinalIgnoreCase)))
            .ToList();
    }
}
