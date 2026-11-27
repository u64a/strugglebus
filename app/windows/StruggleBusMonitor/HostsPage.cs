using System.Globalization;
using System.Text.Json;
using System.Windows;
using System.Windows.Media;

namespace StruggleBusMonitor;

/// <summary>One worker running on a host, as the host reported it.</summary>
public sealed record HostWorker(string Slot, string Engine, string Model, int Minutes);

/// <summary>A host's machine figures. A figure the host has not measured yet is null.</summary>
public sealed record HostMachine(double? CpuPct, double? RamFreeGb, double? DiskFreeGb, double? CommitPct);

/// <summary>
/// What a worker host last reported to the bus (the v2 snapshot). Everything in it is the host's
/// own word: shown as plain text and never acted on. <see cref="Basic"/> holds what the older
/// status also carried.
/// </summary>
public sealed record HostSnapshot(
    HostStatus Basic,
    IReadOnlyList<HostWorker> Running,
    HostMachine Machine,
    string BusState,
    string Channel,
    string Model,
    string Pwsh,
    string UpdateVersion,
    string UpdateWhen,
    IReadOnlyList<KeyValuePair<string, int>> Tasks);

/// <summary>One marked host as the bus knows it. <see cref="Snapshot"/> is null until it has reported.</summary>
public sealed record HostReport(string AgentId, string Agent, DateTimeOffset? ReceivedAt, HostSnapshot? Snapshot);

/// <summary>Every marked host, with the bus's own clock: how old a report is comes from that, not this PC's.</summary>
public sealed record HostsStatus(DateTimeOffset Now, IReadOnlyList<HostReport> Hosts);

/// <summary>One point of a host's twelve hours of history.</summary>
public sealed record HostSample(DateTimeOffset At, int Busy, int Max, double? CpuPct);

/// <summary>Reads the bus's answers about hosts. Anything missing or of the wrong kind becomes an empty value.</summary>
internal static class HostsParser
{
    private const int MaxHosts = 100;
    private const int MaxSamples = 5000;
    private static readonly string[] TaskOutcomes = ["finished", "failed", "timed-out", "interrupted", "refused", "yielded", "cancelled"];

    public static HostsStatus Status(JsonElement answer) => new(
        Time(answer, "now") ?? DateTimeOffset.UtcNow,
        Items(answer, "hosts", MaxHosts).Select(Report).Where(report => report.AgentId.Length > 0).ToList());

    public static IReadOnlyList<HostSample> History(JsonElement answer) =>
        Items(answer, "samples", MaxSamples).Select(Sample).OfType<HostSample>().ToList();

    private static HostReport Report(JsonElement host) => new(
        HostStatusParser.Text(host, "agent_id"),
        HostStatusParser.Text(host, "agent"),
        Time(host, "received_at"),
        HostStatusParser.Property(host, "snapshot") is { ValueKind: JsonValueKind.Object } snapshot ? Snapshot(snapshot) : null);

    internal static HostSnapshot Snapshot(JsonElement snapshot)
    {
        var bus = HostStatusParser.Property(snapshot, "bus");
        var update = HostStatusParser.Property(snapshot, "update");
        return new HostSnapshot(
            Basic: HostStatusParser.FromSnapshot(snapshot),
            Running: Items(HostStatusParser.Property(snapshot, "workers"), "running", 64).Select(Worker).ToList(),
            Machine: Machine(HostStatusParser.Property(snapshot, "machine")),
            BusState: HostStatusParser.Text(bus, "state"),
            Channel: HostStatusParser.Text(bus, "channel"),
            Model: HostStatusParser.Text(snapshot, "model"),
            Pwsh: HostStatusParser.Text(snapshot, "pwsh"),
            UpdateVersion: HostStatusParser.Text(update, "version"),
            UpdateWhen: HostStatusParser.Text(update, "when"),
            Tasks: Tasks(HostStatusParser.Property(snapshot, "tasks")));
    }

    private static HostWorker Worker(JsonElement worker) => new(
        HostStatusParser.Text(worker, "slot"),
        HostStatusParser.Text(worker, "engine"),
        HostStatusParser.Text(worker, "model"),
        (int)Math.Clamp(HostStatusParser.Number(worker, "minutes") ?? 0, 0, 100_000));

    private static HostMachine Machine(JsonElement? machine) => new(
        Figure(machine, "cpu_pct"), Figure(machine, "ram_free_gb"), Figure(machine, "disk_free_gb"), Figure(machine, "commit_pct"));

    private static List<KeyValuePair<string, int>> Tasks(JsonElement? tasks) =>
        TaskOutcomes.Select(name => KeyValuePair.Create(name, (int)Math.Clamp(HostStatusParser.Number(tasks, name) ?? 0, 0, 10_000_000)))
            .ToList();

    private static HostSample? Sample(JsonElement sample)
    {
        if (Time(sample, "received_at") is not { } at) return null;
        var workers = HostStatusParser.Property(sample, "workers");
        return new HostSample(
            at,
            (int)Math.Clamp(HostStatusParser.Number(workers, "busy") ?? 0, 0, 999),
            (int)Math.Clamp(HostStatusParser.Number(workers, "max") ?? 0, 0, 999),
            Figure(HostStatusParser.Property(sample, "machine"), "cpu_pct"));
    }

    private static double? Figure(JsonElement? parent, string name) =>
        HostStatusParser.Property(parent, name) is { ValueKind: JsonValueKind.Number } value
        && value.TryGetDouble(out var number) && double.IsFinite(number)
            ? Math.Clamp(number, 0, 1_000_000_000)
            : null;

    private static DateTimeOffset? Time(JsonElement? parent, string name) =>
        HostStatusParser.Property(parent, name) is { ValueKind: JsonValueKind.String } value
        && DateTimeOffset.TryParse(value.GetString(), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var time)
            ? time
            : null;

    private static IEnumerable<JsonElement> Items(JsonElement? parent, string name, int most) =>
        HostStatusParser.Property(parent, name) is { ValueKind: JsonValueKind.Array } list ? list.EnumerateArray().Take(most) : [];
}

/// <summary>One host on the Hosts page.</summary>
public sealed class HostCard
{
    public required string AgentId { get; init; }
    public required string Name { get; init; }
    public required string StateLabel { get; init; }

    /// <summary>"Ok", "Warn" or "Off": colours the state badge. The state is always written out as well.</summary>
    public required string Tone { get; init; }
    public string Seen { get; init; } = string.Empty;
    public string Workers { get; init; } = string.Empty;

    /// <summary>The workers running now, one per line. Empty when none are.</summary>
    public string Running { get; init; } = string.Empty;
    public bool HasRunning => Running.Length > 0;
    public string Machine { get; init; } = string.Empty;
    public string Tasks { get; init; } = string.Empty;
    public string Details { get; init; } = string.Empty;

    /// <summary>Problems and standing warnings, one per line. Empty when there are none.</summary>
    public string Alerts { get; init; } = string.Empty;
    public bool HasAlerts => Alerts.Length > 0;

    /// <summary>Twelve hours of busy workers and of processor use, drawn as lines. Empty until loaded.</summary>
    public PointCollection BusyLine { get; set; } = HostsPageLogic.NoLine;
    public PointCollection CpuLine { get; set; } = HostsPageLogic.NoLine;
    public bool HasHistory { get; set; }
    public string HistoryLabel { get; set; } = string.Empty;
}

/// <summary>Pure decisions for the Hosts page, kept apart from the window so they can be tested.</summary>
internal static class HostsPageLogic
{
    /// <summary>A host reports every minute, so two and a half minutes of silence means it has stopped.</summary>
    public static readonly TimeSpan ReportingWindow = TimeSpan.FromSeconds(150);
    public static readonly TimeSpan RefreshEvery = TimeSpan.FromSeconds(30);
    public static readonly TimeSpan HistoryWindow = TimeSpan.FromHours(12);
    public const double ChartWidth = 260;
    public const double ChartHeight = 34;
    public static readonly PointCollection NoLine = Frozen([]);

    public static bool IsReporting(DateTimeOffset? receivedAt, DateTimeOffset now) =>
        receivedAt is { } received && now - received <= ReportingWindow;

    /// <summary>Whether the host is reporting comes from the bus's clock; what it is doing comes from the host.</summary>
    internal static (string Label, string Tone) Badge(HostReport report, DateTimeOffset now)
    {
        if (report.Snapshot is null) return ("NO REPORT YET", "Warn");
        return IsReporting(report.ReceivedAt, now) ? HostsLogic.Badge(true, report.Snapshot.Basic.State) : ("NOT REPORTING", "Off");
    }

    public static HostCard Card(HostReport report, DateTimeOffset now)
    {
        var (label, tone) = Badge(report, now);
        var card = new HostCard
        {
            AgentId = report.AgentId,
            Name = Name(report),
            StateLabel = label,
            Tone = tone,
            Seen = Seen(report.ReceivedAt, now)
        };
        return report.Snapshot is { } snapshot ? Filled(card, snapshot) : card;
    }

    /// <summary>The card with what the host reported about itself.</summary>
    private static HostCard Filled(HostCard card, HostSnapshot snapshot) => new()
    {
        AgentId = card.AgentId,
        Name = card.Name,
        StateLabel = card.StateLabel,
        Tone = card.Tone,
        Seen = card.Seen,
        // A host that has stopped reporting is not known to be doing this now.
        Workers = (card.Tone == "Off" ? "When it last reported: " : string.Empty) + $"{snapshot.Basic.Busy} of {snapshot.Basic.Max} workers busy",
        Running = string.Join(Environment.NewLine, snapshot.Running.Select(WorkerLine)),
        Machine = MachineLine(snapshot.Machine),
        Tasks = TasksLine(snapshot.Tasks),
        Details = Joined(Details(snapshot)),
        Alerts = string.Join(Environment.NewLine, Alerts(snapshot))
    };

    /// <summary>The PC's own name when it has reported one; otherwise its bus name.</summary>
    internal static string Name(HostReport report)
    {
        var reported = report.Snapshot?.Basic.Host ?? string.Empty;
        return reported.Length > 0 ? reported : report.Agent;
    }

    internal static string Seen(DateTimeOffset? receivedAt, DateTimeOffset now)
    {
        if (receivedAt is not { } received) return "It has not reported to the bus yet.";
        var age = now - received;
        if (age < TimeSpan.FromSeconds(90)) return "reported less than a minute ago";
        return age < TimeSpan.FromHours(2)
            ? $"last reported {(int)age.TotalMinutes} minutes ago"
            : $"last reported {(int)age.TotalHours} hours ago";
    }

    internal static string WorkerLine(HostWorker worker) =>
        Joined([worker.Slot, worker.Engine, worker.Model, $"{worker.Minutes} min"]);

    internal static string MachineLine(HostMachine machine) => Joined(
    [
        Figure("CPU ", machine.CpuPct, "%", "0"),
        Figure("", machine.RamFreeGb, " GB memory free", "0.0"),
        Figure("", machine.DiskFreeGb, " GB disk free", "0.0"),
        Figure("commit ", machine.CommitPct, "%", "0")
    ]);

    private static string Figure(string before, double? value, string after, string format) =>
        value is { } number ? before + number.ToString(format, CultureInfo.InvariantCulture) + after : string.Empty;

    /// <summary>How the host's tasks have ended since it started. Outcomes that have not happened are left out.</summary>
    internal static string TasksLine(IEnumerable<KeyValuePair<string, int>> tasks)
    {
        var ended = tasks.Where(task => task.Value > 0).Select(task => $"{task.Value} {task.Key.Replace('-', ' ')}").ToList();
        return ended.Count == 0 ? "No tasks have ended since it started." : "Since it started: " + string.Join(", ", ended);
    }

    private static IEnumerable<string> Details(HostSnapshot snapshot) =>
    [
        When(snapshot.Basic.Version.Length > 0, $"version {snapshot.Basic.Version}"),
        string.Join(", ", snapshot.Basic.Engines.Select(HostsLogic.EngineLabel)),
        When(snapshot.Model.Length > 0, $"default model {snapshot.Model}"),
        When(snapshot.Pwsh.Length > 0, $"PowerShell {snapshot.Pwsh}"),
        When(snapshot.Basic.Account.Length > 0, $"runs as {snapshot.Basic.Account}"),
        When(snapshot.Channel.Length > 0, $"channel #{snapshot.Channel}"),
        When(snapshot.Basic.HeldClones > 0, $"{snapshot.Basic.HeldClones} kept for unsaved work"),
        When(snapshot.Basic.Outbox > 0, $"{snapshot.Basic.Outbox} replies waiting to post"),
        When(snapshot.UpdateVersion.Length > 0, $"update to {snapshot.UpdateVersion} at {snapshot.UpdateWhen}"),
        HostsLogic.ReleaseSourceLabel(snapshot.Basic.ReleaseSource)
    ];

    private static IEnumerable<string> Alerts(HostSnapshot snapshot)
    {
        if (snapshot.Basic.ProblemText.Length > 0) yield return $"Problem: {snapshot.Basic.ProblemText}";
        if (snapshot.BusState == "down") yield return "Problem: the host says it cannot reach the bus.";
        foreach (var warning in snapshot.Basic.Warnings) yield return HostsLogic.WarningText(warning);
    }

    private static string When(bool condition, string text) => condition ? text : string.Empty;

    private static string Joined(IEnumerable<string> parts) => string.Join("  ·  ", parts.Where(part => part.Length > 0));

    public static string Summary(IReadOnlyCollection<HostCard> cards, bool whole)
    {
        if (cards.Count == 0) return "No worker hosts are marked on this bus yet. Mark one on Admin, Worker hosts.";
        var hosts = Counted(cards);
        return whole ? hosts : hosts + " Save operator access on Admin to also see each host's account, warnings and channel.";
    }

    private static string Counted(IReadOnlyCollection<HostCard> cards)
    {
        var silent = cards.Count(card => card.Tone == "Off");
        var attention = cards.Count(NeedsAttention);
        return $"{cards.Count} host{(cards.Count == 1 ? "" : "s")}{Note(silent, "not reporting")}{Note(attention, "needing attention")}.";
    }

    private static bool NeedsAttention(HostCard card) => card.Tone == "Warn" || (card.HasAlerts && card.Tone == "Ok");

    private static string Note(int count, string what) => count > 0 ? $", {count} {what}" : string.Empty;

    public const string Unsupported = "This bus does not keep worker host reports yet. It needs StruggleBus 0.2.74 or newer.";

    /// <summary>The page shows what it last loaded for this long before asking the bus again.</summary>
    public static bool IsStale(DateTimeOffset? loadedAt, DateTimeOffset now) =>
        loadedAt is not { } loaded || now - loaded >= RefreshEvery;

    /// <summary>
    /// A line across the chart for one figure of a host's history. Time runs left to right over
    /// the twelve hours before <paramref name="now"/>; the figure runs bottom to top up to
    /// <paramref name="top"/>. Samples outside the twelve hours, or with no figure, are left out.
    /// </summary>
    public static PointCollection Line(IEnumerable<(DateTimeOffset At, double? Value)> samples, DateTimeOffset now, double top)
    {
        var start = now - HistoryWindow;
        var points = samples
            .Where(sample => sample.Value is not null && sample.At >= start && sample.At <= now)
            .Select(sample => new Point(
                Math.Round((sample.At - start) / HistoryWindow * ChartWidth, 1),
                Math.Round(ChartHeight - Math.Clamp(sample.Value!.Value / Math.Max(top, 1), 0, 1) * ChartHeight, 1)));
        return Frozen(points);
    }

    /// <summary>Puts a host's history on its card.</summary>
    public static void Draw(HostCard card, IReadOnlyList<HostSample> samples, DateTimeOffset now)
    {
        var most = samples.Count == 0 ? 1 : samples.Max(sample => sample.Max);
        card.BusyLine = Line(samples.Select(sample => (sample.At, (double?)sample.Busy)), now, most);
        card.CpuLine = Line(samples.Select(sample => (sample.At, sample.CpuPct)), now, 100);
        card.HasHistory = card.BusyLine.Count > 1;
        card.HistoryLabel = card.HasHistory
            ? $"Last 12 hours: workers busy of {most} (bright line) and processor use (faint line)"
            : NoHistoryYet(card);
    }

    /// <summary>A host that has never reported has said so already; one that has gets told why there is no chart.</summary>
    private static string NoHistoryYet(HostCard card) =>
        card.Workers.Length == 0 ? string.Empty : "Not enough reports yet to draw the last 12 hours.";

    private static PointCollection Frozen(IEnumerable<Point> points)
    {
        var line = new PointCollection(points);
        line.Freeze();
        return line;
    }

    // ---- Marking a host (Admin, Worker hosts) ----

    public static string MarkReview(string agentName, bool mark) => mark
        ? $"Mark {agentName} as a worker host?\n\nIt will be allowed to report its status and events to the bus. This gives it no other access."
        : $"Take the worker host mark from {agentName}?\n\nIt will no longer be able to report as a host, and the status the bus holds for it is removed.";

    public static string MarkHelloPrompt(string agentName, bool mark) =>
        mark ? $"Mark {agentName} as a worker host" : $"Unmark {agentName} as a worker host";

    public static string MarkLabel(bool marked) => marked ? "No longer a host" : "Mark as host";

    /// <summary>What the bus records as the reason. The action says what it is; the App says where it came from.</summary>
    public static string MarkReason(bool mark) =>
        mark ? "marked as a worker host from the Windows app" : "worker host mark removed from the Windows app";
}
