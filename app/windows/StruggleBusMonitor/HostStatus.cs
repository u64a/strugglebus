using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace StruggleBusMonitor;

/// <summary>One agent program (engine) a worker host can run, as the host reported it.</summary>
public sealed record HostEngine(string Name, string Version, bool? SignedIn);

/// <summary>
/// What a worker host last said about itself, from the <c>sb_host_status</c> metadata of its status
/// message. Everything here is the host's own word: display text only, never acted on.
/// </summary>
public sealed record HostStatus(
    string Host,
    string Agent,
    string Version,
    string State,
    string Account,
    IReadOnlyList<HostEngine> Engines,
    int Busy,
    int Max,
    int HeldClones,
    int Outbox,
    long? FleetSerial,
    string ProblemText,
    IReadOnlyList<string> Warnings,
    string ReleaseSource = "");

/// <summary>
/// Reads a host's status out of untrusted message metadata. Anything missing or of the wrong type
/// falls back to an empty value; text is cut to a short length and stripped of control characters.
/// </summary>
internal static class HostStatusParser
{
    public const string MetadataKey = "sb_host_status";
    public const int SupportedVersion = 1;
    private const int MaxText = 120;
    private const int MaxItems = 8;

    private static readonly HashSet<string> KnownStates = new(StringComparer.Ordinal)
    {
        "online", "paused", "draining", "needs-sign-in", "needs-fleet", "updating", "error"
    };

    /// <summary>
    /// The status in a message's metadata, or null. A status only counts when the agent it names is
    /// the agent that posted it, so one agent cannot report on behalf of another.
    /// </summary>
    public static HostStatus? FromMetadata(JsonElement? metadata, string author)
    {
        if (VersionOne(metadata) is not { } status) return null;
        var agent = Text(status, "agent");
        return agent.Length > 0 && string.Equals(agent, author, StringComparison.Ordinal) ? Read(status, agent) : null;
    }

    /// <summary>
    /// The same fields out of a v2 snapshot the bus stored for a host. The bus has already tied the
    /// snapshot to the agent that sent it, so there is no author to compare here.
    /// </summary>
    public static HostStatus FromSnapshot(JsonElement snapshot) => Read(snapshot, Text(snapshot, "agent"));

    /// <summary>The status object, when there is one and it is the version this app understands.</summary>
    private static JsonElement? VersionOne(JsonElement? metadata)
    {
        var status = Property(metadata, MetadataKey);
        return status?.ValueKind == JsonValueKind.Object && Number(status, "v") == SupportedVersion ? status : null;
    }

    private static HostStatus Read(JsonElement status, string agent)
    {
        var workers = Property(status, "workers");
        return new HostStatus(
            Host: Text(status, "host"),
            Agent: agent,
            Version: Text(status, "version"),
            State: State(Text(status, "state")),
            Account: Text(status, "account"),
            Engines: Items(status, "engines").Select(Engine).Where(engine => engine.Name.Length > 0).ToList(),
            Busy: Count(workers, "busy", 999),
            Max: Count(workers, "max", 999),
            HeldClones: Count(status, "held_clones", 9999),
            Outbox: Count(status, "outbox", 9999),
            FleetSerial: Number(Property(status, "fleet"), "serial"),
            ProblemText: Text(Property(status, "problem"), "text"),
            Warnings: Items(status, "warnings").Select(Clean).Where(warning => warning.Length > 0).ToList(),
            ReleaseSource: Text(Property(status, "release"), "source"));
    }

    private static string State(string state) => KnownStates.Contains(state) ? state : "unknown";

    private static int Count(JsonElement? parent, string name, int most) =>
        (int)Math.Clamp(Number(parent, name) ?? 0, 0, most);

    private static HostEngine Engine(JsonElement engine) =>
        new(Text(engine, "name"), Text(engine, "version"), Flag(engine, "signed_in"));

    internal static JsonElement? Property(JsonElement? parent, string name) =>
        parent is { ValueKind: JsonValueKind.Object } element && element.TryGetProperty(name, out var value) ? value : null;

    internal static string Text(JsonElement? parent, string name) =>
        Property(parent, name) is { } value ? Clean(value) : string.Empty;

    internal static long? Number(JsonElement? parent, string name) =>
        Property(parent, name) is { ValueKind: JsonValueKind.Number } value && value.TryGetInt64(out var number) ? number : null;

    private static bool? Flag(JsonElement? parent, string name) => Property(parent, name)?.ValueKind switch
    {
        JsonValueKind.True => true,
        JsonValueKind.False => false,
        _ => null
    };

    private static IEnumerable<JsonElement> Items(JsonElement? parent, string name) =>
        Property(parent, name) is { ValueKind: JsonValueKind.Array } list ? list.EnumerateArray().Take(MaxItems) : [];

    /// <summary>A string value as short, single-line display text. Anything that is not a string is empty.</summary>
    private static string Clean(JsonElement value)
    {
        if (value.ValueKind != JsonValueKind.String) return string.Empty;
        var text = new string((value.GetString() ?? string.Empty).Where(character => !char.IsControl(character)).ToArray()).Trim();
        return text.Length <= MaxText ? text : text[..MaxText] + "…";
    }
}

/// <summary>One worker host on the Hosts tab.</summary>
public sealed class HostRow
{
    public required string Name { get; init; }
    public required string StateLabel { get; init; }

    /// <summary>"Ok", "Warn" or "Off": colours the state badge. The state is always written out as well.</summary>
    public required string Tone { get; init; }
    public string Meta { get; init; } = string.Empty;

    /// <summary>
    /// For a host that joined with a host code: the code to compare with the one its installer
    /// printed, and where the code was redeemed from. Empty for any other host.
    /// </summary>
    public string Joined { get; init; } = string.Empty;
    public bool HasJoined => Joined.Length > 0;

    /// <summary>Problems and standing warnings, one per line. Empty when there are none.</summary>
    public string Alerts { get; init; } = string.Empty;
    public bool HasAlerts => Alerts.Length > 0;
}

/// <summary>Pure helpers for the Hosts tab, kept apart from the window so they can be tested.</summary>
internal static class HostsLogic
{
    /// <summary>A worker host's own bus name ends with this; its workers use other suffixes.</summary>
    public const string HostSuffix = "-host";

    /// <summary>An idle host calls the bus every 10 seconds, so 90 seconds of silence means it is not there.</summary>
    public static readonly TimeSpan AliveWindow = TimeSpan.FromSeconds(90);

    /// <summary>How many of a host's newest messages to read when looking for its last status.</summary>
    public const int StatusLookback = 20;
    public const int MaxHosts = 40;

    /// <summary>The agents that are worker hosts, by name, capped so a large roster cannot flood the bus with reads.</summary>
    public static IReadOnlyList<BusAgent> HostAgents(IEnumerable<BusAgent> agents) =>
        agents.Where(agent => agent.Name.EndsWith(HostSuffix, StringComparison.Ordinal) && agent.Name.Length > HostSuffix.Length)
            .OrderBy(agent => agent.Name, StringComparer.Ordinal)
            .Take(MaxHosts)
            .ToList();

    /// <summary>The newest status a host has posted, among its own messages.</summary>
    public static HostStatus? Latest(IEnumerable<BusMessage> messages, string agentName) =>
        messages.Where(message => message.HostStatus is not null && message.AgentName == agentName)
            .OrderByDescending(message => message.Seq)
            .Select(message => message.HostStatus)
            .FirstOrDefault();

    public static bool IsAlive(DateTimeOffset? lastSeen, DateTimeOffset now) =>
        lastSeen is { } seen && now - seen <= AliveWindow;

    /// <summary>
    /// What the host's installer printed if it is the host that redeemed the code: the first eight
    /// hex characters of SHA-256 over the host agent's id, a line feed and the redeem request id.
    /// Only the party that redeemed the code knows that request id.
    /// </summary>
    public static string ConfirmationCode(string agentId, string redeemRequestId) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes($"{agentId}\n{redeemRequestId}")))[..8];

    /// <summary>The service principal a host agent belongs to: the one named as the agent, less "-host".</summary>
    public static ManagedServicePrincipal? PrincipalFor(BusAgent agent, IEnumerable<ManagedServicePrincipal> principals)
    {
        var prefix = agent.Name[..^HostSuffix.Length];
        return principals.FirstOrDefault(principal => principal.Name == prefix);
    }

    /// <summary>Empty unless the host joined with a host code, which is when the bus records a redeem request id.</summary>
    internal static string JoinedText(string agentId, string? redeemRequestId, string? redeemedFrom)
    {
        if (string.IsNullOrEmpty(redeemRequestId)) return string.Empty;
        return $"Confirmation code {ConfirmationCode(agentId, redeemRequestId)}{RedeemedFrom(redeemedFrom)}. It must match the code the installer printed on that PC.";
    }

    private static string RedeemedFrom(string? address) =>
        string.IsNullOrEmpty(address) ? string.Empty : $", redeemed from {address}";

    public static HostRow Row(BusAgent agent, HostStatus? status, DateTimeOffset now, ManagedServicePrincipal? principal = null)
    {
        var alive = IsAlive(agent.LastSeenAt, now);
        var (label, tone) = Badge(alive, status?.State);
        return new HostRow
        {
            Name = DisplayName(agent, status),
            StateLabel = label,
            Tone = tone,
            Meta = string.Join("  ·  ", MetaParts(agent, status, alive, now).Where(part => part.Length > 0)),
            Joined = JoinedText(agent.Id, principal?.HostRedeemRequestId, principal?.HostRedeemedFrom),
            Alerts = string.Join(Environment.NewLine, Alerts(status))
        };
    }

    /// <summary>
    /// The PC's own name. A host that has not reported one is named from its bus name, without the
    /// "host-" in front and "-host" behind, so every row reads the same way.
    /// </summary>
    internal static string DisplayName(BusAgent agent, HostStatus? status)
    {
        var reported = status?.Host ?? string.Empty;
        return reported.Length > 0 ? reported : WithoutPrefix(agent.Name[..^HostSuffix.Length]);
    }

    private static string WithoutPrefix(string name)
    {
        var start = AddHostLogic.PrefixStart;
        return name.Length > start.Length && name.StartsWith(start, StringComparison.Ordinal) ? name[start.Length..] : name;
    }

    private static readonly Dictionary<string, string> StateLabels = new(StringComparer.Ordinal)
    {
        ["needs-sign-in"] = "NEEDS SIGN-IN",
        ["needs-fleet"] = "NOT IN THE FLEET YET",
        ["unknown"] = "UNKNOWN STATE"
    };

    /// <summary>Whether the host answers comes from the bus; what it is doing comes from the host.</summary>
    internal static (string Label, string Tone) Badge(bool alive, string? state)
    {
        if (!alive) return ("NOT RESPONDING", "Off");
        if (state is null) return ("NO STATUS YET", "Warn");
        return state == "online"
            ? ("ONLINE", "Ok")
            : (StateLabels.GetValueOrDefault(state, state.ToUpperInvariant()), "Warn");
    }

    private static IEnumerable<string> MetaParts(BusAgent agent, HostStatus? status, bool alive, DateTimeOffset now)
    {
        var silent = alive ? [] : new[] { FeedLogic.PresenceLabel(agent.LastSeenAt, now) };
        return status is null ? silent : silent.Concat(Details(status));
    }

    private static IEnumerable<string> Details(HostStatus status) =>
    [
        $"{status.Busy} of {status.Max} workers busy",
        When(status.Version.Length > 0, $"version {status.Version}"),
        string.Join(", ", status.Engines.Select(EngineLabel)),
        When(status.Account.Length > 0, $"runs as {status.Account}"),
        When(status.HeldClones > 0, $"{status.HeldClones} kept for unsaved work"),
        When(status.Outbox > 0, $"{status.Outbox} replies waiting to post"),
        ReleaseSourceLabel(status.ReleaseSource)
    ];

    /// <summary>
    /// Where the host takes its own updates from. "fleet" is the long-standing default and is not
    /// worth a mention; anything else is, because it changes whose repository the host follows.
    /// </summary>
    internal static string ReleaseSourceLabel(string source) =>
        source.Length == 0 || source == "fleet" ? string.Empty : $"updates from {source}";

    private static string When(bool condition, string text) => condition ? text : string.Empty;

    internal static string EngineLabel(HostEngine engine) => engine.SignedIn switch
    {
        true => $"{engine.Name} signed in",
        false => $"{engine.Name} needs sign-in",
        _ => engine.Name
    };

    private static IEnumerable<string> Alerts(HostStatus? status)
    {
        if (status is null) yield break;
        if (status.ProblemText.Length > 0) yield return $"Problem: {status.ProblemText}";
        foreach (var warning in status.Warnings) yield return WarningText(warning);
    }

    /// <summary>A standing warning in words. One this version does not know is shown as the host sent it.</summary>
    internal static string WarningText(string code) => code switch
    {
        "not-dedicated" => "Warning: this host runs as a person's own Windows account, so its workers can reach everything that person can.",
        "isolation-weak" => "Warning: the host's account can change programs that other accounts run. Run the isolation check on that PC.",
        _ => $"Warning: {code}"
    };

    public static string Summary(IReadOnlyCollection<HostRow> rows)
    {
        if (rows.Count == 0) return "No worker hosts yet. A host appears here once it has joined the bus.";
        var silent = rows.Count(row => row.Tone == "Off");
        var attention = rows.Count(row => row.Tone == "Warn" || (row.HasAlerts && row.Tone == "Ok"));
        return $"{rows.Count} host{(rows.Count == 1 ? "" : "s")}{Note(silent, "not responding")}{Note(attention, "needing attention")}.";
    }

    private static string Note(int count, string what) => count > 0 ? $", {count} {what}" : string.Empty;
}
