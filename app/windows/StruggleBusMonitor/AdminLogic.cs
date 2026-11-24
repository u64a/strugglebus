namespace StruggleBusMonitor;

public enum AdminRowKind { Agent, Device, ServicePrincipal }

/// <summary>One agent, device or service principal on the Admin page, with the actions the bus allows on it.</summary>
public sealed class AdminRow
{
    public required AdminRowKind Kind { get; init; }
    public required string Id { get; init; }
    public required string Name { get; init; }
    public required string State { get; init; }

    /// <summary>The credential epoch or version the bus listed; sent back so a changed target is refused.</summary>
    public int Version { get; init; }
    public string Meta { get; init; } = string.Empty;
    public string Note { get; init; } = string.Empty;
    public bool IsThisDevice { get; init; }

    /// <summary>Built from the live roster because the bus is too old to list managed targets.</summary>
    public bool Legacy { get; init; }
    public IReadOnlyList<AdminRowAction> Actions { get; private set; } = [];

    public string StateLabel => State.ToUpperInvariant();

    /// <summary>"Ok", "Warn" or "Off": colours the state badge. The state is always written out as well.</summary>
    public string Tone => State switch
    {
        "enabled" => "Ok",
        "blocked" => "Warn",
        _ => "Off"
    };

    internal AdminRow WithActions(IEnumerable<AdminActionOption> options)
    {
        Actions = options.Select(option => new AdminRowAction(this, option.Action, option.Effect)).ToList();
        return this;
    }
}

public sealed class AdminRowAction(AdminRow row, string action, string effect)
{
    public AdminRow Row { get; } = row;
    public string Action { get; } = action;
    public string Effect { get; } = effect;
    public string Label => AdminLogic.ActionLabel(Action);
    public bool IsDanger => AdminLogic.IsDangerAction(Action);
}

/// <summary>Pure helpers for the Admin page, kept apart from the window so they can be tested.</summary>
public static class AdminLogic
{
    public const string LegacyBlockEffect =
        "Block this agent. It loses access immediately; history, keys and cursors are kept.";

    public const string LegacyRevokeEffect =
        "Permanently revoke this device. Its read credential and operator access both stop working immediately.";

    private static readonly Dictionary<string, string> ActionLabels = new(StringComparer.Ordinal)
    {
        ["block"] = "Block",
        ["block-agent"] = "Block",
        ["unblock"] = "Unblock",
        ["retire"] = "Retire",
        ["rotate"] = "Rotate secret",
        ["revoke"] = "Revoke",
        ["revoke-device"] = "Revoke"
    };

    private static readonly HashSet<string> DangerActions =
        new(StringComparer.Ordinal) { "retire", "revoke", "revoke-device", "block", "block-agent" };

    /// <summary>The button text for an action; one this version does not know keeps the bus's own name.</summary>
    public static string ActionLabel(string action) => ActionLabels.GetValueOrDefault(action, action);

    /// <summary>Actions that take access away, which the page marks as dangerous.</summary>
    public static bool IsDangerAction(string action) => DangerActions.Contains(action);

    public static AdminRow AgentRow(ManagedAgent agent, DateTimeOffset now)
    {
        var seen = agent.State == "retired"
            ? "retired"
            : FeedLogic.PresenceLabel(agent.LastSeenAt, now);
        var parts = new[] { agent.Host, seen, agent.Description }.Where(part => !string.IsNullOrWhiteSpace(part));
        return new AdminRow
        {
            Kind = AdminRowKind.Agent,
            Id = agent.Id,
            Name = agent.Name,
            State = agent.State,
            Version = agent.CredentialEpoch,
            Meta = string.Join("  ·  ", parts)
        }.WithActions(agent.Actions);
    }

    /// <summary>An enabled agent from the live roster, for a bus that has no management lists yet.</summary>
    public static AdminRow LegacyAgentRow(BusAgent agent, DateTimeOffset now)
    {
        var parts = new[] { agent.Host, FeedLogic.PresenceLabel(agent.LastSeenAt, now) }.Where(part => !string.IsNullOrWhiteSpace(part));
        return new AdminRow
        {
            Kind = AdminRowKind.Agent,
            Id = agent.Id,
            Name = agent.Name,
            State = "enabled",
            Legacy = true,
            Meta = string.Join("  ·  ", parts)
        }.WithActions([new AdminActionOption("block-agent", LegacyBlockEffect)]);
    }

    public static AdminRow DeviceRow(ManagedDevice device, DateTimeOffset now)
    {
        var parts = new List<string>
        {
            device.Status == "enabled" ? FeedLogic.PresenceLabel(device.LastSeenAt, now) : "no longer has access",
            device.HasWriteGrant ? "operator access saved" : "read only"
        };
        return new AdminRow
        {
            Kind = AdminRowKind.Device,
            Id = device.Id,
            Name = device.Label,
            State = device.Status,
            Note = device.ThisDevice ? "this PC" : string.Empty,
            IsThisDevice = device.ThisDevice,
            Meta = string.Join("  ·  ", parts)
        }.WithActions(device.Actions);
    }

    /// <summary>This PC only, for a bus that has no device list yet.</summary>
    public static AdminRow LegacyDeviceRow(Session session) => new AdminRow
    {
        Kind = AdminRowKind.Device,
        Id = session.DeviceId,
        Name = session.DeviceLabel,
        State = "enabled",
        Note = "this PC",
        IsThisDevice = true,
        Legacy = true
    }.WithActions([new AdminActionOption("revoke-device", LegacyRevokeEffect)]);

    public static AdminRow ServicePrincipalRow(ManagedServicePrincipal principal) => new AdminRow
    {
        Kind = AdminRowKind.ServicePrincipal,
        Id = principal.Id,
        Name = principal.Name,
        State = principal.Status,
        Version = principal.Version,
        Meta = $"creates worker agents named {principal.AgentNamePrefix}-*"
    }.WithActions(principal.Actions);

    /// <summary>Rows whose name or details contain every word typed, ordered enabled, blocked, then the rest.</summary>
    public static IReadOnlyList<AdminRow> Filter(IEnumerable<AdminRow> rows, string? text)
    {
        var words = (text ?? string.Empty).Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        return rows
            .Where(row => words.All(word => Mentions(row, word)))
            .OrderBy(StateOrder)
            .ThenBy(row => row.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static bool Mentions(AdminRow row, string word) =>
        row.Name.Contains(word, StringComparison.OrdinalIgnoreCase) ||
        row.Meta.Contains(word, StringComparison.OrdinalIgnoreCase) ||
        row.State.Contains(word, StringComparison.OrdinalIgnoreCase);

    private static int StateOrder(AdminRow row) => row.State switch { "blocked" => 0, "enabled" => 1, _ => 2 };

    public static string Summary(IReadOnlyCollection<AdminRow> rows, string noun)
    {
        if (rows.Count == 0) return $"No {noun}s.";
        var blocked = rows.Count(row => row.State == "blocked");
        var gone = rows.Count - blocked - rows.Count(row => row.State == "enabled");
        return $"{rows.Count} {noun}{(rows.Count == 1 ? "" : "s")}{CountNote(blocked, "blocked")}{CountNote(gone, "no longer active")}.";
    }

    private static string CountNote(int count, string what) => count > 0 ? $", {count} {what}" : string.Empty;
}
