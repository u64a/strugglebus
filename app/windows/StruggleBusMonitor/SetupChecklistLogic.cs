using System.Windows;

namespace StruggleBusMonitor;

/// <summary>What the app already knows about how far a site's setup has got. Nothing is stored for the checklist.</summary>
/// <param name="Signers">Site signers registered on this PC.</param>
/// <param name="HasRemotes">Whether the site's repository locations have been entered.</param>
/// <param name="FleetHeld">Whether the bus holds a fleet.</param>
/// <param name="Hosts">Worker hosts the fleet lists.</param>
/// <param name="Agents">Agents the fleet lets task the hosts.</param>
internal sealed record SetupFacts(int Signers, bool HasRemotes, bool FleetHeld, int Hosts, int Agents);

/// <summary>One line of the checklist.</summary>
public sealed class SetupItem
{
    /// <summary>Which Admin tab does this step: security, addhost or fleet. Empty for a step done elsewhere.</summary>
    public required string Tab { get; init; }
    public required string Title { get; init; }
    public required string Detail { get; init; }
    public required bool Done { get; init; }
    public string Mark => Done ? "✓" : "○";
    public string Action => "Go there";
    public Visibility ActionVisibility => Done || Tab.Length == 0 ? Visibility.Collapsed : Visibility.Visible;
}

/// <summary>
/// The steps from an enrolled PC to hosts that take work, in order, each done or not from what
/// the app already holds. See docs/OPERATOR_JOURNEY.md.
/// </summary>
internal static class SetupChecklistLogic
{
    public const string Security = "security";
    public const string AddHost = "addhost";
    public const string Fleet = "fleet";

    public static IReadOnlyList<SetupItem> Items(SetupFacts facts) =>
        [Enrolled, Keys(facts.Signers), Remotes(facts.HasRemotes), FleetStarted(facts.FleetHeld), FirstHost(facts.Hosts), FirstAgent(facts.Agents)];

    private static SetupItem Enrolled => new()
    {
        Tab = string.Empty, Done = true,
        Title = "Enrol this PC",
        Detail = "Done: this PC is enrolled with the bus."
    };

    private static SetupItem Keys(int signers) => new()
    {
        Tab = Security, Done = signers >= HostEnrolFile.MinSigners,
        Title = "Register two hardware keys",
        Detail = signers switch
        {
            0 => "On Security. Set up a new key on a YubiKey, or add ones you already have. Two, so that losing one does not lock the site out.",
            1 => "One is registered. Add a second on Security, so that losing one does not lock the site out.",
            _ => $"{signers} are registered."
        }
    };

    private static SetupItem Remotes(bool entered) => new()
    {
        Tab = AddHost, Done = entered,
        Title = "Say where the site's repositories are",
        Detail = entered
            ? "Entered. Every host is fenced to these places."
            : "On Add a host, under repository locations: for example one GitHub organisation. Every host is fenced to these places."
    };

    private static SetupItem FleetStarted(bool held) => new()
    {
        Tab = Fleet, Done = held,
        Title = "Start the site's fleet",
        Detail = held
            ? "The bus holds the site's fleet."
            : "On Who may task the hosts. The fleet is the signed list of hosts and of the agents that may task them. Start a new one, or take over the one your hosts already run."
    };

    private static SetupItem FirstHost(int hosts) => new()
    {
        Tab = AddHost, Done = hosts > 0,
        Title = "Add your first worker host",
        Detail = hosts > 0
            ? $"The fleet lists {Count(hosts, "worker host")}."
            : "On Add a host: create the installer and data file, run them on the new PC, then check its code on Worker hosts."
    };

    private static SetupItem FirstAgent(int agents) => new()
    {
        Tab = Fleet, Done = agents > 0,
        Title = "Authorise your first agent",
        Detail = agents > 0
            ? $"{Count(agents, "agent")} may task the hosts."
            : "On Who may task the hosts: search for an agent and say which repositories it may have the hosts work in."
    };

    private static string Count(int count, string noun) => $"{count} {noun}{(count == 1 ? "" : "s")}";

    public static bool AllDone(IReadOnlyList<SetupItem> items) => items.All(item => item.Done);

    /// <summary>The line above the list: how far along, and what is next.</summary>
    public static string Summary(IReadOnlyList<SetupItem> items)
    {
        var next = items.First(item => !item.Done);
        return $"{items.Count(item => item.Done)} of {items.Count} done. Next: {char.ToLowerInvariant(next.Title[0])}{next.Title[1..]}. This card goes away when every step is done.";
    }
}
