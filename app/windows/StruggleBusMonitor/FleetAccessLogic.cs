namespace StruggleBusMonitor;

/// <summary>One coordinator or host as the fleet on the bus lists it, for the list the operator removes from.</summary>
public sealed class FleetEntryRow
{
    public required string Kind { get; init; }
    public required string Name { get; init; }
    public string KindLabel => Kind == "coordinator" ? "MAY TASK THE HOSTS" : "WORKER HOST";
    public string RemoveLabel => Kind == "coordinator" ? "Take this away" : "Remove from the fleet";
}

/// <summary>An agent the operator could authorise, with what the bus knows about it.</summary>
public sealed class AgentChoice
{
    public required string Id { get; init; }
    public required string Name { get; init; }

    /// <summary>The agent's standing on the bus, shown before it is authorised.</summary>
    public string Identity { get; init; } = string.Empty;
}

/// <summary>What the operator filled in to authorise an agent.</summary>
internal sealed record AccessForm(AgentChoice? Agent, string Project, string NotesRepo, string NotesChannel, string Repos, string Engine);

/// <summary>
/// "This agent may task the hosts", in the app: which agents can be chosen, what the operator is
/// told before signing, and the words for each change. An authorised agent (a coordinator) can
/// have every worker host run code in the repositories it is given, so the confirmation says so
/// in full and calls out any location that covers more than one repository.
/// </summary>
internal static class FleetAccessLogic
{
    public const string AuthoriseCaption = "Authorise an agent to task the hosts";
    public const string RemoveCaption = "Remove from the fleet";
    public const string ChooseAgent = "Choose the agent to authorise from the list first.";

    public const string NoRemotes =
        "This PC has no repository locations for the site yet. Fill in \"Repository locations the host may work in\" on Admin, Add a host first: an agent can only be given repositories inside them.";

    /// <summary>
    /// Removing an entry changes what hosts accept from now on; it does not stop anything at once.
    /// The levers that do are named so the operator reaches for the right one.
    /// </summary>
    public const string NotInstant =
        "This is not instant. Each host takes up the new fleet at its next check, and a task already running is not stopped. To stop an agent now: block or retire it on Admin, Agents, or freeze all agent access on Admin, Access.";

    private static readonly string[] HostSuffixes = [HostsLogic.HostSuffix];

    /// <summary>
    /// The agents that can be authorised: enabled on the bus, not a worker host, and not already
    /// in the fleet. A blocked or retired agent is never offered, and nothing is ever typed.
    /// </summary>
    public static IReadOnlyList<AgentChoice> Choices(IEnumerable<ManagedAgent> agents, IReadOnlyList<FleetAgent> fleet, DateTimeOffset now) =>
        agents
            .Where(agent => agent.State == "enabled" && !HostSuffixes.Any(suffix => agent.Name.EndsWith(suffix, StringComparison.Ordinal)))
            .Where(agent => !fleet.Any(listed => listed.Name == agent.Name || listed.Id == agent.Id))
            .OrderBy(agent => agent.Name, StringComparer.Ordinal)
            .Select(agent => new AgentChoice { Id = agent.Id, Name = agent.Name, Identity = Identity(agent, now) })
            .ToList();

    /// <summary>How many matches are put on screen. A bus can hold hundreds of agents; the operator types to narrow them.</summary>
    public const int ShownMatches = 8;

    public const string SearchHint = "Type part of the agent's name to find it.";

    /// <summary>
    /// The agents whose name holds what was typed, names that start with it first, at most
    /// <see cref="ShownMatches"/>. Nothing typed shows nothing: a list of every agent on a busy
    /// bus is no use to anyone.
    /// </summary>
    public static IReadOnlyList<AgentChoice> Matching(IReadOnlyList<AgentChoice> choices, string typed)
    {
        var wanted = typed.Trim();
        if (wanted.Length == 0) return [];
        return choices
            .Where(choice => choice.Name.Contains(wanted, StringComparison.OrdinalIgnoreCase))
            .OrderBy(choice => choice.Name.StartsWith(wanted, StringComparison.OrdinalIgnoreCase) ? 0 : 1)
            .ThenBy(choice => choice.Name, StringComparer.Ordinal)
            .Take(ShownMatches)
            .ToList();
    }

    /// <summary>What to say under the search box: how to start, that nothing matches, or that there are more than are shown.</summary>
    public static string SearchText(IReadOnlyList<AgentChoice> choices, string typed)
    {
        var wanted = typed.Trim();
        if (wanted.Length == 0) return $"{SearchHint} {choices.Count} enabled agent{(choices.Count == 1 ? "" : "s")} can be authorised.";
        var matches = choices.Count(choice => choice.Name.Contains(wanted, StringComparison.OrdinalIgnoreCase));
        return matches == 0
            ? $"No enabled agent has \"{wanted}\" in its name. A blocked or retired agent, a worker host, and an agent already in the fleet are not offered."
            : MatchesText(matches);
    }

    private static string MatchesText(int matches) => matches > ShownMatches
        ? $"Showing {ShownMatches} of {matches} matches. Keep typing to narrow them."
        : $"{matches} match{(matches == 1 ? "" : "es")}. Choose one.";

    /// <summary>What the bus knows of the agent, for the operator to recognise it by.</summary>
    internal static string Identity(ManagedAgent agent, DateTimeOffset now)
    {
        string[] parts =
        [
            agent.Name,
            $"id {agent.Id}",
            agent.State,
            FeedLogic.PresenceLabel(agent.LastSeenAt, now),
            OwnWord(agent)
        ];
        return string.Join("  ·  ", parts.Where(part => part.Length > 0));
    }

    /// <summary>
    /// The host and description an agent gave for itself. The bus does not check either, so they
    /// are marked as the agent's own word: the name, id and state are what the bus vouches for.
    /// </summary>
    private static string OwnWord(ManagedAgent agent)
    {
        string[] said = [agent.Host.Length > 0 ? $"runs on {agent.Host}" : string.Empty, agent.Description];
        var claims = string.Join("; ", said.Where(claim => claim.Length > 0));
        return claims.Length == 0 ? string.Empty : $"in its own words, not checked: {claims}";
    }

    public static IReadOnlyList<FleetEntryRow> Rows(IEnumerable<FleetAgent> fleet) =>
        fleet.Where(agent => agent.Name is not null).Select(agent => new FleetEntryRow { Kind = agent.Kind, Name = agent.Name! }).ToList();

    /// <summary>The fleet entry the form describes. Throws, in words, when no agent is chosen.</summary>
    public static CoordinatorEntry Entry(AccessForm form)
    {
        var agent = form.Agent ?? throw new InvalidOperationException(ChooseAgent);
        return new CoordinatorEntry(
            agent.Name, agent.Id, form.Project.Trim(), form.NotesRepo.Trim(), form.NotesChannel.Trim(), AddHostLogic.Lines(form.Repos), form.Engine);
    }

    /// <summary>What the operator reads before authorising: who, on how many hosts, where, and what "broad" means.</summary>
    public static string AuthoriseText(CoordinatorEntry entry, AgentChoice agent, int hosts, IReadOnlyList<string> broad) => string.Join("\n",
    [
        $"Authorise {entry.AgentName} to task the worker hosts?",
        "",
        $"On the bus:  {agent.Identity}",
        "",
        $"{entry.AgentName} will be able to have ALL {hosts} worker host{(hosts == 1 ? "" : "s")} in the fleet run agent workers, which run code, in:",
        .. entry.Repos.Select(repo => "  " + repo + (broad.Contains(repo) ? "   <<< WARNING: every repository under this, now and later" : string.Empty)),
        "",
        $"Project: {entry.Project}.  Engine: {entry.DefaultEngine}.  Briefs are read from {entry.NotesRepo}, channel {entry.NotesChannel}.",
        "",
        "Only authorise an agent you set up and whose instructions you control. Taking this away later is not instant (see below).",
        "",
        NotInstant
    ]);

    public static string RemoveText(FleetEntryRow row) => string.Join("\n",
    [
        row.Kind == "coordinator"
            ? $"Take away {row.Name}'s authority to task the worker hosts?"
            : $"Remove worker host {row.Name} from the fleet? It stops taking work, and the other hosts stop counting it.",
        "",
        NotInstant
    ]);

    public static string Authorises(string agentName) => $"authorises {agentName} to task the hosts";

    public static string Removes(FleetEntryRow row) =>
        row.Kind == "coordinator" ? $"takes away {row.Name}'s authority to task the hosts" : $"removes worker host {row.Name}";

    /// <summary>The words for a refusal, with a way forward that is not a dead end in the app.</summary>
    public static string RefusalText(FleetRefusedException refusal) =>
        refusal.Reason == FleetRefusal.HandEdited ? refusal.Message + " Or ask for help on #humans." : refusal.Message;

    /// <summary>What to do with a document saved for signing on a PC where the app cannot ask a key.</summary>
    public static string SavedText(string path, long serial, string change) => string.Join("\n",
    [
        $"Saved fleet serial {serial} ({change}) as {path}",
        $"Saved the signer lines this PC holds as {FleetJoinLogic.SignersPath(path)}",
        "",
        "1. Sign it with the site's hardware key (touch and PIN). From a checkout of the project:",
        $"   pwsh -File worker-host\\tools\\sign-config.ps1 -File \"{path}\" -Signers \"{FleetJoinLogic.SignersPath(path)}\" -KeyFile $HOME\\.ssh\\<your hardware key file>",
        "2. Then choose Publish a signed fleet document and pick the saved file.",
        "",
        "Nothing has been sent to the bus yet."
    ]);
}
