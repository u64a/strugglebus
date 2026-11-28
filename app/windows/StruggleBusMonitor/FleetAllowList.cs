using System.Text.RegularExpressions;

namespace StruggleBusMonitor;

/// <summary>An agent authorised to task the worker hosts: one <c>[[coordinator]]</c> table of the fleet.</summary>
internal sealed record CoordinatorEntry(
    string AgentName, string AgentId, string Project, string NotesRepo, string NotesChannel, IReadOnlyList<string> Repos, string DefaultEngine);

/// <summary>
/// The fleet's allow list, changed one entry at a time: authorise an agent to task the hosts,
/// take that away, or remove a host. Each gives the next document's exact text, with the serial
/// raised by one and every other byte kept, for a hardware key to sign.
///
/// The rules are the shared vectors' (contracts/fleet/compose/coordinators.json), whose reference
/// is worker-host/tests/test_fleet_compose_vectors.py. A coordinator can have every host run
/// code, so what goes into the document is checked hard: each value against the hosts' own
/// patterns, no character that could end a text or start a line or a table, and no repository
/// outside the site's allowed locations.
/// </summary>
internal static partial class FleetAllowList
{
    public static readonly IReadOnlyList<string> Engines = ["ghcp", "claude"];

    /// <summary>Characters that could close a text, start a comment or a table, or break a line.</summary>
    private const string Unsafe = "\"\\\n\r#[]";

    [GeneratedRegex(@"\A[a-z0-9][a-z0-9-]{0,62}\z")]
    private static partial Regex AgentName();

    [GeneratedRegex(@"\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z")]
    private static partial Regex Uuid();

    [GeneratedRegex(@"\A[a-z0-9][a-z0-9-]{0,30}\z")]
    private static partial Regex Project();

    [GeneratedRegex(@"\A[A-Za-z0-9][A-Za-z0-9_-]{0,63}\z")]
    private static partial Regex Channel();

    [GeneratedRegex(@"\A[A-Za-z0-9_.-]+\z")]
    private static partial Regex Segment();

    [GeneratedRegex(@"\Ahttps://(?<host>[a-z0-9]([a-z0-9.-]*[a-z0-9])?)(?<path>/[^?#@:\s]*)\z")]
    private static partial Regex HttpsUrl();

    [GeneratedRegex(@"\A\[\[?([a-z_]+)\]\]?\s*\z")]
    private static partial Regex Header();

    [GeneratedRegex(@"\s+=\s+")]
    private static partial Regex EqualsSign();

    private static FleetRefusedException Refused(FleetRefusal reason, string message, string? field = null) => new(reason, message, field);

    // ---- Repository addresses, as the hosts read them --------------------------------------------

    /// <summary>The host and path segments of a plain https address, or null. No user, port, query or fragment.</summary>
    internal static (string Host, string[] Segments)? Split(string url)
    {
        if (url.Any(char.IsControl) || HttpsUrl().Match(url) is not { Success: true } match) return null;
        return (match.Groups["host"].Value, match.Groups["path"].Value[1..].Split('/'));
    }

    private static bool SegmentsOk(IEnumerable<string> segments) =>
        segments.All(segment => Segment().IsMatch(segment) && segment is not "." and not "..");

    /// <summary>Host, owner and repository of exactly https://host/owner/repo, with ".git" allowed at the end.</summary>
    internal static (string Host, string Owner, string Repo)? Repository(string url)
    {
        return Split(url) is { Segments.Length: 2 } parts ? RepositoryOf(parts.Host, parts.Segments) : null;
    }

    private static (string Host, string Owner, string Repo)? RepositoryOf(string host, string[] segments)
    {
        if (!SegmentsOk(segments)) return null;
        var repo = WithoutGit(segments[1]);
        return IsName(repo) ? (host, segments[0], repo) : null;
    }

    private static string WithoutGit(string name) => name.EndsWith(".git", StringComparison.Ordinal) ? name[..^4] : name;

    private static bool IsName(string name) => name.Length > 0 && name != "." && name != "..";

    /// <summary>A "repos" entry: https://host/, https://host/owner/, or one exact repository.</summary>
    internal static bool PrefixOk(string prefix)
    {
        if (Split(prefix) is not { } parts) return false;
        if (!prefix.EndsWith('/')) return Repository(prefix) is not null;
        var owner = parts.Segments[..^1];
        return owner.Length <= 1 && SegmentsOk(owner);
    }

    /// <summary>Whether a repository is under a prefix, by whole path segments: /acme/ does not cover /acme-evil/x.</summary>
    internal static bool Matches(string url, string prefix)
    {
        return Repository(url) is { } target && PrefixOk(prefix) && Covers(prefix, target);
    }

    private static bool Covers(string prefix, (string Host, string Owner, string Repo) target) =>
        prefix.EndsWith('/') ? CoversOwner(Split(prefix)!.Value, target) : IsThat(Repository(prefix), target);

    private static bool IsThat((string Host, string Owner, string Repo)? repository, (string Host, string Owner, string Repo) target) =>
        repository is { } found && found.Equals(target);

    /// <summary>A location ending in "/" covers a repository on the same host: every owner's, or that one owner's.</summary>
    private static bool CoversOwner((string Host, string[] Segments) prefix, (string Host, string Owner, string Repo) target)
    {
        if (prefix.Host != target.Host) return false;
        var owner = prefix.Segments[..^1];
        return owner.Length == 0 || owner[0] == target.Owner;
    }

    /// <summary>Whether a repository or a prefix lies inside one allowed location, never wider than it.</summary>
    internal static bool Within(string url, string remote)
    {
        if (!url.EndsWith('/')) return Matches(url, remote);
        if (Split(url) is not { } inner || Split(remote) is not { } outer || inner.Host != outer.Host) return false;
        return StartsWith(Path(inner.Segments), Path(outer.Segments));
    }

    private static string[] Path(string[] segments) => segments.Where(segment => segment.Length > 0).ToArray();

    private static bool StartsWith(string[] path, string[] start) => path.Length >= start.Length && path[..start.Length].SequenceEqual(start);

    // ---- Authorising a coordinator ----------------------------------------------------------------

    /// <summary>The first thing wrong with an entry's values, as the vectors name it, or nothing.</summary>
    internal static void CheckEntry(CoordinatorEntry entry, IReadOnlyList<string> remotes)
    {
        CheckCharacters(entry);
        if (BadValue(entry) is { } field) throw Refused(FleetRefusal.BadValue, BadValueText(field), field);
        CheckRemotes(entry, remotes);
    }

    private static void CheckCharacters(CoordinatorEntry entry)
    {
        if (entry.NotesRepo.Any(Unsafe.Contains)) throw Refused(FleetRefusal.UnsafeChar, "The notes repository address has a character that is not allowed in it.", "notes_repo");
        if (entry.Repos.Any(repo => repo.Any(Unsafe.Contains))) throw Refused(FleetRefusal.UnsafeChar, "A repository address has a character that is not allowed in it.", "repos");
    }

    private static void CheckRemotes(CoordinatorEntry entry, IReadOnlyList<string> remotes)
    {
        if (entry.Repos.Any(repo => !remotes.Any(remote => Within(repo, remote))))
        {
            throw Refused(FleetRefusal.OutsideRemotes, "A repository location is outside the locations this site allows its hosts to work in.", "repos");
        }

        if (!remotes.Any(remote => Within(entry.NotesRepo, remote)))
        {
            throw Refused(FleetRefusal.OutsideRemotes, "The notes repository is outside the locations this site allows its hosts to work in.", "notes_repo");
        }
    }

    /// <summary>The first field, in the order they are written, whose value the hosts would refuse.</summary>
    private static string? BadValue(CoordinatorEntry entry)
    {
        (string Field, bool Good)[] checks =
        [
            ("agent_name", AgentName().IsMatch(entry.AgentName)),
            ("agent_id", Uuid().IsMatch(entry.AgentId)),
            ("project", Project().IsMatch(entry.Project)),
            ("notes_repo", Repository(entry.NotesRepo) is not null),
            ("notes_channel", Channel().IsMatch(entry.NotesChannel)),
            ("repos", entry.Repos.Count > 0 && entry.Repos.All(PrefixOk)),
            ("default_engine", Engines.Contains(entry.DefaultEngine))
        ];
        return checks.FirstOrDefault(check => !check.Good).Field;
    }

    private static readonly Dictionary<string, string> BadValueTexts = new()
    {
        ["agent_name"] = "That is not an agent's name on the bus.",
        ["agent_id"] = "The agent's id is not a lower-case UUID.",
        ["project"] = "The project is a short name: lower-case letters, digits and hyphens, 31 at most.",
        ["notes_repo"] = "The notes repository must be one repository's address: https://host/owner/repository.",
        ["notes_channel"] = "The notes channel is a channel name: letters, digits, hyphens and underscores.",
        ["repos"] = "Give at least one repository location: https://host/owner/repository, or https://host/owner/ for everything of that owner.",
        ["default_engine"] = "The engine must be ghcp or claude."
    };

    private static string BadValueText(string field) => BadValueTexts[field];

    /// <summary>The table written for a coordinator: a blank line, the header, then each key padded as today's fleet pads them.</summary>
    internal static string Block(CoordinatorEntry entry)
    {
        (string Key, string Value)[] pairs =
        [
            ("agent_name", Quoted(entry.AgentName)), ("agent_id", Quoted(entry.AgentId)), ("project", Quoted(entry.Project)),
            ("notes_repo", Quoted(entry.NotesRepo)), ("notes_channel", Quoted(entry.NotesChannel)),
            ("repos", "[" + string.Join(", ", entry.Repos.Select(Quoted)) + "]"), ("default_engine", Quoted(entry.DefaultEngine))
        ];
        return "\n[[coordinator]]\n" + string.Concat(pairs.Select(pair => $"{pair.Key,-14} = {pair.Value}\n"));
    }

    private static string Quoted(string value) => $"\"{value}\"";

    /// <summary>
    /// The next document with this coordinator added at the end, and what the operator should be
    /// warned about before signing: a location ending in "/" covers every repository under it.
    /// </summary>
    public static (string Text, IReadOnlyList<string> BroadPrefixes) Add(
        string current, CoordinatorEntry entry, long busSerial, IEnumerable<long> reported, IReadOnlyList<string> remotes)
    {
        CheckEntry(entry, remotes);
        var agents = ReadStrict(current);
        if (agents.Any(agent => agent.Name == entry.AgentName || agent.Id == entry.AgentId))
        {
            throw Refused(FleetRefusal.DuplicateAgent, "The fleet already lists an agent with that name or id.");
        }

        FleetCompose.CheckSerials(FleetCompose.SerialOf(current), busSerial, reported);
        return (FleetCompose.WithSerial(current, busSerial + 1) + Block(entry), entry.Repos.Where(repo => repo.EndsWith('/')).ToList());
    }

    /// <summary>Every agent the document lists, after the strict reading; refuses a name or id listed twice.</summary>
    private static IReadOnlyList<FleetAgent> ReadStrict(string current)
    {
        FleetCompose.SerialOf(current);
        var agents = FleetCompose.Agents(current);
        if (agents.Select(agent => agent.Name).Distinct().Count() != agents.Count || agents.Select(agent => agent.Id).Distinct().Count() != agents.Count)
        {
            throw Refused(FleetRefusal.DuplicateAgent, "The current fleet lists an agent name or id twice. Hosts refuse that, so the app will not build on it.");
        }

        return agents;
    }

    // ---- Removing a coordinator or a host ---------------------------------------------------------

    /// <summary>
    /// The next document without one coordinator's or host's table, and the blank line before it.
    /// <paramref name="kind"/> is "coordinator" or "host". A table that has been edited by hand
    /// (a blank line or a comment inside it) is refused: the app does not guess where it ends.
    /// </summary>
    public static string Remove(string current, string kind, string agentName, long busSerial, IEnumerable<long> reported)
    {
        if (kind == "coordinator") RequireAnother(ReadStrict(current), agentName);
        else ReadStrict(current);

        var lines = current.Split('\n');
        if (BlockOf(lines, kind, agentName) is not { } block) throw Refused(FleetRefusal.NotListed, $"The fleet does not list a {kind} named {agentName}.");
        FleetCompose.CheckSerials(FleetCompose.SerialOf(current), busSerial, reported);
        var kept = lines[..StartOf(lines, block.Header)].Concat(lines[(block.Header + 1 + block.Length)..]);
        return FleetCompose.WithSerial(string.Join("\n", kept), busSerial + 1);
    }

    /// <summary>Refuses to remove the only coordinator: hosts with nobody allowed to task them would have nothing to do.</summary>
    private static void RequireAnother(IReadOnlyList<FleetAgent> agents, string agentName)
    {
        var coordinators = agents.Where(agent => agent.Kind == "coordinator").ToList();
        if (coordinators.Count == 1 && coordinators[0].Name == agentName)
        {
            throw Refused(FleetRefusal.LastCoordinator, "This is the only agent authorised to task the hosts. Authorise another before removing it, or the hosts would have nothing to do.");
        }
    }

    /// <summary>The first line to drop: the blank line before the table's header when there is one.</summary>
    private static int StartOf(string[] lines, int header) => header > 0 && lines[header - 1].Trim().Length == 0 ? header - 1 : header;

    /// <summary>Where the named table starts and how many lines of body it has, or null when it is not there.</summary>
    private static (int Header, int Length)? BlockOf(string[] lines, string kind, string agentName)
    {
        var headers = Enumerable.Range(0, lines.Length).Where(index => Header().IsMatch(lines[index])).ToList();
        for (var number = 0; number < headers.Count; number++)
        {
            var header = headers[number];
            if (lines[header] != $"[[{kind}]]") continue;
            var body = Body(lines, header, number + 1 < headers.Count ? headers[number + 1] : lines.Length);
            if (!Names(body, agentName)) continue;
            RequireUntouched(body, agentName);
            return (header, body.Count);
        }

        return null;
    }

    private static bool Names(List<string> body, string agentName) =>
        body.Select(line => EqualsSign().Replace(line, " = ")).Contains($"agent_name = \"{agentName}\"");

    private static void RequireUntouched(List<string> body, string agentName)
    {
        if (body.Any(line => line.Trim().Length == 0 || line.TrimStart().StartsWith('#')))
        {
            throw Refused(FleetRefusal.HandEdited, $"The table for {agentName} has a blank line or a comment inside it, so the app cannot be sure where it ends. Remove it by hand and sign the fleet with sign-config.ps1.");
        }
    }

    /// <summary>The lines of a table after its header, without the blank lines that end it.</summary>
    private static List<string> Body(string[] lines, int header, int end)
    {
        var body = lines[(header + 1)..end].ToList();
        while (body.Count > 0 && body[^1].Trim().Length == 0) body.RemoveAt(body.Count - 1);
        return body;
    }
}
