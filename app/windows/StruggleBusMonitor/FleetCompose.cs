using System.Text.RegularExpressions;

namespace StruggleBusMonitor;

/// <summary>Why the app will not compose the next fleet document. The names are the shared vectors' (contracts/fleet/compose).</summary>
internal enum FleetRefusal
{
    /// <summary>Not exactly one <c>serial = N</c> line.</summary>
    SerialLine,
    /// <summary>A table, key or piece of syntax the app does not know. A host would ignore an unknown key; the app refuses it.</summary>
    UnknownKey,
    DuplicateAgent,
    HostListed,
    /// <summary>The bus says a different serial from the one the document states.</summary>
    SerialMismatch,
    /// <summary>A host reports a serial above the bus's.</summary>
    SerialAhead,
    /// <summary>A value has a character that could end a text or start a line, a comment or a table.</summary>
    UnsafeChar,
    /// <summary>A value the hosts would refuse.</summary>
    BadValue,
    /// <summary>A repository outside the locations the site allows its hosts to work in.</summary>
    OutsideRemotes,
    NotListed,
    /// <summary>Removing it would leave no agent authorised to task the hosts.</summary>
    LastCoordinator,
    /// <summary>The table to remove has a blank line or a comment inside it, so its end is not certain.</summary>
    HandEdited
}

internal sealed class FleetRefusedException(FleetRefusal reason, string message, string? field = null) : InvalidOperationException(message)
{
    public FleetRefusal Reason { get; } = reason;

    /// <summary>Which value was refused, by its key in the fleet document, when the refusal is about one value.</summary>
    public string? Field { get; } = field;
}

/// <summary>One coordinator or host as the fleet document lists it.</summary>
internal sealed record FleetAgent(string Kind, string? Name, string? Id);

/// <summary>
/// Step 10 of Add a host: the next fleet document, made from the current one by adding one host
/// and raising the serial, with every other byte kept. The app composes; a hardware key signs
/// the result outside the app (see <see cref="FleetPublishLogic"/>).
///
/// The current document is read strictly. It is not a general TOML reader: it knows the fleet
/// schema's tables, keys and the few value forms a fleet uses, and refuses everything else, so
/// the app never builds on a document it only partly understands. Refusing costs little: the
/// document can still be edited and signed by hand.
/// </summary>
internal static partial class FleetCompose
{
    private static readonly string[] TopKeys = ["serial", "owner"];
    private static readonly string[] HostKeys = ["agent_name", "agent_id"];
    private static readonly string[] CoordinatorKeys =
    [
        "agent_name", "agent_id", "project", "notes_repo", "notes_channel", "repos", "default_engine", "repo_instructions", "worker_rules"
    ];

    private const string MultiLine = "\"\"\"";

    [GeneratedRegex(@"(?m)^serial = ([0-9]{1,9})\n")]
    private static partial Regex SerialLine();

    [GeneratedRegex(@"(?m)^\s*serial\s*=")]
    private static partial Regex AnySerial();

    [GeneratedRegex(@"\A(?<key>[a-z_]+)[ \t]*=[ \t]*(?<value>.*)\z")]
    private static partial Regex KeyValue();

    [GeneratedRegex(@"\A(""(?<text>[^""\\]*)""|[0-9]{1,15}|true|false|\[[ \t]*(""[^""\\]*""([ \t]*,[ \t]*""[^""\\]*"")*[ \t]*,?)?[ \t]*\])[ \t]*(#.*)?\z")]
    private static partial Regex Value();

    [GeneratedRegex(@"\A[a-z0-9][a-z0-9-]{0,57}-host\z")]
    private static partial Regex HostName();

    [GeneratedRegex(@"\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z")]
    private static partial Regex AgentId();

    private static FleetRefusedException Refused(FleetRefusal reason, string message) => new(reason, message);

    /// <summary>The serial the document states, when it has exactly one serial line in the one form the app writes.</summary>
    public static long SerialOf(string text)
    {
        var lines = SerialLine().Matches(text);
        if (lines.Count != 1 || AnySerial().Count(text) != 1)
        {
            throw Refused(FleetRefusal.SerialLine, "The current fleet does not have exactly one line of the form \"serial = N\", so the app cannot raise it safely.");
        }

        return long.Parse(lines[0].Groups[1].Value);
    }

    /// <summary>Every coordinator and host the document lists. Throws for anything outside the fleet schema.</summary>
    public static IReadOnlyList<FleetAgent> Agents(string text)
    {
        var agents = new List<FleetAgent>();
        var table = new Table("top", TopKeys);
        var lines = text.Split('\n');
        for (var index = 0; index < lines.Length; index++)
        {
            var line = lines[index].Trim(' ', '\t');
            if (line.Length == 0 || line[0] == '#') continue;
            if (line[0] == '[')
            {
                agents.AddRange(table.Agent());
                table = Open(line);
                continue;
            }

            index = table.Read(line, lines, index);
        }

        agents.AddRange(table.Agent());
        return agents;
    }

    private static Table Open(string header) => HeaderName(header) switch
    {
        "[[host]]" => new Table("host", HostKeys),
        "[[coordinator]]" => new Table("coordinator", CoordinatorKeys),
        var other => throw Refused(FleetRefusal.UnknownKey, $"The current fleet has a table the app does not know: {other}.")
    };

    /// <summary>The header without a trailing comment.</summary>
    private static string HeaderName(string header)
    {
        var comment = header.IndexOf('#');
        return (comment < 0 ? header : header[..comment]).TrimEnd(' ', '\t');
    }

    /// <summary>One table of the document while it is being read: which keys it may hold and which it has.</summary>
    private sealed class Table(string kind, string[] allowed)
    {
        private readonly Dictionary<string, string?> _values = [];

        /// <summary>The table as an agent, or nothing for the top of the document.</summary>
        public IEnumerable<FleetAgent> Agent() =>
            kind == "top" ? [] : [new FleetAgent(kind, _values.GetValueOrDefault("agent_name"), _values.GetValueOrDefault("agent_id"))];

        /// <summary>Reads one "key = value" starting at <paramref name="index"/>; returns the last line it used.</summary>
        public int Read(string line, string[] lines, int index)
        {
            var pair = KeyValue().Match(line);
            if (!pair.Success) throw Refused(FleetRefusal.UnknownKey, $"The app cannot read line {index + 1} of the current fleet.");
            var key = pair.Groups["key"].Value;
            if (!allowed.Contains(key) || _values.ContainsKey(key))
            {
                throw Refused(FleetRefusal.UnknownKey, $"The current fleet has a key the app does not expect in its {kind} table, on line {index + 1}: {key}.");
            }

            var value = pair.Groups["value"].Value;
            if (value.StartsWith(MultiLine, StringComparison.Ordinal))
            {
                _values[key] = null;
                return EndOfMultiLine(value[MultiLine.Length..], lines, index);
            }

            _values[key] = OneLineValue(key, value, index);
            return index;
        }
    }

    /// <summary>A value on one line: its text when it is a plain text, null for a number, true or false, or a list.</summary>
    private static string? OneLineValue(string key, string value, int index)
    {
        var read = Value().Match(value);
        if (!read.Success) throw Refused(FleetRefusal.UnknownKey, $"The app cannot read the value of {key} on line {index + 1} of the current fleet.");
        return read.Groups["text"].Success ? read.Groups["text"].Value : null;
    }

    /// <summary>The line a multi-line text closes on. Only a comment may follow the closing quotes.</summary>
    private static int EndOfMultiLine(string afterOpening, string[] lines, int index)
    {
        var rest = afterOpening;
        while (true)
        {
            var close = rest.IndexOf(MultiLine, StringComparison.Ordinal);
            if (close >= 0)
            {
                var after = rest[(close + MultiLine.Length)..].Trim(' ', '\t');
                if (after.Length == 0 || after[0] == '#') return index;
                throw Refused(FleetRefusal.UnknownKey, $"The app cannot read line {index + 1} of the current fleet.");
            }

            index++;
            if (index >= lines.Length) throw Refused(FleetRefusal.UnknownKey, "A multi-line text in the current fleet is never closed.");
            rest = lines[index];
        }
    }

    /// <summary>Why this name and id cannot be a host entry, or null.</summary>
    public static string? HostProblem(string agentName, string agentId)
    {
        if (!HostName().IsMatch(agentName)) return $"\"{agentName}\" is not a worker host's agent name.";
        return AgentId().IsMatch(agentId) ? null : "The host's agent id is not a lower-case UUID.";
    }

    /// <summary>
    /// The next document's exact text. <paramref name="busSerial"/> is the serial the bus holds
    /// for <paramref name="current"/>; <paramref name="reported"/> are the fleet serials hosts
    /// say they run.
    /// </summary>
    public static string Next(string current, string agentName, string agentId, long busSerial, IEnumerable<long> reported)
    {
        if (HostProblem(agentName, agentId) is { } problem) throw new InvalidOperationException(problem);
        var serial = SerialOf(current);
        CheckAgents(Agents(current), agentName, agentId);
        CheckSerials(serial, busSerial, reported);
        return WithSerial(current, busSerial + 1) + HostBlock(agentName, agentId);
    }

    /// <summary>The same text with its one serial line saying <paramref name="serial"/>.</summary>
    internal static string WithSerial(string text, long serial) => SerialLine().Replace(text, $"serial = {serial}\n", 1);

    /// <summary>The text added for one host: a blank line, then the table, in the form today's fleet uses.</summary>
    public static string HostBlock(string agentName, string agentId) =>
        $"\n[[host]]\nagent_name = \"{agentName}\"\nagent_id   = \"{agentId}\"\n";

    private static void CheckAgents(IReadOnlyList<FleetAgent> agents, string agentName, string agentId)
    {
        if (agents.Select(agent => agent.Name).Distinct().Count() != agents.Count || agents.Select(agent => agent.Id).Distinct().Count() != agents.Count)
        {
            throw Refused(FleetRefusal.DuplicateAgent, "The current fleet lists an agent name or id twice. Hosts refuse that, so the app will not build on it.");
        }

        if (agents.Any(agent => agent.Name == agentName || agent.Id == agentId))
        {
            throw Refused(FleetRefusal.HostListed, "The current fleet already lists this host's name or id.");
        }
    }

    internal static void CheckSerials(long serial, long busSerial, IEnumerable<long> reported)
    {
        if (serial != busSerial)
        {
            throw Refused(FleetRefusal.SerialMismatch, $"The bus says its fleet is serial {busSerial}, but the document it holds says serial {serial}. The app will not build on that.");
        }

        var ahead = reported.Where(value => value > busSerial).DefaultIfEmpty(busSerial).Max();
        if (ahead > busSerial)
        {
            throw Refused(
                FleetRefusal.SerialAhead,
                $"A host reports fleet serial {ahead}, which is above the bus's serial {busSerial}. Either the bus lost a document or a host is reporting a serial it does not have. The app will not jump to it: find out which before changing the fleet.");
        }
    }
}
