using System.Windows.Input;

namespace StruggleBusMonitor;

public enum QuickFindScope { All, Agents, Messages }

public enum QuickFindKeyAction { None, Next, Previous, Open, ChangeScope }

/// <summary>The rows quick find shows, and what to say when there are none.</summary>
internal sealed record QuickFindOutcome(IReadOnlyList<QuickFindResult> Results, string EmptyText);

/// <summary>Pure rules for Ctrl+K quick find: which rows a query produces and what its keys do.</summary>
internal static class QuickFindLogic
{
    public const int MaximumAgents = 6;
    public const int MaximumMessages = 40;
    public const string Prompt = "Type part of an agent name, a host, or any words from a message.";
    public const string NothingLoaded = "Nothing matches in the agents or the messages loaded in this window.";

    /// <summary>Matching agents first, then loaded messages newest first, then the offer to search the whole bus.</summary>
    public static QuickFindOutcome Search(
        string? rawQuery,
        QuickFindScope scope,
        IEnumerable<BusAgent> agents,
        IEnumerable<BusMessage> loadedMessages,
        bool historySupported,
        DateTimeOffset now)
    {
        var query = FeedLogic.ParseQuery(rawQuery);
        if (query.IsEmpty) return new QuickFindOutcome([], Prompt);

        var results = new List<QuickFindResult>();
        if (scope != QuickFindScope.Messages) results.AddRange(AgentRows(agents, query.Text, now));
        if (scope != QuickFindScope.Agents) results.AddRange(LoadedRows(loadedMessages, query, historySupported, now));
        return new QuickFindOutcome(results, NothingLoaded);
    }

    /// <summary>The loaded messages that match, then the offer to search the bus when it can and there are words to search for.</summary>
    private static List<QuickFindResult> LoadedRows(IEnumerable<BusMessage> loadedMessages, FeedQuery query, bool historySupported, DateTimeOffset now)
    {
        var rows = MessageRows(loadedMessages, query, now).ToList();
        if (historySupported && query.Text.Length > 0) rows.Add(HistoryRow(query.Text));
        return rows;
    }

    /// <summary>Agents are found by the words alone; "from:" and "in:" only narrow messages.</summary>
    public static IReadOnlyList<QuickFindResult> AgentRows(IEnumerable<BusAgent> agents, string text, DateTimeOffset now)
    {
        if (text.Length == 0) return [];
        return agents
            .Where(agent => FeedLogic.MatchesAgent(agent, text))
            .OrderBy(agent => agent.Name.StartsWith(text, StringComparison.OrdinalIgnoreCase) ? 0 : 1)
            .ThenBy(agent => FeedLogic.Presence(agent.LastSeenAt, now))
            .ThenBy(agent => agent.Name, StringComparer.OrdinalIgnoreCase)
            .Take(MaximumAgents)
            .Select(agent => new QuickFindResult
            {
                Lead = "AGENT",
                Title = agent.Name,
                Detail = $"{HostPrefix(agent)}{FeedLogic.PresenceLabel(agent.LastSeenAt, now)}  ·  Enter shows its messages",
                Highlight = text,
                Agent = agent
            })
            .ToList();
    }

    private static string HostPrefix(BusAgent agent) => string.IsNullOrWhiteSpace(agent.Host) ? "" : agent.Host + "  ·  ";

    public static IReadOnlyList<QuickFindResult> MessageRows(IEnumerable<BusMessage> messages, FeedQuery query, DateTimeOffset now) =>
        messages
            .Where(message => FeedLogic.Matches(message, query))
            .OrderByDescending(message => message.Seq)
            .Take(MaximumMessages)
            .Select(message => MessageRow(message, query.Text, now))
            .ToList();

    public static QuickFindResult MessageRow(BusMessage message, string highlight, DateTimeOffset now) => new()
    {
        Lead = FeedLogic.TimeLabel(message.CreatedAt, now),
        Title = $"{message.AgentName}  #{message.Channel}",
        Detail = message.Body.ReplaceLineEndings(" "),
        Highlight = highlight,
        Message = message
    };

    public static QuickFindResult HistoryRow(string text) => new()
    {
        Lead = "HISTORY",
        Title = $"Search the whole bus history for “{text}”",
        Detail = "The results above only cover the messages loaded in this window.",
        HistoryQuery = text
    };

    public static string Searching(string text) => $"Searching the bus for “{text}”…";

    public static string NothingOnBus(string text) => $"Nothing on the bus matches “{text}”. The bus matches whole words.";

    public static string SearchFailed(string reason) => $"The search failed: {reason}";

    /// <summary>A bus search answers late; its rows are dropped if the operator has closed quick find or typed something else.</summary>
    public static bool IsStale(bool overlayOpen, string? currentQuery, string searchedText) =>
        !overlayOpen || FeedLogic.ParseQuery(currentQuery).Text != searchedText;

    public static QuickFindKeyAction KeyAction(Key key) => Keys.GetValueOrDefault(key, QuickFindKeyAction.None);

    private static readonly Dictionary<Key, QuickFindKeyAction> Keys = new()
    {
        [Key.Down] = QuickFindKeyAction.Next,
        [Key.Up] = QuickFindKeyAction.Previous,
        [Key.Enter] = QuickFindKeyAction.Open,
        [Key.Tab] = QuickFindKeyAction.ChangeScope
    };

    /// <summary>Tab moves to the next scope and Shift+Tab to the one before, wrapping round.</summary>
    public static int NextScopeIndex(int current, bool backwards, int count) =>
        (current + (backwards ? count - 1 : 1)) % count;

    /// <summary>Up and Down stop at the ends of the list.</summary>
    public static int MoveSelection(int selectedIndex, int step, int count) => Math.Clamp(selectedIndex + step, 0, count - 1);
}
