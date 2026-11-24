using System.Collections.ObjectModel;

namespace StruggleBusMonitor;

/// <summary>What the status pill shows: the state word, its detail and the colour resource.</summary>
internal sealed record StatusDisplay(string State, string Detail, string Tone);

/// <summary>Pure rules for the Monitor page: feed order and roll-over, the agent rows, and wording.</summary>
internal static class MonitorFeedLogic
{
    public const int MaximumLiveEntries = 250;

    public static bool IsFrozenState(string state) => state.Equals("frozen", StringComparison.OrdinalIgnoreCase);

    public static StatusDisplay LiveStatus(bool frozen, string detail) =>
        frozen ? new StatusDisplay("FROZEN", detail, "Bad") : new StatusDisplay("LIVE", detail, "Ok");

    public static string SequenceDetail(long sequence) => $"seq {sequence:N0}";

    // ---- Feed --------------------------------------------------------------------------------

    /// <summary>The feed is newest first: the entry goes above the first one that is older.</summary>
    public static void InsertBySequence(IList<ActivityEntry> feed, ActivityEntry entry)
    {
        var index = 0;
        while (index < feed.Count && feed[index].Sequence > entry.Sequence) index++;
        feed.Insert(index, entry);
    }

    /// <summary>
    /// Only the live window rolls over; history fetched on request stays until the filter changes.
    /// Returns the sequence numbers that were dropped, oldest live entries first.
    /// </summary>
    public static IReadOnlyList<long> TrimLive(IList<ActivityEntry> feed, int maximum = MaximumLiveEntries)
    {
        var removed = new List<long>();
        var live = feed.Count(entry => !entry.Pinned);
        for (var last = feed.Count - 1; last >= 0 && live > maximum; last--)
        {
            if (feed[last].Pinned) continue;
            removed.Add(feed[last].Sequence);
            feed.RemoveAt(last);
            live--;
        }
        return removed;
    }

    /// <summary>Drops the history that was fetched for an agent filter. Returns the sequence numbers removed.</summary>
    public static IReadOnlyList<long> RemovePinned(IList<ActivityEntry> feed)
    {
        var removed = new List<long>();
        for (var index = feed.Count - 1; index >= 0; index--)
        {
            if (!feed[index].Pinned) continue;
            removed.Add(feed[index].Sequence);
            feed.RemoveAt(index);
        }
        return removed;
    }

    public static string HoldText(int waiting) =>
        $"Holding your place while you read. {waiting} new message{(waiting == 1 ? "" : "s")} waiting.";

    public static string ActivityCountText(int shown, int total) =>
        shown == total ? $"{shown} messages" : $"{shown} of {total} shown";

    public static string EmptyActivityText(int total) =>
        total == 0 ? "No messages yet." : "No messages match. Clear a filter to see more.";

    /// <summary>Writes on each agent row how many of the loaded messages are its own; none shows as blank.</summary>
    public static void ApplyMessageCounts(IEnumerable<AgentEntry> agents, IEnumerable<ActivityEntry> feed)
    {
        var counts = feed.GroupBy(entry => entry.AgentName).ToDictionary(group => group.Key, group => group.Count());
        foreach (var agent in agents)
            agent.CountLabel = counts.TryGetValue(agent.Name, out var count) ? count.ToString() : string.Empty;
    }

    // ---- Channels ----------------------------------------------------------------------------

    /// <summary>True when the channel chips must be rebuilt: none exist yet, or the bus's channels differ from those shown after "ALL".</summary>
    public static bool ChannelChipsOutdated(IReadOnlyList<ChannelFilterOption> shown, IReadOnlyList<string> names) =>
        shown.Count == 0 || !names.SequenceEqual(shown.Skip(1).Select(option => option.Name));

    // ---- Agents ------------------------------------------------------------------------------

    public static string AgentCountText(int shown, int total) => shown == total ? total.ToString() : $"{shown} of {total}";

    public static string? AgentChipText(string? name) => name is null ? null : $"from {name}  ✕";

    /// <summary>Active agents first, then idle, then offline; by name within each.</summary>
    public static IReadOnlyList<BusAgent> OrderAgents(IEnumerable<BusAgent> agents, DateTimeOffset now) =>
        agents
            .OrderBy(agent => FeedLogic.Presence(agent.LastSeenAt, now))
            .ThenBy(agent => agent.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();

    /// <summary>Updates the agent rows in place so selection and scroll position survive a refresh.</summary>
    public static void SyncAgentRows(ObservableCollection<AgentEntry> rows, IEnumerable<BusAgent> agents, DateTimeOffset now)
    {
        var ordered = OrderAgents(agents, now);
        var wanted = ordered.Select(agent => agent.Id).ToHashSet();
        for (var index = rows.Count - 1; index >= 0; index--)
            if (!wanted.Contains(rows[index].Id)) rows.RemoveAt(index);

        for (var index = 0; index < ordered.Count; index++)
            PlaceAgentRow(rows, index, ordered[index], now);
    }

    private static void PlaceAgentRow(ObservableCollection<AgentEntry> rows, int index, BusAgent agent, DateTimeOffset now)
    {
        var existing = IndexOfAgent(rows, agent.Id, index);
        if (existing < 0)
        {
            rows.Insert(index, new AgentEntry(agent, now));
            return;
        }
        if (existing != index) rows.Move(existing, index);
        rows[index].Update(agent, now);
    }

    private static int IndexOfAgent(ObservableCollection<AgentEntry> rows, string id, int from)
    {
        for (var probe = from; probe < rows.Count; probe++)
            if (rows[probe].Id == id) return probe;
        return -1;
    }

    /// <summary>The agent filter is dropped when its agent is no longer on the bus.</summary>
    public static bool SelectedAgentGone(string? selected, IEnumerable<AgentEntry> rows) =>
        selected is not null && rows.All(agent => agent.Name != selected);
}
