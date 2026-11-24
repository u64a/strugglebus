using System.Collections.ObjectModel;
using System.Collections.Specialized;

namespace StruggleBusMonitor.Tests;

public sealed class MonitorFeedLogicTests
{
    private static readonly DateTimeOffset Now = new(2025, 6, 1, 12, 0, 0, TimeSpan.Zero);

    private static ActivityEntry Entry(long seq, bool pinned = false, string agent = "agent-one") =>
        new(new BusMessage(seq, "ops", agent, "body", "chat", Now), Now) { Pinned = pinned };

    private static BusAgent Agent(string name, double? minutesAgo = 0, string host = "") =>
        new("id-" + name, name, string.Empty, host, "seen", minutesAgo is { } minutes ? Now.AddMinutes(-minutes) : null);

    [Theory]
    [InlineData("frozen", true)]
    [InlineData("FROZEN", true)]
    [InlineData("normal", false)]
    public void IsFrozenState_IgnoresCase(string state, bool expected) =>
        Assert.Equal(expected, MonitorFeedLogic.IsFrozenState(state));

    [Fact]
    public void LiveStatus_IsBadWhenFrozen()
    {
        Assert.Equal(new StatusDisplay("LIVE", "seq 1", "Ok"), MonitorFeedLogic.LiveStatus(false, "seq 1"));
        Assert.Equal(new StatusDisplay("FROZEN", "", "Bad"), MonitorFeedLogic.LiveStatus(true, ""));
    }

    [Fact]
    public void SequenceDetail_GroupsThousands() =>
        Assert.Equal($"seq {1234567:N0}", MonitorFeedLogic.SequenceDetail(1234567));

    [Fact]
    public void InsertBySequence_KeepsTheFeedNewestFirst()
    {
        var feed = new List<ActivityEntry> { Entry(9), Entry(5), Entry(2) };

        MonitorFeedLogic.InsertBySequence(feed, Entry(7));
        MonitorFeedLogic.InsertBySequence(feed, Entry(12));
        MonitorFeedLogic.InsertBySequence(feed, Entry(1));

        Assert.Equal([12L, 9L, 7L, 5L, 2L, 1L], feed.Select(entry => entry.Sequence));
    }

    [Fact]
    public void TrimLive_DropsTheOldestLiveEntriesAndKeepsPinnedHistory()
    {
        var feed = new List<ActivityEntry> { Entry(9), Entry(8), Entry(7, pinned: true), Entry(6), Entry(5, pinned: true), Entry(4) };

        var removed = MonitorFeedLogic.TrimLive(feed, maximum: 2);

        Assert.Equal([4L, 6L], removed);
        Assert.Equal([9L, 8L, 7L, 5L], feed.Select(entry => entry.Sequence));
    }

    [Fact]
    public void TrimLive_LeavesAFeedWithinTheLimitAlone()
    {
        var feed = new List<ActivityEntry> { Entry(2), Entry(1) };

        Assert.Empty(MonitorFeedLogic.TrimLive(feed));
        Assert.Equal(2, feed.Count);
    }

    [Fact]
    public void RemovePinned_DropsOnlyFetchedHistory()
    {
        var feed = new List<ActivityEntry> { Entry(9), Entry(7, pinned: true), Entry(6), Entry(5, pinned: true) };

        var removed = MonitorFeedLogic.RemovePinned(feed);

        Assert.Equal([5L, 7L], removed);
        Assert.Equal([9L, 6L], feed.Select(entry => entry.Sequence));
    }

    [Theory]
    [InlineData(1, "Holding your place while you read. 1 new message waiting.")]
    [InlineData(4, "Holding your place while you read. 4 new messages waiting.")]
    public void HoldText_UsesThePlural(int waiting, string expected) =>
        Assert.Equal(expected, MonitorFeedLogic.HoldText(waiting));

    [Fact]
    public void ActivityTexts_SayWhenAFilterHidesMessages()
    {
        Assert.Equal("5 messages", MonitorFeedLogic.ActivityCountText(5, 5));
        Assert.Equal("2 of 5 shown", MonitorFeedLogic.ActivityCountText(2, 5));
        Assert.Equal("No messages yet.", MonitorFeedLogic.EmptyActivityText(0));
        Assert.Equal("No messages match. Clear a filter to see more.", MonitorFeedLogic.EmptyActivityText(5));
    }

    [Fact]
    public void ApplyMessageCounts_LabelsEachAgentWithItsLoadedMessages()
    {
        var agents = new[] { new AgentEntry(Agent("agent-one"), Now), new AgentEntry(Agent("agent-two"), Now) };
        agents[1].CountLabel = "7";

        MonitorFeedLogic.ApplyMessageCounts(agents, [Entry(1), Entry(2), Entry(3, agent: "someone-else")]);

        Assert.Equal("2", agents[0].CountLabel);
        Assert.Equal(string.Empty, agents[1].CountLabel);
    }

    [Fact]
    public void ChannelChipsOutdated_WhenNothingIsShownOrTheNamesDiffer()
    {
        ChannelFilterOption[] shown = [new(null), new("ops"), new("humans")];

        Assert.True(MonitorFeedLogic.ChannelChipsOutdated([], []));
        Assert.False(MonitorFeedLogic.ChannelChipsOutdated(shown, ["ops", "humans"]));
        Assert.True(MonitorFeedLogic.ChannelChipsOutdated(shown, ["humans", "ops"]));
        Assert.True(MonitorFeedLogic.ChannelChipsOutdated(shown, ["ops"]));
    }

    [Fact]
    public void AgentTexts_DescribeTheFilter()
    {
        Assert.Equal("4", MonitorFeedLogic.AgentCountText(4, 4));
        Assert.Equal("1 of 4", MonitorFeedLogic.AgentCountText(1, 4));
        Assert.Null(MonitorFeedLogic.AgentChipText(null));
        Assert.Equal("from agent-one  ✕", MonitorFeedLogic.AgentChipText("agent-one"));
    }

    [Fact]
    public void OrderAgents_PutsActiveFirstThenIdleThenOfflineByName()
    {
        var ordered = MonitorFeedLogic.OrderAgents(
            [Agent("offline-b", null), Agent("idle-a", 30), Agent("active-b"), Agent("Active-a"), Agent("offline-a", 600)], Now);

        Assert.Equal(["Active-a", "active-b", "idle-a", "offline-a", "offline-b"], ordered.Select(agent => agent.Name));
    }

    [Fact]
    public void SyncAgentRows_FillsAnEmptyList()
    {
        var rows = new ObservableCollection<AgentEntry>();

        MonitorFeedLogic.SyncAgentRows(rows, [Agent("agent-b"), Agent("agent-a")], Now);

        Assert.Equal(["agent-a", "agent-b"], rows.Select(row => row.Name));
    }

    [Fact]
    public void SyncAgentRows_UpdatesRowsInPlaceWithoutReplacingThem()
    {
        var rows = new ObservableCollection<AgentEntry>();
        MonitorFeedLogic.SyncAgentRows(rows, [Agent("agent-a"), Agent("agent-b"), Agent("agent-c")], Now);
        var (a, c) = (rows[0], rows[2]);
        var actions = new List<NotifyCollectionChangedAction>();
        rows.CollectionChanged += (_, e) => actions.Add(e.Action);

        // agent-b left, agent-a went idle (so it sorts after agent-c) and agent-d joined.
        MonitorFeedLogic.SyncAgentRows(rows, [Agent("agent-a", 30, "new-host"), Agent("agent-c"), Agent("agent-d")], Now);

        Assert.Equal(["agent-c", "agent-d", "agent-a"], rows.Select(row => row.Name));
        Assert.Same(c, rows[0]);
        Assert.Same(a, rows[2]);
        Assert.Equal(AgentPresence.Idle, a.Presence);
        Assert.StartsWith("new-host", a.Meta);
        Assert.DoesNotContain(NotifyCollectionChangedAction.Reset, actions);
        Assert.Contains(NotifyCollectionChangedAction.Remove, actions);
        Assert.Contains(NotifyCollectionChangedAction.Move, actions);
        Assert.Contains(NotifyCollectionChangedAction.Add, actions);
    }

    [Fact]
    public void SyncAgentRows_ClearsTheListWhenNoAgentsRemain()
    {
        var rows = new ObservableCollection<AgentEntry> { new(Agent("agent-a"), Now) };

        MonitorFeedLogic.SyncAgentRows(rows, [], Now);

        Assert.Empty(rows);
    }

    [Fact]
    public void SelectedAgentGone_OnlyWhenASelectedAgentIsMissing()
    {
        var rows = new[] { new AgentEntry(Agent("agent-a"), Now) };

        Assert.False(MonitorFeedLogic.SelectedAgentGone(null, rows));
        Assert.False(MonitorFeedLogic.SelectedAgentGone("agent-a", rows));
        Assert.True(MonitorFeedLogic.SelectedAgentGone("agent-z", rows));
    }
}
