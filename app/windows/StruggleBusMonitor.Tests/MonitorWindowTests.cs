using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using static StruggleBusMonitor.Tests.MonitorWindowHarness;

namespace StruggleBusMonitor.Tests;

/// <summary>The Monitor page of the real window, driven through its controls against a fake bus.</summary>
[Collection(StaWindowAdminCollection.Name)]
public sealed class MonitorWindowTests(StaWindowAdminFixture ui)
{
    private static readonly TimeSpan Seconds1 = TimeSpan.FromSeconds(1);
    private static readonly TimeSpan Seconds2 = TimeSpan.FromSeconds(2);

    private void Run(Func<MonitorWindowHarness, Task> test, Action<MonitorFakeBus>? arrange = null, bool awaitStream = true) => ui.Run(async () =>
    {
        var harness = await StartAsync(arrange, awaitStream: awaitStream);
        try { await test(harness); }
        finally { await harness.CloseAsync(); }
    });

    /// <summary>Twelve dozen is more than a snapshot holds, so the oldest are only reachable as history.</summary>
    private static void BusyBoard(MonitorFakeBus bus)
    {
        bus.Channels.AddRange(["humans", "ops"]);
        bus.Agents.AddRange([Agent("agent-one"), Agent("agent-two", "host-b")]);
        bus.Messages.AddRange(Enumerable.Range(1, 120).Select(seq => Message(seq, agent: seq % 2 == 1 ? "agent-one" : "agent-two", body: $"line {seq}\nsecond line")));
    }

    private static void SmallBoard(MonitorFakeBus bus)
    {
        bus.Channels.AddRange(["humans", "ops"]);
        bus.Agents.AddRange([Agent("agent-one"), Agent("agent-two", "host-b")]);
        bus.Messages.AddRange([Message(1, body: "alpha"), Message(2, agent: "agent-two", body: "beta needle"), Message(3, "humans", body: "gamma")]);
    }

    private static AgentEntry AgentRow(MainWindow window, string name) =>
        window.AgentList.Items.Cast<AgentEntry>().Single(agent => agent.Name == name);

    private static ChannelFilterOption Chip(MainWindow window, string? name) =>
        window.ChannelFilter.Items.Cast<ChannelFilterOption>().Single(option => option.Name == name);

    // ---- Loading -----------------------------------------------------------------------------

    [Fact]
    public void Startup_ShowsTheSnapshotNewestFirstWithAgentsAndChannels() => Run(harness =>
    {
        var window = harness.Window;
        Assert.Equal("LIVE", window.StatusText.Text);
        Assert.Equal("seq 3", window.StatusDetailText.Text);
        Assert.Equal([3L, 2L, 1L], harness.Feed);
        Assert.Equal("3 messages", window.ActivityCountText.Text);
        Assert.Equal(Visibility.Collapsed, window.EmptyActivityText.Visibility);
        Assert.Equal(Visibility.Collapsed, window.ActivityHoldBar.Visibility);
        Assert.Equal(["agent-one", "agent-two"], window.AgentList.Items.Cast<AgentEntry>().Select(agent => agent.Name));
        Assert.Equal("2", window.AgentCountText.Text);
        Assert.Equal("2", AgentRow(window, "agent-one").CountLabel);
        Assert.Equal("1", AgentRow(window, "agent-two").CountLabel);
        Assert.Equal(["ALL", "#humans", "#ops"], window.ChannelFilter.Items.Cast<ChannelFilterOption>().Select(option => option.Label));
        Assert.Same(Chip(window, null), window.ChannelFilter.SelectedItem);
        Assert.Equal(Visibility.Collapsed, window.AgentChip.Visibility);
        return Task.CompletedTask;
    }, SmallBoard);

    [Fact]
    public void Startup_WithNothingOnTheBusSaysSo() => Run(harness =>
    {
        Assert.Equal("0 messages", harness.Window.ActivityCountText.Text);
        Assert.Equal(Visibility.Visible, harness.Window.EmptyActivityText.Visibility);
        Assert.Equal("No messages yet.", harness.Window.EmptyActivityText.Text);
        return Task.CompletedTask;
    });

    [Fact]
    public void Startup_OnAFrozenBusShowsFrozenAndStaysFrozenWhenMessagesArrive() => Run(async harness =>
    {
        Assert.Equal("FROZEN", harness.Window.StatusText.Text);

        harness.Stream.Send(Message(2));
        await MonitorUiThread.Until(() => harness.Feed.Contains(2), "the streamed message");

        Assert.Equal("FROZEN", harness.Window.StatusText.Text);
    }, bus =>
    {
        bus.State = "Frozen";
        bus.Messages.Add(Message(1));
    });

    [Fact]
    public void Startup_LoadsHumansHistoryOnlyWhenTheBusSupportsIt()
    {
        Run(harness =>
        {
            Assert.Equal(1, harness.Bus.RequestCount("channel=humans"));
            return Task.CompletedTask;
        }, SmallBoard);

        Run(harness =>
        {
            Assert.Equal(0, harness.Bus.RequestCount("channel=humans"));
            Assert.Equal("LIVE", harness.Window.StatusText.Text);
            return Task.CompletedTask;
        }, bus =>
        {
            SmallBoard(bus);
            bus.HistorySupported = false;
        });
    }

    [Fact]
    public void Startup_CarriesOnWhenTheBusHasNoHumansChannelYet() => Run(harness =>
    {
        Assert.Equal("LIVE", harness.Window.StatusText.Text);
        Assert.Equal([3L, 2L, 1L], harness.Feed);
        Assert.Equal(string.Empty, harness.Notice);
        return Task.CompletedTask;
    }, bus =>
    {
        SmallBoard(bus);
        bus.Fail("channel=humans", 404, "Channel not found.");
    });

    [Fact]
    public void Refresh_ReloadsTheSnapshotAndReconnectsTheStream() => Run(async harness =>
    {
        harness.Bus.Messages.Add(Message(4, body: "arrived while away"));

        Click(harness.Window.MonitorPage, "Refresh");
        await harness.ListeningAsync(2);

        Assert.Equal([4L, 3L, 2L, 1L], harness.Feed);
        Assert.Equal("seq 4", harness.Window.StatusDetailText.Text);
    }, SmallBoard);

    [Fact]
    public void Refresh_ThatFailsSaysWhyInTheNoticeBar() => Run(async harness =>
    {
        harness.Bus.Fail("api/mobile/status", 500, "The database is locked.");

        Click(harness.Window.MonitorPage, "Refresh");
        await MonitorUiThread.Until(() => harness.Notice.Length > 0, "the failure notice");

        Assert.Contains("The database is locked", harness.Notice);
        Assert.Equal([3L, 2L, 1L], harness.Feed);
    }, SmallBoard);

    [Fact]
    public void Refresh_ThatFinishesAfterTheWindowClosedDoesNotReconnect() => Run(async harness =>
    {
        var refresh = Find<Button>(harness.Window.MonitorPage, button => Equals(button.Content, "Refresh"));
        var release = harness.Bus.Hold("api/mobile/channels");
        Click(refresh);
        await MonitorUiThread.Until(() => harness.Bus.RequestCount("api/mobile/channels") == 2, "the refresh to ask for channels");

        await harness.CloseAsync();
        release();
        await MonitorUiThread.Until(() => refresh.IsEnabled, "the refresh to finish");

        Assert.Single(harness.Bus.Streams);
    }, SmallBoard);

    // ---- Live stream -------------------------------------------------------------------------

    [Fact]
    public void Stream_MessageGoesToTheTopOfTheFeed() => Run(async harness =>
    {
        harness.Stream.Send(Message(9, agent: "agent-two", body: "fresh"));
        await MonitorUiThread.Until(() => harness.Feed.Contains(9), "the streamed message");

        Assert.Equal([9L, 3L, 2L, 1L], harness.Feed);
        Assert.Equal("seq 9", harness.Window.StatusDetailText.Text);
        Assert.Equal("4 messages", harness.Window.ActivityCountText.Text);
        Assert.Equal("2", AgentRow(harness.Window, "agent-two").CountLabel);
    }, SmallBoard);

    [Fact]
    public void Stream_RoutineClosureReconnectsAfterAMoment() => Run(async harness =>
    {
        harness.Stream.End();
        await harness.ElapseAsync(Seconds1);
        await harness.ListeningAsync(2);

        Assert.Equal("LIVE", harness.Window.StatusText.Text);
        Assert.Equal(string.Empty, harness.Notice);
    }, SmallBoard);

    [Fact]
    public void Stream_UnavailableShowsReconnectingUntilANewConnectionHasStayedOpen() => Run(async harness =>
    {
        harness.Stream.Event("agent_access_unavailable", Detail("Agent access is unavailable."));
        await harness.ShowsStatusAsync("RECONNECTING");
        Assert.Equal("Agent access is unavailable.", harness.Window.StatusDetailText.Text);

        await harness.ElapseAsync(Seconds2);
        await harness.ListeningAsync(2);
        Assert.Equal("RECONNECTING", harness.Window.StatusText.Text);

        await harness.ElapseAsync(StreamConfirmWait);
        await harness.ShowsStatusAsync("LIVE");
        var log = harness.Window.ConnectionLogList.Items.Cast<ConnectionEvent>().Select(entry => entry.Text).ToList();
        Assert.StartsWith("Reconnected", log[0]);
        Assert.StartsWith("Bus not reachable", log[1]);
    }, SmallBoard);

    [Fact]
    public void Stream_MessageAfterAnOutageCountsAsBackStraightAway() => Run(async harness =>
    {
        harness.Stream.Event("agent_access_unavailable", Detail("Agent access is unavailable."));
        await harness.ShowsStatusAsync("RECONNECTING");
        await harness.ElapseAsync(Seconds2);
        await harness.ListeningAsync(2);

        harness.Stream.Send(Message(10));
        await MonitorUiThread.Until(() => harness.Feed.Contains(10), "the streamed message");

        Assert.Equal("LIVE", harness.Window.StatusText.Text);
        Assert.Equal("seq 10", harness.Window.StatusDetailText.Text);
    }, SmallBoard);

    [Fact]
    public void Stream_ConfirmingAConnectionThatWasNeverDownChangesNothing() => Run(async harness =>
    {
        await harness.ElapseAsync(StreamConfirmWait);
        await MonitorUiThread.Settle();

        Assert.Equal("LIVE", harness.Window.StatusText.Text);
        Assert.Equal("seq 3", harness.Window.StatusDetailText.Text);
    }, SmallBoard);

    [Fact]
    public void Stream_RateLimitedWaitsAsLongAsTheBusAsks() => Run(async harness =>
    {
        harness.Bus.ScriptStream(MonitorFakeStream.Refused(429, retryAfter: TimeSpan.FromSeconds(7)));
        harness.Stream.End();
        await harness.ElapseAsync(Seconds1);

        await harness.ShowsStatusAsync("WAITING");
        Assert.Equal("The server is limiting live-stream connections.", harness.Window.StatusDetailText.Text);

        await harness.ElapseAsync(TimeSpan.FromSeconds(7));
        await harness.ListeningAsync(3);
    }, SmallBoard);

    [Fact]
    public void Stream_FrozenShowsFrozenAndKeepsRetrying() => Run(async harness =>
    {
        harness.Stream.Event("agent_access_frozen", Detail("Agent access is frozen."));
        await harness.ShowsStatusAsync("FROZEN");
        Assert.Equal("Agent access is frozen.", harness.Window.StatusDetailText.Text);
        Assert.Equal("Agent access is frozen on the bus.", harness.Window.ConnectionLogList.Items.Cast<ConnectionEvent>().First().Text);

        await harness.ElapseAsync(TimeSpan.FromSeconds(5));
        await harness.ListeningAsync(2);
    }, SmallBoard);

    [Fact]
    public void Stream_ServerStoppingSaysTheBusIsRestarting() => Run(async harness =>
    {
        harness.Stream.Event("server_stopping", Detail("Server is stopping."));
        await harness.ShowsStatusAsync("RECONNECTING");

        Assert.Equal("The bus is restarting", harness.Window.StatusDetailText.Text);
        Assert.Contains("stopping for a restart", harness.Window.ConnectionLogList.Items.Cast<ConnectionEvent>().First().Text);
        await harness.WaitingAsync(Seconds2);
    }, SmallBoard);

    [Fact]
    public void Stream_UnknownEventExplainsOnceAndRetriesEveryMinute() => Run(async harness =>
    {
        var minute = TimeSpan.FromSeconds(60);
        harness.Stream.Event("something_new", Detail("An event from the future."));
        await harness.ShowsStatusAsync("RECONNECTING");
        await harness.WaitingAsync(minute);
        Assert.Equal("An event from the future. The app and the bus may be on incompatible versions. Still trying every minute.", harness.Notice);

        Click(harness.Window.NoticeBar, "Dismiss");
        harness.Pauses.Elapse(minute);
        await harness.ListeningAsync(2);
        harness.Stream.Event("something_new", Detail("An event from the future."));
        await harness.WaitingAsync(minute);

        Assert.Equal(string.Empty, harness.Notice);
        Assert.Equal("RECONNECTING", harness.Window.StatusText.Text);
    }, SmallBoard);

    [Fact]
    public void Stream_RevokedCredentialStopsTheLoopsAndOffersToEnrollAgain() => Run(async harness =>
    {
        var window = harness.Window;
        await harness.ShowsStatusAsync("REVOKED");
        await MonitorUiThread.Until(() => harness.Pauses.Waiting.Count == 0, "the background loops to stop");

        Assert.Equal(BusErrors.CredentialInactive + " Enroll this PC again to continue.", harness.Notice);
        Assert.Equal("Enroll again", window.NoticeActionButton.Content);
        Assert.Contains("revoked", window.ConnectionLogList.Items.Cast<ConnectionEvent>().First().Text);

        Click(window.NoticeActionButton);
        await harness.ShowsStatusAsync("NOT ENROLLED");

        Assert.Empty(harness.Feed);
        Assert.Empty(window.AgentList.Items);
        Assert.Equal(Visibility.Visible, window.EnrollmentPanel.Visibility);
        Assert.Equal("0 messages", window.HumansCountText.Text);
        Assert.Equal(Visibility.Visible, window.HumansEmptyText.Visibility);
        Assert.Equal(Visibility.Collapsed, window.HumansBadge.Visibility);
    }, bus =>
    {
        SmallBoard(bus);
        bus.ScriptStream(MonitorFakeStream.Refused(401));
    }, awaitStream: false);

    [Fact]
    public void Stream_BrokenConnectionShowsWhyAndRetries() => Run(async harness =>
    {
        harness.Stream.Break("The connection was reset.");
        await harness.ShowsStatusAsync("RECONNECTING");
        Assert.Equal("Reconnecting: The connection was reset.", harness.Window.StatusDetailText.Text);

        await harness.ElapseAsync(Seconds2);
        await harness.ListeningAsync(2);
    }, SmallBoard);

    [Fact]
    public void Stream_BrokenConnectionIsRetriedAtOnceWhenTheBusAnswersAgain() => Run(async harness =>
    {
        harness.Stream.Break("The connection was reset.");
        await harness.ShowsStatusAsync("RECONNECTING");
        await harness.WaitingAsync(Seconds2);

        // The periodic snapshot check succeeds, so the stream does not sit out its retry wait.
        await harness.ElapseAsync(FeedWait);
        await harness.ListeningAsync(2);

        Assert.False(harness.Pauses.IsWaiting(TimeSpan.FromSeconds(4)));
    }, SmallBoard);

    [Fact]
    public void Stream_UnavailableIsRetriedAtOnceWhenTheBusAnswersAgain() => Run(async harness =>
    {
        harness.Stream.Event("agent_access_unavailable", Detail("Agent access is unavailable."));
        await harness.ShowsStatusAsync("RECONNECTING");
        await harness.WaitingAsync(Seconds2);

        await harness.ElapseAsync(FeedWait);
        await harness.ListeningAsync(2);
    }, SmallBoard);

    [Fact]
    public void Closing_WhileWaitingToRetryABrokenStreamStopsCleanly() => Run(async harness =>
    {
        harness.Stream.Break("The connection was reset.");
        await harness.ShowsStatusAsync("RECONNECTING");
        await harness.WaitingAsync(Seconds2);

        await harness.CloseAsync();

        Assert.Empty(harness.Pauses.Waiting);
        Assert.Single(harness.Bus.Streams);
    }, SmallBoard);

    // ---- Periodic checks ---------------------------------------------------------------------

    [Fact]
    public void SnapshotCheck_AddsMessagesTheStreamMissed() => Run(async harness =>
    {
        harness.Bus.Messages.Add(Message(4, body: "missed"));

        await harness.ElapseAsync(FeedWait);
        await MonitorUiThread.Until(() => harness.Feed.Contains(4), "the missed message");

        Assert.Equal([4L, 3L, 2L, 1L], harness.Feed);
        Assert.Single(harness.Bus.Streams);
        await harness.WaitingAsync(FeedWait);
    }, SmallBoard);

    [Fact]
    public void SnapshotCheck_FailureShowsReconnectingThenRecovers() => Run(async harness =>
    {
        harness.Bus.Fail("snapshot?limit=100", 503, "Bus is restarting.");
        await harness.ElapseAsync(FeedWait);
        await harness.ShowsStatusAsync("RECONNECTING");
        Assert.StartsWith("Snapshot check failed:", harness.Window.StatusDetailText.Text);

        harness.Bus.StopFailing("snapshot?limit=100");
        await harness.ElapseAsync(FeedRetryWait);
        await harness.ElapseAsync(FeedWait);

        // The bus answers again: the quiet stream is reconnected and confirmed.
        await harness.ListeningAsync(2);
        await harness.ElapseAsync(StreamConfirmWait);
        await harness.ShowsStatusAsync("LIVE");
    }, SmallBoard);

    [Fact]
    public void Closing_WhileWaitingToRetryTheSnapshotCheckStopsCleanly() => Run(async harness =>
    {
        harness.Bus.Fail("snapshot?limit=100", 0, "No route to host.");
        await harness.ElapseAsync(FeedWait);
        await harness.WaitingAsync(FeedRetryWait);
        Assert.Contains("No route to host", harness.Window.StatusDetailText.Text);

        await harness.CloseAsync();

        Assert.Empty(harness.Pauses.Waiting);
    }, SmallBoard);

    [Fact]
    public void DirectoryCheck_BringsInNewAgentsAndChannels() => Run(async harness =>
    {
        var window = harness.Window;
        var opsChip = Chip(window, "ops");
        harness.Bus.Agents.Add(Agent("agent-zed", minutesAgo: null));
        await harness.ElapseAsync(DirectoryWait);
        await MonitorUiThread.Until(() => window.AgentList.Items.Count == 3, "the new agent");
        Assert.Equal("3", window.AgentCountText.Text);
        Assert.Same(opsChip, Chip(window, "ops"));

        harness.Bus.Channels.Add("releases");
        await harness.ElapseAsync(DirectoryWait);
        await MonitorUiThread.Until(() => window.ChannelFilter.Items.Count == 4, "the new channel");

        Assert.Equal(["ALL", "#humans", "#ops", "#releases"], window.ChannelFilter.Items.Cast<ChannelFilterOption>().Select(option => option.Label));
        Assert.Same(Chip(window, null), window.ChannelFilter.SelectedItem);
    }, SmallBoard);

    [Fact]
    public void DirectoryCheck_FailureShowsReconnectingAndTriesAgain() => Run(async harness =>
    {
        harness.Bus.Fail("api/mobile/agents", 500, "Agents are unavailable.");

        await harness.ElapseAsync(DirectoryWait);
        await harness.ShowsStatusAsync("RECONNECTING");

        Assert.StartsWith("Agent and channel refresh failed:", harness.Window.StatusDetailText.Text);
        await harness.WaitingAsync(DirectoryWait);
    }, SmallBoard);

    // ---- Filters -----------------------------------------------------------------------------

    [Fact]
    public void MessageFilter_NarrowsTheFeedAndMarksTheMatches() => Run(harness =>
    {
        var window = harness.Window;

        window.MessageFilterBox.Text = " needle ";
        Assert.Equal([2L], harness.Feed);
        Assert.Equal("1 of 3 shown", window.ActivityCountText.Text);
        Assert.All(window.ActivityList.Items.Cast<ActivityEntry>(), entry => Assert.Equal("needle", entry.Highlight));

        window.MessageFilterBox.Text = "nothing has this";
        Assert.Empty(harness.Feed);
        Assert.Equal(Visibility.Visible, window.EmptyActivityText.Visibility);
        Assert.Equal("No messages match. Clear a filter to see more.", window.EmptyActivityText.Text);

        window.MessageFilterBox.Clear();
        Assert.Equal("3 messages", window.ActivityCountText.Text);
        return Task.CompletedTask;
    }, SmallBoard);

    [Fact]
    public void MessageFilter_AppliesToMessagesThatArriveLater() => Run(async harness =>
    {
        harness.Window.MessageFilterBox.Text = "needle";

        harness.Stream.Send(Message(5, body: "another needle")).Send(Message(6, body: "hay"));
        await MonitorUiThread.Until(() => harness.Window.ActivityCountText.Text == "2 of 5 shown", "both streamed messages");

        Assert.Equal([5L, 2L], harness.Feed);
        Assert.Equal("needle", harness.Window.ActivityList.Items.Cast<ActivityEntry>().First().Highlight);
    }, SmallBoard);

    [Fact]
    public void ChannelChip_NarrowsTheFeedToThatChannel() => Run(harness =>
    {
        var window = harness.Window;

        window.ChannelFilter.SelectedItem = Chip(window, "humans");
        Assert.Equal([3L], harness.Feed);
        Assert.Equal("1 of 3 shown", window.ActivityCountText.Text);

        window.ChannelFilter.SelectedItem = Chip(window, null);
        Assert.Equal([3L, 2L, 1L], harness.Feed);
        return Task.CompletedTask;
    }, SmallBoard);

    [Fact]
    public void ChannelChip_IsDroppedWhenItsChannelLeavesTheBus() => Run(async harness =>
    {
        var window = harness.Window;
        window.ChannelFilter.SelectedItem = Chip(window, "humans");

        harness.Bus.Channels.Remove("humans");
        await harness.ElapseAsync(DirectoryWait);
        await MonitorUiThread.Until(() => window.ChannelFilter.Items.Count == 2, "the channel chips to be rebuilt");

        Assert.Same(Chip(window, null), window.ChannelFilter.SelectedItem);
        Assert.Equal("3 messages", window.ActivityCountText.Text);
    }, SmallBoard);

    [Fact]
    public void AgentFilterBox_NarrowsTheAgentListAndKeepsTheSelection() => Run(harness =>
    {
        var window = harness.Window;
        window.AgentList.SelectedItem = AgentRow(window, "agent-two");

        window.AgentFilterBox.Text = "host-b";
        Assert.Equal(["agent-two"], window.AgentList.Items.Cast<AgentEntry>().Select(agent => agent.Name));
        Assert.Equal("1 of 2", window.AgentCountText.Text);
        Assert.Equal("agent-two", (window.AgentList.SelectedItem as AgentEntry)?.Name);
        Assert.Equal(Visibility.Collapsed, window.AgentEmptyText.Visibility);

        window.AgentFilterBox.Text = "nobody";
        Assert.Equal("0 of 2", window.AgentCountText.Text);
        Assert.Equal(Visibility.Visible, window.AgentEmptyText.Visibility);
        Assert.Equal("from agent-two  ✕", window.AgentChip.Content);
        return Task.CompletedTask;
    }, SmallBoard);

    [Fact]
    public void SelectingAnAgent_ShowsOnlyItsMessagesAndFetchesItsOlderOnes() => Run(async harness =>
    {
        var window = harness.Window;
        Assert.Equal("100 messages", window.ActivityCountText.Text);

        window.AgentList.SelectedItem = AgentRow(window, "agent-one");
        await MonitorUiThread.Until(() => window.ActivityCountText.Text == "60 of 110 shown", "agent-one's older messages");

        Assert.Equal(Visibility.Visible, window.AgentChip.Visibility);
        Assert.Equal("from agent-one  ✕", window.AgentChip.Content);
        Assert.All(window.ActivityList.Items.Cast<ActivityEntry>(), entry => Assert.Equal("agent-one", entry.AgentName));
        Assert.Equal(1, harness.Feed.Last());
        Assert.Equal("60", AgentRow(window, "agent-one").CountLabel);

        Click(window.AgentChip);

        Assert.Equal(Visibility.Collapsed, window.AgentChip.Visibility);
        Assert.Null(window.AgentList.SelectedItem);
        Assert.Equal("100 messages", window.ActivityCountText.Text);
        Assert.Equal(21, harness.Feed.Last());
    }, BusyBoard);

    [Fact]
    public void SelectingAnAgent_KeepsItsHistoryWhileTheLiveWindowRollsOver() => Run(async harness =>
    {
        var window = harness.Window;
        window.AgentList.SelectedItem = AgentRow(window, "agent-one");
        await MonitorUiThread.Until(() => window.ActivityCountText.Text == "60 of 110 shown", "agent-one's older messages");

        // A full live window of newer messages pushes out everything the snapshot loaded.
        for (var seq = 121; seq <= 370; seq++) harness.Stream.Send(Message(seq, agent: "agent-two"));
        await MonitorUiThread.Until(() => window.StatusDetailText.Text == "seq 370", "the last streamed message");

        Assert.Equal("10 of 260 shown", window.ActivityCountText.Text);
        Assert.Equal([19L, 17L, 15L, 13L, 11L, 9L, 7L, 5L, 3L, 1L], harness.Feed);
    }, BusyBoard);

    [Fact]
    public void SelectingAnAgent_SaysSoWhenItsOlderMessagesCannotBeLoaded() => Run(async harness =>
    {
        var window = harness.Window;
        harness.Bus.Fail("agent=agent-one", 500, "History is unavailable.");

        window.AgentList.SelectedItem = AgentRow(window, "agent-one");
        await MonitorUiThread.Until(() => harness.Notice.Length > 0, "the failure notice");

        Assert.StartsWith("Could not load agent-one's older messages:", harness.Notice);
        Assert.Equal("50 of 100 shown", window.ActivityCountText.Text);
    }, BusyBoard);

    [Fact]
    public void SelectingAnAgent_OnABusWithoutHistoryOnlyFilters() => Run(harness =>
    {
        var window = harness.Window;

        window.AgentList.SelectedItem = AgentRow(window, "agent-one");

        Assert.Equal("50 of 100 shown", window.ActivityCountText.Text);
        Assert.Equal(0, harness.Bus.RequestCount("agent=agent-one"));
        return Task.CompletedTask;
    }, bus =>
    {
        BusyBoard(bus);
        bus.HistorySupported = false;
    });

    [Fact]
    public void AgentHistory_ThatArrivesAfterTheFilterChangedIsDropped() => Run(async harness =>
    {
        var window = harness.Window;

        await harness.InvokeAsync("LoadAgentHistoryAsync", "agent-one");

        Assert.Equal(1, harness.Bus.RequestCount("agent=agent-one"));
        Assert.Equal("100 messages", window.ActivityCountText.Text);
    }, BusyBoard);

    [Fact]
    public void ClickingTheSelectedAgentAgain_ClearsTheFilter() => Run(harness =>
    {
        var window = harness.Window;
        var row = AgentRow(window, "agent-two");

        Assert.False(PressRow(window.AgentList, row));
        window.AgentList.SelectedItem = row;
        Assert.Equal([2L], harness.Feed);

        Assert.True(PressRow(window.AgentList, row));

        Assert.Null(window.AgentList.SelectedItem);
        Assert.Equal(Visibility.Collapsed, window.AgentChip.Visibility);
        Assert.Equal([3L, 2L, 1L], harness.Feed);
        return Task.CompletedTask;
    }, SmallBoard);

    [Fact]
    public void SelectedAgent_IsDeselectedWhenItLeavesTheBus() => Run(async harness =>
    {
        var window = harness.Window;
        window.AgentList.SelectedItem = AgentRow(window, "agent-two");
        Assert.Equal(Visibility.Visible, window.AgentChip.Visibility);

        harness.Bus.Agents.RemoveAll(agent => agent.Name == "agent-two");
        await harness.ElapseAsync(DirectoryWait);
        await MonitorUiThread.Until(() => window.AgentList.Items.Count == 1, "the agent to leave");

        Assert.Equal(Visibility.Collapsed, window.AgentChip.Visibility);
        Assert.Equal([3L, 2L, 1L], harness.Feed);
    }, SmallBoard);

    // ---- Reading back ------------------------------------------------------------------------

    [Fact]
    public void ReadingBack_HoldsNewMessagesUntilJumpToLatest() => Run(async harness =>
    {
        var window = harness.Window;
        var viewer = ScrollViewerOf(window.ActivityList);
        viewer.ScrollToVerticalOffset(300);
        window.UpdateLayout();

        harness.Stream.Send(Message(121)).Send(Message(122));
        await MonitorUiThread.Until(() => window.ActivityHoldText.Text.Contains("2 new messages"), "the held messages");

        Assert.Equal(Visibility.Visible, window.ActivityHoldBar.Visibility);
        Assert.Equal("Holding your place while you read. 2 new messages waiting.", window.ActivityHoldText.Text);
        Assert.Equal(120, harness.Feed.First());
        Assert.Equal("seq 122", window.StatusDetailText.Text);

        Click(window.ActivityHoldBar, "Jump to latest");
        window.UpdateLayout();

        Assert.Equal(Visibility.Collapsed, window.ActivityHoldBar.Visibility);
        Assert.Equal([122L, 121L, 120L], harness.Feed.Take(3));
        Assert.Equal(0, viewer.VerticalOffset);
    }, BusyBoard);

    [Fact]
    public void ReadingBack_ReleasesHeldMessagesOnScrollingBackToTheTop() => Run(async harness =>
    {
        var window = harness.Window;
        var viewer = ScrollViewerOf(window.ActivityList);
        viewer.ScrollToVerticalOffset(300);
        window.UpdateLayout();
        harness.Stream.Send(Message(121));
        await MonitorUiThread.Until(() => window.ActivityHoldBar.Visibility == Visibility.Visible, "the held message");

        viewer.ScrollToTop();
        window.UpdateLayout();

        Assert.Equal(Visibility.Collapsed, window.ActivityHoldBar.Visibility);
        Assert.Equal(121, harness.Feed.First());
    }, BusyBoard);

    [Fact]
    public void JumpToLatest_AfterTheHeldMessagesWereReleasedOnlyScrolls() => Run(async harness =>
    {
        var window = harness.Window;
        var viewer = ScrollViewerOf(window.ActivityList);
        viewer.ScrollToVerticalOffset(300);
        window.UpdateLayout();
        harness.Stream.Send(Message(121));
        await MonitorUiThread.Until(() => window.ActivityHoldBar.Visibility == Visibility.Visible, "the held message");
        viewer.ScrollToTop();
        window.UpdateLayout();
        viewer.ScrollToVerticalOffset(300);
        window.UpdateLayout();

        harness.InvokeRowHandler("ActivityJump_Click", null);
        window.UpdateLayout();

        Assert.Equal(0, viewer.VerticalOffset);
        Assert.Equal("101 messages", window.ActivityCountText.Text);
    }, BusyBoard);

    // ---- Message rows ------------------------------------------------------------------------

    [Fact]
    public void MessageRow_ExpandsFromItsButtonAndByDoubleClick() => Run(harness =>
    {
        var window = harness.Window;
        var entry = window.ActivityList.Items.Cast<ActivityEntry>().First();

        harness.InvokeRowHandler("ExpandMessage_Click", entry);
        Assert.True(entry.IsExpanded);
        harness.InvokeRowHandler("ExpandMessage_Click", entry);
        Assert.False(entry.IsExpanded);
        harness.InvokeRowHandler("ExpandMessage_Click", "not a message row");
        Assert.False(entry.IsExpanded);

        var doubleClick = new MouseButtonEventArgs(Mouse.PrimaryDevice, 0, MouseButton.Left) { RoutedEvent = Control.MouseDoubleClickEvent };
        window.ActivityList.RaiseEvent(doubleClick);
        Assert.False(entry.IsExpanded);
        window.ActivityList.SelectedItem = entry;
        window.ActivityList.RaiseEvent(doubleClick);
        Assert.True(entry.IsExpanded);
        return Task.CompletedTask;
    }, SmallBoard);

    [Fact]
    public void MessageRow_CopyTakesTheBody() => Run(harness =>
    {
        var entry = harness.Window.ActivityList.Items.Cast<ActivityEntry>().Single(item => item.Sequence == 2);

        harness.InvokeRowHandler("CopyMessage_Click", "not a message row");
        harness.InvokeRowHandler("CopyMessage_Click", entry);

        Assert.Equal(["beta needle"], harness.Copied);
        return Task.CompletedTask;
    }, SmallBoard);
}
