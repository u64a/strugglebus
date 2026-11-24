using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using static StruggleBusMonitor.Tests.MonitorWindowHarness;

namespace StruggleBusMonitor.Tests;

/// <summary>Ctrl+K quick find in the real window, driven through its controls against a fake bus.</summary>
[Collection(StaWindowAdminCollection.Name)]
public sealed class QuickFindWindowTests(StaWindowAdminFixture ui)
{
    private void Run(Func<MonitorWindowHarness, Task> test, Action<MonitorFakeBus>? arrange = null) => ui.Run(async () =>
    {
        var harness = await StartAsync(arrange ?? Board);
        try { await test(harness); }
        finally { await harness.CloseAsync(); }
    });

    private static void Board(MonitorFakeBus bus)
    {
        bus.Channels.AddRange(["humans", "ops"]);
        bus.Agents.AddRange([Agent("deploy-bot"), Agent("agent-two", "deploy-host")]);
        bus.Messages.AddRange(
        [
            Message(1, agent: "deploy-bot", body: "starting"),
            Message(2, agent: "agent-two", body: "deploy needle"),
            Message(3, "humans", "agent-two", "another line\nwith a break")
        ]);
    }

    private static List<QuickFindResult> Results(MainWindow window) => window.QuickFindList.Items.Cast<QuickFindResult>().ToList();

    private static void Open(MonitorWindowHarness harness, string query)
    {
        Click(harness.Window.QuickFindButton);
        harness.Window.QuickFindBox.Text = query;
    }

    [Fact]
    public void Opening_ShowsThePromptAndTakesTheKeyboard() => Run(harness =>
    {
        var window = harness.Window;
        window.QuickFindBox.Text = "left over";
        window.FindScopeMessages.IsChecked = true;

        Click(window.QuickFindButton);

        Assert.Equal(Visibility.Visible, window.QuickFindOverlay.Visibility);
        Assert.Equal(string.Empty, window.QuickFindBox.Text);
        Assert.True(window.FindScopeAll.IsChecked);
        Assert.Equal(QuickFindLogic.Prompt, window.QuickFindEmpty.Text);
        Assert.Equal(Visibility.Visible, window.QuickFindEmpty.Visibility);
        Assert.Equal(Visibility.Collapsed, window.QuickFindList.Visibility);
        Assert.True(window.QuickFindBox.IsKeyboardFocused);
        return Task.CompletedTask;
    });

    [Fact]
    public void Typing_ListsAgentsThenMessagesThenTheHistoryOffer() => Run(harness =>
    {
        var window = harness.Window;

        Open(harness, "deploy");

        var results = Results(window);
        Assert.Equal(["AGENT", "AGENT"], results.Take(2).Select(result => result.Lead));
        Assert.Equal(["deploy-bot", "agent-two"], results.Take(2).Select(result => result.Title));
        Assert.Equal([2L, 1L], results.Skip(2).Take(2).Select(result => result.Message!.Seq));
        Assert.Equal("deploy", results[^1].HistoryQuery);
        Assert.Equal(5, results.Count);
        Assert.Equal(Visibility.Visible, window.QuickFindList.Visibility);
        Assert.Equal(Visibility.Collapsed, window.QuickFindEmpty.Visibility);
        Assert.Equal(0, window.QuickFindList.SelectedIndex);
        return Task.CompletedTask;
    });

    [Fact]
    public void Typing_SomethingThatMatchesNothingSaysSo() => Run(harness =>
    {
        Open(harness, "in:#ops zebra");

        Assert.Single(Results(harness.Window));

        harness.Window.QuickFindBox.Text = "from:nobody";

        Assert.Empty(Results(harness.Window));
        Assert.Equal(QuickFindLogic.NothingLoaded, harness.Window.QuickFindEmpty.Text);
        Assert.Equal(Visibility.Visible, harness.Window.QuickFindEmpty.Visibility);
        Assert.Equal(Visibility.Collapsed, harness.Window.QuickFindList.Visibility);
        return Task.CompletedTask;
    });

    [Fact]
    public void ArrowKeys_MoveTheSelectionAndStopAtTheEnds() => Run(harness =>
    {
        var window = harness.Window;
        Open(harness, "needle");
        Assert.Equal(2, Results(window).Count);

        harness.PressKey(window.QuickFindBox, Key.Up);
        Assert.Equal(0, window.QuickFindList.SelectedIndex);
        harness.PressKey(window.QuickFindBox, Key.Down);
        Assert.Equal(1, window.QuickFindList.SelectedIndex);
        harness.PressKey(window.QuickFindBox, Key.Down);
        Assert.Equal(1, window.QuickFindList.SelectedIndex);
        harness.PressKey(window.QuickFindBox, Key.Up);
        Assert.Equal(0, window.QuickFindList.SelectedIndex);
        return Task.CompletedTask;
    });

    [Fact]
    public void Keys_WithNothingListedDoNothing() => Run(harness =>
    {
        var window = harness.Window;
        Click(window.QuickFindButton);

        harness.PressKey(window.QuickFindBox, Key.Down);
        harness.PressKey(window.QuickFindBox, Key.Enter);

        Assert.Equal(Visibility.Visible, window.QuickFindOverlay.Visibility);
        Assert.Equal(-1, window.QuickFindList.SelectedIndex);
        Assert.Equal(QuickFindLogic.Prompt, window.QuickFindEmpty.Text);
        return Task.CompletedTask;
    });

    [Fact]
    public void Tab_CyclesTheScopeAndTheResultsFollow() => Run(harness =>
    {
        var window = harness.Window;
        Open(harness, "deploy");

        harness.PressKey(window.QuickFindBox, Key.Tab);
        Assert.True(window.FindScopeAgents.IsChecked);
        Assert.All(Results(window), result => Assert.NotNull(result.Agent));
        Assert.Equal(2, Results(window).Count);

        harness.PressKey(window.QuickFindBox, Key.Tab);
        Assert.True(window.FindScopeMessages.IsChecked);
        Assert.Equal(3, Results(window).Count);
        Assert.DoesNotContain(Results(window), result => result.Agent is not null);

        harness.PressKey(window.QuickFindBox, Key.Tab);
        Assert.True(window.FindScopeAll.IsChecked);
        Assert.Equal(5, Results(window).Count);
        return Task.CompletedTask;
    });

    [Fact]
    public void ChangingScope_WhileQuickFindIsClosedSearchesNothing() => Run(harness =>
    {
        var window = harness.Window;
        Open(harness, "deploy");
        HarnessScrim(window).RaiseEvent(new MouseButtonEventArgs(Mouse.PrimaryDevice, 0, MouseButton.Left) { RoutedEvent = UIElement.MouseLeftButtonDownEvent });
        Assert.Equal(Visibility.Collapsed, window.QuickFindOverlay.Visibility);

        window.FindScopeAgents.IsChecked = true;

        Assert.Equal(5, Results(window).Count);
        return Task.CompletedTask;
    });

    private static Border HarnessScrim(MainWindow window) => Find<Border>(window.QuickFindOverlay, _ => true);

    [Fact]
    public void Enter_OnAMessageJumpsToItWithTheFiltersCleared() => Run(harness =>
    {
        var window = harness.Window;
        window.MessageFilterBox.Text = "starting";
        window.ChannelFilter.SelectedItem = window.ChannelFilter.Items.Cast<ChannelFilterOption>().Single(option => option.Name == "ops");
        window.AgentList.SelectedItem = window.AgentList.Items.Cast<AgentEntry>().Single(agent => agent.Name == "deploy-bot");
        window.SettingsNav.IsChecked = true;
        Open(harness, "break");
        Assert.Equal(3, Results(window)[0].Message?.Seq);

        harness.PressKey(window.QuickFindBox, Key.Enter);

        Assert.Equal(Visibility.Collapsed, window.QuickFindOverlay.Visibility);
        Assert.True(window.MonitorNav.IsChecked);
        Assert.Equal(string.Empty, window.MessageFilterBox.Text);
        Assert.Null(window.AgentList.SelectedItem);
        Assert.Null((window.ChannelFilter.SelectedItem as ChannelFilterOption)?.Name);
        Assert.Equal("3 messages", window.ActivityCountText.Text);
        var selected = Assert.IsType<ActivityEntry>(window.ActivityList.SelectedItem);
        Assert.Equal(3, selected.Sequence);
        Assert.True(selected.IsExpanded);
        return Task.CompletedTask;
    });

    [Fact]
    public void Enter_OnAnAgentShowsItsMessages() => Run(harness =>
    {
        var window = harness.Window;
        window.AgentFilterBox.Text = "two";
        window.HumansNav.IsChecked = true;
        Open(harness, "deploy-b");

        harness.PressKey(window.QuickFindBox, Key.Enter);

        Assert.Equal(Visibility.Collapsed, window.QuickFindOverlay.Visibility);
        Assert.True(window.MonitorNav.IsChecked);
        Assert.Equal(string.Empty, window.AgentFilterBox.Text);
        Assert.Equal("deploy-bot", (window.AgentList.SelectedItem as AgentEntry)?.Name);
        Assert.Equal("from deploy-bot  ✕", window.AgentChip.Content);
        Assert.Equal([1L], harness.Feed);
        return Task.CompletedTask;
    });

    [Fact]
    public void ClickingARow_OpensItAndClickingBesideTheRowsDoesNot() => Run(harness =>
    {
        var window = harness.Window;
        Open(harness, "needle");

        Assert.False(PressOn(window.QuickFindList, window.QuickFindList));
        Assert.Equal(Visibility.Visible, window.QuickFindOverlay.Visibility);

        Assert.True(PressRow(window.QuickFindList, Results(window)[0]));

        Assert.Equal(Visibility.Collapsed, window.QuickFindOverlay.Visibility);
        Assert.Equal(2, (window.ActivityList.SelectedItem as ActivityEntry)?.Sequence);
        return Task.CompletedTask;
    });

    [Fact]
    public void HistoryOffer_SearchesTheWholeBusAndAnOlderHitCanBeOpened() => Run(async harness =>
    {
        var window = harness.Window;
        var old = Message(900, agent: "agent-old", body: "needle from long ago");
        harness.Bus.Search = _ => [old];
        var release = harness.Bus.Hold("search?query=needle");
        Open(harness, "needle");
        window.QuickFindList.SelectedIndex = Results(window).Count - 1;

        harness.PressKey(window.QuickFindBox, Key.Enter);

        Assert.Equal(Visibility.Visible, window.QuickFindOverlay.Visibility);
        Assert.Empty(Results(window));
        Assert.Equal("Searching the bus for “needle”…", window.QuickFindEmpty.Text);

        release();
        await MonitorUiThread.Until(() => Results(window).Count == 1, "the bus search to answer");
        Assert.Equal("agent-old  #ops", Results(window)[0].Title);
        Assert.Equal("needle", Results(window)[0].Highlight);
        Assert.Equal(0, window.QuickFindList.SelectedIndex);

        harness.PressKey(window.QuickFindBox, Key.Enter);

        Assert.Equal(Visibility.Collapsed, window.QuickFindOverlay.Visibility);
        Assert.Equal(900, (window.ActivityList.SelectedItem as ActivityEntry)?.Sequence);
        Assert.Equal("4 messages", window.ActivityCountText.Text);
    });

    [Fact]
    public void HistorySearch_ThatFindsNothingSaysTheBusMatchesWholeWords() => Run(async harness =>
    {
        var window = harness.Window;
        harness.Bus.Search = _ => [];
        Open(harness, "need");

        await harness.InvokeAsync("SearchHistoryAsync", "need");

        Assert.Empty(Results(window));
        Assert.Equal("Nothing on the bus matches “need”. The bus matches whole words.", window.QuickFindEmpty.Text);
        Assert.Equal(Visibility.Visible, window.QuickFindEmpty.Visibility);
    });

    [Fact]
    public void HistorySearch_ThatFailsSaysWhy() => Run(async harness =>
    {
        var window = harness.Window;
        Open(harness, "needle");
        harness.Bus.Fail("search?query=needle", 500, "Search index is rebuilding.");

        await harness.InvokeAsync("SearchHistoryAsync", "needle");

        Assert.StartsWith("The search failed:", window.QuickFindEmpty.Text);
        Assert.Contains("Search index is rebuilding", window.QuickFindEmpty.Text);
        Assert.Equal(Visibility.Visible, window.QuickFindEmpty.Visibility);
    });

    [Fact]
    public void HistorySearch_AnswerIsDroppedWhenTheQueryHasChanged() => Run(async harness =>
    {
        var window = harness.Window;
        harness.Bus.Search = _ => [Message(900, body: "needle from long ago")];
        var release = harness.Bus.Hold("search?query=needle");
        Open(harness, "needle");

        var search = harness.InvokeAsync("SearchHistoryAsync", "needle");
        window.QuickFindBox.Text = "starting";
        release();
        await search;

        Assert.DoesNotContain(Results(window), result => result.Message?.Seq == 900);
        Assert.Equal(1, Results(window)[0].Message?.Seq);
    });

    [Fact]
    public void MessagesHeldWhileReadingBack_AreFoundAndOpeningOneReleasesThem() => Run(async harness =>
    {
        var window = harness.Window;
        var viewer = ScrollViewerOf(window.ActivityList);
        viewer.ScrollToVerticalOffset(300);
        window.UpdateLayout();
        harness.Stream.Send(Message(200, body: "held zebra"));
        await MonitorUiThread.Until(() => window.ActivityHoldBar.Visibility == Visibility.Visible, "the held message");

        Open(harness, "zebra");
        Assert.Equal(200, Results(window)[0].Message?.Seq);
        harness.PressKey(window.QuickFindBox, Key.Enter);

        Assert.Equal(Visibility.Collapsed, window.ActivityHoldBar.Visibility);
        Assert.Equal(200, (window.ActivityList.SelectedItem as ActivityEntry)?.Sequence);
        Assert.Equal(200, harness.Feed.First());
    }, bus =>
    {
        bus.Agents.Add(Agent("agent-one"));
        bus.Messages.AddRange(Enumerable.Range(1, 80).Select(seq => Message(seq, body: $"line {seq}\nsecond line")));
    });
}
