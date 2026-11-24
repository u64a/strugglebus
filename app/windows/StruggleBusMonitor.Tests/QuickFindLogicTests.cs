using System.Windows.Input;

namespace StruggleBusMonitor.Tests;

public sealed class QuickFindLogicTests
{
    private static readonly DateTimeOffset Now = new(2025, 6, 1, 12, 0, 0, TimeSpan.Zero);

    private static BusAgent Agent(string name, string host = "", double? minutesAgo = 0) =>
        new(name, name, string.Empty, host, "seen", minutesAgo is { } minutes ? Now.AddMinutes(-minutes) : null);

    private static BusMessage Message(long seq, string body, string agent = "agent-one", string channel = "ops") =>
        new(seq, channel, agent, body, "chat", Now.AddMinutes(-2));

    [Theory]
    [InlineData(null)]
    [InlineData("   ")]
    public void Search_EmptyQueryShowsThePrompt(string? raw)
    {
        var outcome = QuickFindLogic.Search(raw, QuickFindScope.All, [Agent("agent-one")], [Message(1, "hello")], true, Now);

        Assert.Empty(outcome.Results);
        Assert.Equal(QuickFindLogic.Prompt, outcome.EmptyText);
    }

    [Fact]
    public void Search_ListsAgentsThenMessagesNewestFirstThenTheHistoryOffer()
    {
        var agents = new[] { Agent("build-bot", "deploy-host"), Agent("deploy-bot") };
        var messages = new[] { Message(1, "deploy started"), Message(2, "nothing here"), Message(3, "Deploy finished") };

        var outcome = QuickFindLogic.Search("deploy", QuickFindScope.All, agents, messages, true, Now);

        Assert.Equal(5, outcome.Results.Count);
        Assert.Equal(["deploy-bot", "build-bot"], outcome.Results.Take(2).Select(result => result.Title));
        Assert.All(outcome.Results.Take(2), result => Assert.Equal("AGENT", result.Lead));
        Assert.Equal([3L, 1L], outcome.Results.Skip(2).Take(2).Select(result => result.Message!.Seq));
        Assert.Equal("deploy", outcome.Results[^1].HistoryQuery);
        Assert.Equal(QuickFindLogic.NothingLoaded, outcome.EmptyText);
    }

    [Fact]
    public void Search_AgentsScopeLeavesOutMessagesAndHistory()
    {
        var outcome = QuickFindLogic.Search("agent", QuickFindScope.Agents, [Agent("agent-one")], [Message(1, "agent text")], true, Now);

        var only = Assert.Single(outcome.Results);
        Assert.Equal("agent-one", only.Agent?.Name);
    }

    [Fact]
    public void Search_MessagesScopeLeavesOutAgents()
    {
        var outcome = QuickFindLogic.Search("agent", QuickFindScope.Messages, [Agent("agent-one")], [Message(1, "agent text")], false, Now);

        var only = Assert.Single(outcome.Results);
        Assert.Equal(1, only.Message?.Seq);
    }

    [Fact]
    public void Search_NarrowingWithoutWordsFindsMessagesButNoAgentsOrHistory()
    {
        var messages = new[] { Message(1, "one", "agent-one"), Message(2, "two", "agent-two") };

        var outcome = QuickFindLogic.Search("from:agent-two", QuickFindScope.All, [Agent("agent-two")], messages, true, Now);

        var only = Assert.Single(outcome.Results);
        Assert.Equal(2, only.Message?.Seq);
    }

    [Fact]
    public void Search_WithoutHistorySupportMakesNoHistoryOffer()
    {
        var outcome = QuickFindLogic.Search("zzz", QuickFindScope.All, [], [], false, Now);

        Assert.Empty(outcome.Results);
        Assert.Equal(QuickFindLogic.NothingLoaded, outcome.EmptyText);
    }

    [Fact]
    public void AgentRows_PutNamePrefixMatchesFirstThenPresenceThenName()
    {
        var agents = new[]
        {
            Agent("zeta-bot", "bot-farm"),
            Agent("bot-offline", minutesAgo: null),
            Agent("bot-idle", minutesAgo: 20),
            Agent("bot-b"),
            Agent("bot-a")
        };

        var rows = QuickFindLogic.AgentRows(agents, "bot", Now);

        Assert.Equal(["bot-a", "bot-b", "bot-idle", "bot-offline", "zeta-bot"], rows.Select(row => row.Title));
        Assert.All(rows, row => Assert.Equal("bot", row.Highlight));
    }

    [Fact]
    public void AgentRows_DescribeHostAndPresence()
    {
        var rows = QuickFindLogic.AgentRows([Agent("agent-one", "host-a"), Agent("agent-two", minutesAgo: null)], "agent", Now);

        Assert.Equal("host-a  ·  active now  ·  Enter shows its messages", rows[0].Detail);
        Assert.Equal("never seen  ·  Enter shows its messages", rows[1].Detail);
    }

    [Fact]
    public void AgentRows_StopAtTheMaximumAndNeedWords()
    {
        var agents = Enumerable.Range(0, 10).Select(index => Agent($"agent-{index}")).ToList();

        Assert.Equal(QuickFindLogic.MaximumAgents, QuickFindLogic.AgentRows(agents, "agent", Now).Count);
        Assert.Empty(QuickFindLogic.AgentRows(agents, string.Empty, Now));
    }

    [Fact]
    public void MessageRows_StopAtTheMaximumKeepingTheNewest()
    {
        var messages = Enumerable.Range(1, 60).Select(seq => Message(seq, "match"));

        var rows = QuickFindLogic.MessageRows(messages, new FeedQuery("match", null, null), Now);

        Assert.Equal(QuickFindLogic.MaximumMessages, rows.Count);
        Assert.Equal(60, rows[0].Message!.Seq);
        Assert.Equal(21, rows[^1].Message!.Seq);
    }

    [Fact]
    public void MessageRow_FlattensTheBodyAndNamesAuthorAndChannel()
    {
        var row = QuickFindLogic.MessageRow(Message(7, "first\r\nsecond", "agent-x", "humans"), "sec", Now);

        Assert.Equal("agent-x  #humans", row.Title);
        Assert.Equal("first second", row.Detail);
        Assert.Equal("sec", row.Highlight);
        Assert.Equal(FeedLogic.TimeLabel(Now.AddMinutes(-2), Now), row.Lead);
    }

    [Fact]
    public void HistoryRow_CarriesTheQueryAndNoTarget()
    {
        var row = QuickFindLogic.HistoryRow("deploy");

        Assert.Equal("HISTORY", row.Lead);
        Assert.Equal("Search the whole bus history for “deploy”", row.Title);
        Assert.Equal("deploy", row.HistoryQuery);
        Assert.Null(row.Message);
        Assert.Null(row.Agent);
    }

    [Fact]
    public void Texts_QuoteWhatWasSearched()
    {
        Assert.Equal("Searching the bus for “x”…", QuickFindLogic.Searching("x"));
        Assert.Equal("Nothing on the bus matches “x”. The bus matches whole words.", QuickFindLogic.NothingOnBus("x"));
        Assert.Equal("The search failed: boom", QuickFindLogic.SearchFailed("boom"));
    }

    [Theory]
    [InlineData(true, "deploy", "deploy", false)]
    [InlineData(true, "  deploy in:#ops ", "deploy", false)]
    [InlineData(true, "deploys", "deploy", true)]
    [InlineData(false, "deploy", "deploy", true)]
    public void IsStale_WhenClosedOrTheQueryMovedOn(bool open, string current, string searched, bool expected) =>
        Assert.Equal(expected, QuickFindLogic.IsStale(open, current, searched));

    [Theory]
    [InlineData(Key.Down, QuickFindKeyAction.Next)]
    [InlineData(Key.Up, QuickFindKeyAction.Previous)]
    [InlineData(Key.Enter, QuickFindKeyAction.Open)]
    [InlineData(Key.Tab, QuickFindKeyAction.ChangeScope)]
    [InlineData(Key.A, QuickFindKeyAction.None)]
    [InlineData(Key.Escape, QuickFindKeyAction.None)]
    public void KeyAction_MapsTheNavigationKeys(Key key, QuickFindKeyAction expected) =>
        Assert.Equal(expected, QuickFindLogic.KeyAction(key));

    [Theory]
    [InlineData(0, false, 1)]
    [InlineData(2, false, 0)]
    [InlineData(0, true, 2)]
    [InlineData(1, true, 0)]
    [InlineData(-1, false, 0)]
    public void NextScopeIndex_CyclesBothWays(int current, bool backwards, int expected) =>
        Assert.Equal(expected, QuickFindLogic.NextScopeIndex(current, backwards, 3));

    [Theory]
    [InlineData(0, 1, 1)]
    [InlineData(2, 1, 2)]
    [InlineData(0, -1, 0)]
    [InlineData(-1, 1, 0)]
    public void MoveSelection_StopsAtTheEnds(int selected, int step, int expected) =>
        Assert.Equal(expected, QuickFindLogic.MoveSelection(selected, step, 3));
}
