using StruggleBusMonitor;

namespace StruggleBusMonitor.Tests;

public class FeedLogicTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 15, 14, 30, 0, TimeZoneInfo.Local.GetUtcOffset(new DateTime(2026, 11, 15, 14, 30, 0)));

    private static BusMessage Message(long seq, string agent, string body, string channel = "ops", string kind = "chat", long? replyTo = null) =>
        new(seq, channel, agent, body, kind, Now, replyTo);

    private static BusAgent Agent(string name, double? minutesAgo, string host = "host-1") =>
        new("id-" + name, name, "", host, "seen", minutesAgo is { } minutes ? Now.AddMinutes(-minutes) : null);

    [Fact]
    public void ParseQuery_SplitsAgentChannelAndText()
    {
        var query = FeedLogic.ParseQuery("tunnel from:@prox-manager in:#ops latency");

        Assert.Equal("tunnel latency", query.Text);
        Assert.Equal("prox-manager", query.Agent);
        Assert.Equal("ops", query.Channel);
        Assert.True(FeedLogic.ParseQuery("   ").IsEmpty);
    }

    [Fact]
    public void Matches_AppliesEveryPartOfTheQuery()
    {
        var message = Message(1, "prox-manager", "Tunnel latency rose");

        Assert.True(FeedLogic.Matches(message, new FeedQuery("tunnel", "PROX-MANAGER", "ops")));
        Assert.True(FeedLogic.Matches(message, new FeedQuery("prox", null, null)));
        Assert.False(FeedLogic.Matches(message, new FeedQuery("tunnel", "net-watch", null)));
        Assert.False(FeedLogic.Matches(message, new FeedQuery("", null, "humans")));
        Assert.False(FeedLogic.Matches(message, new FeedQuery("backup", null, null)));
    }

    [Theory]
    [InlineData(0.5, AgentPresence.Active, "active now")]
    [InlineData(3.0, AgentPresence.Active, "active 3m ago")]
    [InlineData(14.0, AgentPresence.Idle, "idle 14m")]
    public void Presence_DescribesRecentActivity(double minutesAgo, AgentPresence expected, string label)
    {
        var seen = Now.AddMinutes(-minutesAgo);

        Assert.Equal(expected, FeedLogic.Presence(seen, Now));
        Assert.Equal(label, FeedLogic.PresenceLabel(seen, Now));
    }

    [Fact]
    public void Presence_OldOrMissingActivityIsOffline()
    {
        Assert.Equal(AgentPresence.Offline, FeedLogic.Presence(Now.AddHours(-3), Now));
        Assert.Equal(AgentPresence.Offline, FeedLogic.Presence(null, Now));
        Assert.Equal("never seen", FeedLogic.PresenceLabel(null, Now));
        Assert.StartsWith("last seen yesterday ", FeedLogic.PresenceLabel(Now.AddDays(-1), Now));
    }

    [Fact]
    public void TimeLabel_IncludesTheDayOnceItIsNotToday()
    {
        Assert.Equal("14:30:00", FeedLogic.TimeLabel(Now, Now));
        Assert.Equal("yesterday 14:30", FeedLogic.TimeLabel(Now.AddDays(-1), Now));
        Assert.Equal("10 Nov 14:30", FeedLogic.TimeLabel(Now.AddDays(-5), Now));
    }

    [Fact]
    public void Segment_MarksMentionsAndSearchHits()
    {
        var segments = FeedLogic.Segment("Asked @prox-manager about the Tunnel, mail a@b-c.io", "tunnel");

        Assert.Contains(segments, segment => segment is { Kind: SegmentKind.Mention, Text: "@prox-manager" });
        Assert.Contains(segments, segment => segment is { Kind: SegmentKind.Hit, Text: "Tunnel" });
        // An email address and a name without a hyphen are not mentions on the server either.
        Assert.DoesNotContain(segments, segment => segment.Kind == SegmentKind.Mention && segment.Text.Contains("b-c"));
        Assert.Equal("Asked @prox-manager about the Tunnel, mail a@b-c.io", string.Concat(segments.Select(segment => segment.Text)));
        Assert.All(FeedLogic.Segment("ping @everyone", null), segment => Assert.Equal(SegmentKind.Plain, segment.Kind));
    }

    [Theory]
    [InlineData("hello @pro", 10, 6, "pro")]
    [InlineData("@", 1, 0, "")]
    [InlineData("(@build-r", 9, 1, "build-r")]
    public void ActiveMentionToken_FindsTheMentionBeingTyped(string text, int caret, int start, string prefix)
    {
        var token = FeedLogic.ActiveMentionToken(text, caret);

        Assert.NotNull(token);
        Assert.Equal(start, token.Start);
        Assert.Equal(prefix, token.Prefix);
    }

    [Theory]
    [InlineData("mail a@pro", 10)]
    [InlineData("hello pro", 9)]
    [InlineData("@pro done", 9)]
    public void ActiveMentionToken_IgnoresTextThatIsNotAMention(string text, int caret) =>
        Assert.Null(FeedLogic.ActiveMentionToken(text, caret));

    [Fact]
    public void MentionOptions_OffersOnlyNamesTheBusAccepts()
    {
        var agents = new[] { Agent("build-runner-2", 20), Agent("bus-maintainer", 1), Agent("build-runner-1", 2), Agent("solo", 1), Agent("rebuild-bot", 1) };

        var options = FeedLogic.MentionOptions(agents, "bu", Now);

        // Prefix matches first (active before idle), then names that merely contain the text.
        Assert.Equal(["build-runner-1", "bus-maintainer", "build-runner-2", "rebuild-bot"], options.Select(option => option.Insert));
        Assert.DoesNotContain(FeedLogic.MentionOptions(agents, "", Now), option => option.Insert == "solo");
    }

    [Fact]
    public void MentionOptions_OffersEveryoneWithTheActiveCount()
    {
        var agents = new[] { Agent("net-watch", 1), Agent("docs-writer", 30), Agent("prox-manager", 2) };

        var everyone = Assert.Single(FeedLogic.MentionOptions(agents, "ev", Now));

        Assert.True(everyone.IsGroup);
        Assert.Equal("everyone", everyone.Insert);
        Assert.Contains("2 active agents", everyone.Meta);
    }

    [Fact]
    public void ExpandEveryone_NamesActiveAgentsOnceEach()
    {
        var agents = new[] { Agent("net-watch", 1), Agent("docs-writer", 30), Agent("prox-manager", 2), Agent("solo", 1) };

        var expanded = FeedLogic.ExpandEveryone("@prox-manager and @everyone: freeze at noon, @everyone", agents, Now);

        Assert.Equal("@prox-manager and @net-watch: freeze at noon, everyone", expanded);
        Assert.Equal("no group here", FeedLogic.ExpandEveryone("no group here", agents, Now));
        Assert.Equal("hi everyone", FeedLogic.ExpandEveryone("hi @everyone", [], Now));
    }

    [Fact]
    public void ExpandEveryone_StaysWithinTheServerMentionLimit()
    {
        var agents = Enumerable.Range(0, 50).Select(index => Agent($"worker-{index:00}", 1)).ToArray();

        var expanded = FeedLogic.ExpandEveryone("@everyone stop", agents, Now);

        Assert.Equal(FeedLogic.MaxMentionsPerMessage, expanded.Count(c => c == '@'));
    }

    [Fact]
    public void WaitingOnOperator_ListsUnansweredAgentQuestions()
    {
        var messages = new[]
        {
            Message(1, "prox-manager", "Clone the runner?", "humans", "question"),
            Message(2, "docs-writer", "Cover the gateway?", "humans", "question"),
            Message(3, HumansLogic.OperatorAuthor, "Yes", "humans", "answer", replyTo: 1),
            Message(4, HumansLogic.OperatorAuthor, "Anyone free?", "humans", "question"),
            Message(5, "net-watch", "All quiet", "humans")
        };

        var waiting = FeedLogic.WaitingOnOperator(messages);

        Assert.Equal([2L], waiting.Select(message => message.Seq));
        Assert.Empty(FeedLogic.WaitingOnOperator(messages, new HashSet<long> { 2 }));
    }

    [Fact]
    public void ClearWaiting_KeepsTheNewestWithoutDuplicates()
    {
        var settings = new AppSettings();
        settings.ClearWaiting([5, 3]);
        settings.ClearWaiting(Enumerable.Range(3, AppSettings.MaximumClearedWaiting).Select(value => (long)value));

        Assert.Equal(AppSettings.MaximumClearedWaiting, settings.ClearedWaiting.Count);
        Assert.Equal(3, settings.ClearedWaiting[0]);
        settings.ClearWaiting([9999]);
        Assert.Equal(4, settings.ClearedWaiting[0]);
        Assert.Equal(9999, settings.ClearedWaiting[^1]);
    }

    [Fact]
    public void ParseLocalBoundary_AcceptsDatesWithOrWithoutTime()
    {
        Assert.Null(FeedLogic.ParseLocalBoundary("  ", isUpperBound: false));
        Assert.Equal(new DateTime(2026, 11, 15, 9, 5, 0), FeedLogic.ParseLocalBoundary("2026-11-15 09:05", false)!.Value.LocalDateTime);
        Assert.Equal(new DateTime(2026, 11, 15), FeedLogic.ParseLocalBoundary("2026-11-15", false)!.Value.LocalDateTime);
        Assert.Equal(new DateTime(2026, 11, 16).AddTicks(-1), FeedLogic.ParseLocalBoundary("2026-11-15", true)!.Value.LocalDateTime);
        Assert.Throws<InvalidOperationException>(() => FeedLogic.ParseLocalBoundary("15/11/2026", false));
    }
}

public class ThemeTests
{
    [Fact]
    public void Themes_CoverTheOmarchySetWithUniqueIds()
    {
        Assert.Equal(19, Themes.All.Count);
        Assert.Equal(19, Themes.All.Select(theme => theme.Id).Distinct().Count());
        Assert.Equal(4, Themes.All.Count(theme => theme.IsLight));
    }

    [Fact]
    public void Themes_TextColoursStayReadableOnEveryPalette()
    {
        foreach (var theme in Themes.All)
        {
            var colors = Themes.Derive(theme);
            Assert.True(Themes.Contrast(colors["Fg"], colors["Bg"]) >= 4.5, $"{theme.Id}: body text");
            Assert.True(Themes.Contrast(colors["Muted"], colors["Bg"]) >= 4.5, $"{theme.Id}: muted text");
            Assert.True(Themes.Contrast(colors["AccentText"], colors["Bg"]) >= 4.5, $"{theme.Id}: accent text");
            Assert.True(Themes.Contrast(colors["OnAccent"], colors["Accent"]) >= 4.5, $"{theme.Id}: text on accent");
        }
    }

    [Fact]
    public void Find_FallsBackWhenTheSavedThemeIsUnknownOrTheWrongKind()
    {
        Assert.Equal("nord", Themes.Find("nord", light: false).Id);
        Assert.Equal(Themes.DefaultLight, Themes.Find("nord", light: true).Id);
        Assert.Equal(Themes.DefaultDark, Themes.Find("removed-theme", light: false).Id);
    }

    [Fact]
    public void Settings_RoundTripAndSurviveACorruptFile()
    {
        var path = Path.Combine(Path.GetTempPath(), $"sbm-settings-{Guid.NewGuid():N}.json");
        try
        {
            new AppSettings { Mode = AppThemeMode.System, DarkTheme = "gruvbox", LightTheme = "white", WindowWidth = 1400 }.SaveToPath(path);
            var loaded = AppSettings.LoadFromPath(path);

            Assert.Equal(AppThemeMode.System, loaded.Mode);
            Assert.Equal("gruvbox", loaded.ResolveTheme(windowsPrefersLight: false).Id);
            Assert.Equal("white", loaded.ResolveTheme(windowsPrefersLight: true).Id);
            Assert.Equal(1400, loaded.WindowWidth);

            File.WriteAllText(path, "{ not json");
            Assert.Equal(Themes.DefaultDark, AppSettings.LoadFromPath(path).DarkTheme);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Theory]
    [InlineData("1.4.0+9f2c1ab", "1.4.0")]
    [InlineData("1.4.0", "1.4.0")]
    [InlineData(null, "dev")]
    public void DisplayVersion_DropsBuildMetadata(string? informational, string expected) =>
        Assert.Equal(expected, AppUpdater.DisplayVersion(informational));
}

public class HistoryPathTests
{
    [Fact]
    public void BuildHistoryPath_AddsOnlyTheFiltersThatAreSet()
    {
        Assert.Equal("api/mobile/snapshot?limit=200", BusApi.BuildHistoryPath(null, null, null, 200));
        Assert.Equal(
            "api/mobile/snapshot?limit=50&channel=humans&agent=prox-manager&before=120",
            BusApi.BuildHistoryPath("humans", "prox-manager", 120, 50));
        Assert.Equal("api/mobile/snapshot?limit=10&agent=human%3Aoperator", BusApi.BuildHistoryPath(" ", "human:operator", null, 10));
    }
}
