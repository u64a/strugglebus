using System.Windows;
using System.Windows.Media;

namespace StruggleBusMonitor.Tests;

public sealed class ViewModelsTests
{
    private static readonly DateTimeOffset Now = new(2030, 1, 1, 12, 0, 0, TimeSpan.Zero);

    private static BusMessage Message(long seq, string agent = "agent-one", string body = "hello", string kind = "status", long? replyTo = null, string channel = "humans") =>
        new(seq, channel, agent, body, kind, Now.AddMinutes(-2), replyTo);

    [Fact]
    public void ChannelFilterOption_LabelsAllAndNamedChannels()
    {
        Assert.Equal("ALL", new ChannelFilterOption(null).Label);
        Assert.Equal("#ops", new ChannelFilterOption("ops").Label);
    }

    [Fact]
    public void ActivityEntry_DescribesItsMessage()
    {
        var entry = new ActivityEntry(Message(42, body: "short", kind: "question", channel: "ops"), Now) { Pinned = true };

        Assert.Equal(42, entry.Sequence);
        Assert.Equal("#ops", entry.ChannelLabel);
        Assert.Equal("QUESTION", entry.KindLabel);
        Assert.Equal("agent-one", entry.AgentName);
        Assert.Equal("seq 42", entry.SequenceLabel);
        Assert.Equal("short", entry.DisplayBody);
        Assert.Equal(FeedLogic.TimeLabel(entry.Message.CreatedAt, Now), entry.TimeLabel);
        Assert.True(entry.Pinned);
        Assert.False(entry.IsLong);
        Assert.Equal(Visibility.Collapsed, entry.ExpandVisibility);
    }

    [Theory]
    [InlineData(240, 0, false)]
    [InlineData(241, 0, true)]
    [InlineData(10, 2, false)]
    [InlineData(10, 3, true)]
    public void ActivityEntry_IsLongPastTheLengthOrLineLimit(int length, int lineBreaks, bool expected)
    {
        var body = new string('x', length - lineBreaks) + new string('\n', lineBreaks);

        var entry = new ActivityEntry(Message(1, body: body), Now);

        Assert.Equal(expected, entry.IsLong);
        Assert.Equal(expected ? Visibility.Visible : Visibility.Collapsed, entry.ExpandVisibility);
    }

    [Fact]
    public void ActivityEntry_ExpandingChangesTheLabelAndTellsTheView()
    {
        var entry = new ActivityEntry(Message(1, body: new string('x', 1500)), Now);
        var changed = new List<string?>();
        entry.PropertyChanged += (_, e) => changed.Add(e.PropertyName);

        Assert.Equal($"Show all {1500:N0} characters", entry.ExpandLabel);
        entry.IsExpanded = true;
        entry.IsExpanded = true;

        Assert.True(entry.IsExpanded);
        Assert.Equal("Show less", entry.ExpandLabel);
        Assert.Equal([nameof(ActivityEntry.IsExpanded), nameof(ActivityEntry.ExpandLabel)], changed);
    }

    [Fact]
    public void ActivityEntry_HighlightNotifiesOnlyWhenItChanges()
    {
        var entry = new ActivityEntry(Message(1), Now);
        var changed = new List<string?>();
        entry.PropertyChanged += (_, e) => changed.Add(e.PropertyName);

        entry.Highlight = string.Empty;
        entry.Highlight = "disk";
        entry.Highlight = "disk";

        Assert.Equal("disk", entry.Highlight);
        Assert.Equal([nameof(ActivityEntry.Highlight)], changed);
    }

    [Fact]
    public void AgentEntry_ShowsHostAndPresenceAndFollowsUpdates()
    {
        var entry = new AgentEntry(new BusAgent("a1", "agent-one", "", "box-1", "seen", Now.AddMinutes(-2)), Now);
        var changed = new List<string?>();
        entry.PropertyChanged += (_, e) => changed.Add(e.PropertyName);

        Assert.Equal(("a1", "agent-one"), (entry.Id, entry.Name));
        Assert.Equal("box-1  ·  active 2m ago", entry.Meta);
        Assert.Equal(AgentPresence.Active, entry.Presence);

        var later = new BusAgent("a1", "agent-one", "", " ", "seen", Now.AddMinutes(-30));
        entry.Update(later, Now);
        entry.CountLabel = "3";
        entry.CountLabel = "3";

        Assert.Same(later, entry.Agent);
        Assert.Equal("idle 30m", entry.Meta);
        Assert.Equal(AgentPresence.Idle, entry.Presence);
        Assert.Equal("3", entry.CountLabel);
        Assert.Equal([nameof(AgentEntry.Meta), nameof(AgentEntry.Presence), nameof(AgentEntry.CountLabel)], changed);
    }

    [Fact]
    public void AgentEntry_ANeverSeenAgentIsOffline()
    {
        var entry = new AgentEntry(new BusAgent("a1", "agent-one", "", "", "never-seen", null), Now);

        Assert.Equal("never seen", entry.Meta);
        Assert.Equal(AgentPresence.Offline, entry.Presence);
        Assert.Equal(string.Empty, entry.CountLabel);
    }

    [Fact]
    public void HumansEntry_AnAgentMessageCanBeRepliedToAndCopied()
    {
        var message = Message(5, body: "Need a hand?", kind: "question");

        var entry = HumansEntry.ForMessage(message, null, Now);

        Assert.Same(message, entry.Message);
        Assert.Null(entry.Outgoing);
        Assert.False(entry.IsOperator);
        Assert.Equal("agent-one", entry.AuthorLabel);
        Assert.Equal("QUESTION", entry.KindLabel);
        Assert.Equal(FeedLogic.TimeLabel(message.CreatedAt, Now), entry.TimeLabel);
        Assert.Equal("Need a hand?", entry.Body);
        Assert.Equal(string.Empty, entry.StateLabel);
        Assert.Equal(string.Empty, entry.ReplyContext);
        Assert.Null(entry.Error);
        Assert.Equal(Visibility.Collapsed, entry.ReplyContextVisibility);
        Assert.Equal(Visibility.Collapsed, entry.ErrorVisibility);
        Assert.Equal(Visibility.Visible, entry.ReplyVisibility);
        Assert.Equal(Visibility.Visible, entry.CopyVisibility);
        Assert.Equal(Visibility.Collapsed, entry.RetryVisibility);
        Assert.Equal(Visibility.Collapsed, entry.DiscardVisibility);
    }

    [Fact]
    public void HumansEntry_TheOperatorsOwnMessageIsYouAndCannotBeRepliedTo()
    {
        var parent = Message(5, body: "Need a hand?\r\nIt is urgent.", kind: "question");
        var own = Message(6, HumansLogic.OperatorAuthor, "On it.", "answer", replyTo: 5);

        var entry = HumansEntry.ForMessage(own, parent, Now);

        Assert.True(entry.IsOperator);
        Assert.Equal("You", entry.AuthorLabel);
        Assert.Equal("replying to agent-one: “Need a hand?  It is urgent.”", entry.ReplyContext);
        Assert.Equal(Visibility.Visible, entry.ReplyContextVisibility);
        Assert.Equal(Visibility.Collapsed, entry.ReplyVisibility);
        Assert.Equal(Visibility.Visible, entry.CopyVisibility);
    }

    [Fact]
    public void HumansEntry_AReplyWhoseParentIsNotLoadedNamesItsSequence()
    {
        var entry = HumansEntry.ForMessage(Message(9, replyTo: 3), null, Now);

        Assert.Equal("replying to seq 3", entry.ReplyContext);
    }

    [Fact]
    public void HumansEntry_AReplyToTheOperatorSaysYou()
    {
        var parent = Message(5, HumansLogic.OperatorAuthor, "Status?");

        var entry = HumansEntry.ForMessage(Message(6, replyTo: 5), parent, Now);

        Assert.Equal("replying to you: “Status?”", entry.ReplyContext);
    }

    [Fact]
    public void HumansEntry_APostBeingSentShowsItsState()
    {
        var post = new OutgoingPost { RequestId = "r-1", Body = "On it.", Kind = HumanMessageKind.Answer, ReplyTo = Message(5, body: "Need a hand?") };

        var entry = HumansEntry.ForOutgoing(post);

        Assert.Same(post, entry.Outgoing);
        Assert.Null(entry.Message);
        Assert.True(entry.IsOperator);
        Assert.Equal("You", entry.AuthorLabel);
        Assert.Equal("ANSWER", entry.KindLabel);
        Assert.Equal("sending…", entry.StateLabel);
        Assert.Equal("On it.", entry.Body);
        Assert.Equal("replying to agent-one: “Need a hand?”", entry.ReplyContext);
        Assert.Equal(Visibility.Collapsed, entry.ErrorVisibility);
        Assert.Equal(Visibility.Collapsed, entry.ReplyVisibility);
        Assert.Equal(Visibility.Collapsed, entry.CopyVisibility);
        Assert.Equal(Visibility.Collapsed, entry.RetryVisibility);
        Assert.Equal(Visibility.Collapsed, entry.DiscardVisibility);
        Assert.Equal("r-1", post.RequestId);
    }

    [Theory]
    [InlineData(true, Visibility.Visible)]
    [InlineData(false, Visibility.Collapsed)]
    public void HumansEntry_AFailedPostCanBeDiscardedAndRetriedWhenThatCanHelp(bool retryable, Visibility retry)
    {
        var post = new OutgoingPost
        {
            RequestId = "r-1",
            Body = "Hello",
            Kind = HumanMessageKind.Chat,
            Status = OutgoingStatus.Failed,
            Error = "The message is too long for the server.",
            Retryable = retryable
        };

        var entry = HumansEntry.ForOutgoing(post);

        Assert.Equal("not sent", entry.StateLabel);
        Assert.Equal("CHAT", entry.KindLabel);
        Assert.Equal(string.Empty, entry.ReplyContext);
        Assert.Equal("The message is too long for the server.", entry.Error);
        Assert.Equal(Visibility.Visible, entry.ErrorVisibility);
        Assert.Equal(retry, entry.RetryVisibility);
        Assert.Equal(Visibility.Visible, entry.DiscardVisibility);
    }

    [Fact]
    public void Snippet_FlattensLinesAndCutsAtEightyCharacters()
    {
        Assert.Equal("one two", HumansEntry.Snippet("  one\ntwo  "));
        Assert.Equal(new string('x', 80), HumansEntry.Snippet(new string('x', 80)));
        Assert.Equal(new string('x', 80) + "…", HumansEntry.Snippet(new string('x', 81)));
    }

    [Fact]
    public void WaitingEntry_SummarisesTheQuestion()
    {
        var message = Message(5, body: "Can I deploy?\nIt is ready.", kind: "question");

        var entry = new WaitingEntry(message, Now);

        Assert.Same(message, entry.Message);
        Assert.Equal("agent-one", entry.AgentName);
        Assert.Equal("Can I deploy? It is ready.", entry.Snippet);
        Assert.Equal(FeedLogic.TimeLabel(message.CreatedAt, Now, withSeconds: false), entry.TimeLabel);
    }

    [Fact]
    public void MentionRow_ShowsTheNameWithAnAtSign()
    {
        var option = new MentionOption("agent-one", "active now", AgentPresence.Active, false);

        var row = new MentionRow(option);

        Assert.Same(option, row.Option);
        Assert.Equal("@agent-one", row.Display);
        Assert.Equal("active now", row.Meta);
        Assert.Equal(AgentPresence.Active, row.Presence);
        Assert.Null(new MentionRow(new MentionOption("everyone", "adds 2", null, true)).Presence);
    }

    [Fact]
    public void QuickFindResult_IsEmptyUntilFilled()
    {
        var blank = new QuickFindResult();
        var agent = new BusAgent("a1", "agent-one", "", "", "seen", null);
        var message = Message(3);
        var filled = new QuickFindResult { Lead = "@", Title = "agent-one", Detail = "box", Highlight = "agent", Agent = agent, Message = message, HistoryQuery = "agent" };

        Assert.Equal((string.Empty, string.Empty, string.Empty, string.Empty), (blank.Lead, blank.Title, blank.Detail, blank.Highlight));
        Assert.Null(blank.Agent);
        Assert.Null(blank.Message);
        Assert.Null(blank.HistoryQuery);
        Assert.Equal(("@", "agent-one", "box", "agent", "agent"), (filled.Lead, filled.Title, filled.Detail, filled.Highlight, filled.HistoryQuery));
        Assert.Same(agent, filled.Agent);
        Assert.Same(message, filled.Message);
    }

    [Fact]
    public void ThemeCard_PreviewsThePaletteWithFrozenBrushes()
    {
        var palette = Themes.Find("nord", light: false);
        var colors = Themes.Derive(palette);

        var card = new ThemeCard(palette);

        Assert.Same(palette, card.Palette);
        Assert.Equal("Nord", card.Name);
        var brushes = new Dictionary<string, Brush>
        {
            ["Bg"] = card.Bg, ["Fg"] = card.Fg, ["Accent"] = card.Accent, ["Ok"] = card.Ok,
            ["Warn"] = card.Warn, ["Bad"] = card.Bad, ["Line"] = card.Line
        };
        Assert.All(brushes, pair =>
        {
            var brush = Assert.IsType<SolidColorBrush>(pair.Value);
            Assert.True(brush.IsFrozen);
            Assert.Equal(colors[pair.Key], brush.Color);
        });
    }

    [Fact]
    public void ThemeCard_SelectionNotifiesOnce()
    {
        var card = new ThemeCard(Themes.Find(Themes.DefaultDark, light: false));
        var changed = new List<string?>();
        card.PropertyChanged += (_, e) => changed.Add(e.PropertyName);

        card.IsSelected = true;
        card.IsSelected = true;

        Assert.True(card.IsSelected);
        Assert.Equal([nameof(ThemeCard.IsSelected)], changed);
    }
}
