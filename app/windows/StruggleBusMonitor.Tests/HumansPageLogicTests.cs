using System.Windows.Input;

namespace StruggleBusMonitor.Tests;

public sealed class HumansPageLogicTests
{
    private static readonly DateTimeOffset Now = new(2025, 1, 1, 12, 0, 0, TimeSpan.Zero);

    private static BusMessage Message(long seq, string agent = "agent-a", string body = "hello") =>
        new(seq, "humans", agent, body, "chat", Now);

    private static HumansEntry Row(long seq) => HumansEntry.ForMessage(Message(seq), null, Now);

    private static OutgoingPost Post(OutgoingStatus status = OutgoingStatus.Failed, bool retryable = true) =>
        new() { RequestId = "r", Body = "b", Kind = HumanMessageKind.Chat, Status = status, Retryable = retryable };

    private static BusAgent Agent(string name, double minutesAgo = 0) =>
        new(name, name, string.Empty, "host", "seen", Now.AddMinutes(-minutesAgo));

    [Theory]
    [InlineData(true, true, HumansArrival.FollowToEnd)]
    [InlineData(true, false, HumansArrival.CountBelow)]
    [InlineData(false, true, HumansArrival.Background)]
    [InlineData(false, false, HumansArrival.Background)]
    public void Arrival_DependsOnWhetherTheOperatorIsReadingTheEnd(bool visible, bool atBottom, HumansArrival expected) =>
        Assert.Equal(expected, HumansPageLogic.Arrival(visible, atBottom));

    [Fact]
    public void InsertIndex_KeepsSequenceOrderAndStaysAboveOutgoingRows()
    {
        var rows = new List<HumansEntry> { Row(2), Row(5), Row(9), HumansEntry.ForOutgoing(Post()) };

        Assert.Equal(3, HumansPageLogic.InsertIndex(rows, 1, 12));
        Assert.Equal(2, HumansPageLogic.InsertIndex(rows, 1, 7));
        Assert.Equal(0, HumansPageLogic.InsertIndex(rows, 1, 1));
        Assert.Equal(0, HumansPageLogic.InsertIndex([], 0, 1));
    }

    [Theory]
    [InlineData(0, "0")]
    [InlineData(99, "99")]
    [InlineData(100, "99+")]
    public void BadgeText_CapsAtNinetyNine(int unread, string expected) =>
        Assert.Equal(expected, HumansPageLogic.BadgeText(unread));

    [Theory]
    [InlineData(1, "1 new message below.")]
    [InlineData(3, "3 new messages below.")]
    public void NewBelowText_UsesThePlural(int count, string expected) =>
        Assert.Equal(expected, HumansPageLogic.NewBelowText(count));

    [Fact]
    public void Notice_SaysWhetherPostingIsPossible()
    {
        Assert.Equal(HumansPageLogic.CanPostNotice, HumansPageLogic.Notice(true));
        Assert.Equal(HumansPageLogic.CannotPostNotice, HumansPageLogic.Notice(false));
    }

    [Fact]
    public void HintForWaiting_ChangesWhenNothingIsWaiting()
    {
        Assert.Equal(HumansPageLogic.NothingWaitingHint, HumansPageLogic.HintForWaiting(0));
        Assert.Equal(HumansPageLogic.WaitingHint, HumansPageLogic.HintForWaiting(2));
    }

    [Fact]
    public void ReplyBanner_NamesTheAuthorAndQuotesTheBody()
    {
        Assert.Equal(string.Empty, HumansPageLogic.ReplyBanner(null));
        Assert.Equal("Replying to agent-a: “line one line two”", HumansPageLogic.ReplyBanner(Message(1, body: "line one\nline two")));
    }

    [Fact]
    public void WaitingChanged_ComparesTheQuestionsInOrder()
    {
        var shown = new[] { new WaitingEntry(Message(1), Now), new WaitingEntry(Message(2), Now) };

        Assert.False(HumansPageLogic.WaitingChanged([Message(1), Message(2)], shown));
        Assert.True(HumansPageLogic.WaitingChanged([Message(2), Message(1)], shown));
        Assert.True(HumansPageLogic.WaitingChanged([Message(1)], shown));
    }

    [Theory]
    [InlineData(10, true, true, 2, false, true)]
    [InlineData(10, true, true, 0, true, true)]
    [InlineData(10, true, true, 0, false, false)]
    [InlineData(0, true, true, 2, true, false)]
    [InlineData(10, false, true, 2, true, false)]
    [InlineData(10, true, false, 2, true, false)]
    public void ScrollReadsConversation_OnlyAtTheEndOfAVisiblePageWithSomethingUnread(
        double change, bool visible, bool atBottom, int newBelow, bool badgeShown, bool expected) =>
        Assert.Equal(expected, HumansPageLogic.ScrollReadsConversation(change, visible, atBottom, newBelow, badgeShown));

    [Fact]
    public void FailedPost_OnlyForRowsThatWereNotSent()
    {
        var retryable = Post();
        var final = Post(retryable: false);

        Assert.Same(retryable, HumansPageLogic.FailedPost(HumansEntry.ForOutgoing(retryable), retryableOnly: true));
        Assert.Null(HumansPageLogic.FailedPost(HumansEntry.ForOutgoing(final), retryableOnly: true));
        Assert.Same(final, HumansPageLogic.FailedPost(HumansEntry.ForOutgoing(final), retryableOnly: false));
        Assert.Null(HumansPageLogic.FailedPost(HumansEntry.ForOutgoing(Post(OutgoingStatus.Sending)), retryableOnly: false));
        Assert.Null(HumansPageLogic.FailedPost(Row(1), retryableOnly: false));
        Assert.Null(HumansPageLogic.FailedPost(null, retryableOnly: false));
    }

    [Theory]
    [InlineData(Key.Down, false, true, ComposerKeyAction.MentionNext)]
    [InlineData(Key.Up, false, true, ComposerKeyAction.MentionPrevious)]
    [InlineData(Key.Tab, false, true, ComposerKeyAction.MentionAccept)]
    [InlineData(Key.Enter, false, true, ComposerKeyAction.MentionAccept)]
    [InlineData(Key.Enter, true, true, ComposerKeyAction.MentionAccept)]
    [InlineData(Key.Escape, false, true, ComposerKeyAction.MentionDismiss)]
    [InlineData(Key.A, false, true, ComposerKeyAction.None)]
    [InlineData(Key.Enter, false, false, ComposerKeyAction.Send)]
    [InlineData(Key.Enter, true, false, ComposerKeyAction.None)]
    [InlineData(Key.Down, false, false, ComposerKeyAction.None)]
    [InlineData(Key.Tab, false, false, ComposerKeyAction.None)]
    [InlineData(Key.Escape, false, false, ComposerKeyAction.None)]
    public void KeyAction_ThePopupTakesNavigationKeysAndEnterSendsOtherwise(Key key, bool shift, bool popupOpen, ComposerKeyAction expected) =>
        Assert.Equal(expected, HumansPageLogic.KeyAction(key, shift, popupOpen));

    [Theory]
    [InlineData("hi @ag", 6, 3)]
    [InlineData("hi there", 8, -1)]
    public void MentionStart_FindsTheMentionBeingTyped(string text, int caret, int expected) =>
        Assert.Equal(expected, HumansPageLogic.MentionStart(text, caret));

    [Fact]
    public void PlanMentions_ClosesAndForgetsTheDismissalWithoutFocusOrToken()
    {
        var agents = new[] { Agent("agent-one") };

        var unfocused = HumansPageLogic.PlanMentions(false, "@ag", 3, 0, agents, null, Now);
        var noToken = HumansPageLogic.PlanMentions(true, "plain", 5, 4, agents, null, Now);

        Assert.Equal(new MentionPlan(-1, null, false, -1, string.Empty), unfocused);
        Assert.Equal(new MentionPlan(-1, null, false, -1, string.Empty), noToken);
    }

    [Fact]
    public void PlanMentions_StaysClosedWhereEscapeDismissedIt()
    {
        var plan = HumansPageLogic.PlanMentions(true, "hi @ag", 6, 3, [Agent("agent-one")], null, Now);

        Assert.False(plan.Open);
        Assert.Null(plan.Options);
        Assert.Equal(3, plan.DismissedAt);
    }

    [Fact]
    public void PlanMentions_EmptiesTheListWhenNothingMatches()
    {
        var plan = HumansPageLogic.PlanMentions(true, "@zz", 3, -1, [Agent("agent-one")], null, Now);

        Assert.False(plan.Open);
        Assert.NotNull(plan.Options);
        Assert.Empty(plan.Options);
    }

    [Fact]
    public void PlanMentions_OpensWithTheBestMatchSelected()
    {
        var plan = HumansPageLogic.PlanMentions(true, "@", 1, -1, [Agent("agent-two"), Agent("agent-one")], null, Now);

        Assert.True(plan.Open);
        Assert.Equal(["agent-one", "agent-two", "everyone"], plan.Options!.Select(option => option.Insert));
        Assert.Equal(0, plan.SelectedIndex);
        Assert.Equal("MENTION AN AGENT", plan.Header);
        Assert.Equal(-1, plan.DismissedAt);
    }

    [Fact]
    public void PlanMentions_KeepsTheSelectedRowWhileTyping()
    {
        var agents = new[] { Agent("agent-one"), Agent("agent-two") };

        var kept = HumansPageLogic.PlanMentions(true, "@agent", 6, -1, agents, "agent-two", Now);
        var gone = HumansPageLogic.PlanMentions(true, "@agent", 6, -1, agents, "agent-nine", Now);

        Assert.Equal(1, kept.SelectedIndex);
        Assert.Equal("AGENTS MATCHING “agent”", kept.Header);
        Assert.Equal(0, gone.SelectedIndex);
    }

    [Theory]
    [InlineData(0, 1, 3, 1)]
    [InlineData(2, 1, 3, 0)]
    [InlineData(0, -1, 3, 2)]
    [InlineData(-1, 1, 3, 0)]
    public void WrapSelection_GoesRoundAtBothEnds(int selected, int step, int count, int expected) =>
        Assert.Equal(expected, HumansPageLogic.WrapSelection(selected, step, count));

    [Fact]
    public void InsertMention_ReplacesThePrefixAndAddsOneSpace()
    {
        Assert.Equal(("hi @agent-one ", 14), HumansPageLogic.InsertMention("hi @ag", 6, "agent-one"));
        Assert.Equal(("@agent-one now", 11), HumansPageLogic.InsertMention("@ag now", 3, "agent-one"));
        Assert.Equal(("@agent-one ,now", 11), HumansPageLogic.InsertMention("@ag,now", 3, "agent-one"));
        Assert.Null(HumansPageLogic.InsertMention("no mention", 4, "agent-one"));
    }
}
