using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using static StruggleBusMonitor.Tests.MonitorWindowHarness;

namespace StruggleBusMonitor.Tests;

/// <summary>The Humans page of the real window, driven through its controls against a fake bus.</summary>
[Collection(StaWindowAdminCollection.Name)]
public sealed class HumansWindowTests(StaWindowAdminFixture ui)
{
    private void Run(Func<MonitorWindowHarness, Task> test, Action<MonitorFakeBus>? arrange = null, bool operatorGrant = true) => ui.Run(async () =>
    {
        var harness = await StartAsync(arrange ?? Conversation, operatorGrant: operatorGrant);
        try { await test(harness); }
        finally { await harness.CloseAsync(); }
    });

    private static void Conversation(MonitorFakeBus bus)
    {
        bus.Channels.AddRange(["humans", "ops"]);
        bus.Agents.AddRange([Agent("agent-one"), Agent("agent-two", minutesAgo: 20), Agent("solo")]);
        bus.Messages.AddRange(
        [
            Human(1, body: "first"),
            Human(2, HumansLogic.OperatorAuthor, "noted", replyTo: 1),
            Human(3, "agent-two", "Which branch should I use?", "question"),
            Message(4, body: "not for humans")
        ]);
    }

    private static void LongConversation(MonitorFakeBus bus)
    {
        bus.Agents.Add(Agent("agent-one"));
        bus.Messages.AddRange(Enumerable.Range(1, 60).Select(seq => Human(seq, body: $"message {seq}\nwith a second line\nand a third")));
    }

    private static List<HumansEntry> Rows(MainWindow window) => window.HumansList.Items.Cast<HumansEntry>().ToList();

    private static List<WaitingEntry> Waiting(MainWindow window) => window.WaitingList.Items.Cast<WaitingEntry>().ToList();

    private static List<string> Mentions(MainWindow window) => window.MentionList.Items.Cast<MentionRow>().Select(row => row.Display).ToList();

    private static async Task ShowHumansAsync(MonitorWindowHarness harness)
    {
        harness.Window.HumansNav.IsChecked = true;
        await MonitorUiThread.Settle();
        harness.Window.UpdateLayout();
    }

    /// <summary>Replaces what is in the composer by typing <paramref name="text"/> into it.</summary>
    private static void Type(MainWindow window, string text)
    {
        window.HumansComposer.Clear();
        TypeInto(window.HumansComposer, text);
    }

    // ---- Conversation ------------------------------------------------------------------------

    [Fact]
    public void OpeningThePage_ShowsTheConversationOldestFirst() => Run(async harness =>
    {
        var window = harness.Window;
        Assert.Equal(Visibility.Collapsed, window.HumansBadge.Visibility);

        await ShowHumansAsync(harness);

        Assert.Equal([1L, 2L, 3L], Rows(window).Select(row => row.Message!.Seq));
        Assert.Equal("You", Rows(window)[1].AuthorLabel);
        Assert.Equal("replying to agent-one: “first”", Rows(window)[1].ReplyContext);
        Assert.Equal("3 messages", window.HumansCountText.Text);
        Assert.Equal(Visibility.Collapsed, window.HumansEmptyText.Visibility);
        Assert.Equal(HumansPageLogic.CanPostNotice, window.HumansNotice.Text);
        Assert.Equal(Visibility.Collapsed, window.HumansNewBar.Visibility);
        Assert.True(window.HumansComposer.IsKeyboardFocused);
    });

    [Fact]
    public void OpeningThePage_WithoutOperatorAccessExplainsHowToPost() => Run(async harness =>
    {
        await ShowHumansAsync(harness);

        Assert.Equal(HumansPageLogic.CannotPostNotice, harness.Window.HumansNotice.Text);
        Assert.Equal("0 messages", harness.Window.HumansCountText.Text);
        Assert.Equal(Visibility.Visible, harness.Window.HumansEmptyText.Visibility);
        Assert.Equal(HumansPageLogic.NothingWaitingHint, harness.Window.WaitingHint.Text);
    }, _ => { }, operatorGrant: false);

    [Fact]
    public void MessageFromAnAgent_WhileAnotherPageShowsRaisesTheBadgeUntilThePageIsOpened() => Run(async harness =>
    {
        var window = harness.Window;

        harness.Stream.Send(Human(10, HumansLogic.OperatorAuthor, "from my phone")).Send(Human(11, body: "are you there?"));
        await MonitorUiThread.Until(() => window.HumansCountText.Text == "5 messages", "both messages");

        Assert.Equal(Visibility.Visible, window.HumansBadge.Visibility);
        Assert.Equal("1", window.HumansBadgeText.Text);
        Assert.Equal(Visibility.Collapsed, window.HumansNewBar.Visibility);
        Assert.Equal([11L, 10L], harness.Feed.Take(2));

        await ShowHumansAsync(harness);

        Assert.Equal(Visibility.Collapsed, window.HumansBadge.Visibility);
        Assert.Equal([1L, 2L, 3L, 10L, 11L], Rows(window).Select(row => row.Message!.Seq));
    });

    [Fact]
    public void MessageArrivingWhileReadingTheEnd_IsFollowedAndRead() => Run(async harness =>
    {
        var window = harness.Window;
        await ShowHumansAsync(harness);
        var viewer = ScrollViewerOf(window.HumansList);
        Assert.True(viewer.ScrollableHeight > 0);
        Assert.InRange(viewer.VerticalOffset, viewer.ScrollableHeight - 2, viewer.ScrollableHeight);

        harness.Stream.Send(Human(61, body: "the newest"));
        await MonitorUiThread.Until(() => Rows(window).Count == 61, "the new message");
        await MonitorUiThread.Settle();
        window.UpdateLayout();

        Assert.Equal(Visibility.Collapsed, window.HumansNewBar.Visibility);
        Assert.Equal(Visibility.Collapsed, window.HumansBadge.Visibility);
        Assert.InRange(viewer.VerticalOffset, viewer.ScrollableHeight - 2, viewer.ScrollableHeight);
    }, LongConversation);

    [Fact]
    public void MessagesArrivingWhileReadingFurtherUp_AreCountedUntilJumpToLatest() => Run(async harness =>
    {
        var window = harness.Window;
        await ShowHumansAsync(harness);
        var viewer = ScrollViewerOf(window.HumansList);
        viewer.ScrollToTop();
        window.UpdateLayout();

        harness.Stream.Send(Human(61));
        await MonitorUiThread.Until(() => Rows(window).Count == 61, "the first new message");
        Assert.Equal(Visibility.Visible, window.HumansNewBar.Visibility);
        Assert.Equal("1 new message below.", window.HumansNewText.Text);
        Assert.Equal(Visibility.Visible, window.HumansBadge.Visibility);
        Assert.Equal(0, viewer.VerticalOffset);

        harness.Stream.Send(Human(62));
        await MonitorUiThread.Until(() => Rows(window).Count == 62, "the second new message");
        Assert.Equal("2 new messages below.", window.HumansNewText.Text);
        Assert.Equal("2", window.HumansBadgeText.Text);

        Click(window.HumansNewBar, "Jump to latest");
        await MonitorUiThread.Settle();
        window.UpdateLayout();

        Assert.Equal(Visibility.Collapsed, window.HumansNewBar.Visibility);
        Assert.Equal(Visibility.Collapsed, window.HumansBadge.Visibility);
        Assert.InRange(viewer.VerticalOffset, viewer.ScrollableHeight - 2, viewer.ScrollableHeight);
    }, LongConversation);

    [Fact]
    public void ScrollingToTheEnd_ReadsTheMessagesThatWereBelow() => Run(async harness =>
    {
        var window = harness.Window;
        await ShowHumansAsync(harness);
        var viewer = ScrollViewerOf(window.HumansList);
        viewer.ScrollToTop();
        window.UpdateLayout();
        harness.Stream.Send(Human(61));
        await MonitorUiThread.Until(() => window.HumansNewBar.Visibility == Visibility.Visible, "the new message bar");

        viewer.ScrollToVerticalOffset(viewer.ScrollableHeight / 2);
        window.UpdateLayout();
        Assert.Equal(Visibility.Visible, window.HumansNewBar.Visibility);

        viewer.ScrollToBottom();
        window.UpdateLayout();

        Assert.Equal(Visibility.Collapsed, window.HumansNewBar.Visibility);
        Assert.Equal(Visibility.Collapsed, window.HumansBadge.Visibility);
    }, LongConversation);

    [Fact]
    public void Conversation_KeepsTheNewestFiveHundredMessages() => Run(async harness =>
    {
        var window = harness.Window;
        Assert.Equal(200, Rows(window).Count);

        // The periodic snapshot check brings the rest in, a hundred at a time, until two are over the limit.
        var next = 201;
        foreach (var batch in new[] { 100, 100, 100, 2 })
        {
            harness.Bus.Messages.AddRange(Enumerable.Range(next, batch).Select(seq => Human(seq)));
            next += batch;
            await harness.ElapseAsync(FeedWait);
            await MonitorUiThread.Until(() => Rows(window)[^1].Message?.Seq == next - 1, $"messages up to {next - 1}");
        }

        Assert.Equal(HumansThread.Maximum, Rows(window).Count);
        Assert.Equal(3, Rows(window)[0].Message?.Seq);
        Assert.Equal("500 messages", window.HumansCountText.Text);
    }, bus =>
    {
        bus.Agents.Add(Agent("agent-one"));
        bus.Messages.AddRange(Enumerable.Range(1, 200).Select(seq => Human(seq)));
    }, operatorGrant: false);

    // ---- Waiting list ------------------------------------------------------------------------

    private static void Questions(MonitorFakeBus bus)
    {
        bus.Agents.AddRange([Agent("agent-one"), Agent("agent-two")]);
        bus.Messages.AddRange(
        [
            Human(1, body: "Which branch?", kind: "question"),
            Human(2, "agent-two", "Deploy now?", "question"),
            Human(3, body: "just chatting")
        ]);
    }

    [Fact]
    public void WaitingList_ShowsUnansweredQuestionsAndSelectingOneStartsAReply() => Run(async harness =>
    {
        var window = harness.Window;
        await ShowHumansAsync(harness);
        Assert.Equal([1L, 2L], Waiting(window).Select(entry => entry.Message.Seq));
        Assert.Equal("2", window.WaitingCountText.Text);
        Assert.Equal(Visibility.Visible, window.WaitingClearAll.Visibility);
        Assert.Equal(HumansPageLogic.WaitingHint, window.WaitingHint.Text);

        window.WaitingList.SelectedItem = Waiting(window)[1];

        Assert.Null(window.WaitingList.SelectedItem);
        Assert.Equal(2, (window.HumansList.SelectedItem as HumansEntry)?.Message?.Seq);
        Assert.Equal(Visibility.Visible, window.HumansReplyBanner.Visibility);
        Assert.Equal("Replying to agent-two: “Deploy now?”", window.HumansReplyText.Text);
        Assert.True(window.HumansKindAnswer.IsChecked);
        Assert.Equal(2, Waiting(window).Count);
    }, Questions);

    [Fact]
    public void WaitingList_ClearRemovesAQuestionForGood() => Run(async harness =>
    {
        var window = harness.Window;
        await ShowHumansAsync(harness);

        harness.InvokeRowHandler("WaitingClear_Click", "not a waiting row");
        Assert.Equal(2, Waiting(window).Count);
        harness.InvokeRowHandler("WaitingClear_Click", Waiting(window)[0]);

        Assert.Equal([2L], Waiting(window).Select(entry => entry.Message.Seq));
        Assert.Equal("1", window.WaitingCountText.Text);
        Assert.Equal(Visibility.Collapsed, window.WaitingClearAll.Visibility);
        Assert.Equal([1L], AppSettings.Load().ClearedWaiting);
        Assert.Equal(3, Rows(window).Count);
    }, Questions);

    [Fact]
    public void WaitingList_ClearAllEmptiesIt() => Run(async harness =>
    {
        var window = harness.Window;
        await ShowHumansAsync(harness);

        Click(window.WaitingClearAll);

        Assert.Empty(Waiting(window));
        Assert.Equal("0", window.WaitingCountText.Text);
        Assert.Equal(HumansPageLogic.NothingWaitingHint, window.WaitingHint.Text);
        Assert.Equal([1L, 2L], AppSettings.Load().ClearedWaiting);
    }, Questions);

    [Fact]
    public void WaitingList_GainsAQuestionThatArrivesLater() => Run(async harness =>
    {
        var window = harness.Window;
        await ShowHumansAsync(harness);

        harness.Stream.Send(Human(9, "agent-two", "And this one?", "question"));
        await MonitorUiThread.Until(() => Waiting(window).Count == 3, "the new question");

        Assert.Equal("And this one?", Waiting(window)[2].Snippet);
        Assert.Equal("3", window.WaitingCountText.Text);
    }, Questions);

    // ---- Composer and mentions ---------------------------------------------------------------

    [Fact]
    public void TypingAnAtSign_OffersTheAgentsThatCanBeMentioned() => Run(async harness =>
    {
        var window = harness.Window;
        await ShowHumansAsync(harness);

        Type(window, "hi @");

        Assert.Equal("4 / 4000", window.HumansCharCount.Text);
        Assert.True(window.MentionPopup.IsOpen);
        Assert.Equal("MENTION AN AGENT", window.MentionHeader.Text);
        Assert.Equal(["@agent-one", "@agent-two", "@everyone"], Mentions(window));
        Assert.Equal(0, window.MentionList.SelectedIndex);

        Type(window, "hi @agent-t");
        Assert.Equal("AGENTS MATCHING “agent-t”", window.MentionHeader.Text);
        Assert.Equal(["@agent-two"], Mentions(window));

        Type(window, "hi @zz");
        Assert.False(window.MentionPopup.IsOpen);
        Assert.Empty(Mentions(window));

        Type(window, "hi there");
        Assert.False(window.MentionPopup.IsOpen);
    });

    [Fact]
    public void MentionPopup_ArrowKeysWrapAndTabInsertsTheSelectedAgent() => Run(async harness =>
    {
        var window = harness.Window;
        await ShowHumansAsync(harness);
        Type(window, "hi @");

        harness.PressKey(window.HumansComposer, Key.Up);
        Assert.Equal(2, window.MentionList.SelectedIndex);
        harness.PressKey(window.HumansComposer, Key.Down);
        Assert.Equal(0, window.MentionList.SelectedIndex);
        harness.PressKey(window.HumansComposer, Key.Down);
        Assert.Equal(1, window.MentionList.SelectedIndex);

        harness.PressKey(window.HumansComposer, Key.Tab);

        Assert.Equal("hi @agent-two ", window.HumansComposer.Text);
        Assert.Equal(14, window.HumansComposer.CaretIndex);
        Assert.False(window.MentionPopup.IsOpen);
    });

    [Fact]
    public void MentionPopup_EnterInsertsInsteadOfSending() => Run(async harness =>
    {
        var window = harness.Window;
        await ShowHumansAsync(harness);
        Type(window, "@agent-o");

        harness.PressKey(window.HumansComposer, Key.Enter);

        Assert.Equal("@agent-one ", window.HumansComposer.Text);
        Assert.Equal(0, harness.Bus.RequestCount(HumansLogic.PostPath));
        Assert.DoesNotContain(Rows(window), row => row.Outgoing is not null);
    });

    [Fact]
    public void MentionPopup_EscapeKeepsItClosedForThatMentionOnly() => Run(async harness =>
    {
        var window = harness.Window;
        await ShowHumansAsync(harness);
        Type(window, "@ag");
        Assert.True(window.MentionPopup.IsOpen);

        harness.PressKey(window.HumansComposer, Key.Escape);
        Assert.False(window.MentionPopup.IsOpen);
        TypeInto(window.HumansComposer, "e");
        Assert.Equal("@age", window.HumansComposer.Text);
        Assert.False(window.MentionPopup.IsOpen);

        TypeInto(window.HumansComposer, " and @");
        Assert.True(window.MentionPopup.IsOpen);
    });

    [Fact]
    public void MentionPopup_ClosesWhenTheComposerLosesTheKeyboard() => Run(async harness =>
    {
        var window = harness.Window;
        await ShowHumansAsync(harness);
        Type(window, "@");
        Assert.True(window.MentionPopup.IsOpen);

        window.HumansSendButton.Focus();

        Assert.False(window.MentionPopup.IsOpen);
        window.HumansComposer.Text = "@a";
        window.HumansComposer.CaretIndex = 2;
        Assert.False(window.MentionPopup.IsOpen);
    });

    [Fact]
    public void MentionPopup_ClickingARowInsertsItAndKeepsTheKeyboardInTheComposer() => Run(async harness =>
    {
        var window = harness.Window;
        await ShowHumansAsync(harness);
        Type(window, "ping @");

        Assert.True(PressOn(window.MentionList, window.MentionList));
        Assert.Equal("ping @", window.HumansComposer.Text);

        var everyone = window.MentionList.Items.Cast<MentionRow>().Last();
        Assert.True(PressRow(window.MentionList, everyone));

        Assert.Equal("ping @everyone ", window.HumansComposer.Text);
        Assert.False(window.MentionPopup.IsOpen);
        Assert.True(window.HumansComposer.IsKeyboardFocused);
    });

    [Fact]
    public void MentionPopup_FollowsTheAgentListWhileOpen() => Run(async harness =>
    {
        var window = harness.Window;
        await ShowHumansAsync(harness);
        Type(window, "@");
        harness.PressKey(window.HumansComposer, Key.Down);

        harness.Bus.Agents.Add(Agent("agent-three"));
        await harness.ElapseAsync(DirectoryWait);
        await MonitorUiThread.Until(() => Mentions(window).Count == 4, "the new agent in the mention list");

        Assert.Equal(["@agent-one", "@agent-three", "@agent-two", "@everyone"], Mentions(window));
        Assert.Equal("@agent-two", (window.MentionList.SelectedItem as MentionRow)?.Display);
        Assert.True(window.MentionPopup.IsOpen);
    });

    // ---- Sending -----------------------------------------------------------------------------

    [Fact]
    public void Enter_SendsTheMessageAndShowsItAsSendingUntilTheBusAnswers() => Run(async harness =>
    {
        var window = harness.Window;
        await ShowHumansAsync(harness);
        var release = harness.Bus.Hold(HumansLogic.PostPath);
        Type(window, "  hello there  ");

        harness.PressKey(window.HumansComposer, Key.Enter);

        Assert.Equal(string.Empty, window.HumansComposer.Text);
        var sending = Rows(window)[^1];
        Assert.Equal("sending…", sending.StateLabel);
        Assert.Equal("hello there", sending.Body);
        Assert.Equal("3 messages", window.HumansCountText.Text);

        release();
        await MonitorUiThread.Until(() => Rows(window)[^1].Message is not null, "the post to be confirmed");

        var post = Assert.Single(harness.Bus.Posts);
        Assert.Equal("hello there", post.GetProperty("body").GetString());
        Assert.Equal("chat", post.GetProperty("kind").GetString());
        Assert.Equal("grant-secret", post.GetProperty("grant_secret").GetString());
        Assert.False(post.TryGetProperty("reply_to", out _));
        Assert.Equal(4, Rows(window).Count);
        Assert.Equal("You", Rows(window)[^1].AuthorLabel);
        Assert.Equal("4 messages", window.HumansCountText.Text);
        Assert.Equal(5, harness.Feed.First());
        Assert.Equal(Visibility.Collapsed, window.HumansBadge.Visibility);
    });

    [Fact]
    public void SendButton_PostsAReplyAsAnAnswerAndTheQuestionStopsWaiting() => Run(async harness =>
    {
        var window = harness.Window;
        await ShowHumansAsync(harness);
        Assert.Single(Waiting(window));

        harness.InvokeRowHandler("HumansReply_Click", Rows(window)[2]);
        Assert.Equal("Replying to agent-two: “Which branch should I use?”", window.HumansReplyText.Text);
        Assert.True(window.HumansKindAnswer.IsChecked);
        Type(window, "Use main.");
        Click(window.HumansSendButton);

        Assert.Equal(Visibility.Collapsed, window.HumansReplyBanner.Visibility);
        Assert.True(window.HumansKindChat.IsChecked);
        Assert.Equal("replying to agent-two: “Which branch should I use?”", Rows(window)[^1].ReplyContext);

        await MonitorUiThread.Until(() => Waiting(window).Count == 0, "the question to stop waiting");
        var post = Assert.Single(harness.Bus.Posts);
        Assert.Equal("answer", post.GetProperty("kind").GetString());
        Assert.Equal(3, post.GetProperty("reply_to").GetInt64());
    });

    [Fact]
    public void Reply_KeepsTheChosenKindUnlessTheTargetIsAQuestion() => Run(async harness =>
    {
        var window = harness.Window;
        await ShowHumansAsync(harness);

        harness.InvokeRowHandler("HumansReply_Click", Rows(window)[0]);
        Assert.True(window.HumansKindChat.IsChecked);
        Assert.Equal(Visibility.Visible, window.HumansReplyBanner.Visibility);

        window.HumansKindQuestion.IsChecked = true;
        harness.InvokeRowHandler("HumansReply_Click", Rows(window)[0]);
        Assert.True(window.HumansKindQuestion.IsChecked);

        window.HumansKindAnswer.IsChecked = true;
        harness.InvokeRowHandler("HumansReply_Click", Rows(window)[0]);
        Assert.True(window.HumansKindAnswer.IsChecked);

        Click(window.HumansReplyBanner, "Cancel reply");
        Assert.Equal(Visibility.Collapsed, window.HumansReplyBanner.Visibility);
        Assert.Equal(string.Empty, window.HumansReplyText.Text);

        harness.InvokeRowHandler("HumansReply_Click", "not a message row");
        Assert.Equal(Visibility.Collapsed, window.HumansReplyBanner.Visibility);
    });

    [Fact]
    public void Send_AsAQuestionExpandsEveryoneIntoTheActiveAgents() => Run(async harness =>
    {
        var window = harness.Window;
        await ShowHumansAsync(harness);
        window.HumansKindQuestion.IsChecked = true;
        Type(window, "status @everyone?");

        harness.PressKey(window.HumansComposer, Key.Enter);
        await MonitorUiThread.Until(() => harness.Bus.Posts.Count == 1, "the post");

        Assert.Equal("status @agent-one?", harness.Bus.Posts[0].GetProperty("body").GetString());
        Assert.Equal("question", harness.Bus.Posts[0].GetProperty("kind").GetString());
    });

    [Fact]
    public void Send_WithOnlySpacesDoesNothing() => Run(async harness =>
    {
        var window = harness.Window;
        await ShowHumansAsync(harness);
        Type(window, "   ");

        harness.PressKey(window.HumansComposer, Key.Enter);

        Assert.Equal("   ", window.HumansComposer.Text);
        Assert.Equal(3, Rows(window).Count);
        Assert.Equal(string.Empty, harness.Notice);
    });

    [Fact]
    public void Send_ThatGrowsPastTheLimitWhenEveryoneIsExpandedIsRefused() => Run(async harness =>
    {
        var window = harness.Window;
        await ShowHumansAsync(harness);
        var text = new string('a', 3985) + " @everyone";
        Type(window, text);

        Click(window.HumansSendButton);

        Assert.Equal("Messages are limited to 4000 characters once @everyone is expanded into agent names.", harness.Notice);
        Assert.Equal(text, window.HumansComposer.Text);
        Assert.Equal(3, Rows(window).Count);
    }, bus =>
    {
        Conversation(bus);
        bus.Agents.AddRange([Agent("agent-three"), Agent("agent-four")]);
    });

    [Fact]
    public void Send_WithoutOperatorAccessPointsToTheAdminPage() => Run(async harness =>
    {
        var window = harness.Window;
        await ShowHumansAsync(harness);
        Type(window, "hello");

        harness.PressKey(window.HumansComposer, Key.Enter);

        Assert.Equal("Save operator access on the Admin page once before posting to #humans.", harness.Notice);
        Assert.Equal("Open Admin", window.NoticeActionButton.Content);
        Assert.Equal("hello", window.HumansComposer.Text);
        Assert.Equal(0, harness.Bus.RequestCount(HumansLogic.PostPath));

        Click(window.NoticeActionButton);

        Assert.True(window.AdminNav.IsChecked);
        Assert.Equal(Visibility.Visible, window.AdminPage.Visibility);
    }, operatorGrant: false);

    // ---- Failed posts ------------------------------------------------------------------------

    private static async Task<HumansEntry> SendFailingAsync(MonitorWindowHarness harness, int status, string detail)
    {
        var window = harness.Window;
        await ShowHumansAsync(harness);
        harness.Bus.Fail(HumansLogic.PostPath, status, detail);
        Type(window, "will not arrive");
        harness.PressKey(window.HumansComposer, Key.Enter);
        await MonitorUiThread.Until(() => Rows(window)[^1].StateLabel == "not sent", "the post to fail");
        return Rows(window)[^1];
    }

    [Fact]
    public void FailedPost_CanBeRetriedOnceTheBusIsBack() => Run(async harness =>
    {
        var window = harness.Window;
        var failed = await SendFailingAsync(harness, 503, "Out of disk.");
        Assert.Equal("StruggleBus refused the post: Out of disk.", failed.Error);
        Assert.Equal(Visibility.Visible, failed.RetryVisibility);
        Assert.Equal(4, Rows(window).Count);

        harness.Bus.StopFailing(HumansLogic.PostPath);
        harness.InvokeRowHandler("HumansRetry_Click", failed);
        Assert.Equal("sending…", Rows(window)[^1].StateLabel);
        Assert.Equal(4, Rows(window).Count);
        await MonitorUiThread.Until(() => Rows(window)[^1].Message is not null, "the retry to be confirmed");

        Assert.Equal(4, Rows(window).Count);
        Assert.Equal("will not arrive", Assert.Single(harness.Bus.Posts).GetProperty("body").GetString());
        Assert.Equal(failed.Outgoing!.RequestId, harness.Bus.Posts[0].GetProperty("request_id").GetString());
    });

    [Fact]
    public void FailedPost_WhenTheBusIsUnreachableSaysSo() => Run(async harness =>
    {
        var failed = await SendFailingAsync(harness, 0, "No route to host.");

        Assert.StartsWith("Unable to reach StruggleBus:", failed.Error);
        Assert.True(failed.Outgoing!.Retryable);
    });

    [Fact]
    public void FailedPost_AfterAccessWasRevokedForgetsTheGrantAndRetryAsksForItAgain() => Run(async harness =>
    {
        var window = harness.Window;
        var failed = await SendFailingAsync(harness, 401, "Grant is not valid.");

        Assert.StartsWith("Operator access was revoked or replaced.", failed.Error);
        Assert.Equal(HumansPageLogic.CannotPostNotice, window.HumansNotice.Text);
        Assert.StartsWith("Not set up yet.", window.GrantStatusText.Text);

        harness.InvokeRowHandler("HumansRetry_Click", failed);

        Assert.Equal("Save operator access on the Admin page, then retry.", harness.Notice);
        Assert.Equal("not sent", Rows(window)[^1].StateLabel);
        Assert.Equal(1, harness.Bus.RequestCount(HumansLogic.PostPath));
    });

    [Fact]
    public void FailedPost_ThatCannotBeRetriedCanOnlyBeDiscardedBackIntoTheComposer() => Run(async harness =>
    {
        var window = harness.Window;
        var failed = await SendFailingAsync(harness, 409, "Duplicate request.");
        Assert.Equal(Visibility.Collapsed, failed.RetryVisibility);
        Assert.Equal(Visibility.Visible, failed.DiscardVisibility);

        harness.InvokeRowHandler("HumansRetry_Click", failed);
        Assert.Equal(1, harness.Bus.RequestCount(HumansLogic.PostPath));
        harness.InvokeRowHandler("HumansDiscard_Click", Rows(window)[0]);
        Assert.Equal(4, Rows(window).Count);

        harness.InvokeRowHandler("HumansDiscard_Click", failed);

        Assert.Equal(3, Rows(window).Count);
        Assert.Equal("will not arrive", window.HumansComposer.Text);
    });

    [Fact]
    public void FailedPost_DiscardLeavesADraftInTheComposerAlone() => Run(async harness =>
    {
        var window = harness.Window;
        var failed = await SendFailingAsync(harness, 413, "Too large.");
        Assert.Equal("The message is too long for the server.", failed.Error);
        Type(window, "a new draft");

        harness.InvokeRowHandler("HumansDiscard_Click", failed);

        Assert.Equal("a new draft", window.HumansComposer.Text);
        Assert.DoesNotContain(Rows(window), row => row.Outgoing is not null);
    });

    [Fact]
    public void MessagesArrivingWhileAPostIsUnsent_GoAboveIt() => Run(async harness =>
    {
        var window = harness.Window;
        await SendFailingAsync(harness, 503, "Out of disk.");

        harness.Stream.Send(Human(20, body: "meanwhile"));
        await MonitorUiThread.Until(() => Rows(window).Count == 5, "the streamed message");

        Assert.Equal(20, Rows(window)[3].Message?.Seq);
        Assert.Equal("not sent", Rows(window)[4].StateLabel);
    });

    [Fact]
    public void Copy_TakesTheMessageBody() => Run(async harness =>
    {
        await ShowHumansAsync(harness);
        var row = Rows(harness.Window)[2];

        harness.InvokeRowHandler("CopyHumans_Click", "not a message row");
        harness.InvokeRowHandler("CopyHumans_Click", row);

        Assert.Equal(["Which branch should I use?"], harness.Copied);
    });
}
