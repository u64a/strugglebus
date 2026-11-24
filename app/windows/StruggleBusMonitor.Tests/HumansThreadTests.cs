namespace StruggleBusMonitor.Tests;

public sealed class HumansThreadTests
{
    private static readonly DateTimeOffset Timestamp = new(2025, 1, 1, 0, 0, 0, TimeSpan.Zero);

    private static BusMessage Message(long seq, string agent = "agent-a", string channel = "humans", long? replyTo = null) =>
        new(seq, channel, agent, $"body {seq}", "chat", Timestamp, replyTo);

    [Fact]
    public void Record_FirstBatchSetsTheReadPositionAndCountsNothingAsNew()
    {
        var thread = new HumansThread();

        var change = thread.Record([Message(4), Message(2), Message(9, channel: "ops")]);

        Assert.Equal([2L, 4L], change.Added.Select(item => item.Message.Seq));
        Assert.Equal(0, change.Fresh);
        Assert.Equal(0, change.FreshFromAgents);
        Assert.Equal(4, thread.LastSeenSeq);
        Assert.Equal(2, thread.Count);
        Assert.Equal(0, thread.Unread);
    }

    [Fact]
    public void Record_EmptyFirstBatchStillCountsAsTheFirstLoad()
    {
        var thread = new HumansThread();

        thread.Record([]);
        var change = thread.Record([Message(1)]);

        Assert.Equal(0, thread.LastSeenSeq);
        Assert.Equal(1, change.Fresh);
        Assert.Equal(1, thread.Unread);
    }

    [Fact]
    public void Record_LaterBatchesCountNewMessagesAndThoseFromAgents()
    {
        var thread = new HumansThread();
        thread.Record([Message(1)]);

        var change = thread.Record([Message(1), Message(2), Message(3, HumansLogic.OperatorAuthor)]);

        Assert.Equal([2L, 3L], change.Added.Select(item => item.Message.Seq));
        Assert.Equal(2, change.Fresh);
        Assert.Equal(1, change.FreshFromAgents);
        Assert.Equal(1, thread.Unread);
    }

    [Fact]
    public void Record_PairsAReplyWithItsParentWhenLoaded()
    {
        var thread = new HumansThread();
        thread.Record([Message(1)]);

        var change = thread.Record([Message(3, replyTo: 2), Message(2, replyTo: 1), Message(4, replyTo: 77)]);

        Assert.Equal(1, change.Added[0].Parent?.Seq);
        Assert.Equal(2, change.Added[1].Parent?.Seq);
        Assert.Null(change.Added[2].Parent);
    }

    [Fact]
    public void Record_DropsTheOldestBeyondTheMaximum()
    {
        var thread = new HumansThread();
        thread.Record(Enumerable.Range(1, HumansThread.Maximum).Select(seq => Message(seq)));

        var change = thread.Record([Message(HumansThread.Maximum + 1), Message(HumansThread.Maximum + 2)]);

        Assert.Equal([1L, 2L], change.Trimmed);
        Assert.Equal(HumansThread.Maximum, thread.Count);
        Assert.Equal(3, thread.Messages.First().Seq);
    }

    [Fact]
    public void MarkRead_MovesTheReadPositionForwardOnly()
    {
        var thread = new HumansThread();
        thread.Record([Message(5)]);
        thread.Record([Message(8), Message(9)]);
        Assert.Equal(2, thread.Unread);

        thread.MarkRead();

        Assert.Equal(9, thread.LastSeenSeq);
        Assert.Equal(0, thread.Unread);
    }

    [Fact]
    public void MarkRead_OnAnEmptyThreadKeepsZero()
    {
        var thread = new HumansThread();

        thread.MarkRead();

        Assert.Equal(0, thread.LastSeenSeq);
    }

    [Fact]
    public void Reset_ForgetsEverythingSoTheNextBatchIsAFirstLoadAgain()
    {
        var thread = new HumansThread();
        thread.Record([Message(5)]);
        thread.Record([Message(6)]);

        thread.Reset();
        var change = thread.Record([Message(1)]);

        Assert.Equal(1, thread.Count);
        Assert.Equal(0, change.Fresh);
        Assert.Equal(1, thread.LastSeenSeq);
    }
}
