namespace StruggleBusMonitor.Tests;

public sealed class MonitorStreamTrackerTests
{
    private static readonly DateTimeOffset Now = new(2025, 6, 1, 12, 0, 0, TimeSpan.Zero);

    private static StreamEnd End(StreamEndKind kind, string detail = "detail", TimeSpan? retryAfter = null) => new(kind, detail, retryAfter);

    [Fact]
    public void OnEnd_RoutineClosureRetriesQuietlyAndLeavesTheStatusAlone()
    {
        var step = new MonitorStreamTracker().OnEnd(End(StreamEndKind.RoutineClosure));

        Assert.Equal(StreamDisposition.RetryQuietly, step.Disposition);
        Assert.Equal(TimeSpan.FromSeconds(1), step.Delay);
        Assert.Null(step.Status);
        Assert.Null(step.Notice);
        Assert.False(step.Stops);
    }

    [Fact]
    public void OnEnd_RateLimitedShowsWaitingForAsLongAsTheBusAsked()
    {
        var step = new MonitorStreamTracker().OnEnd(End(StreamEndKind.RateLimited, "slow down", TimeSpan.FromSeconds(42)));

        Assert.Equal(StreamDisposition.RetryQuietly, step.Disposition);
        Assert.Equal(TimeSpan.FromSeconds(42), step.Delay);
        Assert.Equal(new StatusDisplay("WAITING", "slow down", "Warn"), step.Status);
    }

    [Fact]
    public void OnEnd_FrozenShowsFrozen()
    {
        var step = new MonitorStreamTracker().OnEnd(End(StreamEndKind.AccessFrozen, "frozen by operator"));

        Assert.Equal(StreamDisposition.RetryFrozen, step.Disposition);
        Assert.Equal(new StatusDisplay("FROZEN", "frozen by operator", "Bad"), step.Status);
    }

    [Fact]
    public void OnEnd_RepeatedUnavailabilityBacksOffAndARoutineClosureResetsIt()
    {
        var tracker = new MonitorStreamTracker();

        var first = tracker.OnEnd(End(StreamEndKind.AccessUnavailable, "down"));
        var second = tracker.OnEnd(End(StreamEndKind.ServerStopping));
        var third = tracker.OnEnd(End(StreamEndKind.AccessUnavailable));
        tracker.OnEnd(End(StreamEndKind.RoutineClosure));
        var afterReset = tracker.OnEnd(End(StreamEndKind.AccessUnavailable));

        Assert.Equal(StreamDisposition.RetryDegraded, first.Disposition);
        Assert.Equal(new StatusDisplay("RECONNECTING", "down", "Warn"), first.Status);
        Assert.Equal(TimeSpan.FromSeconds(2), first.Delay);
        Assert.Equal(TimeSpan.FromSeconds(4), second.Delay);
        Assert.Equal(TimeSpan.FromSeconds(8), third.Delay);
        Assert.Equal(TimeSpan.FromSeconds(2), afterReset.Delay);
    }

    [Fact]
    public void OnEnd_ServerStoppingSaysTheBusIsRestarting()
    {
        var step = new MonitorStreamTracker().OnEnd(End(StreamEndKind.ServerStopping, "bye"));

        Assert.Equal(StreamDisposition.RetryStopping, step.Disposition);
        Assert.Equal(new StatusDisplay("RECONNECTING", MonitorStreamTracker.RestartingDetail, "Warn"), step.Status);
    }

    [Fact]
    public void OnEnd_ProtocolFailureExplainsOnceThenOnlyShowsReconnecting()
    {
        var tracker = new MonitorStreamTracker();

        var first = tracker.OnEnd(End(StreamEndKind.ProtocolFailure, "Unknown event."));
        var second = tracker.OnEnd(End(StreamEndKind.ProtocolFailure, "Unknown event."));

        Assert.Equal(StreamDisposition.RetryProtocol, first.Disposition);
        Assert.Equal(TimeSpan.FromSeconds(60), first.Delay);
        Assert.Equal(new StatusDisplay("RECONNECTING", "Unknown event.", "Warn"), first.Status);
        Assert.Equal("Unknown event." + MonitorStreamTracker.ProtocolAdvice, first.Notice);
        Assert.Null(second.Notice);
        Assert.NotNull(second.Status);
    }

    [Fact]
    public void OnEnd_RevokedCredentialStopsTheLoop()
    {
        var step = new MonitorStreamTracker().OnEnd(End(StreamEndKind.CredentialInactive));

        Assert.True(step.Stops);
        Assert.Null(step.Status);
        Assert.Null(step.Notice);
    }

    [Fact]
    public void OnError_BacksOffAndSharesTheCountWithStreamEndings()
    {
        var tracker = new MonitorStreamTracker();

        Assert.Equal(TimeSpan.FromSeconds(2), tracker.OnError());
        Assert.Equal(TimeSpan.FromSeconds(4), tracker.OnError());
        Assert.Equal(TimeSpan.FromSeconds(8), tracker.OnEnd(End(StreamEndKind.AccessUnavailable)).Delay);
        Assert.Equal(TimeSpan.FromSeconds(16), tracker.OnError());
    }

    [Fact]
    public void Report_WritesTheOutageToTheConnectionHistoryOnce()
    {
        var tracker = new ConnectionTracker();
        tracker.ReportUp(Now);

        var down = MonitorStreamTracker.Report(tracker, StreamDisposition.RetryDegraded, "no route", Now);
        var again = MonitorStreamTracker.Report(tracker, StreamDisposition.RetryProtocol, "no route", Now);

        Assert.Equal("Bad", down?.Tone);
        Assert.Contains("no route", down?.Text);
        Assert.Null(again);
        Assert.True(tracker.IsDown);
    }

    [Fact]
    public void Report_NotesAFreezeAndAnAnnouncedStop()
    {
        var frozen = MonitorStreamTracker.Report(new ConnectionTracker(), StreamDisposition.RetryFrozen, "x", Now);
        var stopping = MonitorStreamTracker.Report(new ConnectionTracker(), StreamDisposition.RetryStopping, "x", Now);

        Assert.Equal("Agent access is frozen on the bus.", frozen?.Text);
        Assert.Equal("Warn", stopping?.Tone);
    }

    [Fact]
    public void Report_HasNothingToSayForQuietRetriesOrRevocation()
    {
        var tracker = new ConnectionTracker();

        Assert.Null(MonitorStreamTracker.Report(tracker, StreamDisposition.RetryQuietly, "x", Now));
        Assert.Null(MonitorStreamTracker.Report(tracker, StreamDisposition.StopRevoked, "x", Now));
        Assert.False(tracker.IsDown);
    }
}
