namespace StruggleBusMonitor;

/// <summary>
/// What the stream loop does after one connection ended: how long to wait, what the status pill
/// shows (null leaves it alone) and a notice for the operator, if this ending needs one.
/// </summary>
internal sealed record StreamStep(StreamDisposition Disposition, TimeSpan Delay, StatusDisplay? Status, string? Notice)
{
    /// <summary>The credential was revoked: reconnecting cannot help, so the loops stop.</summary>
    public bool Stops => Disposition == StreamDisposition.StopRevoked;
}

/// <summary>
/// Remembers how one run of the live stream has been going, so repeated failures back off and the
/// "incompatible versions" notice is shown once rather than every minute. No UI types.
/// </summary>
internal sealed class MonitorStreamTracker
{
    public const string RestartingDetail = "The bus is restarting";
    public const string ProtocolAdvice = " The app and the bus may be on incompatible versions. Still trying every minute.";

    private int _failures;
    private bool _protocolNoticeShown;

    public StreamStep OnEnd(StreamEnd end)
    {
        if (end.Kind == StreamEndKind.RoutineClosure) _failures = 0;
        if (end.Kind is StreamEndKind.AccessUnavailable or StreamEndKind.ServerStopping) _failures++;
        var decision = MonitorLogic.DecideStreamEnd(end, _failures);
        return new StreamStep(decision.Disposition, decision.Delay, StatusFor(decision.Disposition, end), NoticeFor(decision.Disposition, end));
    }

    /// <summary>The connection attempt threw. Returns how long to wait before the next one.</summary>
    public TimeSpan OnError() => MonitorLogic.RetryDelay(++_failures);

    private static StatusDisplay? StatusFor(StreamDisposition disposition, StreamEnd end) => disposition switch
    {
        StreamDisposition.RetryQuietly => QuietStatus(end),
        StreamDisposition.RetryFrozen => new StatusDisplay("FROZEN", end.Detail, "Bad"),
        StreamDisposition.RetryStopping => new StatusDisplay("RECONNECTING", RestartingDetail, "Warn"),
        StreamDisposition.StopRevoked => null,
        _ => new StatusDisplay("RECONNECTING", end.Detail, "Warn")
    };

    /// <summary>A routine closure is not worth showing; being told to slow down is.</summary>
    private static StatusDisplay? QuietStatus(StreamEnd end) =>
        end.Kind == StreamEndKind.RateLimited ? new StatusDisplay("WAITING", end.Detail, "Warn") : null;

    private string? NoticeFor(StreamDisposition disposition, StreamEnd end)
    {
        if (disposition != StreamDisposition.RetryProtocol || _protocolNoticeShown) return null;
        _protocolNoticeShown = true;
        return end.Detail + ProtocolAdvice;
    }

    /// <summary>Tells the connection history what this ending means; null when there is nothing new to write down.</summary>
    public static ConnectionEvent? Report(ConnectionTracker tracker, StreamDisposition disposition, string detail, DateTimeOffset now) => disposition switch
    {
        StreamDisposition.RetryFrozen => tracker.ReportFrozen(now, true),
        StreamDisposition.RetryStopping => tracker.ReportStopping(now),
        StreamDisposition.RetryDegraded or StreamDisposition.RetryProtocol => tracker.ReportDown(now, detail),
        _ => null
    };
}
