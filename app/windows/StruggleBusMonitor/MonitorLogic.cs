using System.IO;
using System.Net.Http;

namespace StruggleBusMonitor;

internal enum StreamDisposition
{
    RetryQuietly,
    RetryDegraded,
    RetryFrozen,
    RetryStopping,
    RetryProtocol,
    StopRevoked
}

internal sealed record StreamDecision(StreamDisposition Disposition, TimeSpan Delay);

internal sealed class MonitorLifecycle
{
    private readonly SemaphoreSlim _gate = new(1, 1);
    private CancellationTokenSource? _cancellation;
    private Task[] _tasks = [];

    public int ActiveTaskCount => _tasks.Count(task => !task.IsCompleted);

    public async Task RestartAsync(Func<CancellationTokenSource, Task[]> start)
    {
        await _gate.WaitAsync();
        try
        {
            await StopCoreAsync();
            _cancellation = new CancellationTokenSource();
            _tasks = start(_cancellation);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task StopAsync()
    {
        await _gate.WaitAsync();
        try { await StopCoreAsync(); }
        finally { _gate.Release(); }
    }

    private async Task StopCoreAsync()
    {
        var cancellation = _cancellation;
        if (cancellation is null) return;
        _cancellation = null;
        cancellation.Cancel();
        try { await Task.WhenAll(_tasks); }
        catch (OperationCanceledException) { }
        finally
        {
            _tasks = [];
            cancellation.Dispose();
        }
    }
}

internal static class MonitorLogic
{
    public static StreamDecision DecideStreamEnd(StreamEnd end, int failures) => end.Kind switch
    {
        StreamEndKind.RoutineClosure => new(StreamDisposition.RetryQuietly, TimeSpan.FromSeconds(1)),
        StreamEndKind.RateLimited => new(StreamDisposition.RetryQuietly, end.RetryAfter ?? TimeSpan.FromSeconds(5)),
        StreamEndKind.AccessFrozen => new(StreamDisposition.RetryFrozen, TimeSpan.FromSeconds(5)),
        StreamEndKind.AccessUnavailable => new(StreamDisposition.RetryDegraded, RetryDelay(failures)),
        // A restart: the bus is usually back within seconds, so the first retries come quickly.
        StreamEndKind.ServerStopping => new(StreamDisposition.RetryStopping, RetryDelay(failures)),
        StreamEndKind.CredentialInactive => new(StreamDisposition.StopRevoked, TimeSpan.Zero),
        // An event this version does not know. Keep trying slowly: an update to either side fixes it.
        _ => new(StreamDisposition.RetryProtocol, TimeSpan.FromSeconds(60))
    };

    /// <summary>A failure that waiting can fix: the bus is down, restarting, busy or unreachable.</summary>
    public static bool IsTransient(Exception error) =>
        error is BusApiException api ? IsTransientStatus(api.StatusCode) : IsNetworkFailure(error);

    private static bool IsTransientStatus(int statusCode) => statusCode >= 500 || statusCode == 429;

    private static bool IsNetworkFailure(Exception error) =>
        error is HttpRequestException or IOException or TimeoutException or OperationCanceledException;

    public static TimeSpan RetryDelay(int failures) =>
        TimeSpan.FromSeconds(Math.Min(30, Math.Pow(2, Math.Clamp(failures - 1, 0, 4)) * 2));

    public static IReadOnlyList<BusMessage> FilterMessages(
        IEnumerable<BusMessage> messages,
        string? selectedChannel) =>
        (selectedChannel is null
            ? messages
            : messages.Where(message => message.Channel.Equals(selectedChannel, StringComparison.Ordinal)))
        .ToList();

    public static string? NormalizeChannelSelection(
        string? selectedChannel,
        IEnumerable<BusChannel> channels) =>
        selectedChannel is not null && channels.Any(channel => channel.Name == selectedChannel)
            ? selectedChannel
            : null;
}
