using System.IO;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Channels;
using System.Web;

namespace StruggleBusMonitor.Tests;

/// <summary>
/// An in-memory StruggleBus. It answers the requests <see cref="BusApi"/> makes from what the test
/// put in <see cref="Messages"/>, <see cref="Agents"/> and <see cref="Channels"/>, so a window under
/// test never opens a socket.
/// </summary>
internal sealed class MonitorFakeBus : HttpMessageHandler
{
    private readonly object _gate = new();
    private readonly List<(string Match, int Status, string Detail)> _failures = [];
    private readonly List<(string Match, TaskCompletionSource Release)> _holds = [];
    private readonly Queue<MonitorFakeStream> _scriptedStreams = new();
    private readonly List<string> _requests = [];
    private readonly List<JsonElement> _posts = [];
    private readonly List<MonitorFakeStream> _streams = [];

    public List<BusMessage> Messages { get; } = [];
    public List<BusAgent> Agents { get; } = [];
    public List<string> Channels { get; } = [];
    public string State { get; set; } = "normal";

    /// <summary>False behaves like a bus older than the history and search reads.</summary>
    public bool HistorySupported { get; set; } = true;

    /// <summary>What a full-text search returns; by default the messages whose body contains the query.</summary>
    public Func<string, IEnumerable<BusMessage>>? Search { get; set; }

    public IReadOnlyList<string> Requests { get { lock (_gate) return _requests.ToList(); } }
    public IReadOnlyList<JsonElement> Posts { get { lock (_gate) return _posts.ToList(); } }

    /// <summary>Every stream connection made so far, oldest first.</summary>
    public IReadOnlyList<MonitorFakeStream> Streams { get { lock (_gate) return _streams.ToList(); } }

    public int RequestCount(string match) => Requests.Count(request => request.Contains(match, StringComparison.Ordinal));

    /// <summary>
    /// The app's real API client, reading the enrollment from the test data folder as the app does,
    /// with every request it makes answered by this fake.
    /// </summary>
    public BusApi CreateApi() => new(AppPaths.DataDirectory, _ => this);

    /// <summary>Requests whose path and query contain <paramref name="match"/> fail with this status; 0 fails like a dropped connection.</summary>
    public void Fail(string match, int status, string detail = "The fake bus refused this request.")
    {
        lock (_gate) _failures.Add((match, status, detail));
    }

    public void StopFailing(string match)
    {
        lock (_gate) _failures.RemoveAll(failure => failure.Match == match);
    }

    /// <summary>Requests whose path and query contain <paramref name="match"/> wait until the returned action is called.</summary>
    public Action Hold(string match)
    {
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        lock (_gate) _holds.Add((match, release));
        return () =>
        {
            lock (_gate) _holds.RemoveAll(hold => hold.Release == release);
            release.TrySetResult();
        };
    }

    /// <summary>The next stream connection gets this stream instead of a new idle one.</summary>
    public MonitorFakeStream ScriptStream(MonitorFakeStream stream)
    {
        lock (_gate) _scriptedStreams.Enqueue(stream);
        return stream;
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        // Never answer inline: the real bus cannot either, and callers rely on that when they start up.
        await Task.Yield();
        var target = request.RequestUri!.PathAndQuery.TrimStart('/');
        var body = request.Content is null ? null : await request.Content.ReadAsStringAsync(cancellationToken);
        Task? hold;
        (string Match, int Status, string Detail)? failure;
        lock (_gate)
        {
            _requests.Add($"{request.Method} {target}");
            hold = _holds.Where(item => target.Contains(item.Match, StringComparison.Ordinal)).Select(item => item.Release.Task).FirstOrDefault();
            failure = _failures.Where(item => target.Contains(item.Match, StringComparison.Ordinal)).Select(item => ((string, int, string)?)item).FirstOrDefault();
        }
        if (hold is not null) await hold.WaitAsync(cancellationToken);
        if (failure is { } failed)
        {
            if (failed.Status == 0) throw new HttpRequestException(failed.Detail);
            return Json((HttpStatusCode)failed.Status, new { detail = failed.Detail });
        }
        return Route(request.Method, target, body);
    }

    private HttpResponseMessage Route(HttpMethod method, string target, string? body)
    {
        var path = target.Split('?')[0];
        var query = HttpUtility.ParseQueryString(target.Contains('?') ? target[(target.IndexOf('?') + 1)..] : string.Empty);
        lock (_gate)
        {
            return path switch
            {
                "api/mobile/snapshot" => Json(HttpStatusCode.OK, Snapshot(query["channel"], query["agent"], int.Parse(query["limit"]!)).Select(Wire)),
                "api/mobile/agents" => Json(HttpStatusCode.OK, Agents.Select(agent => new { id = agent.Id, name = agent.Name, description = agent.Description, host = agent.Host, last_seen_at = agent.LastSeenAt })),
                "api/mobile/status" => Json(HttpStatusCode.OK, new { api_version = 1, state = State }),
                "api/mobile/channels" => Json(HttpStatusCode.OK, Channels.Select(name => new { id = "channel-" + name, name, purpose = string.Empty })),
                "api/mobile/search" => SearchResponse(query["query"]!),
                "api/mobile/stream" => StreamResponse(),
                HumansLogic.PostPath when method == HttpMethod.Post => PostResponse(body!),
                _ => Json(HttpStatusCode.NotFound, new { detail = "Not found" })
            };
        }
    }

    private List<BusMessage> Snapshot(string? channel, string? agent, int limit) =>
        Messages
            .Where(message => channel is null || message.Channel == channel)
            .Where(message => agent is null || message.AgentName == agent)
            .OrderBy(message => message.Seq)
            .TakeLast(limit)
            .ToList();

    private HttpResponseMessage SearchResponse(string text)
    {
        if (!HistorySupported) return Json(HttpStatusCode.NotFound, new { detail = "Not found" });
        var hits = Search?.Invoke(text) ?? Messages.Where(message => message.Body.Contains(text, StringComparison.OrdinalIgnoreCase)).OrderByDescending(message => message.Seq);
        return Json(HttpStatusCode.OK, hits.Select(Wire));
    }

    private HttpResponseMessage PostResponse(string body)
    {
        using var document = JsonDocument.Parse(body);
        var post = document.RootElement.Clone();
        _posts.Add(post);
        var message = new BusMessage(
            Messages.Select(item => item.Seq).DefaultIfEmpty().Max() + 1,
            HumansLogic.Channel,
            HumansLogic.OperatorAuthor,
            post.GetProperty("body").GetString()!,
            post.GetProperty("kind").GetString()!,
            DateTimeOffset.Now,
            post.TryGetProperty("reply_to", out var replyTo) ? replyTo.GetInt64() : null);
        Messages.Add(message);
        return Json(HttpStatusCode.OK, Wire(message));
    }

    private HttpResponseMessage StreamResponse()
    {
        var stream = _scriptedStreams.Count > 0 ? _scriptedStreams.Dequeue() : new MonitorFakeStream();
        _streams.Add(stream);
        if (stream.Status != HttpStatusCode.OK)
        {
            var refused = Json(stream.Status, new { detail = stream.Detail });
            if (stream.RetryAfter is { } wait) refused.Headers.RetryAfter = new System.Net.Http.Headers.RetryConditionHeaderValue(wait);
            return refused;
        }
        return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StreamContent(stream) };
    }

    internal static object Wire(BusMessage message) => new
    {
        seq = message.Seq,
        channel = message.Channel,
        agent_name = message.AgentName,
        body = message.Body,
        kind = message.Kind,
        created_at = message.CreatedAt,
        reply_to = message.ReplyTo
    };

    private static HttpResponseMessage Json(HttpStatusCode status, object value) =>
        new(status) { Content = new StringContent(JsonSerializer.Serialize(value), Encoding.UTF8, "application/json") };
}

/// <summary>
/// One connection to the fake bus's live stream. By default it opens and stays quiet until the
/// window stops listening; a test can push messages down it, end it, or have it refuse to open.
/// </summary>
internal sealed class MonitorFakeStream : Stream
{
    private readonly Channel<byte[]> _chunks = Channel.CreateUnbounded<byte[]>();
    private byte[] _current = [];
    private int _offset;

    public HttpStatusCode Status { get; private init; } = HttpStatusCode.OK;
    public string Detail { get; private init; } = string.Empty;
    public TimeSpan? RetryAfter { get; private init; }

    /// <summary>True once the window has started reading, which is after it was told the stream is open.</summary>
    public bool Reading { get; private set; }

    public static MonitorFakeStream Refused(int status, string detail = "refused", TimeSpan? retryAfter = null) =>
        new() { Status = (HttpStatusCode)status, Detail = detail, RetryAfter = retryAfter };

    public MonitorFakeStream Send(BusMessage message) => Event("message", JsonSerializer.Serialize(MonitorFakeBus.Wire(message)));

    public MonitorFakeStream Event(string name, string data)
    {
        _chunks.Writer.TryWrite(Encoding.UTF8.GetBytes($"event: {name}\ndata: {data}\n\n"));
        return this;
    }

    /// <summary>The bus closes the connection in the ordinary way.</summary>
    public MonitorFakeStream End()
    {
        _chunks.Writer.TryComplete();
        return this;
    }

    /// <summary>The connection drops while the window is reading.</summary>
    public MonitorFakeStream Break(string reason)
    {
        _chunks.Writer.TryComplete(new IOException(reason));
        return this;
    }

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        Reading = true;
        if (_offset >= _current.Length)
        {
            if (!await _chunks.Reader.WaitToReadAsync(cancellationToken)) return 0;
            _chunks.Reader.TryRead(out _current!);
            _offset = 0;
        }
        var count = Math.Min(buffer.Length, _current.Length - _offset);
        _current.AsMemory(_offset, count).CopyTo(buffer);
        _offset += count;
        return count;
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override int Read(byte[] buffer, int offset, int count) =>
        ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
    public override void Flush() { }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}

/// <summary>
/// Stands in for the waits in the window's background loops. Nothing passes until the test says so,
/// so the loops can be stepped through one wait at a time without real time going by.
/// </summary>
internal sealed class MonitorFakePauses
{
    private readonly object _gate = new();
    private readonly List<(TimeSpan Duration, TaskCompletionSource Done)> _waiting = [];

    public Task Pause(TimeSpan duration, CancellationToken cancellationToken)
    {
        if (cancellationToken.IsCancellationRequested) return Task.FromCanceled(cancellationToken);
        var done = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        lock (_gate) _waiting.Add((duration, done));
        cancellationToken.Register(() =>
        {
            lock (_gate) _waiting.RemoveAll(item => item.Done == done);
            done.TrySetCanceled(cancellationToken);
        });
        return done.Task;
    }

    public bool IsWaiting(TimeSpan duration)
    {
        lock (_gate) return _waiting.Any(item => item.Duration == duration);
    }

    public IReadOnlyList<TimeSpan> Waiting { get { lock (_gate) return _waiting.Select(item => item.Duration).ToList(); } }

    /// <summary>Lets the oldest wait of this length finish, as if that much time had passed.</summary>
    public void Elapse(TimeSpan duration)
    {
        TaskCompletionSource done;
        lock (_gate)
        {
            var index = _waiting.FindIndex(item => item.Duration == duration);
            if (index < 0) throw new InvalidOperationException($"Nothing is waiting {duration}. Waiting: {string.Join(", ", _waiting.Select(item => item.Duration))}");
            done = _waiting[index].Done;
            _waiting.RemoveAt(index);
        }
        done.TrySetResult();
    }
}
