using System.Collections.Concurrent;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

namespace StruggleBusMonitor.Tests;

internal sealed record BusRequest(string Method, string Path, string Query, string Body)
{
    public string Route => $"{Method} {Path}";
}

internal sealed record BusReply(int Status, string Json);

/// <summary>
/// A stand-in StruggleBus on the loopback interface, speaking HTTPS with its own throwaway
/// certificate, so the window's real <see cref="BusApi"/> can be used unchanged and nothing leaves
/// this machine. Routes answer with canned JSON; every request is recorded.
/// </summary>
internal sealed class StaWindowAdminBus : IDisposable
{
    public const string DeviceId = "device-1";
    public const string DeviceLabel = "test-pc";

    private static readonly Lazy<X509Certificate2> SharedCertificate = new(CreateCertificate);
    private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource _stop = new();
    private readonly ConcurrentDictionary<string, Func<BusRequest, BusReply>> _routes = new();
    private readonly ConcurrentQueue<BusRequest> _requests = new();
    private readonly ConcurrentBag<TcpClient> _clients = [];

    public StaWindowAdminBus()
    {
        _listener.Start();
        BaseUrl = $"https://127.0.0.1:{((IPEndPoint)_listener.LocalEndpoint).Port}";
        On("GET /api/mobile/snapshot", _ => Ok(MessagesJson));
        On("GET /api/mobile/agents", _ => Ok(AgentsJson));
        On("GET /api/mobile/status", _ => Ok($$"""{"api_version":1,"state":"{{State}}"}"""));
        On("GET /api/mobile/channels", _ => Ok("""[{"id":"c1","name":"general","purpose":"Everything"}]"""));
        On("GET /api/mobile/search", _ => Ok("[]"));
        _ = AcceptAsync();
    }

    public string BaseUrl { get; }
    public byte[] CaDer => SharedCertificate.Value.RawData;
    public string State { get; set; } = "open";
    public string MessagesJson { get; set; } = "[]";
    public string AgentsJson { get; set; } = "[]";
    public IReadOnlyList<BusRequest> Requests => _requests.ToArray();

    public Session Session => new(BaseUrl, "credential-secret", CaDer, DeviceId, DeviceLabel);

    public static BusReply Ok(string json) => new(200, json);
    public static BusReply Fail(int status, string detail) => new(status, JsonSerializer.Serialize(new { detail }));

    public void On(string route, Func<BusRequest, BusReply> answer) => _routes[route] = answer;

    public IReadOnlyList<BusRequest> RequestsTo(string route) => Requests.Where(request => request.Route == route).ToList();

    /// <summary>A pasteable enrollment payload for this bus, as its device console would produce.</summary>
    public string EnrollmentPayload() => JsonSerializer.Serialize(new
    {
        base_url = BaseUrl,
        ca_der = Convert.ToBase64String(CaDer),
        ca_sha256 = Convert.ToHexString(SHA256.HashData(CaDer)).ToLowerInvariant(),
        device_label = DeviceLabel,
        enrollment = "enrollment-token",
        expires_at = DateTimeOffset.UtcNow.AddMinutes(10),
        version = 1
    });

    public static string MessageJson(long seq, string channel, string agent, string body, DateTimeOffset at, string kind = "chat") =>
        JsonSerializer.Serialize(new { seq, channel, agent_name = agent, body, kind, created_at = at });

    private static X509Certificate2 CreateCertificate()
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=StruggleBus window tests", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var names = new SubjectAlternativeNameBuilder();
        names.AddIpAddress(IPAddress.Loopback);
        names.AddDnsName("localhost");
        request.CertificateExtensions.Add(names.Build());
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(7));
        // Schannel needs the private key in a key container, which a round trip through PKCS#12 gives it.
        return X509CertificateLoader.LoadPkcs12(certificate.Export(X509ContentType.Pfx), null);
    }

    private async Task AcceptAsync()
    {
        try
        {
            while (!_stop.IsCancellationRequested)
            {
                var client = await _listener.AcceptTcpClientAsync(_stop.Token);
                _clients.Add(client);
                _ = ServeAsync(client);
            }
        }
        catch (Exception error) when (error is OperationCanceledException or SocketException or ObjectDisposedException)
        {
        }
    }

    private async Task ServeAsync(TcpClient client)
    {
        try
        {
            using var secure = new SslStream(client.GetStream());
            await secure.AuthenticateAsServerAsync(SharedCertificate.Value, false, SslProtocols.None, false);
            while (await ReadRequestAsync(secure) is { } request)
            {
                _requests.Enqueue(request);
                if (request.Route == "GET /api/mobile/stream" && !_routes.ContainsKey(request.Route))
                {
                    await HoldStreamOpenAsync(secure);
                    return;
                }
                var reply = _routes.TryGetValue(request.Route, out var answer) ? answer(request) : Fail(404, "Not found.");
                var body = Encoding.UTF8.GetBytes(reply.Json);
                var head = $"HTTP/1.1 {reply.Status} Status\r\nContent-Type: application/json\r\nContent-Length: {body.Length}\r\n\r\n";
                await secure.WriteAsync(Encoding.ASCII.GetBytes(head), _stop.Token);
                await secure.WriteAsync(body, _stop.Token);
                await secure.FlushAsync(_stop.Token);
            }
        }
        catch (Exception error) when (error is IOException or OperationCanceledException or ObjectDisposedException or AuthenticationException or SocketException)
        {
            // The window went away, or this bus was disposed.
        }
        finally
        {
            client.Dispose();
        }
    }

    /// <summary>The live stream: accepted, then silent until the window or this bus hangs up.</summary>
    private async Task HoldStreamOpenAsync(SslStream secure)
    {
        await secure.WriteAsync(Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n"), _stop.Token);
        await secure.FlushAsync(_stop.Token);
        var scratch = new byte[64];
        while (await secure.ReadAsync(scratch, _stop.Token) > 0) { }
    }

    private async Task<BusRequest?> ReadRequestAsync(SslStream secure)
    {
        if (await ReadLineAsync(secure) is not { } first) return null;
        var requestLine = first.Split(' ');
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        while (await ReadLineAsync(secure) is { Length: > 0 } line)
        {
            var parts = line.Split(':', 2);
            headers[parts[0]] = parts[1].Trim();
        }

        var body = headers.ContainsKey("Transfer-Encoding")
            ? await ReadChunkedAsync(secure)
            : await ReadBytesAsync(secure, headers.TryGetValue("Content-Length", out var length) ? int.Parse(length) : 0);
        var target = requestLine[1].Split('?', 2);
        return new BusRequest(requestLine[0], target[0], target.Length > 1 ? target[1] : string.Empty, Encoding.UTF8.GetString(body));
    }

    /// <summary>HttpClient sends JSON it has not measured as chunks: a hex length, the bytes, a blank line.</summary>
    private async Task<byte[]> ReadChunkedAsync(SslStream secure)
    {
        var body = new MemoryStream();
        while (true)
        {
            var size = Convert.ToInt32((await ReadLineAsync(secure))!.Split(';')[0], 16);
            body.Write(await ReadBytesAsync(secure, size));
            await ReadLineAsync(secure);
            if (size == 0) return body.ToArray();
        }
    }

    private async Task<byte[]> ReadBytesAsync(SslStream secure, int count)
    {
        var bytes = new byte[count];
        await secure.ReadExactlyAsync(bytes, _stop.Token);
        return bytes;
    }

    /// <summary>One CRLF-terminated line, or null when the connection has closed.</summary>
    private async Task<string?> ReadLineAsync(SslStream secure)
    {
        var line = new StringBuilder();
        var one = new byte[1];
        while (true)
        {
            if (await secure.ReadAsync(one, _stop.Token) == 0) return null;
            if (one[0] == (byte)'\n') return line.ToString().TrimEnd('\r');
            line.Append((char)one[0]);
        }
    }

    public void Dispose()
    {
        _stop.Cancel();
        _listener.Stop();
        foreach (var client in _clients) client.Dispose();
    }
}
