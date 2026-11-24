using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

namespace StruggleBusMonitor.Tests;

public sealed class BusApiTests
{
    [Theory]
    [InlineData("credential_inactive", StreamEndKind.CredentialInactive)]
    [InlineData("agent_access_frozen", StreamEndKind.AccessFrozen)]
    [InlineData("agent_access_unavailable", StreamEndKind.AccessUnavailable)]
    [InlineData("server_stopping", StreamEndKind.ServerStopping)]
    [InlineData("future_terminal", StreamEndKind.ProtocolFailure)]
    public void DecodeStreamEvent_ClassifiesTerminalEvents(string eventName, StreamEndKind expected)
    {
        var decoded = BusApi.DecodeStreamEvent(eventName, "{\"detail\":\"server detail\"}", null);

        Assert.Null(decoded.Message);
        Assert.Equal(expected, decoded.End?.Kind);
        Assert.Equal("server detail", decoded.End?.Detail);
    }

    [Fact]
    public void BuildStreamPath_EscapesSelectedChannel()
    {
        Assert.Equal("api/mobile/stream?since=12&channel=incident%2Fresponse%20team", BusApi.BuildStreamPath(12, "incident/response team"));
        Assert.Equal("api/mobile/stream?since=12", BusApi.BuildStreamPath(12, null));
    }

    [Fact]
    public void DecodeStreamEvent_RejectsMessageOutsideRequestedChannel()
    {
        var payload = "{\"seq\":42,\"channel\":\"ops\",\"agent_name\":\"agent\",\"body\":\"hello\",\"kind\":\"status\",\"created_at\":\"2030-01-01T00:00:00Z\"}";

        var error = Assert.Throws<InvalidOperationException>(() =>
            BusApi.DecodeStreamEvent("message", payload, "announce"));

        Assert.Contains("outside the requested channel", error.Message);
    }

    [Fact]
    public void SessionStore_CorruptFileIsQuarantined()
    {
        var path = TemporaryPath("session.bin");
        File.WriteAllBytes(path, [1, 2, 3, 4]);

        var session = BusApi.SessionStore.LoadFromPath(path, out var warning);

        Assert.Null(session);
        Assert.Contains("quarantined", warning);
        Assert.False(File.Exists(path));
        Assert.Single(Directory.GetFiles(Path.GetDirectoryName(path)!, "session.bin.invalid-*"));
    }

    [Fact]
    public void SessionStore_ValidProtectedSessionLoads()
    {
        var path = TemporaryPath("session.bin");
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=strugglebus.test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(1));
        var json = JsonSerializer.Serialize(new
        {
            Endpoint = "https://strugglebus.test:8443",
            Credential = "credential",
            CaDer = Convert.ToBase64String(certificate.Export(X509ContentType.Cert)),
            DeviceId = "device-1",
            DeviceLabel = "Test PC"
        });
        File.WriteAllBytes(path, ProtectedData.Protect(Encoding.UTF8.GetBytes(json), null, DataProtectionScope.CurrentUser));

        var session = BusApi.SessionStore.LoadFromPath(path, out var warning);

        Assert.NotNull(session);
        Assert.Equal("device-1", session.DeviceId);
        Assert.Null(warning);
    }

    [Fact]
    public void SessionStore_InvalidBase64IsQuarantined()
    {
        var path = TemporaryPath("session.bin");
        var json = "{\"Endpoint\":\"https://strugglebus.test\",\"Credential\":\"credential\",\"CaDer\":\"not-base64\",\"DeviceId\":\"device-1\",\"DeviceLabel\":\"Test PC\"}";
        File.WriteAllBytes(path, ProtectedData.Protect(Encoding.UTF8.GetBytes(json), null, DataProtectionScope.CurrentUser));

        Assert.Null(BusApi.SessionStore.LoadFromPath(path, out var warning));
        Assert.Contains("quarantined", warning);
    }

    [Fact]
    public void GrantStore_CorruptFileIsQuarantined()
    {
        var path = TemporaryPath("grant.bin");
        File.WriteAllBytes(path, [1, 2, 3, 4]);

        var grant = BusApi.GrantStore.LoadFromPath(path, "device-1", out var warning);

        Assert.Null(grant);
        Assert.Contains("Monitoring is still available", warning);
        Assert.False(File.Exists(path));
        Assert.Single(Directory.GetFiles(Path.GetDirectoryName(path)!, "grant.bin.invalid-*"));
    }

    [Fact]
    public void GrantStore_ValidGrantLoadsForMatchingDevice()
    {
        var path = TemporaryPath("grant.bin");
        var encrypted = ProtectedData.Protect(Encoding.UTF8.GetBytes("device-1\nsecret"), null, DataProtectionScope.CurrentUser);
        File.WriteAllBytes(path, encrypted);

        var grant = BusApi.GrantStore.LoadFromPath(path, "device-1", out var warning);

        Assert.Equal("secret", grant);
        Assert.Null(warning);
    }

    [Fact]
    public void GrantStore_MismatchedDeviceDoesNotExposeGrant()
    {
        var path = TemporaryPath("grant.bin");
        var encrypted = ProtectedData.Protect(Encoding.UTF8.GetBytes("device-1\nsecret"), null, DataProtectionScope.CurrentUser);
        File.WriteAllBytes(path, encrypted);

        var grant = BusApi.GrantStore.LoadFromPath(path, "device-2", out var warning);

        Assert.Null(grant);
        Assert.Null(warning);
        Assert.True(File.Exists(path));
    }

    private static string TemporaryPath(string fileName)
    {
        var directory = Path.Combine(Path.GetTempPath(), "StruggleBusMonitor.Tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        return Path.Combine(directory, fileName);
    }
}

public sealed class MonitorLogicTests
{
    private static readonly DateTimeOffset Timestamp = DateTimeOffset.Parse("2030-01-01T00:00:00Z");

    [Fact]
    public async Task MonitorLifecycle_RestartCancelsAndDrainsPreviousTasks()
    {
        var lifecycle = new MonitorLifecycle();
        var firstStopped = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        await lifecycle.RestartAsync(cancellation => [WaitForCancellation(cancellation.Token, firstStopped)]);
        Assert.Equal(1, lifecycle.ActiveTaskCount);

        await lifecycle.RestartAsync(cancellation => [Task.Delay(Timeout.InfiniteTimeSpan, cancellation.Token)]);

        Assert.True(firstStopped.Task.IsCompletedSuccessfully);
        Assert.Equal(1, lifecycle.ActiveTaskCount);
        await lifecycle.StopAsync();
        Assert.Equal(0, lifecycle.ActiveTaskCount);
    }

    [Fact]
    public async Task MonitorLifecycle_RapidRestartsLeaveOneTaskSet()
    {
        var lifecycle = new MonitorLifecycle();
        var restarts = Enumerable.Range(0, 5)
            .Select(_ => lifecycle.RestartAsync(cancellation => [Task.Delay(Timeout.InfiniteTimeSpan, cancellation.Token)]));

        await Task.WhenAll(restarts);

        Assert.Equal(1, lifecycle.ActiveTaskCount);
        await lifecycle.StopAsync();
    }

    private static async Task WaitForCancellation(CancellationToken token, TaskCompletionSource stopped)
    {
        try { await Task.Delay(Timeout.InfiniteTimeSpan, token); }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { }
        finally { stopped.TrySetResult(); }
    }

    [Theory]
    [InlineData(StreamEndKind.RoutineClosure, "RetryQuietly")]
    [InlineData(StreamEndKind.RateLimited, "RetryQuietly")]
    [InlineData(StreamEndKind.AccessFrozen, "RetryFrozen")]
    [InlineData(StreamEndKind.AccessUnavailable, "RetryDegraded")]
    [InlineData(StreamEndKind.CredentialInactive, "StopRevoked")]
    [InlineData(StreamEndKind.ServerStopping, "RetryStopping")]
    [InlineData(StreamEndKind.ProtocolFailure, "RetryProtocol")]
    public void DecideStreamEnd_MapsReconnectBehavior(StreamEndKind kind, string expected)
    {
        var decision = MonitorLogic.DecideStreamEnd(new StreamEnd(kind, "detail"), failures: 2);

        Assert.Equal(expected, decision.Disposition.ToString());
    }

    [Fact]
    public void DecideStreamEnd_HonorsRateLimitAndCapsBackoff()
    {
        var rateLimited = MonitorLogic.DecideStreamEnd(
            new StreamEnd(StreamEndKind.RateLimited, "wait", TimeSpan.FromSeconds(17)),
            failures: 0);

        Assert.Equal(TimeSpan.FromSeconds(17), rateLimited.Delay);
        Assert.Equal(TimeSpan.FromSeconds(30), MonitorLogic.RetryDelay(99));
    }

    [Fact]
    public void FilterMessages_AllReturnsEveryChannel()
    {
        var messages = Messages();

        var filtered = MonitorLogic.FilterMessages(messages, null);

        Assert.Equal([1L, 2L], filtered.Select(message => message.Seq));
    }

    [Fact]
    public void FilterMessages_SelectedChannelReturnsOnlyExactMatches()
    {
        var filtered = MonitorLogic.FilterMessages(Messages(), "ops");

        var message = Assert.Single(filtered);
        Assert.Equal(2, message.Seq);
    }

    [Fact]
    public void NormalizeChannelSelection_RemovedChannelFallsBackToAll()
    {
        var channels = new[] { new BusChannel("1", "announce", "Announcements") };

        Assert.Null(MonitorLogic.NormalizeChannelSelection("ops", channels));
        Assert.Equal("announce", MonitorLogic.NormalizeChannelSelection("announce", channels));
    }

    [Fact]
    public void BuildCsv_SanitizesSpreadsheetFormulaAndHashesOriginalBody()
    {
        var body = "=SUM(1,2)";
        var message = new BusMessage(7, "ops", "agent", body, "status", Timestamp);
        var expectedHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(body))).ToLowerInvariant();

        var csv = MainWindow.BuildCsv([message]);

        Assert.Contains("\"'=SUM(1,2)\"", csv);
        Assert.Contains(expectedHash, csv);
        Assert.Contains(",true", csv);
    }

    private static BusMessage[] Messages() =>
    [
        new(1, "announce", "agent-a", "one", "status", Timestamp),
        new(2, "ops", "agent-b", "two", "status", Timestamp.AddSeconds(1))
    ];
}
