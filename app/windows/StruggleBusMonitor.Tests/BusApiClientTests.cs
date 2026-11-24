using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

namespace StruggleBusMonitor.Tests;

/// <summary>A BusApi wired to a fake bus and a throwaway data folder.</summary>
internal sealed class BusHarness
{
    public const string Endpoint = "https://bus.test:8443";
    private static readonly X509Certificate2 Ca = TestCertificates.CreateCa();

    public static byte[] CaDer { get; } = TestCertificates.Der(Ca);
    public string Directory { get; } = TempFiles.NewDirectory();
    public FakeBus Bus { get; } = new();
    public CaTrust? Trust { get; private set; }
    public string SessionPath => Path.Combine(Directory, "session.bin");
    public string GrantPath => Path.Combine(Directory, "operator-grant.bin");

    public BusApi Create() => new(Directory, trust =>
    {
        Trust = trust;
        return Bus;
    });

    public BusApi Enrolled(bool withGrant = false)
    {
        BusApi.SessionStore.SaveToPath(SessionPath, new Session(Endpoint, "device-credential", CaDer, "device-1", "Test PC"));
        if (withGrant) BusApi.GrantStore.SaveToPath(GrantPath, "device-1", "grant-secret");
        return Create();
    }

    public static string EnrollmentPayload(string baseUrl = Endpoint) => JsonSerializer.Serialize(new
    {
        base_url = baseUrl,
        ca_der = Convert.ToBase64String(CaDer),
        ca_sha256 = Convert.ToHexString(SHA256.HashData(CaDer)).ToLowerInvariant(),
        device_label = "Test PC",
        enrollment = "enrollment-token",
        expires_at = DateTimeOffset.UtcNow.AddMinutes(10),
        version = 1
    });

    public static string Message(long seq, string channel = "ops", string agent = "agent-one", string body = "hello", string kind = "status", long? replyTo = null) =>
        JsonSerializer.Serialize(new { seq, channel, agent_name = agent, body, kind, created_at = "2030-01-01T00:00:00Z", reply_to = replyTo });

    public static string Event(string name, string data) => $"event: {name}\ndata: {data}\n\n";
}

public sealed class BusApiEnrollmentTests
{
    [Fact]
    public async Task ANewPcIsNotEnrolledAndSaysSoWhenAsked()
    {
        var harness = new BusHarness();
        var api = harness.Create();

        Assert.Null(api.Session);
        Assert.Null(api.StartupWarning);
        Assert.False(api.HasOperatorGrant());
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => api.GetAgentsAsync(CancellationToken.None));
        Assert.Equal("Enroll this Windows device first.", error.Message);
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            api.StreamAsync(null, () => Task.CompletedTask, _ => Task.CompletedTask, CancellationToken.None));
        Assert.Empty(harness.Bus.Requests);
    }

    [Fact]
    public void ADamagedSavedEnrollmentIsReportedAtStartup()
    {
        var harness = new BusHarness();
        File.WriteAllBytes(harness.SessionPath, [9, 9, 9]);

        var api = harness.Create();

        Assert.Null(api.Session);
        Assert.Contains("quarantined", api.StartupWarning);
    }

    [Fact]
    public async Task EnrollAsync_RedeemsTheTokenAndRemembersTheSession()
    {
        var harness = new BusHarness();
        harness.Bus.Json("""{"device_id":"device-9","device_label":"Ops PC","credential_secret":"read-credential"}""");
        var api = harness.Create();

        var session = await api.EnrollAsync(BusHarness.EnrollmentPayload(BusHarness.Endpoint + "/"), CancellationToken.None);

        var request = Assert.Single(harness.Bus.Requests);
        Assert.Equal("POST", request.Method);
        Assert.Equal("https://bus.test:8443/api/mobile/enrollments/redeem", request.Url.ToString());
        Assert.Equal("Bearer enrollment-token", request.Authorization);
        using var body = JsonDocument.Parse(request.Body!);
        Assert.True(Guid.TryParse(body.RootElement.GetProperty("request_id").GetString(), out _));

        Assert.Same(session, api.Session);
        Assert.Equal(BusHarness.Endpoint, session.Endpoint);
        Assert.Equal("read-credential", session.Credential);
        Assert.Equal("device-9", session.DeviceId);
        Assert.Equal("Ops PC", session.DeviceLabel);
        Assert.Equal(BusHarness.CaDer, session.CaDer);

        var restarted = harness.Create();
        Assert.Equal("device-9", restarted.Session?.DeviceId);
        Assert.Equal("read-credential", restarted.Session?.Credential);
    }

    [Fact]
    public async Task EnrollAsync_ARefusedTokenLeavesThePcUnenrolled()
    {
        var harness = new BusHarness();
        harness.Bus.Json("""{"detail":"Enrollment token is not valid."}""", HttpStatusCode.Unauthorized);
        var api = harness.Create();

        var error = await Assert.ThrowsAsync<BusApiException>(() => api.EnrollAsync(BusHarness.EnrollmentPayload(), CancellationToken.None));

        Assert.Equal(401, error.StatusCode);
        Assert.Equal("Enrollment token is not valid.", error.Detail);
        Assert.StartsWith("The bus did not accept this enrollment.", error.Message);
        Assert.Null(api.Session);
        Assert.False(File.Exists(harness.SessionPath));
    }

    [Fact]
    public async Task EnrollAsync_AnEmptyAnswerIsNotAnEnrollment()
    {
        var harness = new BusHarness();
        harness.Bus.Json("null");
        var api = harness.Create();

        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => api.EnrollAsync(BusHarness.EnrollmentPayload(), CancellationToken.None));

        Assert.Equal("Enrollment returned no credential.", error.Message);
        Assert.Null(api.Session);
    }

    [Fact]
    public async Task EnrollAsync_ABadPayloadSendsNothing()
    {
        var harness = new BusHarness();
        var api = harness.Create();

        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => api.EnrollAsync("not a payload", CancellationToken.None));

        Assert.Equal(BusApi.IncompleteEnrollment, error.Message);
        Assert.Empty(harness.Bus.Requests);
    }

    [Fact]
    public async Task EnrollAsync_StartsTheLiveStreamFromTheBeginningAgain()
    {
        var harness = new BusHarness();
        var api = harness.Enrolled();
        harness.Bus.Json($"[{BusHarness.Message(40)}]");
        await api.GetRecentMessagesAsync(CancellationToken.None);
        harness.Bus.Json("""{"device_id":"device-2","device_label":"Ops PC","credential_secret":"new-credential"}""");
        await api.EnrollAsync(BusHarness.EnrollmentPayload(), CancellationToken.None);
        harness.Bus.Events(string.Empty);

        await api.StreamAsync(null, () => Task.CompletedTask, _ => Task.CompletedTask, CancellationToken.None);

        var stream = harness.Bus.Requests[^1];
        Assert.Equal("/api/mobile/stream?since=0", stream.PathAndQuery);
        Assert.Equal("Bearer new-credential", stream.Authorization);
    }

    [Fact]
    public void ForgetSession_RemovesTheEnrollmentAndTheGrantFromDisk()
    {
        var harness = new BusHarness();
        var api = harness.Enrolled(withGrant: true);
        Assert.True(api.HasOperatorGrant());

        api.ForgetSession();

        Assert.Null(api.Session);
        Assert.False(api.HasOperatorGrant());
        Assert.False(File.Exists(harness.SessionPath));
        Assert.False(File.Exists(harness.GrantPath));
        Assert.Null(harness.Create().Session);
    }

    [Fact]
    public void ForgetSession_StillForgetsWhenAFileCannotBeDeleted()
    {
        var harness = new BusHarness();
        var api = harness.Enrolled(withGrant: true);

        using (new FileStream(harness.GrantPath, FileMode.Open, FileAccess.Read, FileShare.None))
        {
            api.ForgetSession();
        }

        Assert.Null(api.Session);
        Assert.False(File.Exists(harness.SessionPath));
        Assert.True(File.Exists(harness.GrantPath));
    }
}

public sealed class BusApiReadTests
{
    [Fact]
    public async Task GetSnapshotAsync_ReadsMessagesAgentsAndStateWithTheDeviceCredential()
    {
        var harness = new BusHarness();
        var api = harness.Enrolled();
        harness.Bus
            .Json($"[{BusHarness.Message(12, body: "second")},{BusHarness.Message(11, agent: "agent-two", body: "first", replyTo: 7)}]")
            .Json("""[{"id":"a1","name":"agent-one","description":null,"host":null,"last_seen_at":null},{"id":"a2","name":"agent-two","description":"Builds","host":"box","last_seen_at":"2030-01-01T00:00:00Z"}]""")
            .Json("""{"api_version":1,"state":"frozen"}""");

        var snapshot = await api.GetSnapshotAsync(CancellationToken.None);

        Assert.Equal(
            ["/api/mobile/snapshot?limit=100", "/api/mobile/agents", "/api/mobile/status"],
            harness.Bus.Requests.Select(request => request.PathAndQuery));
        Assert.All(harness.Bus.Requests, request =>
        {
            Assert.Equal("GET", request.Method);
            Assert.Equal("Bearer device-credential", request.Authorization);
            Assert.Equal("bus.test", request.Url.Host);
        });
        Assert.Equal([11L, 12L], snapshot.Messages.Select(message => message.Seq));
        Assert.Equal(new BusMessage(11, "ops", "agent-two", "first", "status", DateTimeOffset.Parse("2030-01-01T00:00:00Z"), 7), snapshot.Messages[0]);
        Assert.Equal("frozen", snapshot.State);
        Assert.Equal(12, snapshot.LatestSeq);
        Assert.Equal(new BusAgent("a1", "agent-one", "", "", "never-seen", null), snapshot.Agents[0]);
        Assert.Equal(new BusAgent("a2", "agent-two", "Builds", "box", "seen", DateTimeOffset.Parse("2030-01-01T00:00:00Z")), snapshot.Agents[1]);
    }

    [Fact]
    public async Task GetSnapshotAsync_AnEmptyBoardKeepsTheCursorAtZero()
    {
        var harness = new BusHarness();
        var api = harness.Enrolled();
        harness.Bus.Json("[]").Json("[]").Json("""{"api_version":1,"state":"normal"}""");

        var snapshot = await api.GetSnapshotAsync(CancellationToken.None);

        Assert.Empty(snapshot.Messages);
        Assert.Equal(0, snapshot.LatestSeq);
    }

    [Fact]
    public async Task GetRecentMessagesAsync_SortsAndMovesTheStreamCursor()
    {
        var harness = new BusHarness();
        var api = harness.Enrolled();
        harness.Bus.Json($"[{BusHarness.Message(31)},{BusHarness.Message(30)}]").Events(string.Empty);

        var messages = await api.GetRecentMessagesAsync(CancellationToken.None);
        await api.StreamAsync(null, () => Task.CompletedTask, _ => Task.CompletedTask, CancellationToken.None);

        Assert.Equal([30L, 31L], messages.Select(message => message.Seq));
        Assert.Equal("/api/mobile/snapshot?limit=100", harness.Bus.Requests[0].PathAndQuery);
        Assert.Equal("/api/mobile/stream?since=31", harness.Bus.Requests[1].PathAndQuery);
    }

    [Fact]
    public async Task GetExportMessagesAsync_AsksForTheLargerPageAndLeavesTheCursorAlone()
    {
        var harness = new BusHarness();
        var api = harness.Enrolled();
        harness.Bus.Json($"[{BusHarness.Message(9)},{BusHarness.Message(8)}]").Events(string.Empty);

        var messages = await api.GetExportMessagesAsync(CancellationToken.None);
        await api.StreamAsync(null, () => Task.CompletedTask, _ => Task.CompletedTask, CancellationToken.None);

        Assert.Equal([8L, 9L], messages.Select(message => message.Seq));
        Assert.Equal("/api/mobile/snapshot?limit=200", harness.Bus.Requests[0].PathAndQuery);
        Assert.Equal("/api/mobile/stream?since=0", harness.Bus.Requests[1].PathAndQuery);
    }

    [Fact]
    public async Task GetAgentsAsync_MapsTheRoster()
    {
        var harness = new BusHarness();
        var api = harness.Enrolled();
        harness.Bus.Json("""[{"id":"a1","name":"agent-one","description":"Does things","host":"box-1","last_seen_at":"2030-01-01T00:00:00Z"}]""");

        var agent = Assert.Single(await api.GetAgentsAsync(CancellationToken.None));

        Assert.Equal("/api/mobile/agents", harness.Bus.Requests[0].PathAndQuery);
        Assert.Equal("a1", agent.Id);
        Assert.Equal("agent-one", agent.Name);
        Assert.Equal("Does things", agent.Description);
        Assert.Equal("box-1", agent.Host);
        Assert.Equal("seen", agent.Presence);
    }

    [Fact]
    public async Task GetChannelsAsync_SortsByNameAndToleratesAMissingPurpose()
    {
        var harness = new BusHarness();
        var api = harness.Enrolled();
        harness.Bus.Json("""[{"id":"2","name":"ops","purpose":null},{"id":"1","name":"Announce","purpose":"News"}]""");

        var channels = await api.GetChannelsAsync(CancellationToken.None);

        Assert.Equal("/api/mobile/channels", harness.Bus.Requests[0].PathAndQuery);
        Assert.Equal([new BusChannel("1", "Announce", "News"), new BusChannel("2", "ops", "")], channels);
    }

    [Fact]
    public async Task GetHistoryAsync_SendsTheFiltersAndReturnsOldestFirst()
    {
        var harness = new BusHarness();
        var api = harness.Enrolled();
        harness.Bus.Json($"[{BusHarness.Message(5, "humans")},{BusHarness.Message(4, "humans")}]");

        var history = await api.GetHistoryAsync("humans", "agent one", 90, 50, CancellationToken.None);

        Assert.Equal("/api/mobile/snapshot?limit=50&channel=humans&agent=agent%20one&before=90", harness.Bus.Requests[0].PathAndQuery);
        Assert.Equal([4L, 5L], history.Select(message => message.Seq));
    }

    [Fact]
    public async Task SearchAsync_EscapesTheQueryAndKeepsTheServerOrder()
    {
        var harness = new BusHarness();
        var api = harness.Enrolled();
        harness.Bus.Json($"[{BusHarness.Message(9)},{BusHarness.Message(3)}]");

        var hits = await api.SearchAsync("disk full & slow", 25, CancellationToken.None);

        Assert.Equal("/api/mobile/search?query=disk%20full%20%26%20slow&limit=25", harness.Bus.Requests[0].PathAndQuery);
        Assert.Equal([9L, 3L], hits.Select(message => message.Seq));
    }

    [Fact]
    public async Task ProbeHistoryAsync_IsTrueOnlyWhenTheBusAnswersTheSearch()
    {
        var harness = new BusHarness();
        var api = harness.Enrolled();
        harness.Bus.Json("[]").Json("""{"detail":"Not Found"}""", HttpStatusCode.NotFound);

        Assert.True(await api.ProbeHistoryAsync(CancellationToken.None));
        Assert.False(await api.ProbeHistoryAsync(CancellationToken.None));
        Assert.Equal("/api/mobile/search?query=bus&limit=1", harness.Bus.Requests[0].PathAndQuery);
    }

    [Fact]
    public async Task ProbeHistoryAsync_DoesNotMistakeAnOutageForAnOldBus()
    {
        var harness = new BusHarness();
        var api = harness.Enrolled();
        harness.Bus.Fails(new HttpRequestException("down", new SocketException((int)SocketError.ConnectionRefused)));

        await Assert.ThrowsAsync<HttpRequestException>(() => api.ProbeHistoryAsync(CancellationToken.None));
    }

    [Fact]
    public async Task GetBusLogAsync_MapsEntriesAndFillsMissingFields()
    {
        var harness = new BusHarness();
        var api = harness.Enrolled();
        harness.Bus.Json("""{"version":"0.2.65","started_at":"2030-01-01T00:00:00Z","entries":[{"ts":"2030-01-01T00:01:00Z","source":"audit","level":"warning","event":"agent.blocked","subject":"agent-one","actor":"operator","status":200,"remote_address":"10.0.0.5","detail":"blocked"},{"ts":"2030-01-01T00:02:00Z"}]}""");

        var log = await api.GetBusLogAsync(40, CancellationToken.None);

        Assert.Equal("/api/mobile/admin/logs?limit=40", harness.Bus.Requests[0].PathAndQuery);
        Assert.Equal("0.2.65", log.Version);
        Assert.Equal(DateTimeOffset.Parse("2030-01-01T00:00:00Z"), log.StartedAt);
        Assert.Equal(
            new BusLogEntry(DateTimeOffset.Parse("2030-01-01T00:01:00Z"), "audit", "warning", "agent.blocked", "agent-one", "operator", 200, "10.0.0.5", "blocked"),
            log.Entries[0]);
        Assert.Equal(
            new BusLogEntry(DateTimeOffset.Parse("2030-01-01T00:02:00Z"), "", "info", "", null, null, null, null, ""),
            log.Entries[1]);
    }

    [Fact]
    public async Task ARefusalCarriesTheStatusAndTheBusDetail()
    {
        var harness = new BusHarness();
        var api = harness.Enrolled();
        harness.Bus.Json("""{"detail":"Agent access is frozen."}""", HttpStatusCode.ServiceUnavailable);

        var error = await Assert.ThrowsAsync<BusApiException>(() => api.GetAgentsAsync(CancellationToken.None));

        Assert.Equal(503, error.StatusCode);
        Assert.Equal("Agent access is frozen.", error.Detail);
        Assert.StartsWith("Agent access is frozen on the bus", error.Message);
    }

    [Fact]
    public async Task AnEmptyAnswerIsAnError()
    {
        var harness = new BusHarness();
        var api = harness.Enrolled();
        harness.Bus.Json("null");

        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => api.GetAgentsAsync(CancellationToken.None));

        Assert.Equal("Bus returned an empty response.", error.Message);
    }

    [Fact]
    public async Task ANetworkFailureIsDescribedInPlainWordsAndStaysTransient()
    {
        var harness = new BusHarness();
        var api = harness.Enrolled();
        harness.Bus.Fails(new HttpRequestException("raw", new SocketException((int)SocketError.HostNotFound)));

        var error = await Assert.ThrowsAsync<HttpRequestException>(() => api.GetAgentsAsync(CancellationToken.None));

        Assert.StartsWith("The bus address bus.test:8443 could not be found.", error.Message);
        Assert.Null(error.InnerException);
        Assert.True(MonitorLogic.IsTransient(error));
    }

    [Fact]
    public async Task ATimeoutIsReportedAsTheBusNotAnswering()
    {
        var harness = new BusHarness();
        var api = harness.Enrolled();
        harness.Bus.Fails(new TaskCanceledException("The request timed out."));

        var error = await Assert.ThrowsAsync<HttpRequestException>(() => api.GetAgentsAsync(CancellationToken.None));

        Assert.StartsWith("The bus at bus.test:8443 did not answer in time.", error.Message);
    }

    [Fact]
    public async Task ACancellationTheCallerAskedForIsNotTurnedIntoAnError()
    {
        var harness = new BusHarness();
        var api = harness.Enrolled();
        using var cancellation = new CancellationTokenSource();
        harness.Bus.Answer((_, token) =>
        {
            cancellation.Cancel();
            token.ThrowIfCancellationRequested();
            return new HttpResponseMessage(HttpStatusCode.OK);
        });

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => api.GetAgentsAsync(cancellation.Token));
    }

    [Fact]
    public async Task ACertificateFailureSaysWhatTheCheckFound()
    {
        var harness = new BusHarness();
        var api = harness.Enrolled();
        harness.Bus.Answer((_, _) =>
        {
            harness.Trust!.Validate(null, null, System.Net.Security.SslPolicyErrors.None);
            throw new HttpRequestException(HttpRequestError.SecureConnectionError, "The SSL connection could not be established.");
        });

        var error = await Assert.ThrowsAsync<HttpRequestException>(() => api.GetAgentsAsync(CancellationToken.None));

        Assert.Equal("The StruggleBus TLS certificate could not be verified. The server did not provide a certificate.", error.Message);
    }
}

public sealed class BusApiOperatorTests
{
    [Theory]
    [InlineData(OperatorAction.ActivateFreeze, "activate-freeze")]
    [InlineData(OperatorAction.ClearFreeze, "clear-freeze")]
    [InlineData(OperatorAction.BlockAgent, "block-agent")]
    [InlineData(OperatorAction.RevokeDevice, "revoke-device")]
    public async Task RequestConfirmationAsync_SendsTheWireActionAndReturnsWhatTheBusWillDo(OperatorAction action, string wire)
    {
        var harness = new BusHarness();
        var api = harness.Enrolled();
        harness.Bus.Json($$"""{"confirmation_id":"c-1","action":"{{wire}}","target_id":"t-1","target_label":"agent-one","effect":"Blocks agent-one"}""");

        var confirmation = await api.RequestConfirmationAsync(action, "t-1", CancellationToken.None);

        var request = Assert.Single(harness.Bus.Requests);
        Assert.Equal("POST", request.Method);
        Assert.Equal("/api/mobile/confirmations", request.PathAndQuery);
        Assert.Equal("Bearer device-credential", request.Authorization);
        using var body = JsonDocument.Parse(request.Body!);
        Assert.Equal(wire, body.RootElement.GetProperty("action").GetString());
        Assert.Equal("t-1", body.RootElement.GetProperty("target_id").GetString());
        Assert.True(Guid.TryParse(body.RootElement.GetProperty("request_id").GetString(), out _));
        Assert.Equal(new Confirmation("c-1", wire, "t-1", "agent-one", "Blocks agent-one"), confirmation);
    }

    [Fact]
    public async Task RequestConfirmationAsync_RefusesAnActionItCannotName()
    {
        var harness = new BusHarness();
        var api = harness.Enrolled();

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() =>
            api.RequestConfirmationAsync((OperatorAction)99, "t-1", CancellationToken.None));
        Assert.Empty(harness.Bus.Requests);
    }

    [Fact]
    public async Task EstablishGrantAsync_SendsThePasswordAndKeepsTheGrantForThisDevice()
    {
        var harness = new BusHarness();
        var api = harness.Enrolled();
        harness.Bus.Json("""{"grant_secret":"fresh-grant"}""");

        await api.EstablishGrantAsync("hunter2", "on call", CancellationToken.None);

        var request = Assert.Single(harness.Bus.Requests);
        Assert.Equal("/api/mobile/grants", request.PathAndQuery);
        using var body = JsonDocument.Parse(request.Body!);
        Assert.Equal("hunter2", body.RootElement.GetProperty("operator_password").GetString());
        Assert.Equal("on call", body.RootElement.GetProperty("reason").GetString());
        Assert.True(api.HasOperatorGrant());
        Assert.Equal("fresh-grant", BusApi.GrantStore.LoadFromPath(harness.GrantPath, "device-1", out _));
        Assert.DoesNotContain("fresh-grant", File.ReadAllText(harness.GrantPath));
    }

    [Fact]
    public async Task EstablishGrantAsync_AWrongPasswordSavesNothing()
    {
        var harness = new BusHarness();
        var api = harness.Enrolled();
        harness.Bus.Json("""{"detail":"Operator password is not valid."}""", HttpStatusCode.Forbidden);

        var error = await Assert.ThrowsAsync<BusApiException>(() => api.EstablishGrantAsync("nope", "on call", CancellationToken.None));

        Assert.Equal("The bus did not accept the operator password. Check it and try again.", error.Message);
        Assert.False(api.HasOperatorGrant());
    }

    [Fact]
    public async Task PerformActionAsync_SendsTheConfirmationWithTheSavedGrant()
    {
        var harness = new BusHarness();
        var api = harness.Enrolled(withGrant: true);
        harness.Bus.Json("""{"applied":true,"detail":"Frozen.","target_label":"all agents"}""");

        var result = await api.PerformActionAsync(new Confirmation("c-1", "activate-freeze", "bus", "all agents", "Freezes"), "incident", CancellationToken.None);

        var request = Assert.Single(harness.Bus.Requests);
        Assert.Equal("/api/mobile/actions", request.PathAndQuery);
        using var body = JsonDocument.Parse(request.Body!);
        Assert.Equal("c-1", body.RootElement.GetProperty("confirmation_id").GetString());
        Assert.Equal("activate-freeze", body.RootElement.GetProperty("action").GetString());
        Assert.Equal("bus", body.RootElement.GetProperty("target_id").GetString());
        Assert.Equal("grant-secret", body.RootElement.GetProperty("grant_secret").GetString());
        Assert.Equal("incident", body.RootElement.GetProperty("reason").GetString());
        Assert.Equal(new ActionResult(true, "Frozen.", "all agents"), result);
    }

    [Fact]
    public async Task PerformActionAsync_NeedsOperatorAccessFirst()
    {
        var harness = new BusHarness();
        var api = harness.Enrolled();

        var error = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            api.PerformActionAsync(new Confirmation("c-1", "activate-freeze", "bus", "all agents", "Freezes"), "incident", CancellationToken.None));

        Assert.Equal("Operator access is not configured.", error.Message);
        Assert.Empty(harness.Bus.Requests);
    }

    [Fact]
    public async Task ADamagedGrantIsQuarantinedAndTheActionSaysWhy()
    {
        var harness = new BusHarness();
        var api = harness.Enrolled();
        File.WriteAllBytes(harness.GrantPath, [1, 2, 3]);

        var error = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            api.ControlAgentAsync("a1", "agent-one", 1, "block", "noisy", CancellationToken.None));

        Assert.Contains("could not be read and was quarantined", error.Message);
        Assert.False(File.Exists(harness.GrantPath));
        Assert.Empty(harness.Bus.Requests);
    }

    [Fact]
    public async Task AGrantSavedForAnotherEnrollmentIsNotUsed()
    {
        var harness = new BusHarness();
        var api = harness.Enrolled();
        BusApi.GrantStore.SaveToPath(harness.GrantPath, "some-other-device", "their-grant");

        Assert.False(api.HasOperatorGrant());
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            api.CreateDeviceEnrollmentAsync("Spare PC", "new machine", CancellationToken.None));
        Assert.Equal("Operator access is not configured. Save it on the Admin page first.", error.Message);
    }

    [Fact]
    public async Task CreateAgentEnrollmentAsync_ReturnsTheOnboardingPackage()
    {
        var harness = new BusHarness();
        var api = harness.Enrolled(withGrant: true);
        harness.Bus.Json("""{"enrollment_id":"e-1","agent_name":"build-bot","expires_at":"2030-01-01T00:00:00Z","package":"PACKAGE TEXT"}""");

        var result = await api.CreateAgentEnrollmentAsync("build-bot", "Builds things", "new agent", CancellationToken.None);

        var request = Assert.Single(harness.Bus.Requests);
        Assert.Equal("/api/mobile/enrollments/agents", request.PathAndQuery);
        using var body = JsonDocument.Parse(request.Body!);
        Assert.Equal("build-bot", body.RootElement.GetProperty("name").GetString());
        Assert.Equal("Builds things", body.RootElement.GetProperty("description").GetString());
        Assert.Equal("new agent", body.RootElement.GetProperty("reason").GetString());
        Assert.Equal("grant-secret", body.RootElement.GetProperty("grant_secret").GetString());
        Assert.Equal("Onboarding package for build-bot", result.Title);
        Assert.StartsWith("Single use. Expires ", result.Detail);
        Assert.EndsWith("Hand it to the agent privately.", result.Detail);
        Assert.Equal("PACKAGE TEXT", result.Secret);
    }

    [Fact]
    public async Task CreateServicePrincipalAsync_ShowsTheSecretOnceAndSaysSoWhenItIsGone()
    {
        var harness = new BusHarness();
        var api = harness.Enrolled(withGrant: true);
        harness.Bus
            .Json("""{"name":"ci","agent_name_prefix":"ci-worker","credential_secret":"sp-secret"}""")
            .Json("""{"name":"ci","agent_name_prefix":"ci-worker","credential_secret":null}""");

        var created = await api.CreateServicePrincipalAsync("ci", "ci-worker", "pipelines", CancellationToken.None);
        var repeated = await api.CreateServicePrincipalAsync("ci", "ci-worker", "pipelines", CancellationToken.None);

        Assert.Equal("/api/mobile/enrollments/service-principals", harness.Bus.Requests[0].PathAndQuery);
        using var body = JsonDocument.Parse(harness.Bus.Requests[0].Body!);
        Assert.Equal("ci-worker", body.RootElement.GetProperty("agent_name_prefix").GetString());
        Assert.Equal("Service principal ci", created.Title);
        Assert.Equal("It can create short-lived worker agents named ci-worker-*. This credential is shown once.", created.Detail);
        Assert.Equal("sp-secret", created.Secret);
        Assert.Null(repeated.Secret);
        Assert.StartsWith("The bus had already created this one", repeated.Detail);
    }

    [Fact]
    public async Task CreateDeviceEnrollmentAsync_ReturnsThePayloadToPaste()
    {
        var harness = new BusHarness();
        var api = harness.Enrolled(withGrant: true);
        harness.Bus.Json("""{"device_label":"Spare PC","expires_at":"2030-01-01T00:00:00Z","payload":"{PAYLOAD}"}""");

        var result = await api.CreateDeviceEnrollmentAsync("Spare PC", "new machine", CancellationToken.None);

        var request = Assert.Single(harness.Bus.Requests);
        Assert.Equal("/api/mobile/enrollments/devices", request.PathAndQuery);
        using var body = JsonDocument.Parse(request.Body!);
        Assert.Equal("Spare PC", body.RootElement.GetProperty("label").GetString());
        Assert.Equal("Enrollment for Spare PC", result.Title);
        Assert.EndsWith("Paste it into the Windows app on the new PC.", result.Detail);
        Assert.Equal("{PAYLOAD}", result.Secret);
    }

    [Fact]
    public async Task CreateHostEnrollmentAsync_ReturnsTheCodeOnce()
    {
        var harness = new BusHarness();
        var api = harness.Enrolled(withGrant: true);
        harness.Bus.Json("""{"host_prefix":"host-office1","expires_at":"2030-01-01T00:00:00Z","code_issued":true,"code":"sbhe1_CODE"}""");

        var code = await api.CreateHostEnrollmentAsync("request-1", "host-office1", "new worker host", CancellationToken.None);

        var request = Assert.Single(harness.Bus.Requests);
        Assert.Equal(("POST", "/api/mobile/enrollments/hosts"), (request.Method, request.PathAndQuery));
        using var body = JsonDocument.Parse(request.Body!);
        Assert.Equal("request-1", body.RootElement.GetProperty("request_id").GetString());
        Assert.Equal("host-office1", body.RootElement.GetProperty("host_prefix").GetString());
        Assert.Equal("new worker host", body.RootElement.GetProperty("reason").GetString());
        Assert.Equal("grant-secret", body.RootElement.GetProperty("grant_secret").GetString());
        Assert.Equal(new HostCode("host-office1", DateTimeOffset.Parse("2030-01-01T00:00:00Z"), "sbhe1_CODE"), code);
    }

    [Fact]
    public async Task CreateHostEnrollmentAsync_ARepeatedRequestHasNoCode()
    {
        var harness = new BusHarness();
        var api = harness.Enrolled(withGrant: true);
        harness.Bus.Json("""{"host_prefix":"host-office1","expires_at":"2030-01-01T00:00:00Z","code_issued":false,"code":null}""");

        var code = await api.CreateHostEnrollmentAsync("request-1", "host-office1", "again", CancellationToken.None);

        Assert.Null(code.Code);
    }

    [Fact]
    public async Task SiteDocuments_AreReadAndPublishedByteForByte()
    {
        // Bytes a careless client would damage: CRLF, a trailing space, non-ASCII, no final newline.
        var signed = Encoding.UTF8.GetBytes("serial = 7\r\nowner = \"caf\u00e9\" \r\n[[host]]");
        var encoded = Convert.ToBase64String(signed);
        var stored = "{\"name\":\"fleet\",\"serial\":7,\"body\":\"" + encoded + "\",\"signature\":\"SIG\",\"signer_fingerprint\":\"SHA256:abc\",\"stored_at\":\"2030-01-01T00:00:00Z\"}";
        var harness = new BusHarness();
        var api = harness.Enrolled(withGrant: true);
        harness.Bus.Json(stored);
        harness.Bus.Json(stored);

        var published = await api.PublishSiteDocumentAsync("fleet", 7, signed, "SIG", "SHA256:abc", "add a host", CancellationToken.None);
        var read = await api.GetSiteDocumentAsync("fleet", CancellationToken.None);

        Assert.Equal(2, harness.Bus.Requests.Count);
        var post = harness.Bus.Requests[0];
        Assert.Equal(("POST", "/api/mobile/site-documents/fleet"), (post.Method, post.PathAndQuery));
        using var body = JsonDocument.Parse(post.Body!);
        Assert.Equal(7, body.RootElement.GetProperty("serial").GetInt64());
        Assert.Equal(encoded, body.RootElement.GetProperty("body").GetString());
        Assert.Equal("SIG", body.RootElement.GetProperty("signature").GetString());
        Assert.Equal("SHA256:abc", body.RootElement.GetProperty("signer_fingerprint").GetString());
        Assert.Equal("grant-secret", body.RootElement.GetProperty("grant_secret").GetString());
        Assert.Equal(("GET", "/api/mobile/site-documents/fleet"), (harness.Bus.Requests[1].Method, harness.Bus.Requests[1].PathAndQuery));
        foreach (var document in new[] { published, read! })
        {
            Assert.Equal(("fleet", 7L, "SIG", "SHA256:abc"), (document.Name, document.Serial, document.Signature, document.SignerFingerprint));
            Assert.Equal(signed, document.Body);
        }
    }

    [Fact]
    public async Task GetSiteDocumentAsync_IsNullBeforeAnythingIsPublished()
    {
        var harness = new BusHarness();
        var api = harness.Enrolled(withGrant: true);
        harness.Bus.Json("""{"detail":"no such document"}""", HttpStatusCode.NotFound);

        Assert.Null(await api.GetSiteDocumentAsync("fleet", CancellationToken.None));
    }

    [Fact]
    public async Task SendHostCommandAsync_CarriesTheSignedBytesUnchanged()
    {
        var command = Encoding.UTF8.GetBytes("""{"v":1,"type":"sb-host-command","host":"host-office1-host","verb":"pause"}""");
        var harness = new BusHarness();
        var api = harness.Enrolled(withGrant: true);
        harness.Bus.Json(BusHarness.Message(91, "worker-hosts", "human:operator", "signed host command; see metadata", "question"));

        var carried = await api.SendHostCommandAsync("request-9", "worker-hosts", command, "SIG", CancellationToken.None);

        var request = Assert.Single(harness.Bus.Requests);
        Assert.Equal(("POST", "/api/mobile/hosts/commands"), (request.Method, request.PathAndQuery));
        using var body = JsonDocument.Parse(request.Body!);
        Assert.Equal("request-9", body.RootElement.GetProperty("request_id").GetString());
        Assert.Equal("worker-hosts", body.RootElement.GetProperty("channel").GetString());
        Assert.Equal(command, Convert.FromBase64String(body.RootElement.GetProperty("document").GetString()!));
        Assert.Equal("SIG", body.RootElement.GetProperty("signature").GetString());
        Assert.Equal("grant-secret", body.RootElement.GetProperty("grant_secret").GetString());
        Assert.Equal((91L, "worker-hosts"), (carried.Seq, carried.Channel));
    }

    [Fact]
    public async Task WorkerHostWrites_NeedSavedOperatorAccess()
    {
        var harness = new BusHarness();
        var api = harness.Enrolled(withGrant: false);

        await Assert.ThrowsAsync<InvalidOperationException>(() => api.CreateHostEnrollmentAsync("r", "host-a", "x", CancellationToken.None));
        await Assert.ThrowsAsync<InvalidOperationException>(() => api.PublishSiteDocumentAsync("fleet", 1, [1], "SIG", "", "x", CancellationToken.None));
        await Assert.ThrowsAsync<InvalidOperationException>(() => api.SendHostCommandAsync("r", "worker-hosts", [1], "SIG", CancellationToken.None));
        Assert.Empty(harness.Bus.Requests);
    }

    [Fact]
    public async Task GetManagedAgentsAsync_FollowsPagesUntilAShortOne()
    {
        var harness = new BusHarness();
        var api = harness.Enrolled();
        var fullPage = Enumerable.Range(0, BusApi.ManagedPageSize)
            .Select(index => new { id = $"id-{index:000}", name = $"agent {index:000}", state = "enabled", credential_epoch = 1 });
        harness.Bus
            .Json(JsonSerializer.Serialize(fullPage))
            .Json("""[{"id":"last","name":"zz-last","description":"Old","host":"box","state":"retired","credential_epoch":4,"last_seen_at":"2030-01-01T00:00:00Z","actions":[{"action":"unblock","effect":null}]}]""");

        var agents = await api.GetManagedAgentsAsync(includeRetired: true, CancellationToken.None);

        Assert.Equal(
            ["/api/mobile/admin/agents?state=all&limit=200", "/api/mobile/admin/agents?state=all&limit=200&after=agent%20199"],
            harness.Bus.Requests.Select(request => request.PathAndQuery));
        Assert.Equal(BusApi.ManagedPageSize + 1, agents.Count);
        Assert.Equal("", agents[0].Description);
        Assert.Empty(agents[0].Actions);
        var last = agents[^1];
        Assert.Equal(("last", "zz-last", "Old", "box", "retired", 4), (last.Id, last.Name, last.Description, last.Host, last.State, last.CredentialEpoch));
        Assert.Equal(DateTimeOffset.Parse("2030-01-01T00:00:00Z"), last.LastSeenAt);
        Assert.Equal([new AdminActionOption("unblock", "")], last.Actions);
    }

    [Fact]
    public async Task GetManagedAgentsAsync_LeavesRetiredAgentsOutUnlessAsked()
    {
        var harness = new BusHarness();
        var api = harness.Enrolled();
        harness.Bus.Json("[]");

        Assert.Empty(await api.GetManagedAgentsAsync(includeRetired: false, CancellationToken.None));
        Assert.Equal("/api/mobile/admin/agents?state=managed&limit=200", Assert.Single(harness.Bus.Requests).PathAndQuery);
    }

    [Fact]
    public async Task GetManagedDevicesAndServicePrincipals_MapTheLists()
    {
        var harness = new BusHarness();
        var api = harness.Enrolled();
        harness.Bus
            .Json("""[{"id":"d1","label":"Ops PC","status":"enabled","last_seen_at":"2030-01-01T00:00:00Z","has_write_grant":true,"this_device":true,"actions":[{"action":"revoke","effect":"Revokes it"}]}]""")
            .Json("""[{"id":"s1","name":"ci","agent_name_prefix":"ci-worker","status":"blocked","version":3,"actions":null}]""");

        var device = Assert.Single(await api.GetManagedDevicesAsync(CancellationToken.None));
        var principal = Assert.Single(await api.GetManagedServicePrincipalsAsync(CancellationToken.None));

        Assert.Equal(["/api/mobile/admin/devices", "/api/mobile/admin/service-principals"], harness.Bus.Requests.Select(request => request.PathAndQuery));
        Assert.Equal(("d1", "Ops PC", "enabled", true, true), (device.Id, device.Label, device.Status, device.HasWriteGrant, device.ThisDevice));
        Assert.Equal(DateTimeOffset.Parse("2030-01-01T00:00:00Z"), device.LastSeenAt);
        Assert.Equal([new AdminActionOption("revoke", "Revokes it")], device.Actions);
        Assert.Equal(("s1", "ci", "ci-worker", "blocked", 3), (principal.Id, principal.Name, principal.AgentNamePrefix, principal.Status, principal.Version));
        Assert.Empty(principal.Actions);
    }

    [Fact]
    public async Task ControlAgentAsync_SendsWhatWasListedSoAChangedAgentIsRefused()
    {
        var harness = new BusHarness();
        var api = harness.Enrolled(withGrant: true);
        harness.Bus.Json("""{"applied":true,"detail":"Blocked.","target_label":"agent-one","state":"blocked","secret":null}""");

        var result = await api.ControlAgentAsync("agent/1", "agent-one", 7, "block", "noisy", CancellationToken.None);

        var request = Assert.Single(harness.Bus.Requests);
        Assert.Equal("POST", request.Method);
        Assert.Equal("/api/mobile/admin/agents/agent%2F1/control", request.PathAndQuery);
        using var body = JsonDocument.Parse(request.Body!);
        Assert.Equal("block", body.RootElement.GetProperty("action").GetString());
        Assert.Equal("agent-one", body.RootElement.GetProperty("expected_name").GetString());
        Assert.Equal(7, body.RootElement.GetProperty("expected_credential_epoch").GetInt32());
        Assert.Equal("noisy", body.RootElement.GetProperty("reason").GetString());
        Assert.Equal("grant-secret", body.RootElement.GetProperty("grant_secret").GetString());
        Assert.True(Guid.TryParseExact(body.RootElement.GetProperty("request_id").GetString(), "D", out _));
        Assert.Equal(new ControlResult(true, "Blocked.", "agent-one", "blocked", null), result);
    }

    [Fact]
    public async Task ControlServicePrincipalAsync_ReturnsARotatedSecret()
    {
        var harness = new BusHarness();
        var api = harness.Enrolled(withGrant: true);
        harness.Bus.Json("""{"applied":true,"detail":"Rotated.","target_label":"ci","state":"enabled","secret":"new-secret"}""");

        var result = await api.ControlServicePrincipalAsync("sp 1", "ci", 3, "rotate", "leaked", CancellationToken.None);

        var request = Assert.Single(harness.Bus.Requests);
        Assert.Equal("/api/mobile/admin/service-principals/sp%201/control", request.PathAndQuery);
        using var body = JsonDocument.Parse(request.Body!);
        Assert.Equal("rotate", body.RootElement.GetProperty("action").GetString());
        Assert.Equal("ci", body.RootElement.GetProperty("expected_name").GetString());
        Assert.Equal(3, body.RootElement.GetProperty("expected_version").GetInt32());
        Assert.Equal("new-secret", result.Secret);
        Assert.Equal("enabled", result.State);
    }

    [Fact]
    public async Task ControlAgentAsync_ARefusalFromTheBusIsReported()
    {
        var harness = new BusHarness();
        var api = harness.Enrolled(withGrant: true);
        harness.Bus.Json("""{"detail":"The agent changed since it was listed."}""", HttpStatusCode.Conflict);

        var error = await Assert.ThrowsAsync<BusApiException>(() =>
            api.ControlAgentAsync("a1", "agent-one", 7, "block", "noisy", CancellationToken.None));

        Assert.Equal(409, error.StatusCode);
        Assert.Equal("StruggleBus said: The agent changed since it was listed.", error.Message);
    }

    [Fact]
    public async Task PostHumanMessageAsync_PostsAsTheOperatorWithTheGrant()
    {
        var harness = new BusHarness();
        var api = harness.Enrolled(withGrant: true);
        harness.Bus.Json(BusHarness.Message(77, "humans", "human:operator", "On it.", "answer", replyTo: 70));

        var posted = await api.PostHumanMessageAsync("request-1", "On it.", HumanMessageKind.Answer, 70, CancellationToken.None);

        var request = Assert.Single(harness.Bus.Requests);
        Assert.Equal("POST", request.Method);
        Assert.Equal("/api/mobile/humans/messages", request.PathAndQuery);
        Assert.Equal("Bearer device-credential", request.Authorization);
        Assert.Equal(HumansLogic.BuildPostJson("request-1", "On it.", HumanMessageKind.Answer, 70, "grant-secret"), request.Body);
        Assert.Equal(new BusMessage(77, "humans", "human:operator", "On it.", "answer", DateTimeOffset.Parse("2030-01-01T00:00:00Z"), 70), posted);
    }

    [Fact]
    public async Task PostHumanMessageAsync_RejectsAPostTheServerPutElsewhere()
    {
        var harness = new BusHarness();
        var api = harness.Enrolled(withGrant: true);
        harness.Bus.Json(BusHarness.Message(77, "ops", "human:operator", "On it.", "chat"));

        var error = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            api.PostHumanMessageAsync("request-1", "On it.", HumanMessageKind.Chat, null, CancellationToken.None));

        Assert.Equal("The server placed the post outside #humans.", error.Message);
    }

    [Fact]
    public async Task PostHumanMessageAsync_NeedsOperatorAccessFirst()
    {
        var harness = new BusHarness();
        var api = harness.Enrolled();

        var error = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            api.PostHumanMessageAsync("request-1", "Hello", HumanMessageKind.Chat, null, CancellationToken.None));

        Assert.Equal("Operator access is not configured.", error.Message);
        Assert.Empty(harness.Bus.Requests);
    }
}

public sealed class BusApiStreamTests
{
    private static async Task<(StreamEnd End, List<BusMessage> Received, int Opened)> Stream(BusApi api, string? channel = null, CancellationToken token = default)
    {
        var received = new List<BusMessage>();
        var opened = 0;
        var end = await api.StreamAsync(
            channel,
            () => { opened++; return Task.CompletedTask; },
            message => { received.Add(message); return Task.CompletedTask; },
            token);
        return (end, received, opened);
    }

    [Fact]
    public async Task DeliversMessagesInOrderAndEndsQuietlyWhenTheBusClosesTheStream()
    {
        var harness = new BusHarness();
        var api = harness.Enrolled();
        harness.Bus.Events(
            ": connected\n\n" +
            BusHarness.Event("message", BusHarness.Message(1, body: "one")) +
            "id: 2\nretry: 500\ndata: " + BusHarness.Message(2, body: "two") + "\n\n");

        var (end, received, opened) = await Stream(api, "ops");

        Assert.Equal(new StreamEnd(StreamEndKind.RoutineClosure, string.Empty), end);
        Assert.Equal(1, opened);
        Assert.Equal(["one", "two"], received.Select(message => message.Body));
        var request = Assert.Single(harness.Bus.Requests);
        Assert.Equal("GET", request.Method);
        Assert.Equal("/api/mobile/stream?since=0&channel=ops", request.PathAndQuery);
        Assert.Equal("Bearer device-credential", request.Authorization);
        Assert.Equal("text/event-stream", request.Headers["Accept"]);
        Assert.Equal("0", request.Headers["Last-Event-ID"]);
    }

    [Fact]
    public async Task ReconnectingResumesAfterTheLastMessageAndSkipsOnesAlreadySeen()
    {
        var harness = new BusHarness();
        var api = harness.Enrolled();
        harness.Bus
            .Events(BusHarness.Event("message", BusHarness.Message(5)) + BusHarness.Event("message", BusHarness.Message(6)))
            .Events(BusHarness.Event("message", BusHarness.Message(6)) + BusHarness.Event("message", BusHarness.Message(4)) + BusHarness.Event("message", BusHarness.Message(7)));

        var first = await Stream(api);
        var second = await Stream(api);

        Assert.Equal([5L, 6L], first.Received.Select(message => message.Seq));
        Assert.Equal([7L], second.Received.Select(message => message.Seq));
        Assert.Equal("/api/mobile/stream?since=6", harness.Bus.Requests[1].PathAndQuery);
        Assert.Equal("6", harness.Bus.Requests[1].Headers["Last-Event-ID"]);
    }

    [Fact]
    public async Task AMessageSplitOverSeveralDataLinesIsOneMessage()
    {
        var harness = new BusHarness();
        var api = harness.Enrolled();
        harness.Bus.Events("data: {\"seq\":3,\"channel\":\"ops\",\ndata: \"agent_name\":\"agent-one\",\"body\":\"split\",\ndata: \"kind\":\"status\",\"created_at\":\"2030-01-01T00:00:00Z\"}\n\n");

        var (_, received, _) = await Stream(api);

        Assert.Equal("split", Assert.Single(received).Body);
    }

    [Theory]
    [InlineData("server_stopping", StreamEndKind.ServerStopping)]
    [InlineData("agent_access_frozen", StreamEndKind.AccessFrozen)]
    [InlineData("credential_inactive", StreamEndKind.CredentialInactive)]
    [InlineData("something_new", StreamEndKind.ProtocolFailure)]
    public async Task ATerminalEventEndsTheStreamWithItsReason(string eventName, StreamEndKind expected)
    {
        var harness = new BusHarness();
        var api = harness.Enrolled();
        harness.Bus.Events(
            BusHarness.Event("message", BusHarness.Message(1)) +
            BusHarness.Event(eventName, """{"detail":"The bus said why."}""") +
            BusHarness.Event("message", BusHarness.Message(2)));

        var (end, received, _) = await Stream(api);

        Assert.Equal(new StreamEnd(expected, "The bus said why."), end);
        Assert.Equal([1L], received.Select(message => message.Seq));
    }

    [Fact]
    public async Task ATerminalEventWithoutReadableDetailStillEndsTheStream()
    {
        var harness = new BusHarness();
        var api = harness.Enrolled();
        harness.Bus.Events(BusHarness.Event("server_stopping", "not json")).Events(BusHarness.Event("server_stopping", "null"));

        var garbled = await Stream(api);
        var empty = await Stream(api);

        Assert.Equal(new StreamEnd(StreamEndKind.ServerStopping, "The live stream returned an invalid terminal event."), garbled.End);
        Assert.Equal(new StreamEnd(StreamEndKind.ServerStopping, "The live stream ended without a detail message."), empty.End);
    }

    [Fact]
    public async Task ARevokedCredentialEndsTheStreamBeforeItOpens()
    {
        var harness = new BusHarness();
        var api = harness.Enrolled();
        harness.Bus.Json("""{"detail":"Device credential is not valid."}""", HttpStatusCode.Unauthorized);

        var (end, received, opened) = await Stream(api);

        Assert.Equal(new StreamEnd(StreamEndKind.CredentialInactive, "The Windows device credential is no longer active."), end);
        Assert.Equal(0, opened);
        Assert.Empty(received);
    }

    [Fact]
    public async Task ARateLimitCarriesHowLongTheBusAskedUsToWait()
    {
        var harness = new BusHarness();
        var api = harness.Enrolled();
        harness.Bus
            .Answer((_, _) =>
            {
                var response = new HttpResponseMessage(HttpStatusCode.TooManyRequests);
                response.Headers.RetryAfter = new System.Net.Http.Headers.RetryConditionHeaderValue(TimeSpan.FromSeconds(7));
                return response;
            })
            .Answer((_, _) => new HttpResponseMessage(HttpStatusCode.TooManyRequests));

        var timed = await Stream(api);
        var untimed = await Stream(api);

        Assert.Equal(new StreamEnd(StreamEndKind.RateLimited, "The server is limiting live-stream connections.", TimeSpan.FromSeconds(7)), timed.End);
        Assert.Equal(0, timed.Opened);
        Assert.Null(untimed.End.RetryAfter);
        Assert.Equal(TimeSpan.FromSeconds(5), MonitorLogic.DecideStreamEnd(untimed.End, 1).Delay);
    }

    [Fact]
    public async Task AServerErrorIsThrownSoTheCallerCanBackOff()
    {
        var harness = new BusHarness();
        var api = harness.Enrolled();
        harness.Bus.Json("""{"detail":"Database is locked."}""", HttpStatusCode.InternalServerError);
        var opened = 0;

        var error = await Assert.ThrowsAsync<BusApiException>(() =>
            api.StreamAsync(null, () => { opened++; return Task.CompletedTask; }, _ => Task.CompletedTask, CancellationToken.None));

        Assert.Equal(500, error.StatusCode);
        Assert.True(MonitorLogic.IsTransient(error));
        Assert.Equal(0, opened);
    }

    [Fact]
    public async Task ADroppedConnectionIsDescribedAndStaysTransient()
    {
        var harness = new BusHarness();
        var api = harness.Enrolled();
        harness.Bus.Fails(new HttpRequestException("raw", new SocketException((int)SocketError.ConnectionRefused)));

        var error = await Assert.ThrowsAsync<HttpRequestException>(() => Stream(api));

        Assert.StartsWith("Could not connect to the bus at bus.test:8443.", error.Message);
    }

    [Fact]
    public async Task AMessageFromAnotherChannelIsAProtocolErrorAndIsNotDelivered()
    {
        var harness = new BusHarness();
        var api = harness.Enrolled();
        harness.Bus.Events(BusHarness.Event("message", BusHarness.Message(1, "announce")));
        var received = new List<BusMessage>();

        var error = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            api.StreamAsync("ops", () => Task.CompletedTask, message => { received.Add(message); return Task.CompletedTask; }, CancellationToken.None));

        Assert.Equal("The stream returned a message outside the requested channel.", error.Message);
        Assert.Empty(received);
    }

    [Fact]
    public async Task AMalformedMessageStopsTheStreamWithAnError()
    {
        var harness = new BusHarness();
        var api = harness.Enrolled();
        harness.Bus.Events(BusHarness.Event("message", "{not json"));

        await Assert.ThrowsAsync<JsonException>(() => Stream(api));
    }

    [Fact]
    public async Task CancellingStopsReadingWithoutAnError()
    {
        var harness = new BusHarness();
        var api = harness.Enrolled();
        harness.Bus.Events(BusHarness.Event("message", BusHarness.Message(1)));
        using var cancellation = new CancellationTokenSource();
        var received = new List<BusMessage>();

        var end = await api.StreamAsync(
            null,
            () => { cancellation.Cancel(); return Task.CompletedTask; },
            message => { received.Add(message); return Task.CompletedTask; },
            cancellation.Token);

        Assert.Equal(StreamEndKind.RoutineClosure, end.Kind);
        Assert.Empty(received);
    }
}

public sealed class DecodeStreamEventTests
{
    [Theory]
    [InlineData("null", "Message event data is empty.")]
    [InlineData("""{"seq":-1,"channel":"ops","body":"x","kind":"status","created_at":"2030-01-01T00:00:00Z"}""", "Message sequence is negative.")]
    [InlineData("""{"seq":1,"channel":" ","body":"x","kind":"status","created_at":"2030-01-01T00:00:00Z"}""", "Message channel is empty.")]
    public void RejectsAMessageThatCannotBeShown(string payload, string expected)
    {
        var error = Assert.Throws<InvalidOperationException>(() => BusApi.DecodeStreamEvent("message", payload, null));

        Assert.Equal(expected, error.Message);
    }

    [Fact]
    public void AMessageWithoutAnAuthorHasAnEmptyAgentName()
    {
        var decoded = BusApi.DecodeStreamEvent("MESSAGE", """{"seq":4,"channel":"ops","body":"x","kind":"status","created_at":"2030-01-01T00:00:00Z"}""", "ops");

        Assert.Null(decoded.End);
        Assert.Equal(new BusMessage(4, "ops", "", "x", "status", DateTimeOffset.Parse("2030-01-01T00:00:00Z")), decoded.Message);
    }

    [Fact]
    public void TerminalEventNamesIgnoreCase() =>
        Assert.Equal(StreamEndKind.ServerStopping, BusApi.DecodeStreamEvent("Server_Stopping", "{}", null).End?.Kind);
}

public sealed class ProtectedStoreTests
{
    private static readonly byte[] CaDer = BusHarness.CaDer;

    [Fact]
    public void SessionStore_RoundTripsThroughTheProtectedFile()
    {
        var path = Path.Combine(TempFiles.NewDirectory(), "nested", "session.bin");

        BusApi.SessionStore.SaveToPath(path, new Session("https://bus.test", "credential", CaDer, "device-1", "Test PC"));
        var loaded = BusApi.SessionStore.LoadFromPath(path, out var warning);

        Assert.Null(warning);
        Assert.Equal(("https://bus.test", "credential", "device-1", "Test PC"), (loaded!.Endpoint, loaded.Credential, loaded.DeviceId, loaded.DeviceLabel));
        Assert.Equal(CaDer, loaded.CaDer);
        Assert.DoesNotContain("credential", File.ReadAllText(path));
    }

    [Theory]
    [InlineData("http://bus.test", "credential", "device-1")]
    [InlineData("not a url", "credential", "device-1")]
    [InlineData("https://bus.test", " ", "device-1")]
    [InlineData("https://bus.test", "credential", "")]
    public void SessionStore_ADecryptedSessionWithInvalidFieldsIsQuarantined(string endpoint, string credential, string deviceId)
    {
        // The app must still start, and ask for a new enrollment, when the saved one is not usable.
        var path = Path.Combine(TempFiles.NewDirectory(), "session.bin");
        BusApi.SessionStore.SaveToPath(path, new Session(endpoint, credential, CaDer, deviceId, "Test PC"));

        Assert.Null(BusApi.SessionStore.LoadFromPath(path, out var warning));

        Assert.Contains("quarantined", warning);
        Assert.False(File.Exists(path));
    }

    [Fact]
    public void SessionStore_AnEmptySessionAndAnUnreadableCertificateAreQuarantined()
    {
        var directory = TempFiles.NewDirectory();
        var empty = Path.Combine(directory, "empty.bin");
        File.WriteAllBytes(empty, System.Security.Cryptography.ProtectedData.Protect("null"u8.ToArray(), null, System.Security.Cryptography.DataProtectionScope.CurrentUser));
        var badCertificate = Path.Combine(directory, "bad-certificate.bin");
        BusApi.SessionStore.SaveToPath(badCertificate, new Session("https://bus.test", "credential", [1, 2, 3], "device-1", "Test PC"));

        Assert.Null(BusApi.SessionStore.LoadFromPath(empty, out var emptyWarning));
        Assert.Contains("quarantined", emptyWarning);
        Assert.False(File.Exists(empty));
        Assert.Null(BusApi.SessionStore.LoadFromPath(badCertificate, out var certificateWarning));
        Assert.Contains("quarantined", certificateWarning);
        Assert.False(File.Exists(badCertificate));
    }

    [Fact]
    public void AFileInUseIsReportedButCannotBeMovedAside()
    {
        var path = Path.Combine(TempFiles.NewDirectory(), "session.bin");
        BusApi.SessionStore.SaveToPath(path, new Session("https://bus.test", "credential", CaDer, "device-1", "Test PC"));

        using (new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.None))
        {
            Assert.Null(BusApi.SessionStore.LoadFromPath(path, out var warning));
            Assert.Contains("could not be read", warning);
        }

        Assert.True(File.Exists(path));
        Assert.NotNull(BusApi.SessionStore.LoadFromPath(path, out _));
    }

    [Fact]
    public void GrantStore_RoundTripsAndAGrantWithoutASecretIsQuarantined()
    {
        var directory = TempFiles.NewDirectory();
        var good = Path.Combine(directory, "nested", "grant.bin");
        var blank = Path.Combine(directory, "blank.bin");
        var unsplit = Path.Combine(directory, "unsplit.bin");
        BusApi.GrantStore.SaveToPath(good, "device-1", "secret\nwith newline");
        BusApi.GrantStore.SaveToPath(blank, "device-1", " ");
        File.WriteAllBytes(unsplit, System.Security.Cryptography.ProtectedData.Protect("no-separator"u8.ToArray(), null, System.Security.Cryptography.DataProtectionScope.CurrentUser));

        Assert.Equal("secret\nwith newline", BusApi.GrantStore.LoadFromPath(good, "device-1", out _));
        Assert.Null(BusApi.GrantStore.LoadFromPath(blank, "device-1", out var blankWarning));
        Assert.Contains("quarantined", blankWarning);
        Assert.Null(BusApi.GrantStore.LoadFromPath(unsplit, "device-1", out _));
        Assert.False(File.Exists(blank));
        Assert.False(File.Exists(unsplit));
    }

    [Fact]
    public void MissingFilesAreSimplyAbsent()
    {
        var directory = TempFiles.NewDirectory();

        Assert.Null(BusApi.SessionStore.LoadFromPath(Path.Combine(directory, "session.bin"), out var sessionWarning));
        Assert.Null(BusApi.GrantStore.LoadFromPath(Path.Combine(directory, "grant.bin"), "device-1", out var grantWarning));
        Assert.Null(sessionWarning);
        Assert.Null(grantWarning);
    }
}

/// <summary>The stores and the default constructor as the app uses them, against the redirected data folder.</summary>
[Collection(StaWindowAdminCollection.Name)]
public sealed class DefaultDataDirectoryTests
{
    public DefaultDataDirectoryTests()
    {
        Assert.Equal(TestDataDirectory.Path, AppPaths.DataDirectory);
        if (Directory.Exists(TestDataDirectory.Path)) Directory.Delete(TestDataDirectory.Path, recursive: true);
    }

    [Fact]
    public void AppPaths_PutFilesInTheDataDirectory() =>
        Assert.Equal(Path.Combine(TestDataDirectory.Path, "settings.json"), AppPaths.File("settings.json"));

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void AppPaths_DefaultToTheUsersLocalAppData(string? custom) =>
        Assert.Equal(
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "StruggleBusMonitor"),
            AppPaths.ResolveDataDirectory(custom));

    [Fact]
    public void AppPaths_HonourTheOverride() =>
        Assert.Equal(@"D:\dev-data", AppPaths.ResolveDataDirectory(@"D:\dev-data"));

    [Fact]
    public void TheStoresSaveLoadAndClearInTheDataDirectory()
    {
        BusApi.SessionStore.Save(new Session("https://bus.test", "credential", BusHarness.CaDer, "device-1", "Test PC"));
        BusApi.GrantStore.Save("device-1", "grant");

        Assert.True(File.Exists(Path.Combine(TestDataDirectory.Path, "session.bin")));
        Assert.True(File.Exists(Path.Combine(TestDataDirectory.Path, "operator-grant.bin")));
        Assert.Equal("device-1", BusApi.SessionStore.Load(out _)?.DeviceId);
        Assert.Equal("grant", BusApi.GrantStore.Load("device-1", out _));
        var api = new BusApi();
        Assert.Equal("device-1", api.Session?.DeviceId);
        Assert.True(api.HasOperatorGrant());

        BusApi.GrantStore.Clear();
        Assert.False(api.HasOperatorGrant());
        BusApi.SessionStore.Clear();
        Assert.Null(BusApi.SessionStore.Load(out _));
        Assert.Null(new BusApi().Session);
    }

    [Fact]
    public void ClearingAStoreThatIsAFolderIsLeftAlone()
    {
        Directory.CreateDirectory(Path.Combine(TestDataDirectory.Path, "operator-grant.bin"));

        BusApi.GrantStore.Clear();

        Assert.True(Directory.Exists(Path.Combine(TestDataDirectory.Path, "operator-grant.bin")));
    }

    [Fact]
    public void SettingsAndConnectionHistoryLiveInTheDataDirectory()
    {
        var settings = AppSettings.Load();
        Assert.True(settings.AutoUpdate);
        settings.AutoUpdate = false;
        settings.Save();
        var log = ConnectionLog.Load();
        Assert.Empty(log.Events);
        log.Add(new ConnectionEvent(DateTimeOffset.Parse("2030-01-01T00:00:00Z"), "Ok", "Connected to the bus."));

        Assert.False(AppSettings.Load().AutoUpdate);
        Assert.Equal("Connected to the bus.", Assert.Single(ConnectionLog.Load().Events).Text);
        Assert.True(File.Exists(Path.Combine(TestDataDirectory.Path, "settings.json")));
        Assert.True(File.Exists(Path.Combine(TestDataDirectory.Path, "connection-log.json")));
    }
}
