using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace StruggleBusMonitor;

public sealed class BusApi
{
    private const int LiveSnapshotLimit = 100;
    private const int ExportSnapshotLimit = 200;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly Func<CaTrust, HttpMessageHandler> _createHandler;
    private readonly string _sessionPath;
    private readonly string _grantPath;
    private HttpMessageHandler? _handler;
    private CaTrust? _trust;
    private HttpClient _http = new();
    private HttpClient _streamHttp = new() { Timeout = Timeout.InfiniteTimeSpan };
    private readonly object _cursorLock = new();
    private Session? _session;
    private long _cursor;

    public BusApi() : this(AppPaths.DataDirectory, CaTrust.CreateHandler)
    {
    }

    /// <summary>
    /// For tests: keeps the enrollment and grant in <paramref name="dataDirectory"/> and sends every
    /// request through the handler <paramref name="createHandler"/> returns, so no network is needed.
    /// </summary>
    internal BusApi(string dataDirectory, Func<CaTrust, HttpMessageHandler> createHandler)
    {
        _createHandler = createHandler;
        _sessionPath = Path.Combine(dataDirectory, SessionStore.FileName);
        _grantPath = Path.Combine(dataDirectory, GrantStore.FileName);
        _session = SessionStore.LoadFromPath(_sessionPath, out var warning);
        StartupWarning = warning;
        if (_session is not null) Configure(_session.CaDer);
    }

    public Session? Session => _session;
    public string? StartupWarning { get; }

    public async Task<Session> EnrollAsync(string rawPayload, CancellationToken cancellationToken)
    {
        var (payload, ca) = ReadEnrollment(rawPayload, DateTimeOffset.UtcNow);
        Configure(ca);
        using var request = new HttpRequestMessage(HttpMethod.Post, new Uri(new Uri(payload.BaseUrl), "api/mobile/enrollments/redeem"));
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", payload.Enrollment);
        request.Content = JsonContent.Create(new { request_id = Guid.NewGuid().ToString() });
        using var response = await SendAsync(_http, request, HttpCompletionOption.ResponseContentRead, cancellationToken);
        await EnsureSuccess(response);
        var body = await ReadBodyAsync<EnrollmentResponse>(response, "Enrollment returned no credential.", cancellationToken);
        var session = new Session(payload.BaseUrl.TrimEnd('/'), body.CredentialSecret, ca, body.DeviceId, body.DeviceLabel);
        _session = session;
        ResetCursor();
        SessionStore.SaveToPath(_sessionPath, session);
        return session;
    }

    internal const string IncompleteEnrollment = "That is not a complete enrollment payload. Paste the whole JSON block from the device console.";
    internal const string UnreadableEnrollmentCertificate = "That is not a complete enrollment payload: its certificate could not be read. Paste the whole JSON block from the device console.";

    /// <summary>
    /// Checks a pasted enrollment payload before anything is sent and returns it with its CA
    /// certificate. Every way it can be wrong is reported as a sentence, never as a .NET error.
    /// </summary>
    internal static (EnrollmentPayload Payload, byte[] Ca) ReadEnrollment(string rawPayload, DateTimeOffset now)
    {
        var payload = ParseEnrollment(rawPayload);
        if (!IsComplete(payload)) throw new InvalidOperationException(IncompleteEnrollment);
        if (!IsSupported(payload)) throw new InvalidOperationException("Only version 1 HTTPS enrollment payloads are supported.");
        RequireUnexpired(payload, now);
        return (payload, ReadEnrollmentCa(payload));
    }

    private static EnrollmentPayload ParseEnrollment(string rawPayload)
    {
        try
        {
            return JsonSerializer.Deserialize<EnrollmentPayload>(rawPayload, JsonOptions)
                ?? throw new InvalidOperationException(IncompleteEnrollment);
        }
        catch (Exception error) when (error is JsonException or ArgumentException)
        {
            throw new InvalidOperationException(IncompleteEnrollment);
        }
    }

    private static bool IsComplete(EnrollmentPayload payload) =>
        payload.ExpiresAt != default &&
        !new[] { payload.BaseUrl, payload.CaDer, payload.CaSha256, payload.Enrollment }.Any(string.IsNullOrWhiteSpace);

    private static bool IsSupported(EnrollmentPayload payload) =>
        payload.Version == 1 && Uri.TryCreate(payload.BaseUrl, UriKind.Absolute, out var address) && address.Scheme == Uri.UriSchemeHttps;

    private static void RequireUnexpired(EnrollmentPayload payload, DateTimeOffset now)
    {
        if (payload.ExpiresAt > now) return;
        var expired = payload.ExpiresAt.ToLocalTime();
        throw new InvalidOperationException(
            $"This enrollment payload expired at {expired:HH:mm} on {expired:d MMM yyyy}. Create a new one on the bus Devices page. " +
            "If it was only just created, check this PC's date and time: a wrong clock also causes this.");
    }

    /// <summary>The payload's CA certificate, once it matches its fingerprint and reads as a certificate.</summary>
    private static byte[] ReadEnrollmentCa(EnrollmentPayload payload)
    {
        byte[] ca;
        try { ca = Convert.FromBase64String(payload.CaDer); }
        catch (FormatException) { throw new InvalidOperationException(UnreadableEnrollmentCertificate); }
        var actual = Convert.ToHexString(SHA256.HashData(ca)).ToLowerInvariant();
        if (!actual.Equals(payload.CaSha256, StringComparison.Ordinal)) throw new InvalidOperationException("CA fingerprint does not match.");
        try { using var certificate = X509CertificateLoader.LoadCertificate(ca); }
        catch (CryptographicException) { throw new InvalidOperationException(UnreadableEnrollmentCertificate); }
        return ca;
    }

    /// <summary>
    /// Removes this PC's enrollment and operator grant from disk. The server-side device stays valid
    /// until it is revoked; this only makes the PC forget it.
    /// </summary>
    public void ForgetSession()
    {
        ProtectedStoreRecovery.DeleteQuietly(_grantPath);
        ProtectedStoreRecovery.DeleteQuietly(_sessionPath);
        _session = null;
        ResetCursor();
    }

    public async Task<List<BusAgent>> GetAgentsAsync(CancellationToken cancellationToken)
    {
        var agents = await GetAsync<List<AgentResponse>>("api/mobile/agents", cancellationToken);
        return agents.Select(MapAgent).ToList();
    }

    public async Task<Snapshot> GetSnapshotAsync(CancellationToken cancellationToken)
    {
        RequireSession();
        var messages = await GetAsync<List<MessageResponse>>($"api/mobile/snapshot?limit={LiveSnapshotLimit}", cancellationToken);
        var agents = await GetAsync<List<AgentResponse>>("api/mobile/agents", cancellationToken);
        var status = await GetAsync<StatusResponse>("api/mobile/status", cancellationToken);
        var mappedMessages = messages.Select(MapMessage).OrderBy(x => x.Seq).ToList();
        AdvanceCursor(mappedMessages.LastOrDefault()?.Seq ?? 0);
        return new Snapshot(mappedMessages, agents.Select(MapAgent).ToList(), status.State, CurrentCursor());
    }

    public async Task<List<BusMessage>> GetRecentMessagesAsync(CancellationToken cancellationToken)
    {
        var messages = await GetMessagesAsync(LiveSnapshotLimit, cancellationToken);
        AdvanceCursor(messages.LastOrDefault()?.Seq ?? 0);
        return messages;
    }

    /// <summary>
    /// True when the bus has the history and search reads (added after 0.2.61). Older servers
    /// ignore the extra snapshot parameters and would return the wrong page, so callers must ask.
    /// </summary>
    public async Task<bool> ProbeHistoryAsync(CancellationToken cancellationToken)
    {
        try
        {
            await GetAsync<List<MessageResponse>>("api/mobile/search?query=bus&limit=1", cancellationToken);
            return true;
        }
        catch (BusApiException)
        {
            return false;
        }
    }

    /// <summary>The newest messages matching the filters, oldest first; <paramref name="before"/> pages back.</summary>
    public async Task<List<BusMessage>> GetHistoryAsync(string? channel, string? agent, long? before, int limit, CancellationToken cancellationToken)
    {
        var messages = await GetAsync<List<MessageResponse>>(BuildHistoryPath(channel, agent, before, limit), cancellationToken);
        return messages.Select(MapMessage).OrderBy(message => message.Seq).ToList();
    }

    /// <summary>Full-text search across the whole board, newest first.</summary>
    public async Task<List<BusMessage>> SearchAsync(string query, int limit, CancellationToken cancellationToken)
    {
        var hits = await GetAsync<List<MessageResponse>>($"api/mobile/search?query={Uri.EscapeDataString(query)}&limit={limit}", cancellationToken);
        return hits.Select(MapMessage).ToList();
    }

    internal static string BuildHistoryPath(string? channel, string? agent, long? before, int limit)
    {
        var path = new StringBuilder($"api/mobile/snapshot?limit={limit}");
        if (!string.IsNullOrWhiteSpace(channel)) path.Append("&channel=").Append(Uri.EscapeDataString(channel));
        if (!string.IsNullOrWhiteSpace(agent)) path.Append("&agent=").Append(Uri.EscapeDataString(agent));
        if (before is { } sequence) path.Append("&before=").Append(sequence);
        return path.ToString();
    }

    public Task<List<BusMessage>> GetExportMessagesAsync(CancellationToken cancellationToken) =>
        GetMessagesAsync(ExportSnapshotLimit, cancellationToken);

    public async Task<List<BusChannel>> GetChannelsAsync(CancellationToken cancellationToken)
    {
        var channels = await GetAsync<List<ChannelResponse>>("api/mobile/channels", cancellationToken);
        return channels.Select(channel => new BusChannel(channel.Id, channel.Name, channel.Purpose ?? string.Empty))
            .OrderBy(channel => channel.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private async Task<List<BusMessage>> GetMessagesAsync(int limit, CancellationToken cancellationToken)
    {
        RequireSession();
        var messages = await GetAsync<List<MessageResponse>>($"api/mobile/snapshot?limit={limit}", cancellationToken);
        return messages.Select(MapMessage).OrderBy(x => x.Seq).ToList();
    }

    public async Task<Confirmation> RequestConfirmationAsync(OperatorAction action, string targetId, CancellationToken cancellationToken)
    {
        var value = await PostAsync<ConfirmationResponse>("api/mobile/confirmations", new { request_id = Guid.NewGuid().ToString(), action = WireAction(action), target_id = targetId }, cancellationToken);
        return new Confirmation(value.ConfirmationId, value.Action, value.TargetId, value.TargetLabel, value.Effect);
    }

    public async Task EstablishGrantAsync(string password, string reason, CancellationToken cancellationToken)
    {
        var value = await PostAsync<GrantResponse>("api/mobile/grants", new { request_id = Guid.NewGuid().ToString(), operator_password = password, reason }, cancellationToken);
        var session = RequireSession();
        GrantStore.SaveToPath(_grantPath, session.DeviceId, value.GrantSecret);
    }

    public async Task<ActionResult> PerformActionAsync(Confirmation confirmation, string reason, CancellationToken cancellationToken)
    {
        var grant = RequireGrant("Operator access is not configured.");
        var value = await PostAsync<ActionResponse>("api/mobile/actions", new { request_id = Guid.NewGuid().ToString(), confirmation_id = confirmation.Id, action = confirmation.Action, target_id = confirmation.TargetId, grant_secret = grant, reason }, cancellationToken);
        return new ActionResult(value.Applied, value.Detail, value.TargetLabel);
    }

    private string RequireGrant(string whenMissing = "Operator access is not configured. Save it on the Admin page first.")
    {
        var session = RequireSession();
        return GrantStore.LoadFromPath(_grantPath, session.DeviceId, out var warning)
            ?? throw new InvalidOperationException(warning ?? whenMissing);
    }

    /// <summary>Creates a single-use agent enrollment and returns its onboarding package text.</summary>
    public async Task<EnrollmentResult> CreateAgentEnrollmentAsync(string name, string description, string reason, CancellationToken cancellationToken)
    {
        var value = await PostAsync<AgentEnrollmentResponse>("api/mobile/enrollments/agents",
            new { request_id = Guid.NewGuid().ToString(), name, description, reason, grant_secret = RequireGrant() }, cancellationToken);
        return new EnrollmentResult(
            $"Onboarding package for {value.AgentName}",
            $"Single use. Expires {FeedLogic.TimeLabel(value.ExpiresAt, DateTimeOffset.Now, withSeconds: false)}. Hand it to the agent privately.",
            value.Package);
    }

    /// <summary>Creates a service principal and returns its credential secret, which the bus shows once.</summary>
    public async Task<EnrollmentResult> CreateServicePrincipalAsync(string name, string agentNamePrefix, string reason, CancellationToken cancellationToken)
    {
        var value = await PostAsync<ServicePrincipalResponse>("api/mobile/enrollments/service-principals",
            new { request_id = Guid.NewGuid().ToString(), name, agent_name_prefix = agentNamePrefix, reason, grant_secret = RequireGrant() }, cancellationToken);
        return new EnrollmentResult(
            $"Service principal {value.Name}",
            value.CredentialSecret is null
                ? "The bus had already created this one and will not show its secret again. Rotate it on the Service principals tab if you need a new secret."
                : $"It can create short-lived worker agents named {value.AgentNamePrefix}-*. This credential is shown once.",
            value.CredentialSecret);
    }

    /// <summary>Creates a single-use enrollment for another phone or PC and returns the payload to paste or scan.</summary>
    public async Task<EnrollmentResult> CreateDeviceEnrollmentAsync(string label, string reason, CancellationToken cancellationToken)
    {
        var value = await PostAsync<DeviceEnrollmentResponse>("api/mobile/enrollments/devices",
            new { request_id = Guid.NewGuid().ToString(), label, reason, grant_secret = RequireGrant() }, cancellationToken);
        return new EnrollmentResult(
            $"Enrollment for {value.DeviceLabel}",
            $"Single use. Expires {FeedLogic.TimeLabel(value.ExpiresAt, DateTimeOffset.Now)}. Paste it into the Windows app on the new PC.",
            value.Payload);
    }

    // ---- Worker hosts (bus with schema 24 and later) -----------------------------------------

    /// <summary>
    /// Mints the single-use code a worker host joins with. Minting again for the same host replaces
    /// the earlier code. The code comes back once; a repeat of the same request returns none.
    /// </summary>
    public async Task<HostCode> CreateHostEnrollmentAsync(string requestId, string hostPrefix, string reason, CancellationToken cancellationToken)
    {
        var value = await PostAsync<HostEnrollmentResponse>("api/mobile/enrollments/hosts",
            new { request_id = requestId, host_prefix = hostPrefix, reason, grant_secret = RequireGrant() }, cancellationToken);
        return new HostCode(value.HostPrefix, value.ExpiresAt, value.Code);
    }

    /// <summary>The site's signed document, or null when nothing has been published under that name.</summary>
    public async Task<SiteDocument?> GetSiteDocumentAsync(string name, CancellationToken cancellationToken)
    {
        try
        {
            return MapSiteDocument(await GetAsync<SiteDocumentResponse>($"api/mobile/site-documents/{Uri.EscapeDataString(name)}", cancellationToken));
        }
        catch (BusApiException error) when (error.StatusCode == 404)
        {
            return null;
        }
    }

    /// <summary>
    /// Publishes signed bytes exactly as given. The bus stores them and checks nothing but that the
    /// serial rises; each host verifies the signature itself.
    /// </summary>
    public async Task<SiteDocument> PublishSiteDocumentAsync(string name, long serial, byte[] body, string signature, string signerFingerprint, string reason, CancellationToken cancellationToken) =>
        MapSiteDocument(await PostAsync<SiteDocumentResponse>($"api/mobile/site-documents/{Uri.EscapeDataString(name)}",
            new { serial, body = Convert.ToBase64String(body), signature, signer_fingerprint = signerFingerprint, reason, grant_secret = RequireGrant() }, cancellationToken));

    /// <summary>
    /// Carries one signed host command to a worker hosts' channel. The bus does not read it; a host
    /// acts only if the signature checks against keys pinned on that host. Reuse
    /// <paramref name="requestId"/> on retry so the command is carried once.
    /// </summary>
    public async Task<BusMessage> SendHostCommandAsync(string requestId, string channel, byte[] document, string signature, CancellationToken cancellationToken) =>
        MapMessage(await PostAsync<MessageResponse>("api/mobile/hosts/commands",
            new { request_id = requestId, channel, document = Convert.ToBase64String(document), signature, grant_secret = RequireGrant() }, cancellationToken));

    private static SiteDocument MapSiteDocument(SiteDocumentResponse x) =>
        new(x.Name, x.Serial, Convert.FromBase64String(x.Body), x.Signature, x.SignerFingerprint ?? "", x.StoredAt);

    // ---- Operator management (bus 0.2.64 and later) ------------------------------------------

    /// <summary>Every managed agent, including blocked ones; retired ones too when asked.</summary>
    public async Task<List<ManagedAgent>> GetManagedAgentsAsync(bool includeRetired, CancellationToken cancellationToken)
    {
        var all = new List<ManagedAgent>();
        string? after = null;
        for (var page = 0; page < 25; page++)
        {
            var rows = await GetAsync<List<ManagedAgentResponse>>(BuildManagedAgentsPath(includeRetired, after), cancellationToken);
            all.AddRange(rows.Select(MapManagedAgent));
            if (rows.Count < ManagedPageSize) break;
            after = rows[^1].Name;
        }
        return all;
    }

    internal const int ManagedPageSize = 200;

    internal static string BuildManagedAgentsPath(bool includeRetired, string? after)
    {
        var path = $"api/mobile/admin/agents?state={(includeRetired ? "all" : "managed")}&limit={ManagedPageSize}";
        return after is null ? path : path + "&after=" + Uri.EscapeDataString(after);
    }

    public async Task<List<ManagedDevice>> GetManagedDevicesAsync(CancellationToken cancellationToken) =>
        (await GetAsync<List<ManagedDeviceResponse>>("api/mobile/admin/devices", cancellationToken)).Select(MapManagedDevice).ToList();

    public async Task<List<ManagedServicePrincipal>> GetManagedServicePrincipalsAsync(CancellationToken cancellationToken) =>
        (await GetAsync<List<ManagedServicePrincipalResponse>>("api/mobile/admin/service-principals", cancellationToken)).Select(MapManagedServicePrincipal).ToList();

    /// <summary>The bus's recent audit, request and server log lines, newest first. Needs StruggleBus 0.2.65.</summary>
    public async Task<BusLog> GetBusLogAsync(int limit, CancellationToken cancellationToken) =>
        MapBusLog(await GetAsync<BusLogResponse>($"api/mobile/admin/logs?limit={limit}", cancellationToken));

    internal static BusLog ParseBusLog(string json) =>
        MapBusLog(JsonSerializer.Deserialize<BusLogResponse>(json, JsonOptions) ?? throw new InvalidOperationException("Bus returned an empty response."));

    private static BusLog MapBusLog(BusLogResponse value) =>
        new(value.Version ?? string.Empty, value.StartedAt, (value.Entries ?? []).Select(MapBusLogEntry).ToList());

    private static BusLogEntry MapBusLogEntry(BusLogEntryResponse entry) =>
        new(entry.Ts, entry.Source ?? string.Empty, entry.Level ?? "info", entry.Event ?? string.Empty,
            entry.Subject, entry.Actor, entry.Status, entry.RemoteAddress, entry.Detail ?? string.Empty);

    /// <summary>Blocks, unblocks or retires the agent exactly as it was listed; a changed agent is refused.</summary>
    public async Task<ControlResult> ControlAgentAsync(string agentId, string expectedName, int expectedEpoch, string action, string reason, CancellationToken cancellationToken)
    {
        var value = await PostAsync<ControlResponse>($"api/mobile/admin/agents/{Uri.EscapeDataString(agentId)}/control",
            new { request_id = Guid.NewGuid().ToString("D"), action, expected_name = expectedName, expected_credential_epoch = expectedEpoch, reason, grant_secret = RequireGrant() }, cancellationToken);
        return MapControl(value);
    }

    /// <summary>Blocks, unblocks, rotates or revokes the service principal exactly as it was listed.</summary>
    public async Task<ControlResult> ControlServicePrincipalAsync(string id, string expectedName, int expectedVersion, string action, string reason, CancellationToken cancellationToken)
    {
        var value = await PostAsync<ControlResponse>($"api/mobile/admin/service-principals/{Uri.EscapeDataString(id)}/control",
            new { request_id = Guid.NewGuid().ToString("D"), action, expected_name = expectedName, expected_version = expectedVersion, reason, grant_secret = RequireGrant() }, cancellationToken);
        return MapControl(value);
    }

    internal static List<ManagedAgent> ParseManagedAgents(string json) =>
        (JsonSerializer.Deserialize<List<ManagedAgentResponse>>(json, JsonOptions) ?? []).Select(MapManagedAgent).ToList();

    internal static List<ManagedDevice> ParseManagedDevices(string json) =>
        (JsonSerializer.Deserialize<List<ManagedDeviceResponse>>(json, JsonOptions) ?? []).Select(MapManagedDevice).ToList();

    internal static List<ManagedServicePrincipal> ParseManagedServicePrincipals(string json) =>
        (JsonSerializer.Deserialize<List<ManagedServicePrincipalResponse>>(json, JsonOptions) ?? []).Select(MapManagedServicePrincipal).ToList();

    internal static ControlResult ParseControlResult(string json) =>
        MapControl(JsonSerializer.Deserialize<ControlResponse>(json, JsonOptions) ?? throw new InvalidOperationException("Bus returned an empty response."));

    private static List<AdminActionOption> MapOptions(List<ActionOptionResponse>? options) =>
        (options ?? []).Select(option => new AdminActionOption(option.Action, option.Effect ?? string.Empty)).ToList();

    private static ManagedAgent MapManagedAgent(ManagedAgentResponse x) =>
        new(x.Id, x.Name, x.Description ?? "", x.Host ?? "", x.State, x.CredentialEpoch, x.LastSeenAt, MapOptions(x.Actions));

    private static ManagedDevice MapManagedDevice(ManagedDeviceResponse x) =>
        new(x.Id, x.Label, x.Status, x.LastSeenAt, x.HasWriteGrant, x.ThisDevice, MapOptions(x.Actions));

    private static ManagedServicePrincipal MapManagedServicePrincipal(ManagedServicePrincipalResponse x) =>
        new(x.Id, x.Name, x.AgentNamePrefix, x.Status, x.Version, MapOptions(x.Actions), x.HostRedeemRequestId, x.HostRedeemedFrom);

    private static ControlResult MapControl(ControlResponse x) => new(x.Applied, x.Detail, x.TargetLabel, x.State, x.Secret);

    public bool HasOperatorGrant() =>
        _session is { } session && GrantStore.LoadFromPath(_grantPath, session.DeviceId, out _) is not null;

    /// <summary>
    /// Posts to #humans as human:operator. Chat uses the DPAPI-protected grant without a Windows Hello
    /// prompt; containment actions still require Hello. Reuse <paramref name="requestId"/> on retry.
    /// </summary>
    public async Task<BusMessage> PostHumanMessageAsync(
        string requestId,
        string body,
        HumanMessageKind kind,
        long? replyTo,
        CancellationToken cancellationToken)
    {
        var grant = RequireGrant("Operator access is not configured.");
        var value = await PostJsonAsync<MessageResponse>(
            HumansLogic.PostPath,
            HumansLogic.BuildPostJson(requestId, body, kind, replyTo, grant),
            cancellationToken);
        if (!value.Channel.Equals(HumansLogic.Channel, StringComparison.Ordinal))
            throw new InvalidOperationException($"The server placed the post outside #{HumansLogic.Channel}.");
        return MapMessage(value);
    }

    public async Task<StreamEnd> StreamAsync(
        string? channel,
        Func<Task> onOpen,
        Func<BusMessage, Task> onMessage,
        CancellationToken cancellationToken)
    {
        var session = RequireSession();
        using var request = BuildStreamRequest(session, CurrentCursor(), channel);
        using var response = await SendAsync(_streamHttp, request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        if (RefusedStream(response) is { } refused) return refused;
        await EnsureSuccess(response);
        await onOpen();

        using var reader = new StreamReader(await response.Content.ReadAsStreamAsync(cancellationToken));
        return await ReadStreamAsync(reader, channel, onMessage, cancellationToken);
    }

    private static HttpRequestMessage BuildStreamRequest(Session session, long cursor, string? channel)
    {
        var request = new HttpRequestMessage(
            HttpMethod.Get,
            new Uri(new Uri(session.Endpoint + "/"), BuildStreamPath(cursor, channel)));
        AddAuth(request, session.Credential);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("text/event-stream"));
        request.Headers.TryAddWithoutValidation("Last-Event-ID", cursor.ToString());
        return request;
    }

    /// <summary>How the stream ends when the bus refuses to open it for a reason the app handles itself.</summary>
    private static StreamEnd? RefusedStream(HttpResponseMessage response) => (int)response.StatusCode switch
    {
        401 => new StreamEnd(StreamEndKind.CredentialInactive, BusErrors.CredentialInactive),
        429 => new StreamEnd(StreamEndKind.RateLimited, "The server is limiting live-stream connections.", response.Headers.RetryAfter?.Delta),
        _ => null
    };

    /// <summary>Reads events until the bus ends the stream, sends a terminal event, or the caller cancels.</summary>
    private async Task<StreamEnd> ReadStreamAsync(
        TextReader reader,
        string? channel,
        Func<BusMessage, Task> onMessage,
        CancellationToken cancellationToken)
    {
        var parser = new SseParser();
        while (!cancellationToken.IsCancellationRequested)
        {
            var line = await reader.ReadLineAsync(cancellationToken);
            if (line is null) break;
            if (parser.Feed(line) is not { } received) continue;
            if (await DeliverAsync(received, channel, onMessage) is { } end) return end;
        }

        return new StreamEnd(StreamEndKind.RoutineClosure, string.Empty);
    }

    /// <summary>Hands a new message to the caller, skipping one already seen, and returns the end a terminal event carries.</summary>
    private async Task<StreamEnd?> DeliverAsync(SseEvent received, string? channel, Func<BusMessage, Task> onMessage)
    {
        var decoded = DecodeStreamEvent(received.Name, received.Data, channel);
        if (decoded.Message is not null && AdvanceCursor(decoded.Message.Seq)) await onMessage(decoded.Message);
        return decoded.End;
    }

    internal static string BuildStreamPath(long cursor, string? channel)
    {
        var channelQuery = string.IsNullOrWhiteSpace(channel)
            ? string.Empty
            : $"&channel={Uri.EscapeDataString(channel)}";
        return $"api/mobile/stream?since={cursor}{channelQuery}";
    }

    internal static DecodedStreamEvent DecodeStreamEvent(string eventName, string payload, string? requestedChannel)
    {
        if (eventName.Equals("message", StringComparison.OrdinalIgnoreCase))
            return new DecodedStreamEvent(DecodeStreamMessage(payload, requestedChannel), null);

        var kind = TerminalEvents.GetValueOrDefault(eventName.ToLowerInvariant(), StreamEndKind.ProtocolFailure);
        return new DecodedStreamEvent(null, new StreamEnd(kind, TryReadTerminalDetail(payload)));
    }

    /// <summary>The events that end a stream on purpose. Any other named event is a protocol failure.</summary>
    private static readonly Dictionary<string, StreamEndKind> TerminalEvents = new(StringComparer.Ordinal)
    {
        ["credential_inactive"] = StreamEndKind.CredentialInactive,
        ["agent_access_frozen"] = StreamEndKind.AccessFrozen,
        ["agent_access_unavailable"] = StreamEndKind.AccessUnavailable,
        ["server_stopping"] = StreamEndKind.ServerStopping
    };

    private static BusMessage DecodeStreamMessage(string payload, string? requestedChannel)
    {
        var wire = JsonSerializer.Deserialize<MessageResponse>(payload, JsonOptions)
            ?? throw new InvalidOperationException("Message event data is empty.");
        if (wire.Seq < 0) throw new InvalidOperationException("Message sequence is negative.");
        if (string.IsNullOrWhiteSpace(wire.Channel)) throw new InvalidOperationException("Message channel is empty.");
        if (!IsRequestedChannel(wire.Channel, requestedChannel))
            throw new InvalidOperationException("The stream returned a message outside the requested channel.");
        return MapMessage(wire);
    }

    private static bool IsRequestedChannel(string channel, string? requestedChannel) =>
        requestedChannel is null || channel.Equals(requestedChannel, StringComparison.Ordinal);

    private static string TryReadTerminalDetail(string payload)
    {
        try
        {
            return JsonSerializer.Deserialize<ErrorResponse>(payload, JsonOptions)?.Detail
                ?? "The live stream ended without a detail message.";
        }
        catch (JsonException)
        {
            return "The live stream returned an invalid terminal event.";
        }
    }

    private long CurrentCursor()
    {
        lock (_cursorLock) return _cursor;
    }

    private void ResetCursor()
    {
        lock (_cursorLock) _cursor = 0;
    }

    private bool AdvanceCursor(long sequence)
    {
        lock (_cursorLock)
        {
            if (sequence <= _cursor) return false;
            _cursor = sequence;
            return true;
        }
    }

    /// <summary>
    /// Sends a request. A network failure, or the bus not answering in time, is rethrown saying what
    /// went wrong in plain words; it stays an HttpRequestException so callers still treat it as transient.
    /// </summary>
    private async Task<HttpResponseMessage> SendAsync(
        HttpClient client,
        HttpRequestMessage request,
        HttpCompletionOption completion,
        CancellationToken cancellationToken)
    {
        try
        {
            return await client.SendAsync(request, completion, cancellationToken);
        }
        catch (Exception failure) when (IsConnectionFailure(failure, cancellationToken))
        {
            // No inner exception: the notice bar appends inner messages, and the raw .NET text adds nothing here.
            throw new HttpRequestException(BusErrors.DescribeConnection(failure, request.RequestUri!.Authority, _trust?.LastFailure));
        }
    }

    /// <summary>A network failure, or a timeout: a cancellation the caller did not ask for.</summary>
    private static bool IsConnectionFailure(Exception failure, CancellationToken cancellationToken) =>
        failure is HttpRequestException ||
        (failure is OperationCanceledException && !cancellationToken.IsCancellationRequested);

    /// <summary>Replaces the HTTP clients with ones that trust only the enrolled bus's CA.</summary>
    private void Configure(byte[] caDer)
    {
        var trust = new CaTrust(X509CertificateLoader.LoadCertificate(caDer));
        var handler = _createHandler(trust);
        _http.Dispose();
        _streamHttp.Dispose();
        _handler?.Dispose();
        _handler = handler;
        _trust = trust;
        _http = new HttpClient(handler, disposeHandler: false) { Timeout = TimeSpan.FromSeconds(25) };
        _streamHttp = new HttpClient(handler, disposeHandler: false) { Timeout = Timeout.InfiniteTimeSpan };
    }

    private Task<T> GetAsync<T>(string path, CancellationToken token) =>
        RequestAsync<T>(HttpMethod.Get, path, null, token);

    private Task<T> PostAsync<T>(string path, object body, CancellationToken token) =>
        RequestAsync<T>(HttpMethod.Post, path, JsonContent.Create(body), token);

    private Task<T> PostJsonAsync<T>(string path, string json, CancellationToken token) =>
        RequestAsync<T>(HttpMethod.Post, path, new StringContent(json, Encoding.UTF8, "application/json"), token);

    /// <summary>Sends an authenticated request to the enrolled bus and reads its JSON answer.</summary>
    private async Task<T> RequestAsync<T>(HttpMethod method, string path, HttpContent? content, CancellationToken token)
    {
        var session = RequireSession();
        using var request = new HttpRequestMessage(method, new Uri(new Uri(session.Endpoint + "/"), path)) { Content = content };
        AddAuth(request, session.Credential);
        using var response = await SendAsync(_http, request, HttpCompletionOption.ResponseContentRead, token);
        await EnsureSuccess(response);
        return await ReadBodyAsync<T>(response, "Bus returned an empty response.", token);
    }

    private static async Task<T> ReadBodyAsync<T>(HttpResponseMessage response, string whenEmpty, CancellationToken token) =>
        await response.Content.ReadFromJsonAsync<T>(JsonOptions, token) ?? throw new InvalidOperationException(whenEmpty);

    private static void AddAuth(HttpRequestMessage request, string credential) => request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", credential);
    private Session RequireSession() => _session ?? throw new InvalidOperationException("Enroll this Windows device first.");
    private static async Task EnsureSuccess(HttpResponseMessage response)
    {
        if (response.IsSuccessStatusCode) return;
        throw BusErrors.FromResponse((int)response.StatusCode, await response.Content.ReadAsStringAsync());
    }

    private static string WireAction(OperatorAction action) => action switch { OperatorAction.ActivateFreeze => "activate-freeze", OperatorAction.ClearFreeze => "clear-freeze", OperatorAction.BlockAgent => "block-agent", OperatorAction.RevokeDevice => "revoke-device", _ => throw new ArgumentOutOfRangeException(nameof(action)) };
    private static BusMessage MapMessage(MessageResponse x) => new(x.Seq, x.Channel, x.AgentName ?? "", x.Body, x.Kind, x.CreatedAt, x.ReplyTo, HostStatusParser.FromMetadata(x.Metadata, x.AgentName ?? ""));
    private static BusAgent MapAgent(AgentResponse x) => new(x.Id, x.Name, x.Description ?? "", x.Host ?? "", x.LastSeenAt is null ? "never-seen" : "seen", x.LastSeenAt);

    public static class SessionStore
    {
        internal const string FileName = "session.bin";
        private static readonly string Path = AppPaths.File(FileName);

        public static void Clear() => ProtectedStoreRecovery.DeleteQuietly(Path);

        public static void Save(Session session) => SaveToPath(Path, session);

        internal static void SaveToPath(string path, Session session)
        {
            Directory.CreateDirectory(System.IO.Path.GetDirectoryName(path)!);
            var json = JsonSerializer.Serialize(new PersistedSession(session.Endpoint, session.Credential, Convert.ToBase64String(session.CaDer), session.DeviceId, session.DeviceLabel));
            File.WriteAllBytes(path, ProtectedData.Protect(Encoding.UTF8.GetBytes(json), null, DataProtectionScope.CurrentUser));
        }

        public static Session? Load(out string? warning) => LoadFromPath(Path, out warning);

        internal static Session? LoadFromPath(string path, out string? warning)
        {
            warning = null;
            if (!File.Exists(path)) return null;
            try
            {
                return Read(path);
            }
            catch (Exception error) when (error is JsonException or FormatException || ProtectedStoreRecovery.IsUnreadable(error))
            {
                ProtectedStoreRecovery.Quarantine(path);
                warning = "The saved Windows enrollment could not be read and was quarantined. Enroll this PC again.";
                return null;
            }
        }

        private static Session Read(string path)
        {
            var json = Encoding.UTF8.GetString(ProtectedData.Unprotect(File.ReadAllBytes(path), null, DataProtectionScope.CurrentUser));
            var value = JsonSerializer.Deserialize<PersistedSession>(json)
                ?? throw new InvalidDataException("The protected session is empty.");
            if (!HasValidFields(value)) throw new InvalidDataException("The protected session has invalid fields.");
            var caDer = Convert.FromBase64String(value.CaDer);
            using var _ = X509CertificateLoader.LoadCertificate(caDer);
            return new Session(value.Endpoint, value.Credential, caDer, value.DeviceId, value.DeviceLabel);
        }

        private static bool HasValidFields(PersistedSession value) =>
            Uri.TryCreate(value.Endpoint, UriKind.Absolute, out var endpoint) && endpoint.Scheme == Uri.UriSchemeHttps &&
            !string.IsNullOrWhiteSpace(value.Credential) && !string.IsNullOrWhiteSpace(value.DeviceId);
    }

    public static class GrantStore
    {
        internal const string FileName = "operator-grant.bin";
        private static readonly string Path = AppPaths.File(FileName);

        public static void Save(string deviceId, string secret) => SaveToPath(Path, deviceId, secret);

        internal static void SaveToPath(string path, string deviceId, string secret)
        {
            Directory.CreateDirectory(System.IO.Path.GetDirectoryName(path)!);
            var data = Encoding.UTF8.GetBytes(deviceId + "\n" + secret);
            File.WriteAllBytes(path, ProtectedData.Protect(data, null, DataProtectionScope.CurrentUser));
        }

        public static string? Load(string deviceId, out string? warning) => LoadFromPath(Path, deviceId, out warning);

        public static void Clear() => ProtectedStoreRecovery.DeleteQuietly(Path);

        internal static string? LoadFromPath(string path, string deviceId, out string? warning)
        {
            warning = null;
            if (!File.Exists(path)) return null;
            try
            {
                return Read(path, deviceId);
            }
            catch (Exception error) when (ProtectedStoreRecovery.IsUnreadable(error))
            {
                ProtectedStoreRecovery.Quarantine(path);
                warning = "The saved operator grant could not be read and was quarantined. Monitoring is still available; configure operator access again before using Admin actions.";
                return null;
            }
        }

        /// <summary>The grant secret, or null when the saved grant belongs to another enrollment.</summary>
        private static string? Read(string path, string deviceId)
        {
            var text = Encoding.UTF8.GetString(ProtectedData.Unprotect(File.ReadAllBytes(path), null, DataProtectionScope.CurrentUser));
            var parts = text.Split('\n', 2);
            if (parts.Length != 2 || string.IsNullOrWhiteSpace(parts[1]))
                throw new InvalidDataException("The protected operator grant is invalid.");
            return parts[0] == deviceId ? parts[1] : null;
        }
    }

    private static class ProtectedStoreRecovery
    {
        /// <summary>A protected file that cannot be decrypted, opened or read, or whose contents are not valid.</summary>
        public static bool IsUnreadable(Exception error) =>
            error is CryptographicException or IOException or UnauthorizedAccessException or InvalidDataException;

        /// <summary>Deletes the file; one that is missing, in use or not allowed to be deleted is left alone.</summary>
        public static void DeleteQuietly(string path)
        {
            try { File.Delete(path); }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException) { }
        }

        public static void Quarantine(string path)
        {
            try
            {
                var quarantinePath = $"{path}.invalid-{DateTime.UtcNow:yyyyMMddHHmmssfff}";
                File.Move(path, quarantinePath, overwrite: true);
            }
            catch (IOException)
            {
                try { File.Delete(path); } catch (IOException) { }
            }
            catch (UnauthorizedAccessException)
            {
            }
        }
    }

    private sealed record PersistedSession(string Endpoint, string Credential, string CaDer, string DeviceId, string DeviceLabel);
    private sealed record EnrollmentResponse([property: JsonPropertyName("device_id")] string DeviceId, [property: JsonPropertyName("device_label")] string DeviceLabel, [property: JsonPropertyName("credential_secret")] string CredentialSecret);
    private sealed record AgentEnrollmentResponse([property: JsonPropertyName("enrollment_id")] string EnrollmentId, [property: JsonPropertyName("agent_name")] string AgentName, [property: JsonPropertyName("expires_at")] DateTimeOffset ExpiresAt, string Package);
    private sealed record ServicePrincipalResponse(string Name, [property: JsonPropertyName("agent_name_prefix")] string AgentNamePrefix, [property: JsonPropertyName("credential_secret")] string? CredentialSecret);
    private sealed record DeviceEnrollmentResponse([property: JsonPropertyName("device_label")] string DeviceLabel, [property: JsonPropertyName("expires_at")] DateTimeOffset ExpiresAt, string Payload);
    private sealed record HostEnrollmentResponse([property: JsonPropertyName("host_prefix")] string HostPrefix, [property: JsonPropertyName("expires_at")] DateTimeOffset ExpiresAt, string? Code);
    private sealed record SiteDocumentResponse(string Name, long Serial, string Body, string Signature, [property: JsonPropertyName("signer_fingerprint")] string? SignerFingerprint, [property: JsonPropertyName("stored_at")] DateTimeOffset StoredAt);
    private sealed record GrantResponse([property: JsonPropertyName("grant_secret")] string GrantSecret);
    private sealed record ConfirmationResponse([property: JsonPropertyName("confirmation_id")] string ConfirmationId, string Action, [property: JsonPropertyName("target_id")] string TargetId, [property: JsonPropertyName("target_label")] string TargetLabel, string Effect);
    private sealed record ActionResponse(bool Applied, string Detail, [property: JsonPropertyName("target_label")] string TargetLabel);
    private sealed record ActionOptionResponse(string Action, string? Effect);
    private sealed record ManagedAgentResponse(string Id, string Name, string? Description, string? Host, string State, [property: JsonPropertyName("credential_epoch")] int CredentialEpoch, [property: JsonPropertyName("last_seen_at")] DateTimeOffset? LastSeenAt, List<ActionOptionResponse>? Actions);
    private sealed record ManagedDeviceResponse(string Id, string Label, string Status, [property: JsonPropertyName("last_seen_at")] DateTimeOffset? LastSeenAt, [property: JsonPropertyName("has_write_grant")] bool HasWriteGrant, [property: JsonPropertyName("this_device")] bool ThisDevice, List<ActionOptionResponse>? Actions);
    private sealed record ManagedServicePrincipalResponse(string Id, string Name, [property: JsonPropertyName("agent_name_prefix")] string AgentNamePrefix, string Status, int Version, List<ActionOptionResponse>? Actions, [property: JsonPropertyName("host_redeem_request_id")] string? HostRedeemRequestId = null, [property: JsonPropertyName("host_redeemed_from")] string? HostRedeemedFrom = null);
    private sealed record ControlResponse(bool Applied, string Detail, [property: JsonPropertyName("target_label")] string TargetLabel, string State, string? Secret);
    private sealed record BusLogEntryResponse(DateTimeOffset Ts, string? Source, string? Level, string? Event, string? Subject, string? Actor, int? Status, [property: JsonPropertyName("remote_address")] string? RemoteAddress, string? Detail);
    private sealed record BusLogResponse(string? Version, [property: JsonPropertyName("started_at")] DateTimeOffset? StartedAt, List<BusLogEntryResponse>? Entries);
    private sealed record StatusResponse([property: JsonPropertyName("api_version")] int ApiVersion, string State);
    private sealed record ErrorResponse(string Detail);
    private sealed record ChannelResponse(string Id, string Name, string? Purpose);
    private sealed record MessageResponse(long Seq, string Channel, [property: JsonPropertyName("agent_name")] string? AgentName, string Body, string Kind, [property: JsonPropertyName("created_at")] DateTimeOffset CreatedAt, [property: JsonPropertyName("reply_to")] long? ReplyTo = null, JsonElement? Metadata = null);
    private sealed record AgentResponse(string Id, string Name, string? Description, string? Host, [property: JsonPropertyName("last_seen_at")] DateTimeOffset? LastSeenAt);
}
