using System.Text.Json.Serialization;

namespace StruggleBusMonitor;

public sealed record EnrollmentPayload(
    [property: JsonPropertyName("base_url")] string BaseUrl,
    [property: JsonPropertyName("ca_der")] string CaDer,
    [property: JsonPropertyName("ca_sha256")] string CaSha256,
    [property: JsonPropertyName("device_label")] string DeviceLabel,
    [property: JsonPropertyName("enrollment")] string Enrollment,
    [property: JsonPropertyName("expires_at")] DateTimeOffset ExpiresAt,
    [property: JsonPropertyName("version")] int Version);

public sealed record Session(string Endpoint, string Credential, byte[] CaDer, string DeviceId, string DeviceLabel);
public sealed record BusMessage(long Seq, string Channel, string AgentName, string Body, string Kind, DateTimeOffset CreatedAt, long? ReplyTo = null, HostStatus? HostStatus = null);
public sealed record BusChannel(string Id, string Name, string Purpose);
public sealed record BusAgent(string Id, string Name, string Description, string Host, string Presence, DateTimeOffset? LastSeenAt);
public sealed record Snapshot(List<BusMessage> Messages, List<BusAgent> Agents, string State, long LatestSeq);
public sealed record Confirmation(string Id, string Action, string TargetId, string TargetLabel, string Effect);
public sealed record ActionResult(bool Applied, string Detail, string TargetLabel);
public sealed record StreamEnd(StreamEndKind Kind, string Detail, TimeSpan? RetryAfter = null);
public sealed record DecodedStreamEvent(BusMessage? Message, StreamEnd? End);

/// <summary>What an enrollment created from this PC returns. <see cref="Secret"/> is shown once and never stored.</summary>
public sealed record EnrollmentResult(string Title, string Detail, string? Secret);

public enum EnrollmentKind { Agent, ServicePrincipal, Device }

/// <summary>A single-use code that lets one worker host join the bus. <see cref="Code"/> is shown once and never stored.</summary>
public sealed record HostCode(string HostPrefix, DateTimeOffset ExpiresAt, string? Code);

/// <summary>
/// A site's signed document as the bus holds it. The bus does not verify it: <see cref="Body"/> is
/// exactly the bytes that were signed, and <see cref="Serial"/> is only what the publisher stated.
/// </summary>
public sealed record SiteDocument(string Name, long Serial, byte[] Body, string Signature, string SignerFingerprint, DateTimeOffset StoredAt);

/// <summary>An action the bus currently allows on a listed target, with its effect in words.</summary>
public sealed record AdminActionOption(string Action, string Effect);
public sealed record ManagedAgent(string Id, string Name, string Description, string Host, string State, int CredentialEpoch, DateTimeOffset? LastSeenAt, IReadOnlyList<AdminActionOption> Actions);
public sealed record ManagedDevice(string Id, string Label, string Status, DateTimeOffset? LastSeenAt, bool HasWriteGrant, bool ThisDevice, IReadOnlyList<AdminActionOption> Actions);
/// <summary>
/// <see cref="HostRedeemRequestId"/> and <see cref="HostRedeemedFrom"/> are set only for a worker host
/// that joined with a host code: the request it redeemed with and the address it came from.
/// </summary>
public sealed record ManagedServicePrincipal(string Id, string Name, string AgentNamePrefix, string Status, int Version, IReadOnlyList<AdminActionOption> Actions, string? HostRedeemRequestId = null, string? HostRedeemedFrom = null);

/// <summary>The outcome of a management action. <see cref="Secret"/> is shown once and never stored.</summary>
public sealed record ControlResult(bool Applied, string Detail, string TargetLabel, string State, string? Secret);

public enum StreamEndKind
{
    RoutineClosure,
    RateLimited,
    CredentialInactive,
    AccessFrozen,
    AccessUnavailable,
    ServerStopping,
    ProtocolFailure
}

public enum OperatorAction { ActivateFreeze, ClearFreeze, BlockAgent, RevokeDevice }

public enum HumanMessageKind { Chat, Question, Answer }

/// <summary>A failed request that carries the HTTP status code returned by StruggleBus.</summary>
public sealed class BusApiException(int statusCode, string detail, string message) : InvalidOperationException(message)
{
    public int StatusCode { get; } = statusCode;
    public string Detail { get; } = detail;
}
