using System.Net.Http;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace StruggleBusMonitor;

public enum OutgoingStatus { Sending, Failed }

public sealed class OutgoingPost
{
    /// <summary>Fixed for the life of the post so every retry is idempotent on the server.</summary>
    public required string RequestId { get; init; }
    public required string Body { get; init; }
    public required HumanMessageKind Kind { get; init; }
    public BusMessage? ReplyTo { get; init; }
    public OutgoingStatus Status { get; set; } = OutgoingStatus.Sending;
    public string? Error { get; set; }
    public bool Retryable { get; set; } = true;
}

public sealed record PostFailure(string Detail, bool Retryable, bool ClearGrant);

internal static class HumansLogic
{
    public const string Channel = "humans";
    public const string OperatorAuthor = "human:operator";
    public const string PostPath = "api/mobile/humans/messages";
    public const int MaxBodyChars = 4000;

    private static readonly JsonSerializerOptions PostJsonOptions = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    public static string WireKind(HumanMessageKind kind) => kind switch
    {
        HumanMessageKind.Chat => "chat",
        HumanMessageKind.Question => "question",
        HumanMessageKind.Answer => "answer",
        _ => throw new ArgumentOutOfRangeException(nameof(kind))
    };

    public static string BuildPostJson(string requestId, string body, HumanMessageKind kind, long? replyTo, string grantSecret) =>
        JsonSerializer.Serialize(new HumanPostRequest(requestId, body, WireKind(kind), replyTo, grantSecret), PostJsonOptions);

    public static bool IsOperator(BusMessage message) =>
        message.AgentName.Equals(OperatorAuthor, StringComparison.Ordinal);

    /// <summary>Trimmed body with Unix newlines, or null when empty or too long.</summary>
    public static string? NormalizeBody(string? text)
    {
        var body = (text ?? string.Empty).Replace("\r\n", "\n").Replace('\r', '\n').Trim();
        return body.Length == 0 || body.Length > MaxBodyChars ? null : body;
    }

    public static IReadOnlyList<BusMessage> Conversation(IEnumerable<BusMessage> messages) =>
        messages.Where(message => message.Channel.Equals(Channel, StringComparison.Ordinal))
            .OrderBy(message => message.Seq)
            .ToList();

    public static int UnreadCount(IEnumerable<BusMessage> messages, long lastSeenSequence) =>
        messages.Count(message =>
            message.Channel.Equals(Channel, StringComparison.Ordinal) &&
            message.Seq > lastSeenSequence &&
            !IsOperator(message));

    public static HumanMessageKind DefaultKindForReply(BusMessage target, HumanMessageKind current) =>
        target.Kind.Equals("question", StringComparison.OrdinalIgnoreCase) ? HumanMessageKind.Answer : current;

    public static PostFailure ClassifyFailure(Exception failure) =>
        failure is BusApiException refusal ? ClassifyRefusal(refusal) : ClassifyOther(failure);

    /// <summary>Refusals whose meaning does not depend on what the bus wrote in its detail.</summary>
    private static readonly Dictionary<int, PostFailure> KnownRefusals = new()
    {
        [401] = new(
            "Operator access was revoked or replaced. Save operator access again on the ADMIN page, then retry.",
            Retryable: true,
            ClearGrant: true),
        [409] = new(
            "The server already holds a different post with this ID. Discard it and write it again.",
            Retryable: false,
            ClearGrant: false),
        [413] = new("The message is too long for the server.", false, false)
    };

    private static PostFailure ClassifyRefusal(BusApiException refusal)
    {
        if (KnownRefusals.TryGetValue(refusal.StatusCode, out var known)) return known;
        return refusal.StatusCode is 400 or 422
            ? new(refusal.Detail, false, false)
            : new($"StruggleBus refused the post: {refusal.Detail}", true, false);
    }

    private static PostFailure ClassifyOther(Exception failure)
    {
        if (failure is HttpRequestException or TaskCanceledException)
            return new($"Unable to reach StruggleBus: {failure.Message}", true, false);
        return new(string.IsNullOrWhiteSpace(failure.Message) ? failure.GetType().Name : failure.Message, true, false);
    }

    private sealed record HumanPostRequest(
        [property: JsonPropertyName("request_id")] string RequestId,
        [property: JsonPropertyName("body")] string Body,
        [property: JsonPropertyName("kind")] string Kind,
        [property: JsonPropertyName("reply_to")] long? ReplyTo,
        [property: JsonPropertyName("grant_secret")] string GrantSecret);
}
