using System.Net.Http;
using System.Text.Json;

namespace StruggleBusMonitor.Tests;

public sealed class HumansLogicTests
{
    private static readonly DateTimeOffset Timestamp = new(2025, 1, 1, 0, 0, 0, TimeSpan.Zero);

    [Fact]
    public void BuildPostJson_OmitsNullReplyTo()
    {
        using var document = JsonDocument.Parse(HumansLogic.BuildPostJson("req", "hello", HumanMessageKind.Chat, null, "grant"));
        var root = document.RootElement;

        Assert.Equal("req", root.GetProperty("request_id").GetString());
        Assert.Equal("hello", root.GetProperty("body").GetString());
        Assert.Equal("chat", root.GetProperty("kind").GetString());
        Assert.Equal("grant", root.GetProperty("grant_secret").GetString());
        Assert.False(root.TryGetProperty("reply_to", out _));
    }

    [Fact]
    public void BuildPostJson_IncludesReplyToAndAnswerKind()
    {
        using var document = JsonDocument.Parse(HumansLogic.BuildPostJson("req", "yes", HumanMessageKind.Answer, 42, "grant"));

        Assert.Equal(42, document.RootElement.GetProperty("reply_to").GetInt64());
        Assert.Equal("answer", document.RootElement.GetProperty("kind").GetString());
    }

    [Theory]
    [InlineData("  hi \r\nthere  ", "hi \nthere")]
    [InlineData("   ", null)]
    [InlineData(null, null)]
    public void NormalizeBody_TrimsAndUsesUnixNewlines(string? input, string? expected) =>
        Assert.Equal(expected, HumansLogic.NormalizeBody(input));

    [Fact]
    public void NormalizeBody_RejectsBodiesOverLimit()
    {
        Assert.NotNull(HumansLogic.NormalizeBody(new string('a', HumansLogic.MaxBodyChars)));
        Assert.Null(HumansLogic.NormalizeBody(new string('a', HumansLogic.MaxBodyChars + 1)));
    }

    [Fact]
    public void Conversation_KeepsOnlyHumansOldestFirst()
    {
        var conversation = HumansLogic.Conversation(
        [
            Message(5, "humans", "agent-a"),
            Message(3, "ops", "agent-b"),
            Message(2, "humans", HumansLogic.OperatorAuthor)
        ]);

        Assert.Equal([2L, 5L], conversation.Select(message => message.Seq));
    }

    [Fact]
    public void UnreadCount_IgnoresOperatorOtherChannelsAndSeenMessages()
    {
        var count = HumansLogic.UnreadCount(
        [
            Message(1, "humans", "agent-a"),
            Message(2, "humans", "agent-a"),
            Message(3, "humans", HumansLogic.OperatorAuthor),
            Message(4, "ops", "agent-b"),
            Message(5, "humans", "agent-c")
        ], lastSeenSequence: 1);

        Assert.Equal(2, count);
    }

    [Fact]
    public void DefaultKindForReply_AnswersQuestions()
    {
        Assert.Equal(HumanMessageKind.Answer, HumansLogic.DefaultKindForReply(Message(1, "humans", "a", "question"), HumanMessageKind.Chat));
        Assert.Equal(HumanMessageKind.Chat, HumansLogic.DefaultKindForReply(Message(1, "humans", "a", "chat"), HumanMessageKind.Chat));
    }

    [Theory]
    [InlineData(401, true, true)]
    [InlineData(409, false, false)]
    [InlineData(413, false, false)]
    [InlineData(400, false, false)]
    [InlineData(503, true, false)]
    public void ClassifyFailure_MapsStatusCodes(int status, bool retryable, bool clearGrant)
    {
        var failure = HumansLogic.ClassifyFailure(new BusApiException(status, "detail", "message"));

        Assert.Equal(retryable, failure.Retryable);
        Assert.Equal(clearGrant, failure.ClearGrant);
    }

    [Fact]
    public void ClassifyFailure_NetworkErrorsAreRetryable()
    {
        var failure = HumansLogic.ClassifyFailure(new HttpRequestException("connection refused"));

        Assert.True(failure.Retryable);
        Assert.False(failure.ClearGrant);
        Assert.Contains("Unable to reach StruggleBus", failure.Detail);
    }

    private static BusMessage Message(long seq, string channel, string agent, string kind = "chat") =>
        new(seq, channel, agent, $"body {seq}", kind, Timestamp);
}
