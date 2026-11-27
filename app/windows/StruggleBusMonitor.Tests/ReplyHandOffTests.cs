namespace StruggleBusMonitor.Tests;

/// <summary>The draft Humans opens with when a Monitor message is replied to or quoted.</summary>
public sealed class ReplyHandOffTests
{
    private static BusMessage Message(string channel = "ops", string agent = "agent-one", string body = "hello") =>
        new(42, channel, agent, body, "chat", DateTimeOffset.Parse("2030-01-01T00:00:00Z"));

    [Fact]
    public void OnlyAMessageInHumansCanBeLinked()
    {
        Assert.True(ReplyHandOff.CanLink(Message("humans")));
        Assert.False(ReplyHandOff.CanLink(Message("ops")));
    }

    [Theory]
    [InlineData("agent-one", "@agent-one ")]
    [InlineData("human:operator", "")]
    [InlineData("nohyphen", "")]
    [InlineData("", "")]
    public void TheAuthorIsMentionedOnlyWhenTheBusWouldAcceptTheName(string agent, string expected)
    {
        Assert.Equal(expected, ReplyHandOff.Address(Message(agent: agent)));
    }

    [Fact]
    public void AReplyNamesTheMessageWhenItCannotBeLinked()
    {
        Assert.Equal("@agent-one ", ReplyHandOff.ReplyDraft(Message("humans")));
        Assert.Equal("@agent-one about message 42 in #ops: ", ReplyHandOff.ReplyDraft(Message("ops")));
        Assert.Equal("about message 42 in #ops: ", ReplyHandOff.ReplyDraft(Message("ops", "human:operator")));
    }

    [Fact]
    public void AQuoteMarksEveryLineAndSaysWhoseItIs()
    {
        var draft = ReplyHandOff.QuoteDraft(Message(body: "  first line\r\nsecond line\n\nfourth  "));

        Assert.Equal("@agent-one wrote in #ops (message 42):\n> first line\n> second line\n> \n> fourth\n\n", draft);
    }

    [Fact]
    public void ALongMessageIsQuotedInPartAndTheDraftStaysWellInsideTheLimit()
    {
        var draft = ReplyHandOff.QuoteDraft(Message(body: new string('x', 5000)));

        Assert.Contains("> " + new string('x', ReplyHandOff.MaxQuote) + " […]", draft);
        Assert.True(draft.Length < HumansLogic.MaxBodyChars / 2);
    }

    [Fact]
    public void WhatWasBeingWrittenIsKept()
    {
        Assert.Equal("draft", ReplyHandOff.Merge("", "draft"));
        Assert.Equal("draft", ReplyHandOff.Merge("   ", "draft"));
        Assert.Equal("already here\ndraft", ReplyHandOff.Merge("already here  \n", "draft"));
    }
}
