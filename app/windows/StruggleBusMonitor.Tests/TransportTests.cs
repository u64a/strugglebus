using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace StruggleBusMonitor.Tests;

public sealed class SseParserTests
{
    private static List<SseEvent> Parse(string stream)
    {
        var parser = new SseParser();
        return stream.Split('\n').Select(parser.Feed).OfType<SseEvent>().ToList();
    }

    [Fact]
    public void ABlankLineCompletesAnEvent()
    {
        var parser = new SseParser();

        Assert.Null(parser.Feed("event: server_stopping"));
        Assert.Null(parser.Feed("data: {\"detail\":\"bye\"}"));
        Assert.Equal(new SseEvent("server_stopping", "{\"detail\":\"bye\"}"), parser.Feed(string.Empty));
    }

    [Fact]
    public void AnEventWithoutANameIsAMessageAndTheNameDoesNotCarryOver()
    {
        var events = Parse("event: custom\ndata: one\n\ndata: two\n\n");

        Assert.Equal([new SseEvent("custom", "one"), new SseEvent("message", "two")], events);
    }

    [Fact]
    public void DataLinesAreJoinedWithNewlines()
    {
        var events = Parse("data: first\ndata:second\ndata:   third\n\n");

        Assert.Equal("first\nsecond\nthird", Assert.Single(events).Data);
    }

    [Fact]
    public void CommentsAndOtherFieldsAreIgnored()
    {
        var events = Parse(": keep-alive\nid: 7\nretry: 1000\ndata: payload\n\n");

        Assert.Equal([new SseEvent("message", "payload")], events);
    }

    [Fact]
    public void AnEventWithoutDataIsDroppedAndItsNameForgotten()
    {
        var events = Parse("event: ping\n\n\ndata:\n\ndata: real\n\n");

        Assert.Equal([new SseEvent("message", "real")], events);
    }

    [Fact]
    public void AnUnfinishedEventIsNotReported() =>
        Assert.Empty(Parse("event: message\ndata: half"));

    [Fact]
    public void FieldNamesAreCaseSensitive() =>
        Assert.Empty(Parse("Data: nope\nEVENT: nope\n\n"));
}

public sealed class CaTrustTests
{
    private static readonly X509Certificate2 Ca = TestCertificates.CreateCa("CN=CaTrust Test Root");
    private static readonly X509Certificate2 Leaf = TestCertificates.CreateSignedBy(Ca, "CN=bus.test");

    [Fact]
    public void AcceptsACertificateIssuedByTheEnrolledCa()
    {
        var trust = new CaTrust(Ca);

        Assert.True(trust.Validate(Leaf, null, SslPolicyErrors.RemoteCertificateChainErrors));
        Assert.Null(trust.LastFailure);
    }

    [Fact]
    public void RefusesACertificateFromAnotherCaAndSaysWhy()
    {
        using var otherCa = TestCertificates.CreateCa("CN=Somebody Else");
        using var impostor = TestCertificates.CreateSignedBy(otherCa, "CN=bus.test");
        var trust = new CaTrust(Ca);

        Assert.False(trust.Validate(impostor, null, SslPolicyErrors.RemoteCertificateChainErrors));
        Assert.StartsWith("Certificate chain failure: ", trust.LastFailure);
        Assert.True(trust.LastFailure!.Length > "Certificate chain failure: ".Length);
    }

    [Fact]
    public void RefusesAMissingCertificate()
    {
        var trust = new CaTrust(Ca);

        Assert.False(trust.Validate(null, null, SslPolicyErrors.None));
        Assert.Equal("The server did not provide a certificate.", trust.LastFailure);
    }

    [Theory]
    [InlineData(SslPolicyErrors.RemoteCertificateNameMismatch, "The certificate name does not match the enrolled server address.")]
    [InlineData(SslPolicyErrors.RemoteCertificateNameMismatch | SslPolicyErrors.RemoteCertificateChainErrors, "The certificate name does not match the enrolled server address.")]
    [InlineData(SslPolicyErrors.RemoteCertificateNotAvailable, "The server certificate is unavailable.")]
    public void RefusesAValidChainWhenTlsPolicyAlreadyFailed(SslPolicyErrors errors, string expected)
    {
        var trust = new CaTrust(Ca);

        Assert.False(trust.Validate(Leaf, null, errors));
        Assert.Equal(expected, trust.LastFailure);
    }

    [Fact]
    public void ASuccessClearsTheEarlierFailure()
    {
        var trust = new CaTrust(Ca);
        trust.Validate(null, null, SslPolicyErrors.None);

        Assert.True(trust.Validate(Leaf, null, SslPolicyErrors.None));
        Assert.Null(trust.LastFailure);
    }

    [Fact]
    public void UsesTheIntermediatesTheServerSent()
    {
        using var intermediate = TestCertificates.CreateSignedBy(Ca, "CN=StruggleBus Intermediate", isCa: true);
        using var leaf = TestCertificates.CreateSignedBy(intermediate, "CN=bus.test");
        var trust = new CaTrust(Ca);

        // Checked first, before the intermediate has been part of any chain built in this process.
        Assert.False(trust.Validate(leaf, null, SslPolicyErrors.RemoteCertificateChainErrors));
        Assert.StartsWith("Certificate chain failure: ", trust.LastFailure);

        using var sent = new X509Chain();
        sent.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        sent.ChainPolicy.CustomTrustStore.Add(Ca);
        sent.ChainPolicy.ExtraStore.Add(intermediate);
        sent.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        Assert.True(sent.Build(leaf));
        Assert.Equal(3, sent.ChainElements.Count);

        Assert.True(trust.Validate(leaf, sent, SslPolicyErrors.RemoteCertificateChainErrors));
        Assert.Null(trust.LastFailure);
    }

    [Fact]
    public void TheAppsHandlerAsksThisTrustAboutEveryServerCertificate()
    {
        var trust = new CaTrust(Ca);

        using var handler = Assert.IsType<HttpClientHandler>(CaTrust.CreateHandler(trust));
        var callback = handler.ServerCertificateCustomValidationCallback;

        Assert.NotNull(callback);
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://bus.test");
        Assert.True(callback(request, Leaf, null, SslPolicyErrors.RemoteCertificateChainErrors));
        Assert.False(callback(request, null, null, SslPolicyErrors.None));
        Assert.Equal("The server did not provide a certificate.", trust.LastFailure);
    }
}
