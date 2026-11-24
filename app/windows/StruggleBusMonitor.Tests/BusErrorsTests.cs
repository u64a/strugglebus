using System.IO;
using System.Net.Http;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Windows.Security.Credentials.UI;

namespace StruggleBusMonitor.Tests;

public class ConnectionFailureTests
{
    private static HttpRequestException Http(HttpRequestError error, Exception? inner = null) => new(error, "raw", inner);

    [Theory]
    [InlineData(SocketError.HostNotFound, ConnectionFailure.NameNotFound)]
    [InlineData(SocketError.TryAgain, ConnectionFailure.NameNotFound)]
    [InlineData(SocketError.NoData, ConnectionFailure.NameNotFound)]
    [InlineData(SocketError.ConnectionRefused, ConnectionFailure.Unreachable)]
    [InlineData(SocketError.HostUnreachable, ConnectionFailure.Unreachable)]
    [InlineData(SocketError.NetworkUnreachable, ConnectionFailure.Unreachable)]
    [InlineData(SocketError.TimedOut, ConnectionFailure.TimedOut)]
    public void ClassifyConnection_ReadsTheSocketErrorUnderTheHttpFailure(SocketError socket, ConnectionFailure expected) =>
        Assert.Equal(expected, BusErrors.ClassifyConnection(Http(HttpRequestError.ConnectionError, new SocketException((int)socket))));

    [Fact]
    public void ClassifyConnection_FallsBackToTheHttpErrorKind()
    {
        Assert.Equal(ConnectionFailure.NameNotFound, BusErrors.ClassifyConnection(Http(HttpRequestError.NameResolutionError)));
        Assert.Equal(ConnectionFailure.Unreachable, BusErrors.ClassifyConnection(Http(HttpRequestError.ConnectionError)));
        Assert.Equal(ConnectionFailure.Certificate, BusErrors.ClassifyConnection(Http(HttpRequestError.SecureConnectionError)));
        Assert.Equal(ConnectionFailure.Unknown, BusErrors.ClassifyConnection(Http(HttpRequestError.ResponseEnded, new IOException("reset"))));
    }

    [Fact]
    public void ClassifyConnection_KnowsCertificateFailuresAndTimeouts()
    {
        Assert.Equal(ConnectionFailure.Certificate, BusErrors.ClassifyConnection(
            new HttpRequestException("The SSL connection could not be established", new AuthenticationException("bad chain"))));
        Assert.Equal(ConnectionFailure.TimedOut, BusErrors.ClassifyConnection(
            new TaskCanceledException("The request was canceled", new TimeoutException())));
    }

    [Fact]
    public void DescribeConnection_SaysWhatFailedInPlainWords()
    {
        const string address = "bus.example:8443";
        Assert.Equal(
            "The bus address bus.example:8443 could not be found. Check the address is right and that this PC's DNS knows the name.",
            BusErrors.DescribeConnection(Http(HttpRequestError.NameResolutionError, new SocketException((int)SocketError.HostNotFound)), address));
        Assert.Equal(
            "Could not connect to the bus at bus.example:8443. The bus may be stopped, or a firewall is blocking the connection.",
            BusErrors.DescribeConnection(Http(HttpRequestError.ConnectionError, new SocketException((int)SocketError.ConnectionRefused)), address));
        Assert.Equal(
            "The bus at bus.example:8443 did not answer in time. Check that it is running and that this PC is on the same network.",
            BusErrors.DescribeConnection(new TaskCanceledException("canceled", new TimeoutException()), address));
        Assert.Equal(
            "Could not reach the bus at bus.example:8443. reset",
            BusErrors.DescribeConnection(Http(HttpRequestError.ResponseEnded, new IOException("reset")), address));
    }

    [Fact]
    public void DescribeConnection_KeepsTheSpecificCertificateReason()
    {
        var failure = new HttpRequestException("ssl", new AuthenticationException("remote certificate rejected"));
        Assert.Equal(
            "The StruggleBus TLS certificate could not be verified. The certificate name does not match the enrolled server address.",
            BusErrors.DescribeConnection(failure, "bus.example", "The certificate name does not match the enrolled server address."));
        Assert.Equal(
            "The StruggleBus TLS certificate could not be verified. remote certificate rejected",
            BusErrors.DescribeConnection(failure, "bus.example"));
        // A certificate reason left over from an earlier attempt must not relabel a plain network failure.
        Assert.StartsWith("Could not connect to the bus", BusErrors.DescribeConnection(
            Http(HttpRequestError.ConnectionError, new SocketException((int)SocketError.ConnectionRefused)), "bus.example", "stale reason"));
    }
}

public class ResponseErrorTests
{
    [Fact]
    public void FromResponse_ShowsTheDetailNotTheJson()
    {
        var error = BusErrors.FromResponse(409, """{"detail":"device label is already in use"}""");
        Assert.Equal(409, error.StatusCode);
        Assert.Equal("device label is already in use", error.Detail);
        Assert.Equal("StruggleBus said: device label is already in use.", error.Message);
    }

    [Theory]
    [InlineData("enrollment token has expired", "This enrollment has expired. Create a new one on the bus Devices page and paste it here. Enrollments are single use and short lived; if the old one was already used, give the new one a different label.")]
    [InlineData("enrollment token is not valid", "The bus did not accept this enrollment. It may already have been used. Create a new one on the bus Devices page and paste it here. Enrollments are single use and short lived; if the old one was already used, give the new one a different label.")]
    [InlineData("agent access is frozen", "Agent access is frozen on the bus, so it refused this. Clear the freeze on the Admin page under Access and freeze, then try again.")]
    [InlineData("operator password is not valid", "The bus did not accept the operator password. Check it and try again.")]
    [InlineData("operator password is not configured", "This bus has no operator password yet, so operator access cannot be set up from this app. Set the operator password on the bus first, then try again.")]
    [InlineData("Enrollment token has expired.", "This enrollment has expired. Create a new one on the bus Devices page and paste it here. Enrollments are single use and short lived; if the old one was already used, give the new one a different label.")]
    public void FromResponse_GivesANextStepForKnownDetails(string detail, string expected)
    {
        var error = BusErrors.FromResponse(401, JsonSerializer.Serialize(new { detail }));
        Assert.Equal(expected, error.Message);
        Assert.Equal(401, error.StatusCode);
        Assert.Equal(detail, error.Detail);
    }

    [Theory]
    [InlineData("<html>Bad Gateway</html>", "StruggleBus returned HTTP 502: <html>Bad Gateway</html>")]
    [InlineData("""{"detail":[{"msg":"field required"}]}""", """StruggleBus returned HTTP 502: {"detail":[{"msg":"field required"}]}""")]
    [InlineData("", "StruggleBus returned HTTP 502.")]
    public void FromResponse_FallsBackToTheStatusWhenThereIsNoDetailString(string body, string expected)
    {
        var error = BusErrors.FromResponse(502, body);
        Assert.Equal(expected, error.Message);
        Assert.Equal("HTTP 502", error.Detail);
    }
}

public class EnrollmentPayloadTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 20, 12, 0, 0, TimeSpan.Zero);

    private static byte[] Certificate()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=strugglebus.test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(Now.AddDays(-1), Now.AddDays(1));
        return certificate.Export(X509ContentType.Cert);
    }

    private static string Sha256(byte[] data) => Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();

    private static string Payload(Dictionary<string, object?>? changes = null)
    {
        var ca = Certificate();
        var fields = new Dictionary<string, object?>
        {
            ["base_url"] = "https://bus.example:8443",
            ["ca_der"] = Convert.ToBase64String(ca),
            ["ca_sha256"] = Sha256(ca),
            ["device_label"] = "desk-pc",
            ["enrollment"] = "sbe1_token",
            ["expires_at"] = Now.AddMinutes(10),
            ["version"] = 1
        };
        foreach (var (key, value) in changes ?? [])
        {
            if (value is null) fields.Remove(key);
            else fields[key] = value;
        }
        return JsonSerializer.Serialize(fields);
    }

    private static string Failure(string raw) =>
        Assert.Throws<InvalidOperationException>(() => BusApi.ReadEnrollment(raw, Now)).Message;

    [Fact]
    public void ReadEnrollment_AcceptsACompletePayload()
    {
        var (payload, ca) = BusApi.ReadEnrollment(Payload(), Now);
        Assert.Equal("https://bus.example:8443", payload.BaseUrl);
        Assert.Equal(payload.CaSha256, Sha256(ca));
    }

    [Theory]
    [InlineData("")]
    [InlineData("null")]
    [InlineData("not json")]
    [InlineData("""{"version":1""")]
    [InlineData("{}")]
    public void ReadEnrollment_RejectsTextThatIsNotAPayload(string raw) =>
        Assert.Equal(BusApi.IncompleteEnrollment, Failure(raw));

    [Theory]
    [InlineData("base_url")]
    [InlineData("ca_der")]
    [InlineData("ca_sha256")]
    [InlineData("enrollment")]
    [InlineData("expires_at")]
    public void ReadEnrollment_NamesAMissingFieldAsIncomplete(string field) =>
        Assert.Equal(BusApi.IncompleteEnrollment, Failure(Payload(new() { [field] = null })));

    [Fact]
    public void ReadEnrollment_RejectsOtherVersionsAndPlainHttp()
    {
        const string expected = "Only version 1 HTTPS enrollment payloads are supported.";
        Assert.Equal(expected, Failure(Payload(new() { ["version"] = 2 })));
        Assert.Equal(expected, Failure(Payload(new() { ["base_url"] = "http://bus.example:8443" })));
        Assert.Equal(expected, Failure(Payload(new() { ["base_url"] = "bus.example" })));
    }

    [Fact]
    public void ReadEnrollment_ExpiredPayloadMentionsTheClock()
    {
        var message = Failure(Payload(new() { ["expires_at"] = Now.AddMinutes(-1) }));
        Assert.StartsWith("This enrollment payload expired at ", message);
        Assert.EndsWith("Create a new one on the bus Devices page. If it was only just created, check this PC's date and time: a wrong clock also causes this.", message);
    }

    [Fact]
    public void ReadEnrollment_DamagedCertificateIsNotARawDotNetError()
    {
        Assert.Equal(BusApi.UnreadableEnrollmentCertificate, Failure(Payload(new() { ["ca_der"] = "not base64 !!" })));

        var junk = new byte[] { 1, 2, 3, 4 };
        Assert.Equal(BusApi.UnreadableEnrollmentCertificate,
            Failure(Payload(new() { ["ca_der"] = Convert.ToBase64String(junk), ["ca_sha256"] = Sha256(junk) })));
    }

    [Fact]
    public void ReadEnrollment_RejectsACertificateThatDoesNotMatchItsFingerprint() =>
        Assert.Equal("CA fingerprint does not match.", Failure(Payload(new() { ["ca_sha256"] = new string('0', 64) })));
}

public class WindowsHelloTests
{
    [Theory]
    [InlineData(UserConsentVerifierAvailability.NotConfiguredForUser, "Windows Hello is not set up for your Windows account. Set up a PIN in Windows Settings > Accounts > Sign-in options, then try again.")]
    [InlineData(UserConsentVerifierAvailability.DeviceNotPresent, "Windows Hello has nothing to sign in with on this PC. Set up a PIN in Windows Settings > Accounts > Sign-in options, then try again.")]
    [InlineData(UserConsentVerifierAvailability.DisabledByPolicy, "Windows Hello is turned off on this PC by a policy. Ask whoever manages this PC to allow it.")]
    [InlineData(UserConsentVerifierAvailability.DeviceBusy, "Windows Hello is busy with another request. Close any other Windows sign-in prompt and try again.")]
    public void DescribeUnavailable_IsASentenceForEveryState(UserConsentVerifierAvailability availability, string expected)
    {
        Assert.Equal(expected, WindowsHello.DescribeUnavailable(availability));
        Assert.DoesNotContain(availability.ToString(), expected);
    }

    [Fact]
    public void Settings_UpdatesAreAutomaticUnlessTurnedOff()
    {
        var path = Path.Combine(Path.GetTempPath(), $"sbm-settings-{Guid.NewGuid():N}.json");
        try
        {
            File.WriteAllText(path, """{"Mode":1}""");
            Assert.True(AppSettings.LoadFromPath(path).AutoUpdate);
            new AppSettings { AutoUpdate = false }.SaveToPath(path);
            Assert.False(AppSettings.LoadFromPath(path).AutoUpdate);
        }
        finally
        {
            File.Delete(path);
        }
    }
}
