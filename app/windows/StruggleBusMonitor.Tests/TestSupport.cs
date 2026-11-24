using System.Net;
using System.Runtime.CompilerServices;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace StruggleBusMonitor.Tests;

/// <summary>
/// Points the app's per-user data folder at a throwaway directory before any app code runs, so no
/// test can read or change the real enrollment, grant, settings or connection history. It has to
/// happen before the app's AppPaths is first touched, hence a module initializer rather than a
/// fixture. This is the only place the test run sets the folder.
/// </summary>
internal static class TestDataDirectory
{
    public static readonly string Path = System.IO.Path.Combine(
        System.IO.Path.GetTempPath(), "StruggleBusMonitor.Tests", "data-" + Guid.NewGuid().ToString("N"));

    [ModuleInitializer]
    internal static void Redirect()
    {
        Environment.SetEnvironmentVariable("STRUGGLEBUS_MONITOR_DATA_DIR", Path);
        AppDomain.CurrentDomain.ProcessExit += (_, _) =>
        {
            try { Directory.Delete(Path, recursive: true); }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException) { }
        };
    }

    /// <summary>
    /// Empties the data folder so the next window starts as a fresh install. Refuses to touch any
    /// folder but the throwaway one.
    /// </summary>
    internal static void Reset()
    {
        if (!string.Equals(AppPaths.DataDirectory, Path, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException($"The app's data folder is '{AppPaths.DataDirectory}', not the test folder. Refusing to run tests against it.");
        if (Directory.Exists(Path)) Directory.Delete(Path, recursive: true);
        Directory.CreateDirectory(Path);
    }
}

internal static class TempFiles
{
    public static string NewDirectory()
    {
        var directory = Path.Combine(Path.GetTempPath(), "StruggleBusMonitor.Tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        return directory;
    }
}

/// <summary>Runs WPF code on a single-threaded apartment thread, which WPF elements require.</summary>
internal static class Sta
{
    public static void Run(Action action)
    {
        ExceptionDispatchInfo? failure = null;
        var thread = new Thread(() =>
        {
            try { action(); }
            catch (Exception error) { failure = ExceptionDispatchInfo.Capture(error); }
        });
        thread.SetApartmentState(ApartmentState.STA);
        thread.IsBackground = true;
        thread.Start();
        thread.Join();
        failure?.Throw();
    }
}

internal sealed record RecordedRequest(string Method, Uri Url, string? Authorization, string? Body, IReadOnlyDictionary<string, string> Headers)
{
    public string PathAndQuery => Url.PathAndQuery;
}

/// <summary>
/// Stands in for the bus: answers each request with the next queued response and records what was
/// sent. A request nobody queued an answer for fails the test.
/// </summary>
internal sealed class FakeBus : HttpMessageHandler
{
    private readonly Queue<Func<HttpRequestMessage, CancellationToken, HttpResponseMessage>> _answers = new();

    public List<RecordedRequest> Requests { get; } = [];

    public FakeBus Answer(Func<HttpRequestMessage, CancellationToken, HttpResponseMessage> answer)
    {
        _answers.Enqueue(answer);
        return this;
    }

    public FakeBus Json(string json, HttpStatusCode status = HttpStatusCode.OK) =>
        Answer((_, _) => new HttpResponseMessage(status) { Content = new StringContent(json, Encoding.UTF8, "application/json") });

    public FakeBus Events(string stream) =>
        Answer((_, _) => new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(stream, Encoding.UTF8, "text/event-stream") });

    public FakeBus Fails(Exception failure) => Answer((_, _) => throw failure);

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var body = request.Content is null ? null : await request.Content.ReadAsStringAsync(CancellationToken.None);
        var headers = request.Headers.ToDictionary(header => header.Key, header => string.Join(",", header.Value), StringComparer.OrdinalIgnoreCase);
        Requests.Add(new RecordedRequest(request.Method.Method, request.RequestUri!, request.Headers.Authorization?.ToString(), body, headers));
        if (_answers.Count == 0) throw new InvalidOperationException($"The test queued no answer for {request.Method} {request.RequestUri}.");
        return _answers.Dequeue()(request, cancellationToken);
    }
}

internal static class TestCertificates
{
    public static X509Certificate2 CreateCa(string name = "CN=StruggleBus Test CA")
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest(name, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
    }

    /// <summary>A certificate signed by <paramref name="issuer"/>; pass <paramref name="isCa"/> for an intermediate.</summary>
    public static X509Certificate2 CreateSignedBy(X509Certificate2 issuer, string name, bool isCa = false)
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest(name, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(isCa, false, 0, true));
        if (isCa) request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        var serial = RandomNumberGenerator.GetBytes(8);
        // Valid strictly inside the issuer's own period, whatever the clock does between calls.
        using var signed = request.Create(issuer, issuer.NotBefore, issuer.NotAfter.AddHours(-1), serial);
        return signed.CopyWithPrivateKey(key);
    }

    public static byte[] Der(X509Certificate2 certificate) => certificate.Export(X509ContentType.Cert);
}
