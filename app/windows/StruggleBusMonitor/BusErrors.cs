using System.Net.Http;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text.Json;

namespace StruggleBusMonitor;

public enum ConnectionFailure
{
    /// <summary>DNS has no answer for the bus's name.</summary>
    NameNotFound,
    /// <summary>Nothing accepted the connection: the bus is down or something blocks the way.</summary>
    Unreachable,
    TimedOut,
    /// <summary>The bus answered but its TLS certificate was not accepted.</summary>
    Certificate,
    Unknown
}

/// <summary>Turns network failures and bus error responses into sentences a new operator can act on.</summary>
internal static class BusErrors
{
    public const string CredentialInactive = "The Windows device credential is no longer active.";

    private const string NewEnrollmentAdvice =
        "Create a new one on the bus Devices page and paste it here. Enrollments are single use and short lived; if the old one was already used, give the new one a different label.";

    public static ConnectionFailure ClassifyConnection(Exception error)
    {
        var fallback = ConnectionFailure.Unknown;
        for (var current = error; current is not null; current = current.InnerException)
        {
            if (ClassifyOne(current) is { } known) return known;
            // Usually wraps a socket error that says more; this is the answer if it does not.
            if (IsConnectionError(current)) fallback = ConnectionFailure.Unreachable;
        }
        return fallback;
    }

    /// <summary>What this one exception says on its own, ignoring what it wraps; null when it does not say.</summary>
    private static ConnectionFailure? ClassifyOne(Exception error) => ClassifyTransport(error) ?? ClassifyRequest(error);

    private static bool IsConnectionError(Exception error) =>
        error is HttpRequestException { HttpRequestError: HttpRequestError.ConnectionError };

    /// <summary>What a TLS or socket failure says on its own, or null when it is neither.</summary>
    private static ConnectionFailure? ClassifyTransport(Exception error) => error switch
    {
        AuthenticationException => ConnectionFailure.Certificate,
        SocketException socket => ClassifySocket(socket.SocketErrorCode),
        _ => null
    };

    private static ConnectionFailure ClassifySocket(SocketError code) => code switch
    {
        SocketError.HostNotFound or SocketError.TryAgain or SocketError.NoData => ConnectionFailure.NameNotFound,
        SocketError.TimedOut => ConnectionFailure.TimedOut,
        _ => ConnectionFailure.Unreachable
    };

    /// <summary>What a timeout or an HTTP-level failure says on its own, or null when an inner error must decide.</summary>
    private static ConnectionFailure? ClassifyRequest(Exception error) => error switch
    {
        TimeoutException or OperationCanceledException => ConnectionFailure.TimedOut,
        HttpRequestException request => ClassifyRequestError(request.HttpRequestError),
        _ => null
    };

    private static ConnectionFailure? ClassifyRequestError(HttpRequestError kind) => kind switch
    {
        HttpRequestError.NameResolutionError => ConnectionFailure.NameNotFound,
        HttpRequestError.SecureConnectionError => ConnectionFailure.Certificate,
        _ => null
    };

    /// <summary>
    /// What went wrong reaching <paramref name="address"/>, in plain words. <paramref name="tlsReason"/>
    /// is the certificate check's own finding, when it made one.
    /// </summary>
    public static string DescribeConnection(Exception error, string address, string? tlsReason = null)
    {
        var innermost = error;
        while (innermost.InnerException is { } inner) innermost = inner;
        return ClassifyConnection(error) switch
        {
            ConnectionFailure.NameNotFound =>
                $"The bus address {address} could not be found. Check the address is right and that this PC's DNS knows the name.",
            ConnectionFailure.Unreachable =>
                $"Could not connect to the bus at {address}. The bus may be stopped, or a firewall is blocking the connection.",
            ConnectionFailure.TimedOut =>
                $"The bus at {address} did not answer in time. Check that it is running and that this PC is on the same network.",
            ConnectionFailure.Certificate =>
                $"The StruggleBus TLS certificate could not be verified. {tlsReason ?? innermost.Message}",
            _ => $"Could not reach the bus at {address}. {innermost.Message}"
        };
    }

    /// <summary>
    /// The exception for a refused request. The message is the bus's own "detail" as a sentence, with
    /// a next step where one is known, instead of the raw response body.
    /// </summary>
    public static BusApiException FromResponse(int statusCode, string body)
    {
        var detail = TryReadErrorDetail(body)?.Trim();
        if (string.IsNullOrEmpty(detail))
        {
            var message = string.IsNullOrWhiteSpace(body)
                ? $"StruggleBus returned HTTP {statusCode}."
                : $"StruggleBus returned HTTP {statusCode}: {body}";
            return new BusApiException(statusCode, $"HTTP {statusCode}", message);
        }
        return new BusApiException(statusCode, detail, DescribeDetail(detail));
    }

    /// <summary>Bus refusals this app can give a next step for, keyed by the bus's detail in lower case without its full stop.</summary>
    private static readonly Dictionary<string, string> KnownDetails = new(StringComparer.Ordinal)
    {
        ["enrollment token has expired"] = "This enrollment has expired. " + NewEnrollmentAdvice,
        ["enrollment token is not valid"] =
            "The bus did not accept this enrollment. It may already have been used. " + NewEnrollmentAdvice,
        ["agent access is frozen"] =
            "Agent access is frozen on the bus, so it refused this. Clear the freeze on the Admin page under Access and freeze, then try again.",
        ["operator password is not valid"] =
            "The bus did not accept the operator password. Check it and try again.",
        ["operator password is not configured"] =
            "This bus has no operator password yet, so operator access cannot be set up from this app. Set the operator password on the bus first, then try again."
    };

    internal static string DescribeDetail(string detail) =>
        KnownDetails.TryGetValue(detail.TrimEnd('.').ToLowerInvariant(), out var advice)
            ? advice
            : $"StruggleBus said: {detail.TrimEnd('.')}.";

    private static string? TryReadErrorDetail(string raw)
    {
        try
        {
            using var document = JsonDocument.Parse(raw);
            return document.RootElement.ValueKind == JsonValueKind.Object &&
                   document.RootElement.TryGetProperty("detail", out var detail) &&
                   detail.ValueKind == JsonValueKind.String
                ? detail.GetString()
                : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }
}
