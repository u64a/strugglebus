using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace StruggleBusMonitor;

/// <summary>
/// Decides whether a server certificate belongs to the enrolled bus: it must chain to the CA from
/// the enrollment and nothing else. <see cref="LastFailure"/> keeps the reason for the latest
/// refusal so a failed request can say why.
/// </summary>
internal sealed class CaTrust(X509Certificate2 ca)
{
    public string? LastFailure { get; private set; }

    /// <summary>The handler the app talks to the bus through, trusting only this CA.</summary>
    public static HttpMessageHandler CreateHandler(CaTrust trust) => new HttpClientHandler
    {
        ServerCertificateCustomValidationCallback = (_, certificate, peerChain, policyErrors) =>
            trust.Validate(certificate, peerChain, policyErrors)
    };

    public bool Validate(X509Certificate2? certificate, X509Chain? peerChain, SslPolicyErrors policyErrors)
    {
        LastFailure = certificate is null
            ? "The server did not provide a certificate."
            : PolicyFailure(policyErrors) ?? ChainFailure(certificate, peerChain);
        return LastFailure is null;
    }

    private static string? PolicyFailure(SslPolicyErrors policyErrors)
    {
        if ((policyErrors & SslPolicyErrors.RemoteCertificateNameMismatch) != 0)
            return "The certificate name does not match the enrolled server address.";
        if ((policyErrors & SslPolicyErrors.RemoteCertificateNotAvailable) != 0)
            return "The server certificate is unavailable.";
        return null;
    }

    private string? ChainFailure(X509Certificate2 leaf, X509Chain? peerChain)
    {
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(ca);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        if (peerChain is not null) chain.ChainPolicy.ExtraStore.AddRange(Intermediates(leaf, peerChain));
        return chain.Build(leaf)
            ? null
            : "Certificate chain failure: " + string.Join("; ", chain.ChainStatus.Select(status => status.StatusInformation.Trim()));
    }

    /// <summary>What the server sent besides its own certificate and the enrolled CA.</summary>
    private X509Certificate2[] Intermediates(X509Certificate2 leaf, X509Chain peerChain) =>
        peerChain.ChainElements
            .Select(element => element.Certificate)
            .Where(certificate => !IsSame(certificate, leaf) && !IsSame(certificate, ca))
            .ToArray();

    private static bool IsSame(X509Certificate2 a, X509Certificate2 b) => a.RawData.AsSpan().SequenceEqual(b.RawData);
}
