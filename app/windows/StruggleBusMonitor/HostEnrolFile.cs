using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace StruggleBusMonitor;

/// <summary>
/// Everything a worker host's installer needs for one host. It is written to a data file that is
/// never executed; the installer re-checks every value and refuses the file unless its bytes are
/// exactly what <see cref="HostEnrolFile.Render"/> produces for the values it read.
/// </summary>
public sealed record HostEnrolData(
    DateTimeOffset WrittenAt,
    string Device,
    string BusUrl,
    byte[] CaDer,
    string HostPrefix,
    string EnrolCode,
    IReadOnlyList<string> Engines,
    bool Dedicated,
    IReadOnlyList<string> Signers,
    string FleetSource,
    IReadOnlyList<string> Remotes);

/// <summary>
/// The worker host enrolment data file, <c>sbhost-enrol.json</c>: one line of JSON in a fixed key
/// order with no spaces, ASCII only, then one line feed. The patterns here are the installer's own
/// (tools/bootstrap.ps1 in strugglebus-worker-host), so a file this app writes is one it accepts.
/// </summary>
internal static partial class HostEnrolFile
{
    public const string FileName = "sbhost-enrol.json";
    public const int MaxBytes = 65536;
    public const int MinSigners = 2;

    [GeneratedRegex(@"\A(?=.{1,63}\z)[a-z0-9]+(?:-[a-z0-9]+)*\z")]
    private static partial Regex Device();

    [GeneratedRegex(@"\Ahttps://[a-z0-9][a-z0-9.-]{0,252}(:[0-9]{1,5})?/?\z")]
    private static partial Regex BusUrl();

    [GeneratedRegex(@"\A(?=.{2,31}\z)[a-z0-9]+(?:-[a-z0-9]+)*\z")]
    private static partial Regex HostPrefix();

    [GeneratedRegex(@"\Asbhe1_[A-Za-z0-9_-]{22}_[A-Za-z0-9_-]{43}\z")]
    private static partial Regex EnrolCode();

    [GeneratedRegex(@"\A(ghcp|claude)\z")]
    private static partial Regex Engine();

    [GeneratedRegex(@"\Ahttps://[a-z0-9][a-z0-9.-]{0,252}/([A-Za-z0-9_.-]{1,100}/)?\z")]
    private static partial Regex Remote();

    [GeneratedRegex(@"\A[A-Za-z0-9][A-Za-z0-9._@-]{0,63} namespaces=""(strugglebus-fleet|strugglebus-host-command)(,(strugglebus-fleet|strugglebus-host-command))?"" (ssh-ed25519|sk-ssh-ed25519@openssh\.com|ecdsa-sha2-nistp256|sk-ecdsa-sha2-nistp256@openssh\.com|ssh-rsa) [A-Za-z0-9+/]+={0,2}( [A-Za-z0-9._@-]{1,64})?\z")]
    private static partial Regex Signer();

    private static readonly string[] FleetSources = ["bus", "git", "either"];

    /// <summary>The first thing wrong with the values, in words, or null when the installer would accept them.</summary>
    public static string? Problem(HostEnrolData data) =>
        IdentityProblem(data) ?? EngineProblem(data.Engines) ?? SignerProblem(data.Signers) ?? SourceProblem(data);

    private static string? IdentityProblem(HostEnrolData data) => BusProblem(data) ?? HostProblem(data);

    private static string? BusProblem(HostEnrolData data)
    {
        if (!Device().IsMatch(data.Device)) return "This PC's device label is not one the installer accepts.";
        if (!BusUrl().IsMatch(data.BusUrl)) return "The bus address must be https with a plain host name, for example https://bus.example.lan.";
        return data.CaDer.Length == 0 ? "This PC has no certificate root saved for the bus." : null;
    }

    private static string? HostProblem(HostEnrolData data)
    {
        if (!HostPrefix().IsMatch(data.HostPrefix)) return "The host name is not valid.";
        return EnrolCode().IsMatch(data.EnrolCode) ? null : "The bus did not return a host code in the expected form.";
    }

    private static string? EngineProblem(IReadOnlyList<string> engines)
    {
        var valid = engines.Count is 1 or 2 && engines.All(engine => Engine().IsMatch(engine)) && engines.Distinct().Count() == engines.Count;
        return valid ? null : "Choose GitHub Copilot, Claude Code or both.";
    }

    private static string? SignerProblem(IReadOnlyList<string> signers)
    {
        if (signers.Any(signer => !Signer().IsMatch(signer))) return "A signer line is not a valid allowed_signers line for the site's two namespaces.";
        return signers.Count >= MinSigners ? null : "A site needs two signers before a host can be added, so losing one PC does not lock the site out.";
    }

    private static string? SourceProblem(HostEnrolData data)
    {
        if (!FleetSources.Contains(data.FleetSource)) return "The fleet source must be bus, git or either.";
        return data.Remotes.Count >= 1 && data.Remotes.All(remote => Remote().IsMatch(remote))
            ? null
            : "Each repository location must be https and end with a slash, for example https://github.com/acme/.";
    }

    /// <summary>The certificate root as the installer wants it: base64 of its PEM text.</summary>
    public static string CaPemBase64(byte[] der)
    {
        // PEM lines are 64 characters, joined with line feeds.
        var body = string.Join("\n", Convert.ToBase64String(der).Chunk(64).Select(line => new string(line)));
        return Convert.ToBase64String(Encoding.ASCII.GetBytes($"-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n"));
    }

    /// <summary>
    /// The file's exact bytes. Call only for values with no <see cref="Problem"/>: once they have
    /// passed their patterns, the one character JSON must escape is the double quote in a signer line.
    /// </summary>
    public static byte[] Render(HostEnrolData data) => Encoding.ASCII.GetBytes(RenderText(data, CaPemBase64(data.CaDer)));

    internal static string RenderText(HostEnrolData data, string caPemBase64) => "{" + string.Join(",",
        "\"v\":1",
        Pair("written_at", data.WrittenAt.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm'Z'", System.Globalization.CultureInfo.InvariantCulture)),
        Pair("device", data.Device),
        Pair("bus_url", data.BusUrl),
        Pair("bus_ca_pem", caPemBase64),
        Pair("host_prefix", data.HostPrefix),
        Pair("enrol_code", data.EnrolCode),
        "\"engines\":" + List(data.Engines),
        "\"dedicated\":" + (data.Dedicated ? "true" : "false"),
        "\"signers\":" + List(data.Signers),
        Pair("fleet_source", data.FleetSource),
        "\"remotes\":" + List(data.Remotes)) + "}\n";

    private static string Pair(string key, string value) => $"\"{key}\":{Text(value)}";

    private static string List(IEnumerable<string> values) => "[" + string.Join(",", values.Select(Text)) + "]";

    private static string Text(string value) => "\"" + value.Replace("\"", "\\\"") + "\"";

    /// <summary>What the installer prints for the operator to compare: 16 hex of SHA-256, in fours.</summary>
    public static string Digest(byte[] bytes)
    {
        var hex = Convert.ToHexStringLower(SHA256.HashData(bytes))[..16];
        return string.Join(" ", Enumerable.Range(0, 4).Select(group => hex.Substring(group * 4, 4)));
    }

    /// <summary>A file's whole SHA-256, as <c>Get-FileHash</c> prints it, for the installer script itself.</summary>
    public static string Sha256(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes));

    /// <summary>The key fingerprint of an allowed_signers line, as <c>ssh-keygen -lf</c> prints it.</summary>
    public static string SignerFingerprint(string line) =>
        "SHA256:" + Convert.ToBase64String(SHA256.HashData(Convert.FromBase64String(line.Split(' ')[3]))).TrimEnd('=');
}
