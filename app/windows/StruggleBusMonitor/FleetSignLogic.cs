using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace StruggleBusMonitor;

/// <summary>A held signer whose key file is on this PC, so the app can ask the hardware key to sign with it.</summary>
internal sealed record SigningKey(SiteSigner Signer, string KeyFile);

/// <summary>
/// Signing a fleet document with the site's hardware key, from inside the app. The app holds no
/// key: it starts Windows' ssh-keygen, Windows asks for the key's PIN and a touch, and what comes
/// back is checked exactly as a signature made anywhere else would be.
///
/// The same hardware keys also sign software releases, under other namespaces. So the namespace
/// the app signs with is a constant, never a setting or anything read from a file or the bus, and
/// nothing is signed unless it reads strictly as a fleet document. The app is not a way to get a
/// release signature out of the operator's key.
/// </summary>
internal static class FleetSignLogic
{
    /// <summary>The only namespace this app ever asks a key to sign a document for.</summary>
    public const string Namespace = FleetPublishLogic.Namespace;

    public const string NoSigningKey =
        "This PC has no key file for any of its site signers, so the app cannot ask a hardware key to sign. Add the key again with Add a hardware key, choosing the .pub file that sits beside the key's own file.";

    public const string NoTool =
        @"The app cannot ask the hardware key to sign on this PC: it found no ssh-keygen validly signed by Microsoft in C:\Program Files\OpenSSH or in Windows' own System32\OpenSSH. Add it in Windows Settings > System > Optional features > OpenSSH Client. Until then a fleet change is saved for signing with sign-config.ps1 and published with Publish a signed fleet document.";

    public const string NotSigned =
        "The hardware key did not sign. Nothing was published. If no prompt appeared, check that the right key is plugged in: the app asked for";

    public const string Changed =
        "The file that was signed is not byte for byte what the app showed you. The signature was thrown away and nothing was published.";

    /// <summary>The key file that goes with a public file: the same path without ".pub", when it exists.</summary>
    public static string? KeyFileBeside(string publicKeyPath, Func<string, bool> exists)
    {
        if (!publicKeyPath.EndsWith(".pub", StringComparison.OrdinalIgnoreCase)) return null;
        var keyFile = publicKeyPath[..^4];
        return exists(keyFile) ? keyFile : null;
    }

    /// <summary>
    /// The key to sign with: the chosen one when its file is still there, otherwise the first
    /// held signer that has a key file on this PC. Null when none has.
    /// </summary>
    public static SigningKey? KeyToUse(IReadOnlyList<SiteSigner> held, IReadOnlyDictionary<string, string> keyFiles, string? chosen, Func<string, bool> exists)
    {
        var usable = held
            .Where(signer => signer.KeyType == FleetPublishLogic.HardwareKeyType && keyFiles.TryGetValue(signer.KeyBase64, out var file) && exists(file))
            .Select(signer => new SigningKey(signer, keyFiles[signer.KeyBase64]))
            .ToList();
        return usable.FirstOrDefault(key => key.Signer.KeyBase64 == chosen) ?? usable.FirstOrDefault();
    }

    /// <summary>
    /// Throws unless these bytes read strictly as a fleet document. A release file or a release
    /// statement fails here, before any key is asked for anything.
    /// </summary>
    public static long RequireFleet(byte[] document)
    {
        if (FleetPublishLogic.BodyProblem(document) is { } problem) throw new InvalidOperationException(problem + " It is not a fleet document, so it is not signed.");
        var text = Encoding.UTF8.GetString(document);
        var serial = FleetCompose.SerialOf(text);
        FleetCompose.Agents(text);
        return serial;
    }

    /// <summary>The first sixteen hex characters of the SHA-256 of the exact bytes, in fours: enough to compare by eye.</summary>
    public static string ShortHash(byte[] document)
    {
        var hex = Convert.ToHexStringLower(SHA256.HashData(document))[..16];
        return string.Join(" ", Enumerable.Range(0, 4).Select(group => hex.Substring(group * 4, 4)));
    }

    /// <summary>What the operator reads before touching the key: the serial, the change in words, and a short hash of the exact bytes.</summary>
    public static string TouchText(long serial, string change, byte[] document, SigningKey key) => string.Join("\n",
    [
        $"Sign fleet serial {serial} with your hardware key?",
        "",
        $"Change:   {change}",
        $"SHA-256:  {ShortHash(document)} ...  ({document.Length:N0} bytes)",
        $"Key:      {key.Signer.Fingerprint}",
        "",
        "Windows will ask for the key's PIN and a touch. The app then checks the signature, asks Windows Hello, and publishes the fleet to the bus. Every worker host that reads its fleet from the bus takes it up.",
        "",
        "The app only ever asks your key to sign a fleet document, never a software release."
    ]);

    /// <summary>Which key the app will ask to sign, or why it cannot ask any on this PC.</summary>
    public static string SigningKeyText(SigningKey? key, bool toolHere)
    {
        if (key is null) return "The app cannot sign on this PC yet: none of the signers above has its key file here. Add the key from the .pub file beside its key file.";
        return toolHere
            ? $"The app signs the fleet with {key.Signer.Fingerprint} ({Path.GetFileName(key.KeyFile)}). To use another, plug it in and choose Sign with this key beside it."
            : NoTool;
    }

    public static string AddsHost(string agentName) => $"adds worker host {agentName}";

    /// <summary>What to say when ssh-keygen fails: which key was asked for and what the tool said, kept short.</summary>
    public static string NotSignedText(SigningKey key, string toolSaid)
    {
        var said = toolSaid.Replace("\r\n", "\n").Trim();
        var detail = said.Length == 0 ? string.Empty : "\n\nssh-keygen said: " + (said.Length > 400 ? said[..400] : said);
        return $"{NotSigned} {key.Signer.Fingerprint} ({Path.GetFileName(key.KeyFile)}).{detail}";
    }

    public static string SignedReason(long serial, string change)
    {
        var reason = $"Signed and published in the Windows app: fleet serial {serial}, {change}";
        return reason.Length > 256 ? reason[..256] : reason;
    }

    public static string PublishedText(SignedFleet fleet, string change, DateTimeOffset storedAt) =>
        $"Published fleet serial {fleet.Serial} at {storedAt.ToLocalTime():HH:mm:ss}: {change}. Signed in this app with {fleet.Signer.Fingerprint}.\n" +
        "Hosts that read the fleet from the bus take it up at their next check and report the serial on the Hosts page.";
}
