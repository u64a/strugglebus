using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace StruggleBusMonitor;

/// <summary>One signer line this PC holds: an allowed_signers line the operator pasted for Add a host.</summary>
internal sealed record SiteSigner(string Line, string Principal, IReadOnlyList<string> Namespaces, string KeyType, string KeyBase64)
{
    /// <summary>The key's fingerprint as <c>ssh-keygen -lf</c> prints it.</summary>
    public string Fingerprint =>
        "SHA256:" + Convert.ToBase64String(SHA256.HashData(Convert.FromBase64String(KeyBase64))).TrimEnd('=');
}

/// <summary>A fleet document and signature that passed every check the app can make without running a program.</summary>
internal sealed record SignedFleet(byte[] Body, string Signature, long Serial, SiteSigner Signer);

/// <summary>What <c>ssh-keygen -Y verify</c> said.</summary>
internal enum SshVerdict
{
    Good,
    Bad,
    /// <summary>Windows' own ssh-keygen is not on this PC.</summary>
    NoTool,
    /// <summary>The ssh-keygen on this PC is not validly signed by Microsoft, so its answer is not used.</summary>
    UntrustedTool
}

/// <summary>
/// Publishing a fleet document that was signed somewhere else. The app does not sign: until it is
/// a packaged Windows app, a key it made could be used by other programs in the operator's
/// session, so the site's hardware keys stay the only fleet signers. The app's part is to refuse
/// anything that is not what the hosts would accept, before the bus stores it and the serial is
/// spent.
///
/// Every check is against what this PC already holds. Nothing here trusts the bus: a bus that was
/// tampered with must not be able to hand the app the keys to check against.
/// </summary>
internal static partial class FleetPublishLogic
{
    public const string DocumentName = "fleet";
    public const string Namespace = "strugglebus-fleet";
    public const string HardwareKeyType = "sk-ssh-ed25519@openssh.com";

    /// <summary>Touched (bit 0) and verified with the PIN (bit 2), and nothing else: what the hosts require.</summary>
    public const byte TouchAndPin = 0x05;

    /// <summary>The bus's and the hosts' limit for a fleet document.</summary>
    public const int MaxBytes = 64 * 1024;

    public const string NeedsOperator = "Publishing the fleet needs operator access saved on this PC. Save it on Admin first.";
    public const string NoSigners = "This PC holds no signer lines to check a fleet against. Paste the site's signer lines under Add a host first; they are the ones every host was given.";
    public const string NotASignature = "The .sig file is not an OpenSSH signature file.";
    public const string WrongPurpose = "The signature was not made for a fleet document (namespace " + Namespace + "). It is not published.";
    public const string UnknownSigner = "The signature was made by a key that is not one of this PC's signer lines for the fleet. It is not published.";
    public const string NotAHardwareKey = "The fleet must be signed with one of the site's hardware keys (a YubiKey). This signature was made by another kind of key. It is not published.";
    public const string NoTouchAndPin = "The hardware key did not record both a touch and the PIN for this signature, which every host requires. Sign again with a key that asks for both. It is not published.";
    public const string BadSignature = "The signature does not verify for these exact bytes. The file was changed after it was signed, or the signature belongs to another file. It is not published.";
    public const string NoTool = @"Windows' own ssh-keygen was not found (System32\OpenSSH\ssh-keygen.exe), so the signature could not be checked and nothing is published. Add it in Windows Settings > System > Optional features > OpenSSH Client.";
    public const string UntrustedTool = @"The ssh-keygen in System32\OpenSSH on this PC is not validly signed by Microsoft, so the app will not take its word that a signature verifies. Nothing is published. Repair it in Windows Settings > System > Optional features > OpenSSH Client.";
    public const string NoSerial = "The document does not have exactly one serial line before its first table, so the app cannot tell its serial. It is not published.";

    [GeneratedRegex(@"\A(?<principal>[A-Za-z0-9][A-Za-z0-9._@-]{0,63}) namespaces=""(?<namespaces>[a-z,-]+)"" (?<type>[a-z0-9@.-]+) (?<key>[A-Za-z0-9+/]+={0,2})( [A-Za-z0-9._@-]{1,64})?\z")]
    private static partial Regex SignerLine();

    [GeneratedRegex(@"\Aserial[ \t]*=[ \t]*(?<serial>[1-9][0-9]{0,14})[ \t]*(#.*)?\z")]
    private static partial Regex SerialLine();

    /// <summary>The signer lines held on this PC, one per line of the saved text. A line that is not a valid signer line is left out.</summary>
    public static IReadOnlyList<SiteSigner> Signers(string held) =>
        held.Replace("\r\n", "\n").Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(HostEnrolFile.IsSignerLine)
            .Select(line => (line, match: SignerLine().Match(line)))
            .Where(entry => entry.match.Success)
            .Select(entry => new SiteSigner(
                entry.line, entry.match.Groups["principal"].Value, entry.match.Groups["namespaces"].Value.Split(','),
                entry.match.Groups["type"].Value, entry.match.Groups["key"].Value))
            .ToList();

    /// <summary>Why these bytes cannot be a fleet document as hosts read one, or null.</summary>
    public static string? BodyProblem(byte[] body)
    {
        if (body.Length == 0) return "The document is empty.";
        if (body.Length > MaxBytes) return $"The document is {body.Length:N0} bytes. A fleet document is at most {MaxBytes:N0}.";
        return TextProblem(body);
    }

    private static string? TextProblem(byte[] body)
    {
        if (body.AsSpan().StartsWith(Encoding.UTF8.Preamble)) return "The document starts with a byte-order mark, which hosts refuse. Save it as UTF-8 without one.";
        if (body.Contains((byte)'\r')) return "The document has Windows line endings, which hosts refuse. Save it with LF line endings.";
        return IsUtf8(body) ? null : "The document is not valid UTF-8.";
    }

    private static bool IsUtf8(byte[] body)
    {
        try
        {
            new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true).GetCharCount(body);
            return true;
        }
        catch (DecoderFallbackException)
        {
            return false;
        }
    }

    /// <summary>
    /// The serial the signed bytes state: the one serial line before the first table. Null when
    /// there is none or more than one, so the app never sends the bus a serial the document does
    /// not say.
    /// </summary>
    public static long? Serial(byte[] body)
    {
        var top = Encoding.UTF8.GetString(body).Split('\n').TakeWhile(line => !line.TrimStart().StartsWith('['));
        var serials = top.Select(line => SerialLine().Match(line)).Where(match => match.Success).ToList();
        return serials.Count == 1 ? long.Parse(serials[0].Groups["serial"].Value) : null;
    }

    /// <summary>
    /// The held signer that made this signature, after the checks on what the signature says about
    /// itself. Throws with the reason in words when any fails.
    /// </summary>
    public static SiteSigner SignerOf(string? signatureText, IReadOnlyList<SiteSigner> held)
    {
        if (held.Count == 0) throw new InvalidOperationException(NoSigners);
        var signature = SshSignature.Read(signatureText) ?? throw new InvalidOperationException(NotASignature);
        var signer = HeldSignerOf(signature, held);
        if (KeyProblem(signature) is { } problem) throw new InvalidOperationException(problem);
        return signer;
    }

    /// <summary>The held line whose key made a signature for fleets. A key held only for commands does not count.</summary>
    private static SiteSigner HeldSignerOf(SshSignature signature, IReadOnlyList<SiteSigner> held)
    {
        if (signature.Namespace != Namespace) throw new InvalidOperationException(WrongPurpose);
        return held.FirstOrDefault(candidate => candidate.KeyBase64 == signature.KeyBase64 && candidate.Namespaces.Contains(Namespace))
            ?? throw new InvalidOperationException(UnknownSigner);
    }

    /// <summary>Hosts accept a fleet only from a hardware key that recorded a touch and its PIN.</summary>
    private static string? KeyProblem(SshSignature signature)
    {
        if (signature.KeyType != HardwareKeyType) return NotAHardwareKey;
        return signature.Flags == TouchAndPin ? null : NoTouchAndPin;
    }

    /// <summary>Everything checked before <c>ssh-keygen</c> is asked: the bytes, their serial, and the signature's own claims.</summary>
    public static SignedFleet Check(byte[] body, string? signatureText, IReadOnlyList<SiteSigner> held)
    {
        if (BodyProblem(body) is { } problem) throw new InvalidOperationException(problem + " It is not published.");
        if (Serial(body) is not { } serial) throw new InvalidOperationException(NoSerial);
        var signer = SignerOf(signatureText, held);
        return new SignedFleet(body, signatureText!.Replace("\r\n", "\n"), serial, signer);
    }

    /// <summary>Why <c>ssh-keygen</c>'s answer stops the publish, or null when the signature verified.</summary>
    public static string? VerdictProblem(SshVerdict verdict) => verdict switch
    {
        SshVerdict.Good => null,
        SshVerdict.NoTool => NoTool,
        SshVerdict.UntrustedTool => UntrustedTool,
        _ => BadSignature
    };

    /// <summary>Why this serial cannot be published over what the bus holds, or null. The bus refuses it too; saying so first spares the Windows Hello prompt.</summary>
    public static string? SerialProblem(long serial, long? stored) =>
        stored is { } held && serial <= held
            ? $"The bus already holds fleet serial {held}. This document is serial {serial}, which is not higher, so hosts would ignore it. It is not published."
            : null;

    public static string ConfirmText(SignedFleet fleet, long? stored) =>
        $"Publish fleet serial {fleet.Serial} to the bus?\n\n" +
        $"Signed by {fleet.Signer.Principal}, {fleet.Signer.Fingerprint}. The signature verifies for these exact {fleet.Body.Length:N0} bytes.\n" +
        (stored is { } held ? $"It replaces serial {held}." : "The bus holds no fleet document yet.") +
        "\n\nEvery worker host that reads its fleet from the bus will take it up. The app publishes the bytes and the signature unchanged.";

    public static string HelloPrompt(long serial) => $"Publish fleet serial {serial} to the bus";

    public static string Reason(long serial) => $"Published from the Windows app, signed elsewhere: fleet serial {serial}";

    public static string ResultText(SignedFleet fleet, DateTimeOffset storedAt) =>
        $"Published fleet serial {fleet.Serial} at {storedAt.ToLocalTime():HH:mm:ss}, signed by {fleet.Signer.Principal} ({fleet.Signer.Fingerprint}).\n" +
        "Hosts that read the fleet from the bus take it up at their next check and report the serial on the Hosts page.";
}
