using System.Text.RegularExpressions;

namespace StruggleBusMonitor;

/// <summary>
/// The site's signers, set up from the app: the operator points at a hardware key's public file
/// and the app writes the signer line. Nothing here is secret; a signer line holds a public key.
/// </summary>
internal static partial class SiteSignersLogic
{
    /// <summary>The name a line the app writes is given. It is a label only; the key is what counts.</summary>
    public const string Principal = "owner";

    public const string Namespaces = "strugglebus-fleet,strugglebus-host-command";

    public const string NotAPublicKey =
        "That is not a public key file. Choose the .pub file beside the hardware key's file, for example id_ed25519_sk_....pub. It is one line starting with the key's type.";

    public const string NotAHardwareKey =
        "That key is not a hardware key (its type is not sk-ssh-ed25519). Hosts accept fleet signatures only from a hardware key that asks for a touch and its PIN, so the app does not add it.";

    public const string AlreadyHeld = "That key is already one of this PC's site signers.";

    public const string PrivateKeyChosen =
        "That is the key file itself, not its public half. Choose the file ending in .pub beside it.";

    public const string TwoNeeded =
        "A site keeps at least two signers, so that losing one key does not lock it out. Add another hardware key before removing this one.";

    [GeneratedRegex(@"\A(?<type>(ssh|sk|ecdsa)-[a-z0-9@.-]+) (?<key>[A-Za-z0-9+/]+={0,2})( [^\n]*)?\z")]
    private static partial Regex PublicKey();

    /// <summary>The signer line for a public key file's text. Throws, in words, for anything that is not a hardware key's public file.</summary>
    public static string LineFor(string publicKeyFile)
    {
        var key = KeyIn(publicKeyFile.Trim());
        if (key.Groups["type"].Value != FleetPublishLogic.HardwareKeyType) throw new InvalidOperationException(NotAHardwareKey);

        var line = $"{Principal} namespaces=\"{Namespaces}\" {FleetPublishLogic.HardwareKeyType} {key.Groups["key"].Value}";
        return HostEnrolFile.IsSignerLine(line) ? line : throw new InvalidOperationException(NotAPublicKey);
    }

    /// <summary>The type and key of a one-line public key file.</summary>
    private static Match KeyIn(string text)
    {
        if (text.StartsWith("-----BEGIN", StringComparison.Ordinal)) throw new InvalidOperationException(PrivateKeyChosen);
        var match = PublicKey().Match(text);
        return match.Success ? match : throw new InvalidOperationException(NotAPublicKey);
    }

    /// <summary>The held lines without the one for this key. Refuses to go below two signers.</summary>
    public static string Remove(string held, string keyBase64)
    {
        var signers = FleetPublishLogic.Signers(held);
        if (signers.Count <= HostEnrolFile.MinSigners) throw new InvalidOperationException(TwoNeeded);
        return string.Join("\n", signers.Where(signer => signer.KeyBase64 != keyBase64).Select(signer => signer.Line));
    }

    /// <summary>
    /// The question before a key is added. The fingerprint is what the operator checks against
    /// the key itself, so a public file swapped on disk does not become a site signer unnoticed.
    /// </summary>
    public static string AddReview(SiteSigner signer, string fileName) =>
        $"Add this hardware key as a site signer?\n\nFingerprint:  {signer.Fingerprint}\nFrom file:    {fileName}\n\n" +
        "Check the fingerprint against the key itself before saying yes: with the key plugged in, " +
        $"ssh-keygen -lf <that file> prints it.\n\n" +
        "A site signer can sign the fleet: it decides which agents may task every worker host. " +
        "New hosts are told to trust it. Hosts already installed trust only the keys pinned on them, and are not changed by this.";

    public static string RemoveReview(SiteSigner signer) =>
        $"Remove this hardware key from the site's signers?\n\nFingerprint:  {signer.Fingerprint}\n\n" +
        "This app will no longer accept a fleet signed by it, and new hosts will not be told to trust it. " +
        "Hosts already installed keep trusting it until it is removed on each host.";

    public static string AddHelloPrompt(SiteSigner signer) => $"Add site signer {signer.Fingerprint}";

    public static string RemoveHelloPrompt(SiteSigner signer) => $"Remove site signer {signer.Fingerprint}";

    [GeneratedRegex(@" (?<type>[a-z0-9@.-]+) (?<key>[A-Za-z0-9+/]+={0,2})( [A-Za-z0-9._@-]{1,64})?\z")]
    private static partial Regex KeyOfLine();

    /// <summary>
    /// The hardware keys named in lines an earlier version of the app kept in its plain settings
    /// file, as lines the app would write today, less any already held. That file could be changed
    /// by any program running as the operator, and its lines could carry other namespaces. So
    /// nothing is taken from it as it stands: only a hardware key survives, its line is rebuilt
    /// with the app's own name and namespaces, and the operator confirms each fingerprint.
    /// </summary>
    public static IReadOnlyList<SiteSigner> Earlier(string earlierLines, string held)
    {
        var known = FleetPublishLogic.Signers(held).Select(signer => signer.KeyBase64).ToHashSet();
        var rebuilt = earlierLines.Replace("\r\n", "\n").Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(Rebuilt)
            .OfType<string>()
            .Distinct();
        return FleetPublishLogic.Signers(string.Join("\n", rebuilt)).Where(signer => !known.Contains(signer.KeyBase64)).ToList();
    }

    /// <summary>The line the app would write for the key on an earlier line, or null when it is not a hardware key's line.</summary>
    private static string? Rebuilt(string earlierLine)
    {
        var match = KeyOfLine().Match(earlierLine);
        if (!match.Success) return null;
        try
        {
            return LineFor($"{match.Groups["type"].Value} {match.Groups["key"].Value}");
        }
        catch (InvalidOperationException)
        {
            return null;
        }
    }

    public static string EarlierReview(IReadOnlyList<SiteSigner> earlier) =>
        $"An earlier version of this app kept {earlier.Count} site signer key{(earlier.Count == 1 ? "" : "s")} in its settings file. Keep {(earlier.Count == 1 ? "it" : "them")} as site signers?\n\n" +
        string.Join("\n", earlier.Select(signer => $"Fingerprint:  {signer.Fingerprint}")) +
        "\n\nCheck each fingerprint against the key itself before saying yes. That file was not protected, so a key you do not recognise must not be kept; say no and add your keys with Add a hardware key instead.";

    public static string EarlierHelloPrompt(int count) => $"Keep {count} earlier site signer key{(count == 1 ? "" : "s")}";

    public static string EarlierButton(int count) => $"Confirm {count} signer key{(count == 1 ? "" : "s")} from an earlier version";

    /// <summary>The held lines with these added.</summary>
    public static string With(string held, IEnumerable<SiteSigner> more) =>
        string.Join("\n", FleetPublishLogic.Signers(held).Concat(more).Select(signer => signer.Line));

    /// <summary>The held lines with one more. Throws when that key is already among them.</summary>
    public static string Add(string held, string line)
    {
        var key = line.Split(' ')[3];
        if (FleetPublishLogic.Signers(held).Any(signer => signer.KeyBase64 == key)) throw new InvalidOperationException(AlreadyHeld);
        var kept = held.Replace("\r\n", "\n").TrimEnd('\n', ' ');
        return kept.Length == 0 ? line : kept + "\n" + line;
    }

    /// <summary>What the held lines amount to, in a sentence, with each key's fingerprint.</summary>
    public static string Summary(string held)
    {
        var signers = FleetPublishLogic.Signers(held);
        var hardware = signers.Count(signer => signer.KeyType == FleetPublishLogic.HardwareKeyType);
        if (signers.Count == 0) return "No site signers yet. Add each hardware key with the button; a site needs two, so that losing one does not lock it out.";
        var keys = string.Join(",  ", signers.Select(signer => signer.Fingerprint));
        var enough = signers.Count >= HostEnrolFile.MinSigners ? string.Empty : "  A site needs two before a host can be added.";
        return $"{signers.Count} site signer{(signers.Count == 1 ? "" : "s")}, {hardware} on a hardware key:  {keys}.{enough}";
    }
}
