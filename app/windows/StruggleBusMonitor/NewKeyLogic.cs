using System.Text.RegularExpressions;

namespace StruggleBusMonitor;

/// <summary>
/// Setting up a new signing key on a hardware security key, from the app. The key is made by
/// Windows' own ssh-keygen; the private half never leaves the security key, and the app never
/// sees its PIN. A key made here is trusted by nothing until it is added as a site signer, which
/// takes the same question and Windows Hello as any other key.
/// </summary>
internal static partial class NewKeyLogic
{
    /// <summary>The same as the project's existing keys, so every site key is one kind and hosts treat them alike.</summary>
    public const string Application = "ssh:strugglebus-signing";

    public const string FilePrefix = "id_ed25519_sk_strugglebus_";

    public const string NameNeeded =
        "Give the key a short name first, for example A, spare or desk: 1 to 24 letters, digits or hyphens, starting with a letter or digit. It becomes part of the key's file name.";

    public const string NoTool =
        "This PC has no ssh-keygen signed by Microsoft that can talk to a hardware key. Install the Windows OpenSSH Client (Settings, System, Optional features), then try again.";

    public const string TouchText =
        "Windows is asking for the security key now: enter its PIN and touch it when it flashes. If no prompt appears, look behind this window.";

    [GeneratedRegex(@"\A[A-Za-z0-9][A-Za-z0-9-]{0,23}\z")]
    private static partial Regex Name();

    /// <summary>Why this name cannot be used, or null when it can.</summary>
    public static string? NameProblem(string name) => Name().IsMatch(name) ? null : NameNeeded;

    public static string FileName(string name) => FilePrefix + name;

    /// <summary>
    /// What ssh-keygen is asked: a key on the security key, kept on it (resident) so its file can
    /// be recovered from the key, needing the PIN as well as a touch for every signature, and no
    /// passphrase on the file, which is only a handle.
    /// </summary>
    public static string[] Arguments(string name, string keyFile) =>
    [
        "-t", "ed25519-sk",
        "-O", "resident",
        "-O", "verify-required",
        "-O", "application=" + Application,
        "-O", "user=" + name,
        "-N", string.Empty,
        "-C", "strugglebus-" + name,
        "-f", keyFile
    ];

    public static string Exists(string fileName) =>
        $"A key file named {fileName} is already in your .ssh folder, and the app never overwrites a key. Choose another name; if that file is the key you mean, add it from the list instead.";

    public static string Failed(string toolSaid) =>
        "No key was made. " + (toolSaid.Length == 0 ? "ssh-keygen stopped without saying why." : "ssh-keygen said: " + toolSaid) +
        "\n\nThe usual causes: the prompt was cancelled or timed out, the security key has no PIN yet (set one in Windows Settings, Accounts, Sign-in options, Security key), or the key already holds one with this name.";

    /// <summary>
    /// The question for a key the app has just made. There is nothing to compare a new key's
    /// fingerprint with, so the operator is asked to record it: the comparison happens later,
    /// against what each host reports it trusts.
    /// </summary>
    public static string Review(SiteSigner signer, string fileName) =>
        $"A new key was made on your security key.\n\nFingerprint:  {signer.Fingerprint}\nFile:         {fileName}  (in your .ssh folder)\n\n" +
        "Write the fingerprint down or photograph it now. It is how you will recognise this key later, on this screen and in what each host says it trusts.\n\n" +
        "Add it as a site signer? A site signer can sign the fleet: it decides which agents may task every worker host. " +
        "New hosts are told to trust it. Hosts already installed trust only the keys pinned on them, and are not changed by this.\n\n" +
        "If you say no, the key stays on the security key and is listed under the keys found on this PC.";
}
