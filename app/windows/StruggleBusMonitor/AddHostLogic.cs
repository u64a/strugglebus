namespace StruggleBusMonitor;

/// <summary>What the operator filled in on the Add a host form.</summary>
public sealed record AddHostForm(
    string PcName,
    bool Claude,
    bool Copilot,
    bool Dedicated,
    string Signers,
    string Remotes,
    string FleetSource,
    string Reason);

/// <summary>Pure decisions for adding a worker host, kept apart from the window so they can be tested.</summary>
internal static class AddHostLogic
{
    public const string PrefixStart = "host-";
    public const string DefaultFleetSource = "bus";

    public const string BusTooOld =
        "This bus does not have host codes yet. Update the bus to a release with worker host support, then try again.";

    /// <summary>
    /// A code that passes the installer's shape check, used to test every other value before a
    /// real code is asked for. A real code is single use, so it is never spent on a form that
    /// would be refused anyway.
    /// </summary>
    internal static readonly string PlaceholderCode = "sbhe1_" + new string('A', 22) + "_" + new string('A', 43);

    /// <summary>The host's name on the bus: "host-" and the PC's name, tidied the way the bus tidies names.</summary>
    public static string Prefix(string pcName)
    {
        var name = EnrollmentNames.Canonical(NameRule.Device, pcName);
        return name.StartsWith(PrefixStart, StringComparison.Ordinal) ? name : PrefixStart + name;
    }

    /// <summary>What to show under the PC name box while the operator types.</summary>
    public static NameFeedback NameFeedback(string pcName)
    {
        if (pcName.Trim().Length == 0) return StruggleBusMonitor.NameFeedback.None;
        if (EnrollmentNames.Problem(NameRule.Device, pcName) is { } problem) return new NameFeedback(problem, true);
        var prefix = Prefix(pcName);
        return prefix.Length > 31
            ? new NameFeedback($"That name is too long: {prefix} has {prefix.Length} characters and the limit is 31.", true)
            : new NameFeedback($"It will join the bus as {prefix}", false);
    }

    /// <summary>The non-empty lines of a multi-line box, trimmed.</summary>
    public static IReadOnlyList<string> Lines(string text) =>
        text.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();

    /// <summary>The chosen engines. Claude Code comes first, so it is the default when both are chosen.</summary>
    public static IReadOnlyList<string> Engines(bool claude, bool copilot)
    {
        var engines = new List<string>();
        if (claude) engines.Add("claude");
        if (copilot) engines.Add("ghcp");
        return engines;
    }

    public static HostEnrolData Data(AddHostForm form, Session session, string code, DateTimeOffset now) => new(
        WrittenAt: now,
        Device: session.DeviceLabel,
        BusUrl: session.Endpoint.TrimEnd('/'),
        CaDer: session.CaDer,
        HostPrefix: Prefix(form.PcName),
        EnrolCode: code,
        Engines: Engines(form.Claude, form.Copilot),
        Dedicated: form.Dedicated,
        Signers: Lines(form.Signers),
        FleetSource: form.FleetSource,
        Remotes: Lines(form.Remotes));

    /// <summary>
    /// Everything wrong with the form that can be known before a code is minted, or null.
    /// The order follows the form from top to bottom.
    /// </summary>
    public static string? Problem(AddHostForm form, Session session, bool hasGrant, DateTimeOffset now)
    {
        if (form.PcName.Trim().Length == 0) return "Enter the PC's name.";
        if (NameFeedback(form.PcName) is { IsProblem: true } name) return name.Text;
        return HostEnrolFile.Problem(Data(form, session, PlaceholderCode, now)) ?? AuditProblem(form.Reason, hasGrant);
    }

    private static string? AuditProblem(string reason, bool hasGrant)
    {
        if (reason.Trim().Length == 0) return "Enter an audit reason.";
        return hasGrant ? null : "Save operator access on the Access and freeze tab before adding a host.";
    }

    public static string HelloPrompt(string prefix) => $"Create a one-time code for worker host {prefix}";

    public const string BootstrapFileName = "bootstrap.ps1";

    /// <summary>
    /// The worker host's installer, exactly as it is in this build's source (worker-host/tools). The
    /// app hands it over unchanged and never edits it: only its hash is shown, for the operator to
    /// check on the new PC before running it.
    /// </summary>
    public static byte[] Bootstrap()
    {
        using var stream = typeof(AddHostLogic).Assembly.GetManifestResourceStream(BootstrapFileName)!;
        using var copy = new System.IO.MemoryStream();
        stream.CopyTo(copy);
        return copy.ToArray();
    }

    /// <summary>
    /// How to check the installer on the new PC before running it. A signed installer is checked
    /// by its signature and the certificate's thumbprint (a name can be shared, a thumbprint
    /// cannot); an unsigned one by its hash.
    /// </summary>
    internal static IReadOnlyList<string> InstallerCheck(HostInstaller installer) => installer.Signed
        ?
        [
            $@"1. On the new PC, check the installer before running it:  $s = Get-AuthenticodeSignature .\{BootstrapFileName}; $s.Status -eq 'Valid' -and $s.SignerCertificate.Thumbprint -eq '{installer.Thumbprint}'",
            "   It must print:   True"
        ]
        :
        [
            $@"1. On the new PC, check the installer before running it:  Get-FileHash -Algorithm SHA256 .\{BootstrapFileName}",
            $"   It must print:   {HostEnrolFile.Sha256(installer.Bytes)}"
        ];

    /// <summary>What the operator checks on the new PC, in the order they do it.</summary>
    public static string ResultText(string fileName, HostEnrolData data, byte[] file, HostInstaller installer, DateTimeOffset expiresAt, DateTimeOffset now)
    {
        var lines = new List<string>();
        if (installer.Warning is not null) lines.AddRange([installer.Warning, string.Empty]);
        lines.AddRange(
        [
            $"Saved {fileName} and {BootstrapFileName} for {data.HostPrefix}. Move both to the new PC.",
            string.Empty,
            .. InstallerCheck(installer),
            string.Empty,
            $@"2. Run it as an administrator:  powershell -ExecutionPolicy Bypass -File .\{BootstrapFileName} -DataFile .\{HostEnrolFile.FileName}",
            string.Empty,
            "3. Before it does anything, the installer prints these. Check they match, then press Enter there:",
            $"   Data file digest:  {HostEnrolFile.Digest(file)}"
        ]);
        lines.AddRange(data.Signers.Select(signer => $"   Signer:            {HostEnrolFile.SignerFingerprint(signer)}"));
        lines.Add(string.Empty);
        lines.Add($"The data file holds a one-time code that works once and expires {FeedLogic.TimeLabel(expiresAt, now)}. Move it privately. The installer blanks the code once it has been used.");
        return string.Join(Environment.NewLine, lines);
    }
}
