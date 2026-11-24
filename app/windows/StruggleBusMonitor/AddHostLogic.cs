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

    /// <summary>What the operator compares with the installer's own printout, and what to do next.</summary>
    public static string ResultText(string fileName, HostEnrolData data, byte[] file, DateTimeOffset expiresAt, DateTimeOffset now)
    {
        var lines = new List<string>
        {
            $"Saved {fileName} for {data.HostPrefix}.",
            string.Empty,
            $"Data file digest:  {HostEnrolFile.Digest(file)}"
        };
        lines.AddRange(data.Signers.Select(signer => $"Signer:            {HostEnrolFile.SignerFingerprint(signer)}"));
        lines.Add(string.Empty);
        lines.Add("The installer prints the same digest and signer fingerprints before it does anything. Check they match, then press Enter there.");
        lines.Add($"The file holds a one-time code that works once and expires {FeedLogic.TimeLabel(expiresAt, now)}. Move it to the new PC privately. The installer blanks the code once it has been used.");
        lines.Add($@"On the new PC, as an administrator:  powershell -ExecutionPolicy Bypass -File .\bootstrap.ps1 -DataFile .\{HostEnrolFile.FileName}");
        return string.Join(Environment.NewLine, lines);
    }
}
