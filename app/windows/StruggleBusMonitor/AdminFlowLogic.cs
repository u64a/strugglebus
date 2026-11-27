using System.Globalization;

namespace StruggleBusMonitor;

/// <summary>What the Enroll tab shows for the kind of enrollment that is selected.</summary>
internal sealed record EnrollmentForm(string NameLabel, bool ShowSecond, string SecondLabel, bool MonoSecond, string Hint, string CreateLabel);

/// <summary>
/// The words, checks and choices behind the Admin page's actions, kept apart from the window so they
/// can be tested. A failed check is an <see cref="InvalidOperationException"/> whose message is shown
/// in the notice bar.
/// </summary>
internal static class AdminFlow
{
    public const string LegacyLists =
        "This bus is older than 0.2.64, so only containment is available here. Update the bus to manage everything from this app.";

    public const string LegacyAgents =
        "This bus is older than 0.2.64, so only enabled agents are listed and blocking is the only action. Update the bus to unblock and retire from this app.";

    public const string HelloNotCompleted = "Windows Hello verification was not completed.";

    // ---- Lists -------------------------------------------------------------------------------

    /// <summary>
    /// What a bus says to a route it is too old to have. Its permission check comes before its
    /// routing and refuses, with these words, any route it has no rule for; so from a real bus an
    /// unknown route is this "forbidden", not "not found".
    /// </summary>
    public const string UnknownRouteDetail = "route declares no capability";

    /// <summary>
    /// True when the answer means the bus is too old to have the route: "not found", "not allowed",
    /// or the bus's own refusal of a route it has no rule for. Any other "forbidden" is a real one.
    /// </summary>
    public static bool IsLegacyBus(BusApiException error) =>
        error.StatusCode is 404 or 405 || (error.StatusCode == 403 && error.Detail == UnknownRouteDetail);

    /// <summary>How many agent rows are put on screen at a time. Each row is a real control with its buttons.</summary>
    public const int AgentPageSize = 100;

    /// <summary>
    /// How long the lists are trusted before opening Admin fetches them again. Within this time
    /// the page opens at once with what it has; Reload always fetches.
    /// </summary>
    public static readonly TimeSpan ListsFreshFor = TimeSpan.FromSeconds(60);

    public static bool ListsAreStale(DateTimeOffset? loadedAt, DateTimeOffset now) =>
        loadedAt is not { } loaded || now - loaded >= ListsFreshFor;

    /// <summary>The label on the button under a long list, or null when every matching row is showing.</summary>
    public static string? MoreAgentsLabel(int showing, int matching)
    {
        var hidden = matching - showing;
        if (hidden <= 0) return null;
        return $"Show {Math.Min(AgentPageSize, hidden)} more ({hidden} not shown)";
    }

    public static string AgentsSummary(bool legacy, int shown, IReadOnlyCollection<AdminRow> all)
    {
        if (legacy) return LegacyAgents;
        return shown == all.Count ? AdminLogic.Summary(all, "agent") : $"{shown} of {all.Count} agents match.";
    }

    public static string DevicesSummary(bool legacy, IReadOnlyCollection<AdminRow> devices) =>
        legacy ? LegacyLists : AdminLogic.Summary(devices, "device");

    public static string ServicePrincipalsSummary(bool legacy, IReadOnlyCollection<AdminRow> principals)
    {
        if (legacy) return LegacyLists;
        return principals.Count == 0
            ? "No service principals. Create one on the Enroll tab."
            : AdminLogic.Summary(principals, "service principal");
    }

    // ---- Row actions -------------------------------------------------------------------------

    /// <summary>
    /// Device revocation and, on an older bus, blocking go through the server-confirmed flow. Null
    /// means the row is acted on directly with the action the bus listed for it.
    /// </summary>
    public static OperatorAction? ConfirmedAction(AdminRow row)
    {
        if (row.Kind == AdminRowKind.Device) return OperatorAction.RevokeDevice;
        return row.Legacy ? OperatorAction.BlockAgent : null;
    }

    public static string KindNoun(AdminRowKind kind) => kind == AdminRowKind.Agent ? "agent" : "service principal";

    public const string GrantNeeded = "Save operator access on the Access tab first.";

    /// <summary>The trimmed audit reason for a direct action, once it and the operator grant are in place.</summary>
    public static string RequireControl(string reasonText, bool hasGrant)
    {
        var reason = reasonText.Trim();
        if (reason.Length == 0) throw new InvalidOperationException("Enter an audit reason before requesting an action.");
        if (!hasGrant) throw new InvalidOperationException(GrantNeeded);
        return reason;
    }

    public static void RequireReason(string reasonText)
    {
        if (string.IsNullOrWhiteSpace(reasonText))
            throw new InvalidOperationException("Enter an audit reason before requesting an action.");
    }

    public static string ControlReview(AdminRowAction action) =>
        $"TARGET\n{KindNoun(action.Row.Kind)} {action.Row.Name}\n\nACTION\n{action.Label}\n\nEFFECT\n{action.Effect}\n\nContinue to Windows Hello?";

    public static string ControlHelloPrompt(AdminRowAction action) =>
        $"{action.Label} {KindNoun(action.Row.Kind)} {action.Row.Name}";

    public static string ControlConflict(AdminRow row) =>
        $"{row.Name} changed before this ran, so nothing was done. The list has been reloaded.";

    public static string ControlResultText(ControlResult result) => $"{result.TargetLabel}: {result.Detail}";

    public static string ContainmentReview(Confirmation confirmation) =>
        $"TARGET\n{confirmation.TargetLabel}\n\nEFFECT\n{confirmation.Effect}\n\nContinue to Windows Hello?";

    public static string ActionResultText(ActionResult result) =>
        result.Applied ? $"Applied: {result.Detail}" : $"Not applied: {result.Detail}";

    /// <summary>This PC just revoked itself, so its saved enrollment is of no further use.</summary>
    public static bool RevokedThisPc(OperatorAction action, ActionResult result, string target, Session? session) =>
        action == OperatorAction.RevokeDevice && result.Applied && target == session?.DeviceId;

    // ---- Enrollment --------------------------------------------------------------------------

    public static EnrollmentKind KindOf(bool servicePrincipal, bool device)
    {
        if (servicePrincipal) return EnrollmentKind.ServicePrincipal;
        return device ? EnrollmentKind.Device : EnrollmentKind.Agent;
    }

    public static EnrollmentForm Form(EnrollmentKind kind) => kind switch
    {
        EnrollmentKind.ServicePrincipal => new EnrollmentForm(
            "Service principal name", true, "Agent name prefix", true,
            "A service principal is an automation identity. Its name and prefix use lowercase letters, digits and hyphens. It can only create short-lived worker agents whose names start with the prefix; they expire within 12 hours.",
            "Create service principal"),
        EnrollmentKind.Device => new EnrollmentForm(
            "Device label", false, "Description (optional)", false,
            "Creates a single-use enrollment for another phone or PC, valid for a few minutes. Labels use lowercase letters, digits and hyphens, for example owner-phone, and stay reserved even after the device is revoked.",
            "Create device enrollment"),
        _ => new EnrollmentForm(
            "Agent name", true, "Description (optional)", false,
            "Names use lowercase letters, digits and hyphens, with at least one hyphen, for example adlab-cli-win. The package is single use and expires shortly after it is created.",
            "Create onboarding package")
    };

    /// <summary>Checks the Enroll tab's inputs in the order the operator fills them in.</summary>
    public static void RequireEnrollment(EnrollmentKind kind, string name, string second, string reason, bool hasGrant)
    {
        if (EnrollmentProblem(kind, name, second, reason, hasGrant) is { } problem) throw new InvalidOperationException(problem);
    }

    private static string? EnrollmentProblem(EnrollmentKind kind, string name, string second, string reason, bool hasGrant) =>
        NamingProblem(kind, name, second) ?? AuditProblem(reason, hasGrant);

    private static string? NamingProblem(EnrollmentKind kind, string name, string second)
    {
        if (name.Length == 0) return $"Enter the {Form(kind).NameLabel.ToLowerInvariant()}.";
        return EnrollmentNames.Problem(NameRule.For(kind), name) ?? PrefixProblem(kind, second);
    }

    private static string? PrefixProblem(EnrollmentKind kind, string prefix)
    {
        if (kind != EnrollmentKind.ServicePrincipal) return null;
        return prefix.Length == 0 ? "Enter the agent name prefix its workers will use." : EnrollmentNames.Problem(NameRule.Prefix, prefix);
    }

    /// <summary>What to show under the name box while the operator types.</summary>
    public static NameFeedback NameFeedback(EnrollmentKind kind, string name) =>
        EnrollmentNames.Feedback(NameRule.For(kind), name);

    /// <summary>What to show under the second box: only a service principal's prefix follows a naming rule.</summary>
    public static NameFeedback SecondFeedback(EnrollmentKind kind, string second) =>
        kind == EnrollmentKind.ServicePrincipal ? EnrollmentNames.Feedback(NameRule.Prefix, second) : StruggleBusMonitor.NameFeedback.None;

    /// <summary>The name to send and to show at Windows Hello: what the bus will store.</summary>
    public static string EnrollmentName(EnrollmentKind kind, string name) => EnrollmentNames.Canonical(NameRule.For(kind), name);

    /// <summary>The second box as sent: a prefix is stored trimmed and lowercased, a description is left alone.</summary>
    public static string EnrollmentSecond(EnrollmentKind kind, string second) =>
        kind == EnrollmentKind.ServicePrincipal ? EnrollmentNames.Canonical(NameRule.Prefix, second) : second;

    private static string? AuditProblem(string reason, bool hasGrant)
    {
        if (reason.Length == 0) return "Enter an audit reason.";
        return hasGrant ? null : "Save operator access above before creating enrollments.";
    }

    public static string EnrollmentHelloPrompt(EnrollmentKind kind, string name) => "Create an enrollment for " + kind switch
    {
        EnrollmentKind.ServicePrincipal => $"service principal {name}",
        EnrollmentKind.Device => $"device {name}",
        _ => $"agent {name}"
    };

    // ---- Export ------------------------------------------------------------------------------

    public static string ExportBoundary(DateTimeOffset moment) =>
        moment.LocalDateTime.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture);

    public static string ExportFileName(DateTime now) => $"strugglebus-messages-{now:yyyyMMdd-HHmmss}.csv";

    /// <summary>Reads the two date boxes. Either may be empty; together they must be in order.</summary>
    public static (DateTimeOffset? From, DateTimeOffset? To) ExportWindow(string fromText, string toText)
    {
        var from = FeedLogic.ParseLocalBoundary(fromText, isUpperBound: false);
        var to = FeedLogic.ParseLocalBoundary(toText, isUpperBound: true);
        if (from > to) throw new InvalidOperationException("The export start must be earlier than the end.");
        return (from, to);
    }

    /// <summary>The messages inside the window, oldest first. An empty export is refused.</summary>
    public static List<BusMessage> SelectExport(IEnumerable<BusMessage> messages, DateTimeOffset? from, DateTimeOffset? to)
    {
        var filtered = messages
            .Where(message => !(message.CreatedAt < from) && !(message.CreatedAt > to))
            .OrderBy(message => message.Seq)
            .ToList();
        if (filtered.Count == 0) throw new InvalidOperationException("No retained messages fall inside those dates.");
        return filtered;
    }

    public static string ExportSaved(string fileName, int count) => $"Saved {fileName} with {count} messages.";
}
