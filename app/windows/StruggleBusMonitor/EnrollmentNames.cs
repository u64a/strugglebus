using System.Text.RegularExpressions;

namespace StruggleBusMonitor;

/// <summary>What the Enroll tab says under a name box: nothing, a note, or a problem that blocks creating.</summary>
internal sealed record NameFeedback(string Text, bool IsProblem)
{
    public static readonly NameFeedback None = new("", false);
}

/// <summary>
/// One of the bus's naming rules. The bus tidies agent names and device labels itself (spaces and
/// underscores become hyphens); service principal names and prefixes are only trimmed and lowercased.
/// </summary>
internal sealed record NameRule(string Noun, int MaxLength, bool NeedsHyphen, bool TidiesSeparators, string Example)
{
    public static readonly NameRule Agent = new("Agent names", 128, true, true, "adlab-cli-win");
    public static readonly NameRule Device = new("Device labels", 64, false, true, "owner-phone");
    public static readonly NameRule ServicePrincipal = new("Service principal names", 64, false, false, "nightly-audit");
    public static readonly NameRule Prefix = new("Agent name prefixes", 128, false, false, "audit-worker");

    public static NameRule For(EnrollmentKind kind) => kind switch
    {
        EnrollmentKind.ServicePrincipal => ServicePrincipal,
        EnrollmentKind.Device => Device,
        _ => Agent
    };
}

/// <summary>The bus's naming rules, checked here so a bad name is explained before anything is sent.</summary>
internal static partial class EnrollmentNames
{
    [GeneratedRegex(@"[\s_]+")]
    private static partial Regex Separators();

    [GeneratedRegex("-+")]
    private static partial Regex RepeatedHyphens();

    [GeneratedRegex("^[a-z0-9]+(?:-[a-z0-9]+)*$")]
    private static partial Regex Kebab();

    [GeneratedRegex("[^a-z0-9-]")]
    private static partial Regex NotAllowed();

    /// <summary>The name as the bus will store it.</summary>
    public static string Canonical(NameRule rule, string typed)
    {
        var lowered = typed.Trim().ToLowerInvariant();
        return rule.TidiesSeparators ? RepeatedHyphens().Replace(Separators().Replace(lowered, "-"), "-") : lowered;
    }

    /// <summary>Why the bus would refuse this name, in plain words, or null when it would accept it. Empty is not judged here.</summary>
    public static string? Problem(NameRule rule, string typed)
    {
        var name = Canonical(rule, typed);
        if (name.Length == 0) return null;
        return CharacterProblem(rule, name) ?? ShapeProblem(rule, name);
    }

    private static string? CharacterProblem(NameRule rule, string name)
    {
        var unwanted = NotAllowed().Matches(name).Select(match => Shown(match.Value)).Distinct().ToList();
        if (unwanted.Count == 0) return null;
        return $"{rule.Noun} can only use lowercase letters, digits and hyphens. Remove: {string.Join(" ", unwanted)}";
    }

    private static string Shown(string character) => string.IsNullOrWhiteSpace(character) ? "space" : character;

    private static string? ShapeProblem(NameRule rule, string name)
    {
        if (!Kebab().IsMatch(name)) return $"{rule.Noun} cannot start or end with a hyphen, or have two hyphens in a row.";
        if (rule.NeedsHyphen && !name.Contains('-'))
            return $"{rule.Noun} need at least one hyphen, joining a project and a platform, for example {rule.Example}.";
        return name.Length > rule.MaxLength ? $"{rule.Noun} are limited to {rule.MaxLength} characters; this one has {name.Length}." : null;
    }

    /// <summary>What to show under the box while the operator types.</summary>
    public static NameFeedback Feedback(NameRule rule, string typed)
    {
        if (Problem(rule, typed) is { } problem) return new NameFeedback(problem, true);
        var name = Canonical(rule, typed);
        return name == typed.Trim() ? NameFeedback.None : new NameFeedback($"Will be created as {name}", false);
    }
}
