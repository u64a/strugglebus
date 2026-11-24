using System.Globalization;
using System.Text.RegularExpressions;

namespace StruggleBusMonitor;

public enum AgentPresence { Active, Idle, Offline }

/// <summary>What the operator is looking for: free text plus optional agent and channel.</summary>
public sealed record FeedQuery(string Text, string? Agent, string? Channel)
{
    public static readonly FeedQuery Empty = new(string.Empty, null, null);
    public bool IsEmpty => Text.Length == 0 && Agent is null && Channel is null;
}

public enum SegmentKind { Plain, Hit, Mention }
public sealed record TextSegment(string Text, SegmentKind Kind);

public sealed record MentionToken(int Start, string Prefix);
public sealed record MentionOption(string Insert, string Meta, AgentPresence? Presence, bool IsGroup);

/// <summary>Pure rules for searching, presence, time labels and @mentions. No UI types.</summary>
internal static partial class FeedLogic
{
    public const string EveryoneToken = "everyone";
    public const int MaxMentionsPerMessage = 32;
    public static readonly TimeSpan ActiveWindow = TimeSpan.FromMinutes(5);
    public static readonly TimeSpan IdleWindow = TimeSpan.FromHours(1);

    // Mirrors the server's mention pattern (strugglebus service.py): a name must contain a hyphen.
    [GeneratedRegex(@"(?<![A-Za-z0-9._%+-])@(?<name>[a-z0-9]+(?:-[a-z0-9]+)+)(?![A-Za-z0-9-]|\.[A-Za-z0-9])", RegexOptions.IgnoreCase)]
    private static partial Regex MentionPattern();

    [GeneratedRegex(@"(?<![A-Za-z0-9._%+-])@everyone(?![A-Za-z0-9-])", RegexOptions.IgnoreCase)]
    private static partial Regex EveryonePattern();

    /// <summary>Splits "from:name in:#channel some words" into its parts. Unknown text stays as text.</summary>
    public static FeedQuery ParseQuery(string? raw)
    {
        string? agent = null, channel = null;
        var words = new List<string>();
        foreach (var token in SplitWords(raw))
        {
            if (HasValueAfter(token, "from:"))
                agent = token[5..].TrimStart('@');
            else if (HasValueAfter(token, "in:"))
                channel = NullIfEmpty(token[3..].TrimStart('#'));
            else
                words.Add(token);
        }
        return new FeedQuery(string.Join(' ', words), agent, channel);
    }

    private static string[] SplitWords(string? raw) =>
        (raw ?? string.Empty).Split(' ', StringSplitOptions.RemoveEmptyEntries);

    private static bool HasValueAfter(string token, string prefix) =>
        token.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) && token.Length > prefix.Length;

    private static string? NullIfEmpty(string value) => value.Length == 0 ? null : value;

    public static bool Matches(BusMessage message, FeedQuery query) =>
        IsWanted(query.Channel, message.Channel) && IsWanted(query.Agent, message.AgentName) && MatchesText(message, query.Text);

    /// <summary>True when no particular value is wanted, or the actual one is it (ignoring case).</summary>
    private static bool IsWanted(string? wanted, string actual) =>
        wanted is null || actual.Equals(wanted, StringComparison.OrdinalIgnoreCase);

    private static bool MatchesText(BusMessage message, string text) =>
        text.Length == 0 ||
        message.Body.Contains(text, StringComparison.OrdinalIgnoreCase) ||
        message.AgentName.Contains(text, StringComparison.OrdinalIgnoreCase);

    public static bool MatchesAgent(BusAgent agent, string? filter) =>
        string.IsNullOrWhiteSpace(filter) ||
        agent.Name.Contains(filter.Trim(), StringComparison.OrdinalIgnoreCase) ||
        agent.Host.Contains(filter.Trim(), StringComparison.OrdinalIgnoreCase);

    public static AgentPresence Presence(DateTimeOffset? lastSeen, DateTimeOffset now)
    {
        if (lastSeen is not { } seen) return AgentPresence.Offline;
        var age = now - seen;
        return age <= ActiveWindow ? AgentPresence.Active : age <= IdleWindow ? AgentPresence.Idle : AgentPresence.Offline;
    }

    public static string PresenceLabel(DateTimeOffset? lastSeen, DateTimeOffset now)
    {
        if (lastSeen is null) return "never seen";
        var seen = lastSeen.Value;
        var age = now - seen;
        if (age < TimeSpan.FromMinutes(1)) return "active now";
        if (age <= ActiveWindow) return $"active {(int)age.TotalMinutes}m ago";
        if (age <= IdleWindow) return $"idle {(int)age.TotalMinutes}m";
        return "last seen " + TimeLabel(seen, now, withSeconds: false);
    }

    /// <summary>Time only for today; otherwise the day is included so old messages are not mistaken for new.</summary>
    public static string TimeLabel(DateTimeOffset when, DateTimeOffset now, bool withSeconds = true)
    {
        var local = when.ToLocalTime();
        var today = now.ToLocalTime().Date;
        var time = local.ToString(withSeconds ? "HH:mm:ss" : "HH:mm", CultureInfo.InvariantCulture);
        if (local.Date == today) return time;
        if (local.Date == today.AddDays(-1)) return "yesterday " + local.ToString("HH:mm", CultureInfo.InvariantCulture);
        return local.ToString("d MMM HH:mm", CultureInfo.InvariantCulture);
    }

    /// <summary>Breaks text into plain runs, @mentions and search hits, in order.</summary>
    public static IReadOnlyList<TextSegment> Segment(string text, string? highlight)
    {
        var segments = new List<TextSegment>();
        var position = 0;
        foreach (Match mention in MentionPattern().Matches(text))
        {
            AddWithHits(segments, text[position..mention.Index], highlight);
            segments.Add(new TextSegment(mention.Value, SegmentKind.Mention));
            position = mention.Index + mention.Length;
        }
        AddWithHits(segments, text[position..], highlight);
        return segments;
    }

    private static void AddWithHits(List<TextSegment> segments, string text, string? highlight)
    {
        if (text.Length == 0) return;
        if (string.IsNullOrEmpty(highlight))
        {
            segments.Add(new TextSegment(text, SegmentKind.Plain));
            return;
        }
        AddHits(segments, text, highlight);
    }

    private static void AddHits(List<TextSegment> segments, string text, string highlight)
    {
        var position = 0;
        while (position < text.Length)
        {
            var hit = text.IndexOf(highlight, position, StringComparison.OrdinalIgnoreCase);
            if (hit < 0) break;
            if (hit > position) segments.Add(new TextSegment(text[position..hit], SegmentKind.Plain));
            segments.Add(new TextSegment(text.Substring(hit, highlight.Length), SegmentKind.Hit));
            position = hit + highlight.Length;
        }
        if (position < text.Length) segments.Add(new TextSegment(text[position..], SegmentKind.Plain));
    }

    public static bool IsMentionable(string agentName) => MentionPattern().IsMatch("@" + agentName);

    /// <summary>The "@prefix" being typed at the caret, if the caret sits inside one.</summary>
    public static MentionToken? ActiveMentionToken(string text, int caret)
    {
        if (caret < 0 || caret > text.Length) return null;
        var start = NameStart(text, caret);
        var at = start - 1;
        return StartsMention(text, at) ? new MentionToken(at, text[start..caret]) : null;
    }

    /// <summary>Where the run of name characters ending at the caret begins.</summary>
    private static int NameStart(string text, int caret)
    {
        var start = caret;
        while (start > 0 && IsNameCharacter(text[start - 1])) start--;
        return start;
    }

    private static bool IsNameCharacter(char character) => char.IsAsciiLetterOrDigit(character) || character == '-';

    /// <summary>True when an "@" sits at <paramref name="at"/> and what comes before it lets a mention begin.</summary>
    private static bool StartsMention(string text, int at) =>
        at >= 0 && text[at] == '@' && (at == 0 || CanPrecedeMention(text[at - 1]));

    private static bool CanPrecedeMention(char character) => char.IsWhiteSpace(character) || "([,".Contains(character);

    /// <summary>Agents the bus will accept as a mention, best match first, then the @everyone group.</summary>
    public static IReadOnlyList<MentionOption> MentionOptions(IEnumerable<BusAgent> agents, string prefix, DateTimeOffset now, int limit = 8)
    {
        var mentionable = agents.Where(agent => IsMentionable(agent.Name)).ToList();
        var options = mentionable
            .Where(agent => agent.Name.Contains(prefix, StringComparison.OrdinalIgnoreCase))
            .OrderBy(agent => agent.Name.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) ? 0 : 1)
            .ThenBy(agent => Presence(agent.LastSeenAt, now))
            .ThenBy(agent => agent.Name, StringComparer.OrdinalIgnoreCase)
            .Take(limit)
            .Select(agent => new MentionOption(agent.Name, PresenceLabel(agent.LastSeenAt, now), Presence(agent.LastSeenAt, now), false))
            .ToList();

        if (EveryoneToken.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        {
            var active = mentionable.Count(agent => Presence(agent.LastSeenAt, now) == AgentPresence.Active);
            options.Add(new MentionOption(EveryoneToken, $"adds the {active} active agent{(active == 1 ? "" : "s")} by name", null, true));
        }
        return options;
    }

    /// <summary>
    /// The bus has no group mention, so "@everyone" is replaced with each active agent's name. Names
    /// already mentioned are not repeated, and the total stays within the server's per-message cap.
    /// </summary>
    public static string ExpandEveryone(string body, IEnumerable<BusAgent> agents, DateTimeOffset now)
    {
        if (!EveryonePattern().IsMatch(body)) return body;
        var already = MentionPattern().Matches(body)
            .Select(match => match.Groups["name"].Value.ToLowerInvariant())
            .ToHashSet();
        var names = agents
            .Where(agent => IsMentionable(agent.Name) && Presence(agent.LastSeenAt, now) == AgentPresence.Active)
            .Select(agent => agent.Name)
            .Where(name => !already.Contains(name.ToLowerInvariant()))
            .OrderBy(name => name, StringComparer.OrdinalIgnoreCase)
            .Take(Math.Max(0, MaxMentionsPerMessage - already.Count))
            .Select(name => "@" + name)
            .ToList();
        var replacement = names.Count == 0 ? "everyone" : string.Join(' ', names);
        var first = true;
        return EveryonePattern().Replace(body, _ =>
        {
            if (!first) return "everyone";
            first = false;
            return replacement;
        });
    }

    /// <summary>
    /// Agent questions on #humans that no operator message has replied to yet and the operator has
    /// not cleared, oldest first.
    /// </summary>
    public static IReadOnlyList<BusMessage> WaitingOnOperator(IEnumerable<BusMessage> humansMessages, IReadOnlySet<long>? cleared = null)
    {
        var all = humansMessages.ToList();
        var answered = all.Where(HumansLogic.IsOperator).Select(message => message.ReplyTo).OfType<long>().ToHashSet();
        return all
            .Where(message => !HumansLogic.IsOperator(message) &&
                              message.Kind.Equals("question", StringComparison.OrdinalIgnoreCase) &&
                              !answered.Contains(message.Seq) &&
                              cleared?.Contains(message.Seq) != true)
            .OrderBy(message => message.Seq)
            .ToList();
    }

    /// <summary>Accepts "yyyy-MM-dd", "yyyy-MM-dd HH:mm" or "yyyy-MM-dd HH:mm:ss" in local time; blank means no bound.</summary>
    public static DateTimeOffset? ParseLocalBoundary(string? text, bool isUpperBound)
    {
        if (string.IsNullOrWhiteSpace(text)) return null;
        var local = DateTime.SpecifyKind(ParseBoundary(text.Trim(), isUpperBound), DateTimeKind.Local);
        RequireExistingTime(local, TimeZoneInfo.Local);
        return new DateTimeOffset(local);
    }

    private static DateTime ParseBoundary(string value, bool isUpperBound)
    {
        if (DateTime.TryParseExact(value, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out var day))
            return isUpperBound ? day.AddDays(1).AddTicks(-1) : day;
        if (DateTime.TryParseExact(value, ["yyyy-MM-dd HH:mm", "yyyy-MM-dd HH:mm:ss", "yyyy-MM-dd H:mm"], CultureInfo.InvariantCulture, DateTimeStyles.None, out var moment))
            return moment;
        throw new InvalidOperationException($"'{value}' is not a valid date. Use YYYY-MM-DD or YYYY-MM-DD HH:mm.");
    }

    /// <summary>Refuses a wall-clock time that <paramref name="zone"/> skips when its clocks go forward.</summary>
    internal static void RequireExistingTime(DateTime local, TimeZoneInfo zone)
    {
        if (zone.IsInvalidTime(local))
            throw new InvalidOperationException($"The local time {local:g} does not exist because of a daylight-saving transition.");
    }
}
