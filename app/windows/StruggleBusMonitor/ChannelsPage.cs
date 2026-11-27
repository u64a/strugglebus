namespace StruggleBusMonitor;

/// <summary>
/// One channel with what it is for and how busy it is. The three figures are null from a bus too
/// old to give them.
/// </summary>
public sealed record ChannelActivity(string Name, string Purpose, int? Messages, int? Subscribers, DateTimeOffset? LastActivityAt);

/// <summary>One channel on the Channels page.</summary>
public sealed class ChannelCard
{
    public required string Name { get; init; }
    public string Label => "#" + Name;

    /// <summary>What the channel is for, in its owner's words. Shown as plain text.</summary>
    public string Purpose { get; init; } = string.Empty;
    public bool HasPurpose => Purpose.Length > 0;
    public string Figures { get; init; } = string.Empty;
    public bool HasFigures => Figures.Length > 0;
}

/// <summary>Pure decisions for the Channels page, kept apart from the window so they can be tested.</summary>
internal static class ChannelsPageLogic
{
    public static readonly TimeSpan FreshFor = TimeSpan.FromSeconds(60);

    public const string NoFigures = "This bus gives each channel's name and purpose. Message and subscriber counts need a newer StruggleBus.";

    public static ChannelCard Card(ChannelActivity channel, DateTimeOffset now) => new()
    {
        Name = channel.Name,
        Purpose = channel.Purpose.Trim(),
        Figures = Figures(channel, now)
    };

    /// <summary>"12 messages · 3 agents listening · last message 14:02", or nothing from a bus that gives no figures.</summary>
    internal static string Figures(ChannelActivity channel, DateTimeOffset now)
    {
        if (channel.Messages is not { } messages || channel.Subscribers is not { } subscribers) return string.Empty;
        string[] parts =
        [
            Counted(messages, "message"),
            $"{Counted(subscribers, "agent")} listening",
            channel.LastActivityAt is { } last ? "last message " + FeedLogic.TimeLabel(last, now, withSeconds: false) : "nothing posted yet"
        ];
        return string.Join("  ·  ", parts);
    }

    private static string Counted(int count, string what) => $"{count} {what}{(count == 1 ? "" : "s")}";

    public static string Summary(IReadOnlyCollection<ChannelCard> cards, bool withFigures)
    {
        if (cards.Count == 0) return "This bus has no channels yet.";
        var counted = $"{Counted(cards.Count, "channel")}.";
        return withFigures ? counted : $"{counted} {NoFigures}";
    }

    public static bool IsStale(DateTimeOffset? loadedAt, DateTimeOffset now) =>
        loadedAt is not { } loaded || now - loaded >= FreshFor;

    /// <summary>The same channels from a bus that gives only names and purposes.</summary>
    public static IReadOnlyList<ChannelActivity> WithoutFigures(IEnumerable<BusChannel> channels) =>
        channels.Select(channel => new ChannelActivity(channel.Name, channel.Purpose, null, null, null)).ToList();
}
