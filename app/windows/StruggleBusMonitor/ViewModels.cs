using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Media;

namespace StruggleBusMonitor;

public abstract class Notifier : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler? PropertyChanged;

    protected bool Set<T>(ref T field, T value, [CallerMemberName] string? name = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value)) return false;
        field = value;
        Raise(name);
        return true;
    }

    protected void Raise([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}

public sealed record ChannelFilterOption(string? Name)
{
    public string Label => Name is null ? "ALL" : $"#{Name}";
}

public sealed class ActivityEntry(BusMessage message, DateTimeOffset now) : Notifier
{
    private bool _isExpanded;
    private string _highlight = string.Empty;

    public BusMessage Message { get; } = message;

    /// <summary>Fetched from history on request, so it is not trimmed as the live feed rolls over.</summary>
    public bool Pinned { get; init; }
    public long Sequence => Message.Seq;
    public string ChannelLabel => $"#{Message.Channel}";
    public string KindLabel => Message.Kind.ToUpperInvariant();
    public string AgentName => Message.AgentName;
    public string SequenceLabel => $"seq {Message.Seq}";
    public string TimeLabel { get; } = FeedLogic.TimeLabel(message.CreatedAt, now);
    public string DisplayBody => Message.Body;
    public bool IsLong => Message.Body.Length > 240 || Message.Body.Count(c => c == '\n') >= 3;
    public Visibility ExpandVisibility => IsLong ? Visibility.Visible : Visibility.Collapsed;
    public string ExpandLabel => IsExpanded ? "Show less" : $"Show all {Message.Body.Length:N0} characters";

    public bool IsExpanded
    {
        get => _isExpanded;
        set { if (Set(ref _isExpanded, value)) Raise(nameof(ExpandLabel)); }
    }

    /// <summary>The text filter currently applied, so matches can be marked in the body.</summary>
    public string Highlight
    {
        get => _highlight;
        set => Set(ref _highlight, value);
    }
}

public sealed class AgentEntry : Notifier
{
    private BusAgent _agent;
    private string _meta = string.Empty;
    private AgentPresence _presence;
    private string _countLabel = string.Empty;

    public AgentEntry(BusAgent agent, DateTimeOffset now)
    {
        _agent = agent;
        Update(agent, now);
    }

    public BusAgent Agent => _agent;
    public string Id => _agent.Id;
    public string Name => _agent.Name;
    public string Meta { get => _meta; private set => Set(ref _meta, value); }
    public AgentPresence Presence { get => _presence; private set => Set(ref _presence, value); }
    public string CountLabel { get => _countLabel; set => Set(ref _countLabel, value); }

    public void Update(BusAgent agent, DateTimeOffset now)
    {
        _agent = agent;
        var seen = FeedLogic.PresenceLabel(agent.LastSeenAt, now);
        Meta = string.IsNullOrWhiteSpace(agent.Host) ? seen : $"{agent.Host}  ·  {seen}";
        Presence = FeedLogic.Presence(agent.LastSeenAt, now);
    }
}

public sealed class HumansEntry
{
    private HumansEntry() { }

    public BusMessage? Message { get; private init; }
    public OutgoingPost? Outgoing { get; private init; }
    public bool IsOperator { get; private init; }
    public string AuthorLabel { get; private init; } = string.Empty;
    public string KindLabel { get; private init; } = string.Empty;
    public string TimeLabel { get; private init; } = string.Empty;
    public string StateLabel { get; private init; } = string.Empty;
    public string Body { get; private init; } = string.Empty;
    public string ReplyContext { get; private init; } = string.Empty;
    public string? Error { get; private init; }
    public Visibility ReplyContextVisibility => ReplyContext.Length > 0 ? Visibility.Visible : Visibility.Collapsed;
    public Visibility ErrorVisibility => string.IsNullOrEmpty(Error) ? Visibility.Collapsed : Visibility.Visible;
    public Visibility ReplyVisibility => Message is not null && !IsOperator ? Visibility.Visible : Visibility.Collapsed;
    public Visibility CopyVisibility => Message is not null ? Visibility.Visible : Visibility.Collapsed;
    public Visibility RetryVisibility => Outgoing is { Status: OutgoingStatus.Failed, Retryable: true } ? Visibility.Visible : Visibility.Collapsed;
    public Visibility DiscardVisibility => Outgoing is { Status: OutgoingStatus.Failed } ? Visibility.Visible : Visibility.Collapsed;

    public static HumansEntry ForMessage(BusMessage message, BusMessage? parent, DateTimeOffset now)
    {
        var isOperator = HumansLogic.IsOperator(message);
        return new HumansEntry
        {
            Message = message,
            IsOperator = isOperator,
            AuthorLabel = isOperator ? "You" : message.AgentName,
            KindLabel = message.Kind.ToUpperInvariant(),
            TimeLabel = FeedLogic.TimeLabel(message.CreatedAt, now),
            Body = message.Body,
            ReplyContext = message.ReplyTo is { } replyTo
                ? parent is null ? $"replying to seq {replyTo}" : $"replying to {Author(parent)}: “{Snippet(parent.Body)}”"
                : string.Empty
        };
    }

    public static HumansEntry ForOutgoing(OutgoingPost post) => new()
    {
        Outgoing = post,
        IsOperator = true,
        AuthorLabel = "You",
        KindLabel = HumansLogic.WireKind(post.Kind).ToUpperInvariant(),
        StateLabel = post.Status == OutgoingStatus.Sending ? "sending…" : "not sent",
        Body = post.Body,
        ReplyContext = post.ReplyTo is { } parent ? $"replying to {Author(parent)}: “{Snippet(parent.Body)}”" : string.Empty,
        Error = post.Error
    };

    private static string Author(BusMessage message) => HumansLogic.IsOperator(message) ? "you" : message.AgentName;

    public static string Snippet(string body)
    {
        var flat = body.Replace('\n', ' ').Replace('\r', ' ').Trim();
        return flat.Length <= 80 ? flat : flat[..80] + "…";
    }
}

public sealed class WaitingEntry(BusMessage message, DateTimeOffset now)
{
    public BusMessage Message { get; } = message;
    public string AgentName => Message.AgentName;
    public string TimeLabel { get; } = FeedLogic.TimeLabel(message.CreatedAt, now, withSeconds: false);
    public string Snippet { get; } = HumansEntry.Snippet(message.Body);
}

public sealed class MentionRow(MentionOption option)
{
    public MentionOption Option { get; } = option;
    public string Display => "@" + Option.Insert;
    public string Meta => Option.Meta;
    public AgentPresence? Presence => Option.Presence;
}

public sealed class QuickFindResult
{
    public string Lead { get; init; } = string.Empty;
    public string Title { get; init; } = string.Empty;
    public string Detail { get; init; } = string.Empty;
    public string Highlight { get; init; } = string.Empty;
    public BusAgent? Agent { get; init; }
    public BusMessage? Message { get; init; }

    /// <summary>Set on the row that runs a server-side search instead of opening something.</summary>
    public string? HistoryQuery { get; init; }
}

public sealed class ThemeCard : Notifier
{
    private bool _isSelected;

    public ThemeCard(ThemePalette palette)
    {
        Palette = palette;
        var colors = Themes.Derive(palette);
        Brush Frozen(string key)
        {
            var brush = new SolidColorBrush(colors[key]);
            brush.Freeze();
            return brush;
        }
        Bg = Frozen("Bg");
        Fg = Frozen("Fg");
        Accent = Frozen("Accent");
        Ok = Frozen("Ok");
        Warn = Frozen("Warn");
        Bad = Frozen("Bad");
        Line = Frozen("Line");
    }

    public ThemePalette Palette { get; }
    public string Name => Palette.Name;
    public Brush Bg { get; }
    public Brush Fg { get; }
    public Brush Accent { get; }
    public Brush Ok { get; }
    public Brush Warn { get; }
    public Brush Bad { get; }
    public Brush Line { get; }
    public bool IsSelected { get => _isSelected; set => Set(ref _isSelected, value); }
}
