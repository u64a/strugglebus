using System.Windows.Input;

namespace StruggleBusMonitor;

/// <summary>What to do with messages that arrived on #humans after the first load.</summary>
public enum HumansArrival
{
    /// <summary>The operator is reading the end of the conversation: keep it in view and mark it read.</summary>
    FollowToEnd,
    /// <summary>The operator is reading further up: count the messages in the "new below" bar.</summary>
    CountBelow,
    /// <summary>Another page is showing: only the navigation badge changes.</summary>
    Background
}

public enum ComposerKeyAction { None, MentionNext, MentionPrevious, MentionAccept, MentionDismiss, Send }

/// <summary>
/// The state the mention popup should take. <see cref="Options"/> is null when the list is left as
/// it is, and <see cref="DismissedAt"/> is where Escape last closed the popup (-1 for nowhere).
/// </summary>
internal sealed record MentionPlan(int DismissedAt, IReadOnlyList<MentionOption>? Options, bool Open, int SelectedIndex, string Header);

/// <summary>Pure rules for the Humans page: wording, where rows go, and what the composer keys do.</summary>
internal static class HumansPageLogic
{
    public const string CanPostNotice = "You post as human:operator. Agents read and reply here.";
    public const string CannotPostNotice = "Reading works now. To post, save operator access on the Admin page once.";
    public const string NothingWaitingHint = "Nothing is waiting. Questions from agents that you have not replied to appear here.";
    public const string WaitingHint = "Questions from agents that you have not replied to. Click one to jump to it and start a reply, or Clear it once it is dealt with.";

    public static HumansArrival Arrival(bool pageVisible, bool wasAtBottom) =>
        !pageVisible ? HumansArrival.Background : wasAtBottom ? HumansArrival.FollowToEnd : HumansArrival.CountBelow;

    /// <summary>
    /// Message rows are in sequence order; the rows for posts still being sent stay after them.
    /// </summary>
    public static int InsertIndex(IReadOnlyList<HumansEntry> rows, int outgoingCount, long sequence)
    {
        var index = rows.Count - outgoingCount;
        while (index > 0 && rows[index - 1].Message is { } previous && previous.Seq > sequence) index--;
        return index;
    }

    public static string BadgeText(int unread) => unread > 99 ? "99+" : unread.ToString();

    public static string NewBelowText(int count) => $"{count} new message{(count == 1 ? "" : "s")} below.";

    public static string Notice(bool hasOperatorGrant) => hasOperatorGrant ? CanPostNotice : CannotPostNotice;

    public static string HintForWaiting(int waiting) => waiting == 0 ? NothingWaitingHint : WaitingHint;

    public static string ReplyBanner(BusMessage? target) =>
        target is null ? string.Empty : $"Replying to {target.AgentName}: “{HumansEntry.Snippet(target.Body)}”";

    /// <summary>True when the waiting list on screen no longer shows exactly these questions, in order.</summary>
    public static bool WaitingChanged(IEnumerable<BusMessage> waiting, IEnumerable<WaitingEntry> shown) =>
        !waiting.Select(message => message.Seq).SequenceEqual(shown.Select(entry => entry.Message.Seq));

    /// <summary>Scrolling to the end reads what was waiting there, if anything was.</summary>
    public static bool ScrollReadsConversation(double verticalChange, bool pageVisible, bool atBottom, int newBelow, bool badgeShown) =>
        verticalChange != 0 && pageVisible && atBottom && (newBelow > 0 || badgeShown);

    /// <summary>The post behind a "not sent" row, or null for any other row.</summary>
    public static OutgoingPost? FailedPost(HumansEntry? entry, bool retryableOnly)
    {
        if (entry?.Outgoing is not { } post) return null;
        return IsFailed(post, retryableOnly) ? post : null;
    }

    private static bool IsFailed(OutgoingPost post, bool retryableOnly) =>
        post.Status == OutgoingStatus.Failed && (post.Retryable || !retryableOnly);

    // ---- Composer ----------------------------------------------------------------------------

    /// <summary>While the mention popup is open it takes the navigation keys; otherwise Enter sends and Shift+Enter is a new line.</summary>
    public static ComposerKeyAction KeyAction(Key key, bool shift, bool mentionPopupOpen)
    {
        if (mentionPopupOpen && MentionKeys.TryGetValue(key, out var mention)) return mention;
        return key == Key.Enter && !shift ? ComposerKeyAction.Send : ComposerKeyAction.None;
    }

    private static readonly Dictionary<Key, ComposerKeyAction> MentionKeys = new()
    {
        [Key.Down] = ComposerKeyAction.MentionNext,
        [Key.Up] = ComposerKeyAction.MentionPrevious,
        [Key.Tab] = ComposerKeyAction.MentionAccept,
        [Key.Enter] = ComposerKeyAction.MentionAccept,
        [Key.Escape] = ComposerKeyAction.MentionDismiss
    };

    /// <summary>Where the mention being typed starts, remembered so the popup stays closed there after Escape.</summary>
    public static int MentionStart(string text, int caret) => FeedLogic.ActiveMentionToken(text, caret)?.Start ?? -1;

    public static MentionPlan PlanMentions(
        bool composerFocused,
        string text,
        int caret,
        int dismissedAt,
        IEnumerable<BusAgent> agents,
        string? selectedInsert,
        DateTimeOffset now)
    {
        if (!composerFocused || FeedLogic.ActiveMentionToken(text, caret) is not { } token)
            return new MentionPlan(-1, null, false, -1, string.Empty);
        if (token.Start == dismissedAt)
            return new MentionPlan(dismissedAt, null, false, -1, string.Empty);
        return PlanOptions(FeedLogic.MentionOptions(agents, token.Prefix, now), token.Prefix, dismissedAt, selectedInsert);
    }

    private static MentionPlan PlanOptions(IReadOnlyList<MentionOption> options, string prefix, int dismissedAt, string? selectedInsert)
    {
        if (options.Count == 0) return new MentionPlan(dismissedAt, options, false, -1, string.Empty);
        var header = prefix.Length == 0 ? "MENTION AN AGENT" : $"AGENTS MATCHING “{prefix}”";
        return new MentionPlan(dismissedAt, options, true, IndexOfInsert(options, selectedInsert), header);
    }

    /// <summary>Keeps the row that was selected while the list narrows; otherwise the best match, which is first.</summary>
    private static int IndexOfInsert(IReadOnlyList<MentionOption> options, string? insert)
    {
        for (var index = 0; index < options.Count; index++)
            if (options[index].Insert == insert) return index;
        return 0;
    }

    /// <summary>The row an arrow key moves to; the list wraps round at both ends.</summary>
    public static int WrapSelection(int selectedIndex, int step, int count) => (selectedIndex + step + count) % count;

    /// <summary>Replaces the "@prefix" at the caret with the chosen name and one space after it.</summary>
    public static (string Text, int Caret)? InsertMention(string text, int caret, string name)
    {
        if (FeedLogic.ActiveMentionToken(text, caret) is not { } token) return null;
        var insert = "@" + name + " ";
        var end = caret < text.Length && text[caret] == ' ' ? caret + 1 : caret;
        return (text[..token.Start] + insert + text[end..], token.Start + insert.Length);
    }
}
