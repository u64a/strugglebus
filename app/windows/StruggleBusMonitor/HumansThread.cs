namespace StruggleBusMonitor;

/// <summary>
/// What one batch of messages changed in the #humans conversation. <see cref="Fresh"/> counts the
/// messages that arrived after the first load, which is what "new" means to the operator.
/// </summary>
internal sealed record HumansChange(
    IReadOnlyList<(BusMessage Message, BusMessage? Parent)> Added,
    IReadOnlyList<long> Trimmed,
    int Fresh,
    int FreshFromAgents,
    int FreshForOperator = 0);

/// <summary>The loaded #humans messages and how far the operator has read. No UI types.</summary>
internal sealed class HumansThread
{
    public const int Maximum = 500;
    private readonly SortedDictionary<long, BusMessage> _messages = [];
    private bool _lastSeenInitialized;

    public IReadOnlyCollection<BusMessage> Messages => _messages.Values;
    public int Count => _messages.Count;
    public long LastSeenSeq { get; private set; }
    public int Unread => HumansLogic.UnreadCount(_messages.Values, LastSeenSeq);

    /// <summary>
    /// Adds the #humans messages not yet known, oldest first, each with the message it replies to
    /// when that is loaded. The first batch only sets the read position: nothing in it is new.
    /// </summary>
    public HumansChange Record(IEnumerable<BusMessage> messages)
    {
        var added = new List<(BusMessage Message, BusMessage? Parent)>();
        foreach (var message in HumansLogic.Conversation(messages))
        {
            if (!_messages.TryAdd(message.Seq, message)) continue;
            _messages.TryGetValue(message.ReplyTo ?? -1, out var parent);
            added.Add((message, parent));
        }

        var trimmed = TrimOldest();
        if (_lastSeenInitialized)
            return new HumansChange(
                added, trimmed, added.Count, added.Count(item => !HumansLogic.IsOperator(item.Message)),
                added.Count(item => HumansLogic.AddressesOperator(item.Message, item.Parent)));

        _lastSeenInitialized = true;
        LastSeenSeq = NewestSeq();
        return new HumansChange(added, trimmed, 0, 0);
    }

    public void MarkRead() => LastSeenSeq = Math.Max(LastSeenSeq, NewestSeq());

    public void Reset()
    {
        _messages.Clear();
        _lastSeenInitialized = false;
        LastSeenSeq = 0;
    }

    private long NewestSeq() => _messages.Count == 0 ? 0 : _messages.Keys.Last();

    private List<long> TrimOldest()
    {
        var trimmed = new List<long>();
        while (_messages.Count > Maximum)
        {
            var oldest = _messages.Keys.First();
            _messages.Remove(oldest);
            trimmed.Add(oldest);
        }
        return trimmed;
    }
}
