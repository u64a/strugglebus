using System.Text;

namespace StruggleBusMonitor;

/// <summary>One complete server-sent event: its name ("message" unless the server named it) and its data.</summary>
internal sealed record SseEvent(string Name, string Data);

/// <summary>
/// Assembles the lines of a server-sent event stream into events. Feed it one line at a time; a
/// blank line ends an event. Lines that are neither "event:" nor "data:" (comments, ids, retry
/// hints) are ignored, and an event without data is dropped.
/// </summary>
internal sealed class SseParser
{
    private const string DefaultName = "message";
    private readonly StringBuilder _data = new();
    private string _name = DefaultName;

    /// <summary>Takes the next line and returns the event it completes, if it completes one.</summary>
    public SseEvent? Feed(string line)
    {
        if (line.Length == 0) return Complete();
        if (line.StartsWith("event:", StringComparison.Ordinal)) _name = line[6..].Trim();
        else if (line.StartsWith("data:", StringComparison.Ordinal)) AppendData(line[5..].TrimStart());
        return null;
    }

    private void AppendData(string text)
    {
        if (_data.Length > 0) _data.Append('\n');
        _data.Append(text);
    }

    private SseEvent? Complete()
    {
        var completed = _data.Length > 0 ? new SseEvent(_name, _data.ToString()) : null;
        _data.Clear();
        _name = DefaultName;
        return completed;
    }
}
