using System.Windows;

namespace StruggleBusMonitor;

/// <summary>What a failed startup connection means for the window.</summary>
internal enum ConnectFailure
{
    /// <summary>The bus is away for now; keep trying.</summary>
    Retry,
    /// <summary>The bus no longer accepts this PC's credential.</summary>
    Revoked,
    /// <summary>Anything else: report it and stop.</summary>
    Fatal
}

/// <summary>Pure decisions for the window shell, kept apart from the window so they can be tested.</summary>
internal static class WindowLogic
{
    /// <summary>
    /// Where to put the window at startup, or null to let Windows place it: nothing was saved, the
    /// saved spot is no longer on any screen (a monitor was unplugged), or it is smaller than the
    /// window is allowed to be.
    /// </summary>
    public static Rect? RestoredBounds(double? left, double? top, double? width, double? height, Rect screen, double minWidth, double minHeight)
    {
        if (!left.HasValue || !top.HasValue || !width.HasValue || !height.HasValue) return null;
        return UsableBounds(left.Value, top.Value, width.Value, height.Value, screen, minWidth, minHeight);
    }

    private static Rect? UsableBounds(double left, double top, double width, double height, Rect screen, double minWidth, double minHeight)
    {
        if (width < minWidth || height < minHeight) return null;
        return IsOnScreen(left, top, width, screen) ? new Rect(left, top, width, height) : null;
    }

    /// <summary>Enough of the title bar is on the virtual screen to grab and drag.</summary>
    internal static bool IsOnScreen(double left, double top, double width, Rect screen) =>
        left + 80 < screen.Left + screen.Width &&
        left + width - 80 > screen.Left &&
        top + 40 < screen.Top + screen.Height &&
        top >= screen.Top - 10;

    /// <summary>The notice for a failed operation: its message, plus the inner one when that adds something.</summary>
    public static string FailureText(Exception error)
    {
        var inner = error.InnerException?.Message;
        return inner is null || error.Message.Contains(inner, StringComparison.Ordinal) ? error.Message : $"{error.Message} {inner}";
    }

    public static ConnectFailure ClassifyConnectFailure(Exception error)
    {
        if (MonitorLogic.IsTransient(error)) return ConnectFailure.Retry;
        return error is BusApiException { StatusCode: 401 } ? ConnectFailure.Revoked : ConnectFailure.Fatal;
    }

    /// <summary>
    /// Runs <paramref name="action"/> after a first wait and then at every interval until
    /// <paramref name="stopped"/> says to stop. A failure ends the loop quietly.
    /// </summary>
    public static async Task RepeatAsync(Func<TimeSpan, Task> delay, TimeSpan first, TimeSpan interval, Func<bool> stopped, Func<Task> action)
    {
        try
        {
            await delay(first);
            while (!stopped())
            {
                await action();
                await delay(interval);
            }
        }
        catch (Exception)
        {
            // Best effort; the next launch tries again.
        }
    }
}
