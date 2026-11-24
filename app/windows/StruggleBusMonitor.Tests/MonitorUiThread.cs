using System.Diagnostics;
using System.Windows.Threading;

namespace StruggleBusMonitor.Tests;

/// <summary>
/// Waiting on the UI thread for tests written as async methods. The thread itself is the one
/// <see cref="StaWindowAdminFixture"/> owns: WPF allows a single Application per process, so every
/// window test shares it.
/// </summary>
internal static class MonitorUiThread
{
    /// <summary>Only a guard against a hung test; nothing waits this long when the code works.</summary>
    private static readonly TimeSpan Limit = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Lets the dispatcher and the thread pool work until the condition holds. Call it on the UI
    /// thread. The limit only turns a wait that would never end into a failure.
    /// </summary>
    public static async Task Until(Func<bool> condition, string what)
    {
        var watch = Stopwatch.StartNew();
        while (!condition())
        {
            if (watch.Elapsed > Limit) throw new TimeoutException($"Gave up waiting for: {what}");
            await Dispatcher.Yield(DispatcherPriority.ContextIdle);
            Thread.Yield();
        }
    }

    /// <summary>Runs everything already queued on the dispatcher, down to layout and rendering.</summary>
    public static async Task Settle() => await Dispatcher.Yield(DispatcherPriority.ContextIdle);
}
