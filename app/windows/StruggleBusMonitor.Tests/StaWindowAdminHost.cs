using System.Runtime.ExceptionServices;
using System.Windows;
using System.Windows.Threading;

namespace StruggleBusMonitor.Tests;

/// <summary>
/// One STA thread with a running dispatcher and the WPF application object, shared by every test
/// that builds the real window. WPF allows a single Application per process, so all window tests
/// belong to the <see cref="StaWindowAdminCollection"/> collection and run one at a time. So does
/// every other test that uses the redirected default data folder, which the windows use too.
/// </summary>
public sealed class StaWindowAdminFixture : IDisposable
{
    private static readonly TimeSpan Patience = TimeSpan.FromSeconds(30);
    private readonly Thread _thread;
    private readonly Dispatcher _dispatcher;
    private Exception? _unhandled;

    public StaWindowAdminFixture()
    {
        var started = new TaskCompletionSource<Dispatcher>();
        _thread = new Thread(() =>
        {
            try
            {
                var dispatcher = Dispatcher.CurrentDispatcher;
                SynchronizationContext.SetSynchronizationContext(new DispatcherSynchronizationContext(dispatcher));
                // A bare Application, not the app's own App: that one carries a StartupUri, and WPF would
                // open the real window, with the real Windows behind it, as soon as the dispatcher ran.
                // Closing a test's window must not shut the shared application down either.
                _ = new Application { ShutdownMode = ShutdownMode.OnExplicitShutdown };
                // What a handler throws while the dispatcher is pumping fails the test that caused
                // it, instead of taking the thread and every later test down with it.
                dispatcher.UnhandledException += (_, e) =>
                {
                    _unhandled ??= e.Exception;
                    e.Handled = true;
                };
                started.SetResult(dispatcher);
            }
            catch (Exception error)
            {
                started.SetException(error);
                return;
            }
            Dispatcher.Run();
        })
        { IsBackground = true, Name = "StaWindowAdmin" };
        _thread.SetApartmentState(ApartmentState.STA);
        _thread.Start();
        _dispatcher = started.Task.GetAwaiter().GetResult();
    }

    /// <summary>Runs a test body on the STA thread and rethrows whatever it, or a handler it triggered, threw.</summary>
    public void Run(Action body)
    {
        _unhandled = null;
        _dispatcher.Invoke(body);
        ThrowUnhandled();
    }

    /// <summary>The same for a test body that awaits: the dispatcher keeps working while it does.</summary>
    public void Run(Func<Task> test)
    {
        _unhandled = null;
        var task = _dispatcher.InvokeAsync(test).Task.Unwrap();
        var finished = Task.WhenAny(task, Task.Delay(Patience + Patience)).GetAwaiter().GetResult();
        if (finished != task) throw new TimeoutException("The test did not finish on the UI thread.");
        task.GetAwaiter().GetResult();
        ThrowUnhandled();
    }

    private void ThrowUnhandled()
    {
        if (_unhandled is { } unhandled) ExceptionDispatchInfo.Capture(unhandled).Throw();
    }

    /// <summary>
    /// Keeps the dispatcher working until the condition holds. Only for use inside <see cref="Run"/>.
    /// The time limit is a guard against a hung test, not something a passing test depends on.
    /// </summary>
    internal static void PumpUntil(Func<bool> condition, string waitingFor)
    {
        if (condition()) return;
        var frame = new DispatcherFrame();
        var deadline = DateTime.UtcNow + Patience;
        var timedOut = false;
        var timer = new DispatcherTimer(DispatcherPriority.Background) { Interval = TimeSpan.FromMilliseconds(5) };
        timer.Tick += (_, _) =>
        {
            timedOut = DateTime.UtcNow > deadline;
            if (timedOut || condition()) frame.Continue = false;
        };
        timer.Start();
        try { Dispatcher.PushFrame(frame); }
        finally { timer.Stop(); }
        if (timedOut) throw new TimeoutException($"Gave up waiting for {waitingFor}.");
    }

    /// <summary>Waits for a task while the dispatcher keeps working, then surfaces its result or failure.</summary>
    internal static void Await(Task task, string waitingFor)
    {
        PumpUntil(() => task.IsCompleted, waitingFor);
        task.GetAwaiter().GetResult();
    }

    /// <summary>Lets everything already queued on the dispatcher run.</summary>
    internal static void Drain() =>
        Dispatcher.CurrentDispatcher.Invoke(() => { }, DispatcherPriority.ContextIdle);

    public void Dispose()
    {
        _dispatcher.Invoke(() => Application.Current?.Shutdown());
        _dispatcher.InvokeShutdown();
        _thread.Join(Patience);
    }
}

[CollectionDefinition(Name)]
public sealed class StaWindowAdminCollection : ICollectionFixture<StaWindowAdminFixture>
{
    public const string Name = "StaWindowAdmin";
}
