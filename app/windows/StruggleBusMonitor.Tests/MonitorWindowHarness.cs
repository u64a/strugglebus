using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media;

namespace StruggleBusMonitor.Tests;

/// <summary>
/// The real <see cref="MainWindow"/>, enrolled against a <see cref="MonitorFakeBus"/> and shown far
/// off screen without being activated, so its controls are laid out but nothing appears or takes
/// focus from whoever is running the tests.
/// </summary>
internal sealed class MonitorWindowHarness
{
    public const string DeviceId = "device-test";
    public static readonly TimeSpan StreamConfirmWait = TimeSpan.FromSeconds(2);
    public static readonly TimeSpan FeedWait = TimeSpan.FromSeconds(10);
    public static readonly TimeSpan FeedRetryWait = TimeSpan.FromSeconds(5);
    public static readonly TimeSpan DirectoryWait = TimeSpan.FromSeconds(15);

    private static readonly Lazy<byte[]> Certificate = new(() =>
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=Fake StruggleBus", key, HashAlgorithmName.SHA256);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        return certificate.Export(X509ContentType.Cert);
    });

    private bool _closed;

    private MonitorWindowHarness(MainWindow window, MonitorFakeBus bus, MonitorFakePauses pauses)
    {
        (Window, Bus, Pauses) = (window, bus, pauses);
        window.Closed += (_, _) => _closed = true;
    }

    public MainWindow Window { get; }
    public MonitorFakeBus Bus { get; }
    public MonitorFakePauses Pauses { get; }

    /// <summary>The stream connection the window is listening on now.</summary>
    public MonitorFakeStream Stream => Bus.Streams[^1];

    /// <summary>
    /// Builds the window the way the app does at startup. When enrolled it has loaded its first
    /// snapshot and is listening on the live stream by the time this returns.
    /// </summary>
    public static async Task<MonitorWindowHarness> StartAsync(Action<MonitorFakeBus>? arrange = null, bool enrolled = true, bool operatorGrant = false, bool awaitStream = true)
    {
        TestDataDirectory.Reset();
        if (enrolled) BusApi.SessionStore.Save(new Session("https://bus.invalid", "credential", Certificate.Value, DeviceId, "Test PC"));
        if (operatorGrant) BusApi.GrantStore.Save(DeviceId, "grant-secret");

        var bus = new MonitorFakeBus();
        arrange?.Invoke(bus);
        var api = bus.CreateApi();
        var pauses = new MonitorFakePauses();
        var platform = new StaWindowAdminPlatform();
        var window = new MainWindow(platform, api)
        {
            Pause = pauses.Pause,
            ShowActivated = false,
            ShowInTaskbar = false,
            WindowStartupLocation = WindowStartupLocation.Manual,
            Left = -20000,
            Top = -20000
        };
        // WPF keeps popups on a monitor even when their window is not, so the mention popup would
        // show up on screen. Its window allows transparency: with clear content nothing is drawn.
        window.MentionPopup.Child.Opacity = 0;
        var harness = new MonitorWindowHarness(window, bus, pauses);
        window.CopyText = harness.Copied.Add;
        window.Show();
        if (enrolled && awaitStream) await harness.ListeningAsync(1);
        return harness;
    }

    /// <summary>Waits until the window is reading its <paramref name="connection"/>th stream connection.</summary>
    public Task ListeningAsync(int connection) =>
        MonitorUiThread.Until(() => Bus.Streams.Count >= connection && Bus.Streams[connection - 1].Reading, $"stream connection {connection}");

    public Task ShowsStatusAsync(string state) =>
        MonitorUiThread.Until(() => Window.StatusText.Text == state, $"status {state} (it is {Window.StatusText.Text} {Window.StatusDetailText.Text})");

    public Task WaitingAsync(TimeSpan pause) =>
        MonitorUiThread.Until(() => Pauses.IsWaiting(pause), $"a loop to wait {pause} (waiting: {string.Join(", ", Pauses.Waiting)})");

    /// <summary>Lets one background wait of this length pass once a loop has reached it.</summary>
    public async Task ElapseAsync(TimeSpan pause)
    {
        await WaitingAsync(pause);
        Pauses.Elapse(pause);
    }

    public IEnumerable<long> Feed => Window.ActivityList.Items.Cast<ActivityEntry>().Select(entry => entry.Sequence);

    public string Notice => Window.NoticeBar.Visibility == Visibility.Visible ? Window.NoticeText.Text : string.Empty;

    /// <summary>What the window's Copy buttons have copied. The real clipboard is never touched.</summary>
    public List<string> Copied { get; } = [];

    public async Task CloseAsync()
    {
        if (_closed) return;
        // The app exits when its window closes. Here the process lives on, and a popup left open
        // would stay alive and keep answering every layout pass of the windows that follow.
        Window.MentionPopup.IsOpen = false;
        Window.Close();
        await MonitorUiThread.Until(() => _closed, "the window to close");
    }

    // ---- Driving the window ------------------------------------------------------------------

    public static void Click(ButtonBase button) => button.RaiseEvent(new RoutedEventArgs(ButtonBase.ClickEvent, button));

    /// <summary>Clicks a button that has no name in the XAML, found by its caption under <paramref name="root"/>.</summary>
    public static void Click(DependencyObject root, string caption) => Click(Find<Button>(root, button => Equals(button.Content, caption)));

    public void PressKey(UIElement target, Key key)
    {
        var source = PresentationSource.FromVisual(Window) ?? throw new InvalidOperationException("The window is not shown.");
        target.RaiseEvent(new KeyEventArgs(Keyboard.PrimaryDevice, source, 0, key) { RoutedEvent = Keyboard.PreviewKeyDownEvent });
    }

    /// <summary>Types text at the caret, through the same text-input path the keyboard uses.</summary>
    public static void TypeInto(TextBox box, string text) =>
        TextCompositionManager.StartComposition(new TextComposition(InputManager.Current, box, text));

    /// <summary>Presses the left button on the list item showing <paramref name="row"/>, as a click on that row would.</summary>
    public static bool PressRow(ItemsControl list, object row)
    {
        list.UpdateLayout();
        var container = list.ItemContainerGenerator.ContainerFromItem(row) as UIElement
            ?? throw new InvalidOperationException("That row has no list item on screen.");
        return PressOn(list, container);
    }

    /// <summary>Raises the left-button press on <paramref name="list"/> as coming from <paramref name="origin"/>. Returns whether it was handled.</summary>
    public static bool PressOn(UIElement list, object origin)
    {
        var press = new MouseButtonEventArgs(Mouse.PrimaryDevice, 0, MouseButton.Left)
        {
            RoutedEvent = UIElement.PreviewMouseLeftButtonDownEvent,
            Source = origin
        };
        list.RaiseEvent(press);
        return press.Handled;
    }

    /// <summary>
    /// Calls a handler that the XAML wires to a control inside an item template, passing a sender
    /// that carries the row in its Tag exactly as the template's binding does.
    /// </summary>
    public void InvokeRowHandler(string handler, object? row) =>
        Handler(handler).Invoke(Window, [new Button { Tag = row }, new RoutedEventArgs()]);

    /// <summary>Starts one of the window's own background operations directly so the test can wait for it to finish.</summary>
    public Task InvokeAsync(string method, params object[] arguments) => (Task)Handler(method).Invoke(Window, arguments)!;

    private static MethodInfo Handler(string name) =>
        typeof(MainWindow).GetMethod(name, BindingFlags.Instance | BindingFlags.NonPublic)
        ?? throw new MissingMethodException(nameof(MainWindow), name);

    public static ScrollViewer ScrollViewerOf(DependencyObject list) => Find<ScrollViewer>(list, _ => true, visual: true);

    public static T Find<T>(DependencyObject root, Func<T, bool> match, bool visual = false) where T : DependencyObject =>
        Descendants(root, visual).OfType<T>().FirstOrDefault(match)
        ?? throw new InvalidOperationException($"No matching {typeof(T).Name} under {root.GetType().Name}.");

    private static IEnumerable<DependencyObject> Descendants(DependencyObject root, bool visual)
    {
        var children = visual
            ? Enumerable.Range(0, VisualTreeHelper.GetChildrenCount(root)).Select(index => VisualTreeHelper.GetChild(root, index))
            : LogicalTreeHelper.GetChildren(root).OfType<DependencyObject>();
        foreach (var child in children)
        {
            yield return child;
            foreach (var nested in Descendants(child, visual)) yield return nested;
        }
    }

    // ---- Test data ---------------------------------------------------------------------------

    public static readonly DateTimeOffset Now = DateTimeOffset.Now;

    public static BusMessage Message(long seq, string channel = "ops", string agent = "agent-one", string body = "hello", string kind = "chat", long? replyTo = null) =>
        new(seq, channel, agent, body, kind, Now.AddMinutes(-1), replyTo);

    public static BusMessage Human(long seq, string agent = "agent-one", string body = "hello", string kind = "chat", long? replyTo = null) =>
        Message(seq, HumansLogic.Channel, agent, body, kind, replyTo);

    public static string Detail(string detail) => System.Text.Json.JsonSerializer.Serialize(new { detail });

    public static BusAgent Agent(string name, string host = "host-a", double? minutesAgo = 0) =>
        new("id-" + name, name, string.Empty, host, "seen", minutesAgo is { } minutes ? DateTimeOffset.Now.AddMinutes(-minutes) : null);
}
