using System.IO;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;

namespace StruggleBusMonitor.Tests;

/// <summary>The Hosts page, marking a host on Admin, and the whole bus log, in the real window.</summary>
[Collection(StaWindowAdminCollection.Name)]
public sealed class HostsWindowTests(StaWindowAdminFixture sta)
{
    private const string DeviceRoute = "GET /api/mobile/hosts/status";
    private const string WholeRoute = "POST /api/mobile/admin/hosts/status";
    private const string HistoryRoute = "GET /api/mobile/hosts/a-1/status/history";
    private const string MarkRoute = "POST /api/mobile/admin/agents/a1/host";
    private const string FullLogRoute = "POST /api/mobile/admin/logs/full";

    private static string Contract(string name) =>
        File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Contracts", "host-status", name));

    /// <summary>The bus's answer for one host that reported a few seconds before the bus's "now".</summary>
    private static string Hosts(string snapshotFile) =>
        "{\"now\":\"2026-11-27T04:00:20Z\",\"hosts\":[{\"agent_id\":\"a-1\",\"agent\":\"host-box1-host\",\"marked_at\":\"x\",\"received_at\":\"2026-11-27T04:00:00Z\",\"snapshot\":"
        + Contract(snapshotFile) + "}]}";

    private const string History = """
        {"now":"2026-11-27T04:00:20Z","agent_id":"a-1","samples":[
          {"received_at":"2026-11-27T02:00:00Z","workers":{"busy":1,"max":12},"machine":{"cpu_pct":10.0}},
          {"received_at":"2026-11-27T04:00:00Z","workers":{"busy":2,"max":12},"machine":{"cpu_pct":37.2}}]}
        """;

    private static void ServeHosts(StaWindowAdminBus bus)
    {
        bus.On(DeviceRoute, _ => StaWindowAdminBus.Ok(Hosts("snapshot-v2-device.json")));
        bus.On(WholeRoute, _ => StaWindowAdminBus.Ok(Hosts("snapshot-v2.json")));
        bus.On(HistoryRoute, _ => StaWindowAdminBus.Ok(History));
    }

    /// <summary>An enrolled window with the Hosts page open and loaded.</summary>
    private static StaWindowAdminScene OpenHosts(bool withGrant = true, Action<StaWindowAdminBus>? arrange = null)
    {
        var scene = new StaWindowAdminScene().Enroll(withGrant);
        try
        {
            (arrange ?? ServeHosts)(scene.Bus);
            scene.Open();
            scene.Window.HostsNav.IsChecked = true;
            StaWindowAdminScene.Until(() => scene.Window.HostsSummary.Text.Length > 0, "the hosts");
            return scene;
        }
        catch
        {
            scene.Dispose();
            throw;
        }
    }

    private static List<HostCard> Cards(MainWindow window) => ((IEnumerable<HostCard>)window.HostsList.ItemsSource).ToList();

    private static JsonElement Body(BusRequest request) => JsonDocument.Parse(request.Body).RootElement.Clone();

    // ---- The Hosts page ----------------------------------------------------------------------

    [Fact]
    public void TheHostsPageShowsEachHostWholeWhenOperatorAccessIsSaved() => sta.Run(() =>
    {
        using var scene = OpenHosts();
        var window = scene.Window;

        Assert.Equal(Visibility.Visible, window.HostsPage.Visibility);
        Assert.Equal(Visibility.Collapsed, window.MonitorPage.Visibility);
        Assert.Equal(Visibility.Collapsed, window.AdminPage.Visibility);
        var card = Assert.Single(Cards(window));
        Assert.Equal(("box1", "ONLINE", "Ok", "2 of 12 workers busy"), (card.Name, card.StateLabel, card.Tone, card.Workers));
        Assert.Contains("runs as sbworker", card.Details);
        Assert.Contains("channel #worker-hosts", card.Details);
        Assert.True(card.HasAlerts && card.HasHistory);
        Assert.Equal(2, card.BusyLine.Count);
        Assert.Equal("1 host, 1 needing attention.", window.HostsSummary.Text);
        Assert.Equal("grant-secret", Body(scene.Bus.RequestsTo(WholeRoute).Single()).GetProperty("grant_secret").GetString());
        Assert.Empty(scene.Bus.RequestsTo(DeviceRoute));
        Assert.Equal(string.Empty, scene.Notice);
    });

    [Fact]
    public void WithoutOperatorAccessTheAccountWarningsAndChannelAreNotShown() => sta.Run(() =>
    {
        using var scene = OpenHosts(withGrant: false);
        var card = Assert.Single(Cards(scene.Window));

        Assert.DoesNotContain("runs as", card.Details);
        Assert.DoesNotContain("channel #", card.Details);
        Assert.False(card.HasAlerts);
        Assert.EndsWith("Save operator access on Admin to also see each host's account, warnings and channel.", scene.Window.HostsSummary.Text);
        Assert.Empty(scene.Bus.RequestsTo(WholeRoute));
        Assert.Single(scene.Bus.RequestsTo(DeviceRoute));
    });

    [Fact]
    public void ABusTooOldForHostsSaysSoWithoutANotice() => sta.Run(() =>
    {
        using var scene = OpenHosts(arrange: _ => { });

        Assert.Equal(HostsPageLogic.Unsupported, scene.Window.HostsSummary.Text);
        Assert.Empty(Cards(scene.Window));
        Assert.Equal(string.Empty, scene.Notice);
    });

    [Fact]
    public void ReloadAsksTheBusAgainAndAFailureIsANotice() => sta.Run(() =>
    {
        using var scene = OpenHosts();
        var window = scene.Window;

        StaWindowAdminScene.ClickAndWait(window.HostsReload);
        Assert.Equal(2, scene.Bus.RequestsTo(WholeRoute).Count);

        scene.Bus.On(WholeRoute, _ => StaWindowAdminBus.Fail(503, "unavailable"));
        StaWindowAdminScene.ClickAndWait(window.HostsReload);
        Assert.NotEqual(string.Empty, scene.Notice);
        Assert.Single(Cards(window));
    });

    [Fact]
    public void ThePageRefreshesEveryHalfMinuteWhileItIsShowingAndStopsWhenItIsNot() => sta.Run(() =>
    {
        using var scene = OpenHosts();
        var window = scene.Window;
        StaWindowAdminScene.Until(() => scene.Platform.Delays.Count == 1, "the first wait");
        Assert.Equal([HostsPageLogic.RefreshEvery], scene.Platform.Delays);

        scene.Platform.EndDelay(0);
        StaWindowAdminScene.Until(() => scene.Bus.RequestsTo(WholeRoute).Count == 2, "the refresh");
        StaWindowAdminScene.Until(() => scene.Platform.Delays.Count == 2, "the next wait");

        // A refresh that fails says so on the page and raises no notice.
        scene.Bus.On(WholeRoute, _ => StaWindowAdminBus.Fail(503, "unavailable"));
        scene.Platform.EndDelay(1);
        StaWindowAdminScene.Until(() => window.HostsSummary.Text.StartsWith("Could not refresh the hosts:", StringComparison.Ordinal), "the failed refresh");
        Assert.Equal(string.Empty, scene.Notice);
        StaWindowAdminScene.Until(() => scene.Platform.Delays.Count == 3, "the wait after a failure");

        // Opening the page again while a wait is running does not start a second one.
        window.MonitorNav.IsChecked = true;
        window.HostsNav.IsChecked = true;
        Assert.Equal(3, scene.Platform.Delays.Count);

        // On another page the wait ends and nothing more is asked.
        window.MonitorNav.IsChecked = true;
        var asked = scene.Bus.RequestsTo(WholeRoute).Count;
        scene.Platform.EndDelay(2);

        // Let the ended wait be noticed while another page is showing: nothing more is asked.
        var turns = 0;
        StaWindowAdminScene.Until(() => ++turns > 25, "the ended wait to be noticed");
        Assert.Equal(asked, scene.Bus.RequestsTo(WholeRoute).Count);
        Assert.Equal(3, scene.Platform.Delays.Count);

        // Coming back starts waiting again.
        window.HostsNav.IsChecked = true;
        StaWindowAdminScene.Until(() => scene.Platform.Delays.Count == 4, "a new wait after coming back");
    });

    [Fact]
    public void AnUnenrolledPcCannotOpenHosts() => sta.Run(() =>
    {
        using var scene = new StaWindowAdminScene().Open();

        Assert.False(scene.Window.HostsNav.IsEnabled);
    });

    // ---- Marking a host on Admin, Worker hosts -----------------------------------------------

    private const string Agents = """[{"id":"a1","name":"host-office1-host","description":"","host":"office1","last_seen_at":null}]""";

    private static StaWindowAdminScene OpenWorkerHosts(string marked, bool withGrant = true, bool modernBus = true)
    {
        var scene = new StaWindowAdminScene().Enroll(withGrant);
        try
        {
            scene.Bus.AgentsJson = Agents;
            scene.Bus.On("GET /api/mobile/admin/agents", _ => StaWindowAdminBus.Ok("[]"));
            scene.Bus.On("GET /api/mobile/admin/devices", _ => StaWindowAdminBus.Ok("[]"));
            scene.Bus.On("GET /api/mobile/admin/service-principals", _ => StaWindowAdminBus.Ok("[]"));
            if (modernBus) scene.Bus.On(DeviceRoute, _ => StaWindowAdminBus.Ok($$"""{"now":"2026-11-27T04:00:20Z","hosts":[{{marked}}]}"""));
            scene.Bus.On(MarkRoute, _ => StaWindowAdminBus.Ok("""{"applied":true,"detail":"Agent is now a worker host.","target_label":"host-office1-host","state":"a worker host","secret":null}"""));
            scene.Open();
            scene.Window.AdminNav.IsChecked = true;
            scene.Window.AdminTabHosts.IsChecked = true;
            StaWindowAdminScene.Until(() => scene.Window.AdminHostsSummary.Text.Length > 0, "the worker hosts");
            return scene;
        }
        catch
        {
            scene.Dispose();
            throw;
        }
    }

    private const string MarkedHost = """{"agent_id":"a1","agent":"host-office1-host","marked_at":"x","received_at":null,"snapshot":null}""";

    private static HostRow Row(MainWindow window) => Assert.Single((IEnumerable<HostRow>)window.AdminHostList.ItemsSource);

    private static void PressMark(MainWindow window)
    {
        var button = new Button { Tag = Row(window) };
        window.HostMark_Click(button, new RoutedEventArgs());
        StaWindowAdminScene.WaitFor(button);
    }

    [Fact]
    public void MarkingAHostIsReviewedConfirmedWithHelloAndThenSent() => sta.Run(() =>
    {
        using var scene = OpenWorkerHosts(marked: string.Empty);
        var window = scene.Window;
        Assert.Equal((true, "Mark as host"), (Row(window).CanMark, Row(window).MarkLabel));

        PressMark(window);

        Assert.Equal(string.Empty, scene.Notice);
        Assert.Equal((HostsPageLogic.MarkReview("host-office1-host", mark: true), "Review operator action"), scene.Platform.Confirmations.Single());
        Assert.Equal(["Mark host-office1-host as a worker host"], scene.Platform.HelloPrompts);
        var sent = Body(scene.Bus.RequestsTo(MarkRoute).Single());
        Assert.Equal(
            ("mark", "host-office1-host", "marked as a worker host from the Windows app", "grant-secret"),
            (sent.GetProperty("action").GetString(), sent.GetProperty("expected_name").GetString(), sent.GetProperty("reason").GetString(), sent.GetProperty("grant_secret").GetString()));
        Assert.Equal("host-office1-host: Agent is now a worker host.", window.AdminResult.Text);
        Assert.Equal(2, scene.Bus.RequestsTo(DeviceRoute).Count);
    });

    [Fact]
    public void AMarkedHostIsOfferedTheWayBack() => sta.Run(() =>
    {
        using var scene = OpenWorkerHosts(marked: MarkedHost);
        var window = scene.Window;
        Assert.Equal("No longer a host", Row(window).MarkLabel);

        PressMark(window);

        Assert.Equal("unmark", Body(scene.Bus.RequestsTo(MarkRoute).Single()).GetProperty("action").GetString());
        Assert.Equal(["Unmark host-office1-host as a worker host"], scene.Platform.HelloPrompts);
    });

    [Fact]
    public void NothingIsSentWithoutTheGrantTheReviewOrWindowsHello() => sta.Run(() =>
    {
        using (var scene = OpenWorkerHosts(marked: string.Empty, withGrant: false))
        {
            PressMark(scene.Window);
            Assert.Equal(AdminFlow.GrantNeeded, scene.Notice);
            Assert.Empty(scene.Platform.Confirmations);
            Assert.Empty(scene.Bus.RequestsTo(MarkRoute));
        }
        using (var scene = OpenWorkerHosts(marked: string.Empty))
        {
            scene.Platform.ConfirmAnswer = false;
            PressMark(scene.Window);
            Assert.Empty(scene.Platform.HelloPrompts);
            Assert.Empty(scene.Bus.RequestsTo(MarkRoute));
        }
        using (var scene = OpenWorkerHosts(marked: string.Empty))
        {
            scene.Platform.HelloAnswer = false;
            PressMark(scene.Window);
            Assert.Equal(AdminFlow.HelloNotCompleted, scene.Notice);
            Assert.Empty(scene.Bus.RequestsTo(MarkRoute));
        }
    });

    [Fact]
    public void ABusTooOldToMarkHostsOffersNoButton() => sta.Run(() =>
    {
        using var scene = OpenWorkerHosts(marked: string.Empty, modernBus: false);

        Assert.False(Row(scene.Window).CanMark);
        scene.Window.HostMark_Click(new Button { Tag = "not a row" }, new RoutedEventArgs());
        Assert.Empty(scene.Platform.Confirmations);
    });

    // ---- The whole bus log -------------------------------------------------------------------

    private const string OrdinaryLog = """{"version":"0.2.74","started_at":null,"entries":[{"ts":"2030-01-01T00:01:00Z","source":"update","level":"info","event":"update-applied","subject":"0.2.74","detail":"version=0.2.74"}]}""";
    private const string WholeLog = """{"version":"0.2.74","started_at":null,"entries":[{"ts":"2030-01-01T00:02:00Z","source":"host","level":"error","event":"fatal","subject":"host-box1-host","detail":"error=KeyError"},{"ts":"2030-01-01T00:01:00Z","source":"update","level":"info","event":"update-applied","subject":"0.2.74","detail":"version=0.2.74"}]}""";

    private static List<string> LogEvents(bool withGrant, Func<BusRequest, BusReply>? whole, out StaWindowAdminScene opened)
    {
        var scene = new StaWindowAdminScene().Enroll(withGrant);
        opened = scene;
        scene.Bus.On("GET /api/mobile/admin/logs", _ => StaWindowAdminBus.Ok(OrdinaryLog));
        if (whole is not null) scene.Bus.On(FullLogRoute, whole);
        scene.Open();
        scene.Window.SettingsNav.IsChecked = true;
        scene.Window.SettingsTabLogs.IsChecked = true;
        StaWindowAdminScene.Until(() => scene.Window.BusLogStatus.Text.Length > 0, "the bus log");
        return ((IEnumerable<BusLogEntry>)scene.Window.BusLogList.ItemsSource).Select(entry => entry.Event).ToList();
    }

    [Fact]
    public void WithOperatorAccessTheLogsTabShowsTheWholeLog() => sta.Run(() =>
    {
        var events = LogEvents(withGrant: true, _ => StaWindowAdminBus.Ok(WholeLog), out var scene);
        using (scene)
        {
            Assert.Equal(["fatal", "update-applied"], events);
            var sent = Body(scene.Bus.RequestsTo(FullLogRoute).Last());
            Assert.Equal(("grant-secret", 500), (sent.GetProperty("grant_secret").GetString(), sent.GetProperty("limit").GetInt32()));
        }
    });

    [Theory]
    [InlineData(404)]
    [InlineData(401)]
    public void ABusWithoutTheWholeLogOrAccessItNoLongerAcceptsFallsBackToTheOrdinaryOne(int status) => sta.Run(() =>
    {
        var events = LogEvents(withGrant: true, _ => StaWindowAdminBus.Fail(status, "no"), out var scene);
        using (scene)
        {
            Assert.Equal(["update-applied"], events);
            Assert.DoesNotContain("Could not load", scene.Window.BusLogStatus.Text);
        }
    });

    [Fact]
    public void WithoutOperatorAccessOnlyTheOrdinaryLogIsAskedFor() => sta.Run(() =>
    {
        var events = LogEvents(withGrant: false, _ => StaWindowAdminBus.Ok(WholeLog), out var scene);
        using (scene)
        {
            Assert.Equal(["update-applied"], events);
            Assert.Empty(scene.Bus.RequestsTo(FullLogRoute));
        }
    });

    [Fact]
    public void TheBusLogReloadsEveryHalfMinuteWhileItsTabIsShowingAndStopsWhenItIsNot() => sta.Run(() =>
    {
        LogEvents(withGrant: false, whole: null, out var scene);
        using (scene)
        {
            var window = scene.Window;
            const string route = "GET /api/mobile/admin/logs";
            StaWindowAdminScene.Until(() => scene.Platform.Delays.Count == 1, "the first wait");
            Assert.Equal([SettingsLogic.BusLogRefreshEvery], scene.Platform.Delays);
            var asked = scene.Bus.RequestsTo(route).Count;

            scene.Platform.EndDelay(0);
            StaWindowAdminScene.Until(() => scene.Bus.RequestsTo(route).Count == asked + 1, "the reload");
            StaWindowAdminScene.Until(() => scene.Platform.Delays.Count == 2, "the next wait");

            // Showing the tab again while a wait is running does not start a second one.
            window.SettingsTabGeneral.IsChecked = true;
            window.SettingsTabLogs.IsChecked = true;
            StaWindowAdminScene.Until(() => scene.Bus.RequestsTo(route).Count == asked + 2, "the load on showing the tab");
            Assert.Equal(2, scene.Platform.Delays.Count);

            // Away from the tab, the wait ends and nothing more is asked.
            window.SettingsTabGeneral.IsChecked = true;
            scene.Platform.EndDelay(1);
            var turns = 0;
            StaWindowAdminScene.Until(() => ++turns > 25, "the ended wait to be noticed");
            Assert.Equal(asked + 2, scene.Bus.RequestsTo(route).Count);
            Assert.Equal(2, scene.Platform.Delays.Count);
        }
    });

    [Fact]
    public void AnyOtherFailureOfTheWholeLogIsSaid() => sta.Run(() =>
    {
        LogEvents(withGrant: true, _ => StaWindowAdminBus.Fail(503, "unavailable"), out var scene);
        using (scene) Assert.StartsWith("Could not load the bus log:", scene.Window.BusLogStatus.Text);
    });
}
