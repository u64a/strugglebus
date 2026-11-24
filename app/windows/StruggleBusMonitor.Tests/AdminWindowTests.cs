using System.IO;
using System.Text;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;

namespace StruggleBusMonitor.Tests;

/// <summary>The Admin page of the real window, against a loopback bus and a fake Windows.</summary>
[Collection(StaWindowAdminCollection.Name)]
public class AdminWindowTests(StaWindowAdminFixture sta)
{
    private const string AgentsJson = """
        [{"id":"a1","name":"prox-manager","description":"Looks after the host","host":"pve1","state":"enabled",
          "credential_epoch":3,"last_seen_at":null,
          "actions":[{"action":"block","effect":"Block this agent."},{"action":"retire","effect":"Retire this agent permanently."}]},
         {"id":"a2","name":"old-runner","description":"","host":"","state":"retired","credential_epoch":9,"last_seen_at":null,"actions":[]}]
        """;

    private const string DevicesJson = """
        [{"id":"device-1","label":"test-pc","status":"enabled","last_seen_at":null,"has_write_grant":true,"this_device":true,
          "actions":[{"action":"revoke-device","effect":"Permanently revoke this device."}]},
         {"id":"d2","label":"old-phone","status":"enabled","last_seen_at":null,"has_write_grant":false,"this_device":false,
          "actions":[{"action":"revoke-device","effect":"Permanently revoke this device."}]}]
        """;

    private const string PrincipalsJson = """
        [{"id":"s1","name":"nightly-audit","agent_name_prefix":"audit-worker","status":"enabled","version":4,
          "actions":[{"action":"block","effect":"Block."},{"action":"rotate","effect":"Issue a new secret."}]}]
        """;

    private const string HelloNotCompleted = "Windows Hello verification was not completed.";

    private static void ServeManagementLists(StaWindowAdminBus bus)
    {
        bus.On("GET /api/mobile/admin/agents", _ => StaWindowAdminBus.Ok(AgentsJson));
        bus.On("GET /api/mobile/admin/devices", _ => StaWindowAdminBus.Ok(DevicesJson));
        bus.On("GET /api/mobile/admin/service-principals", _ => StaWindowAdminBus.Ok(PrincipalsJson));
    }

    /// <summary>An enrolled window with the Admin page open and its lists loaded.</summary>
    private static StaWindowAdminScene OpenAdmin(bool withGrant = true, bool modernBus = true, Action<StaWindowAdminBus>? arrange = null)
    {
        var scene = new StaWindowAdminScene().Enroll(withGrant);
        try
        {
            if (modernBus) ServeManagementLists(scene.Bus);
            arrange?.Invoke(scene.Bus);
            scene.Open();
            scene.Window.AdminNav.IsChecked = true;
            StaWindowAdminScene.Until(() => scene.Window.AdminDevicesSummary.Text.Length > 0, "the Admin lists");
            return scene;
        }
        catch
        {
            scene.Dispose();
            throw;
        }
    }

    private static List<AdminRow> Rows(ItemsControl list) => ((IEnumerable<AdminRow>)list.ItemsSource).ToList();

    private static AdminRowAction ActionOn(ItemsControl list, string name, string action) =>
        Rows(list).Single(row => row.Name == name).Actions.Single(option => option.Action == action);

    /// <summary>Presses a row's action button and waits for everything behind it to finish.</summary>
    private static void Press(MainWindow window, AdminRowAction action)
    {
        var button = new Button { Tag = action };
        window.AdminRowAction_Click(button, new RoutedEventArgs());
        StaWindowAdminScene.WaitFor(button);
    }

    private static void Press(Action<object, RoutedEventArgs> handler)
    {
        var button = new Button();
        handler(button, new RoutedEventArgs());
        StaWindowAdminScene.WaitFor(button);
    }

    private static JsonElement Body(BusRequest request) => JsonDocument.Parse(request.Body).RootElement;

    private static string Text(JsonElement body, string name) => body.GetProperty(name).GetString()!;

    private static void AnswerControl(StaWindowAdminBus bus, string route, string label, string? secret = null) =>
        bus.On(route, _ => StaWindowAdminBus.Ok(JsonSerializer.Serialize(
            new { applied = true, detail = "Done.", target_label = label, state = "blocked", secret })));

    private static void AnswerContainment(StaWindowAdminBus bus, string label, bool applied = true)
    {
        bus.On("POST /api/mobile/confirmations", request => StaWindowAdminBus.Ok(JsonSerializer.Serialize(new
        {
            confirmation_id = "confirm-1",
            action = Text(Body(request), "action"),
            target_id = Text(Body(request), "target_id"),
            target_label = label,
            effect = $"Contain {label}."
        })));
        bus.On("POST /api/mobile/actions", _ => StaWindowAdminBus.Ok(JsonSerializer.Serialize(
            new { applied, detail = applied ? "Contained." : "Nothing to do.", target_label = label })));
    }

    // ---- Lists and tabs ----------------------------------------------------------------------

    [Fact]
    public void TheListsShowWhatTheBusManages() => sta.Run(() =>
    {
        using var scene = OpenAdmin();
        var window = scene.Window;

        Assert.Equal(["prox-manager", "old-runner"], Rows(window.AdminAgentList).Select(row => row.Name));
        Assert.Equal("2 agents, 1 no longer active.", window.AdminAgentsSummary.Text);
        Assert.Equal(["old-phone", "test-pc"], Rows(window.AdminDeviceList).Select(row => row.Name));
        Assert.Equal("2 devices.", window.AdminDevicesSummary.Text);
        Assert.Equal(["nightly-audit"], Rows(window.AdminSpnList).Select(row => row.Name));
        Assert.Equal("1 service principal.", window.AdminSpnSummary.Text);
        Assert.Equal(Visibility.Visible, window.AdminShowRetired.Visibility);
        Assert.Equal("Operator access is saved on this PC, protected for your Windows account. Saving again replaces it.", window.GrantStatusText.Text);
        Assert.Equal("state=managed&limit=200", scene.Bus.RequestsTo("GET /api/mobile/admin/agents").Single().Query);
    });

    [Fact]
    public void TheWorkerHostsTabListsEachHostFromItsOwnLatestStatus() => sta.Run(() =>
    {
        var seen = DateTimeOffset.UtcNow.ToString("O");
        using var scene = OpenAdmin(arrange: bus =>
        {
            bus.AgentsJson = $$"""
                [{"id":"a1","name":"host-office1-host","description":"","host":"office1","last_seen_at":"{{seen}}"},
                 {"id":"a2","name":"host-lab2-host","description":"","host":"lab2","last_seen_at":null},
                 {"id":"a3","name":"prox-manager","description":"","host":"pve1","last_seen_at":"{{seen}}"}]
                """;
            bus.On("GET /api/mobile/snapshot", request => StaWindowAdminBus.Ok(request.Query.Contains("agent=host-office1-host")
                ? """
                  [{"seq":7,"channel":"worker-hosts","agent_name":"host-office1-host","body":"host=office1 busy=1/2","kind":"status","created_at":"2026-11-24T10:00:00Z","reply_to":null,
                    "metadata":{"sb_host_status":{"v":1,"host":"office1","agent":"host-office1-host","version":"1.4.0","state":"online","account":"sbworker",
                      "engines":[{"name":"claude","signed_in":true}],"workers":{"busy":1,"max":2},"warnings":["not-dedicated"]}}}]
                  """
                : "[]"));
        });
        var window = scene.Window;
        Assert.Equal(Visibility.Collapsed, window.AdminHostsPanel.Visibility);

        window.AdminTabHosts.IsChecked = true;
        StaWindowAdminScene.Until(() => window.AdminHostsSummary.Text.Length > 0, "the worker hosts");

        Assert.Equal(Visibility.Visible, window.AdminHostsPanel.Visibility);
        Assert.Equal(Visibility.Collapsed, window.AdminReasonCard.Visibility);
        var rows = ((IEnumerable<HostRow>)window.AdminHostList.ItemsSource).ToList();
        Assert.Equal(["host-lab2", "office1"], rows.Select(row => row.Name));
        Assert.Equal(["NOT RESPONDING", "ONLINE"], rows.Select(row => row.StateLabel));
        Assert.Equal("1 of 2 workers busy  ·  version 1.4.0  ·  claude signed in  ·  runs as sbworker", rows[1].Meta);
        Assert.Equal(HostsLogic.WarningText("not-dedicated"), rows[1].Alerts);
        Assert.Equal("2 hosts, 1 not responding, 1 needing attention.", window.AdminHostsSummary.Text);
        Assert.All(rows, row => Assert.False(row.HasJoined));
        Assert.Contains(scene.Bus.RequestsTo("GET /api/mobile/snapshot"), request => request.Query == "limit=20&agent=host-lab2-host");

        scene.Bus.AgentsJson = "[]";
        StaWindowAdminScene.ClickAndWait(window.AdminHostsReload);
        Assert.Equal("No worker hosts yet. A host appears here once it has joined the bus.", window.AdminHostsSummary.Text);
    });

    [Fact]
    public void AHostThatJoinedWithACodeShowsTheCodeToCompare() => sta.Run(() =>
    {
        using var scene = OpenAdmin(arrange: bus =>
        {
            bus.AgentsJson = """[{"id":"3b283d99-7521-4216-aceb-d39e6b5d5402","name":"host-office1-host","description":"","host":"office1","last_seen_at":null}]""";
            bus.On("GET /api/mobile/admin/service-principals", _ => StaWindowAdminBus.Ok(
                """[{"id":"s1","name":"host-office1","agent_name_prefix":"host-office1","status":"enabled","version":1,"actions":[],"host_redeem_request_id":"11111111-2222-4333-8444-555555555555","host_redeemed_from":"10.0.0.5","host_redeemed_at":"2026-11-24T10:00:00Z"}]"""));
        });
        var window = scene.Window;

        window.AdminTabHosts.IsChecked = true;
        StaWindowAdminScene.Until(() => window.AdminHostsSummary.Text.Length > 0, "the worker hosts");

        var row = Assert.Single((IEnumerable<HostRow>)window.AdminHostList.ItemsSource);
        Assert.Equal("Confirmation code 6be98e36, redeemed from 10.0.0.5. It must match the code the installer printed on that PC.", row.Joined);
    });

    [Fact]
    public void AnOlderBusStillListsHostsWithoutConfirmationCodes() => sta.Run(() =>
    {
        using var scene = OpenAdmin(modernBus: false, arrange: bus =>
            bus.AgentsJson = """[{"id":"a1","name":"host-office1-host","description":"","host":"office1","last_seen_at":null}]""");
        var window = scene.Window;

        window.AdminTabHosts.IsChecked = true;
        StaWindowAdminScene.Until(() => window.AdminHostsSummary.Text.Length > 0, "the worker hosts");

        var row = Assert.Single((IEnumerable<HostRow>)window.AdminHostList.ItemsSource);
        Assert.Equal(("host-office1", false), (row.Name, row.HasJoined));
    });

    [Fact]
    public void AnOlderBusOnlyOffersContainmentFromTheLiveRoster() => sta.Run(() =>
    {
        using var scene = OpenAdmin(modernBus: false, arrange: bus =>
            bus.AgentsJson = """[{"id":"a1","name":"prox-manager","description":"","host":"pve1","last_seen_at":null}]""");
        var window = scene.Window;

        Assert.Equal(AdminFlow.LegacyAgents, window.AdminAgentsSummary.Text);
        Assert.Equal(AdminFlow.LegacyLists, window.AdminDevicesSummary.Text);
        Assert.Equal(AdminFlow.LegacyLists, window.AdminSpnSummary.Text);
        Assert.Equal(Visibility.Collapsed, window.AdminShowRetired.Visibility);
        var agent = Assert.Single(Rows(window.AdminAgentList));
        Assert.Equal(("prox-manager", true, "block-agent"), (agent.Name, agent.Legacy, agent.Actions.Single().Action));
        var device = Assert.Single(Rows(window.AdminDeviceList));
        Assert.Equal((StaWindowAdminBus.DeviceLabel, true, "revoke-device"), (device.Name, device.IsThisDevice, device.Actions.Single().Action));
        Assert.Empty(Rows(window.AdminSpnList));
    });

    [Fact]
    public void TypingInTheAgentFilterNarrowsTheListAndSaysSo() => sta.Run(() =>
    {
        using var scene = OpenAdmin();
        var window = scene.Window;

        window.AdminAgentFilter.Text = "retired";

        Assert.Equal(["old-runner"], Rows(window.AdminAgentList).Select(row => row.Name));
        Assert.Equal("1 of 2 agents match.", window.AdminAgentsSummary.Text);
    });

    [Fact]
    public void ShowRetiredAsksTheBusForEveryAgent() => sta.Run(() =>
    {
        using var scene = OpenAdmin();
        var window = scene.Window;

        window.AdminShowRetired.IsChecked = true;
        StaWindowAdminScene.Until(() => scene.Bus.RequestsTo("GET /api/mobile/admin/service-principals").Count == 2, "the lists to reload");

        Assert.Equal("state=all&limit=200", scene.Bus.RequestsTo("GET /api/mobile/admin/agents")[^1].Query);
    });

    [Fact]
    public void ReloadFetchesTheListsAgain() => sta.Run(() =>
    {
        using var scene = OpenAdmin();
        scene.Bus.On("GET /api/mobile/admin/service-principals", _ => StaWindowAdminBus.Ok("[]"));

        Press(scene.Window.AdminReload_Click);

        Assert.Equal("No service principals. Create one on the Enroll tab.", scene.Window.AdminSpnSummary.Text);
        Assert.Equal(2, scene.Bus.RequestsTo("GET /api/mobile/admin/agents").Count);
    });

    [Fact]
    public void EachTabShowsItsOwnPanelAndOnlySomeShareTheAuditReason() => sta.Run(() =>
    {
        using var scene = OpenAdmin();
        var window = scene.Window;
        (RadioButton Tab, FrameworkElement Panel, bool SharesReason)[] tabs =
        [
            (window.AdminTabDevices, window.AdminDevicesPanel, true),
            (window.AdminTabSpn, window.AdminSpnPanel, true),
            (window.AdminTabEnroll, window.AdminEnrollPanel, false),
            (window.AdminTabAccess, window.AdminAccessPanel, true),
            (window.AdminTabExport, window.AdminExportPanel, false),
            (window.AdminTabAgents, window.AdminAgentsPanel, true)
        ];

        foreach (var (tab, panel, sharesReason) in tabs)
        {
            tab.IsChecked = true;

            Assert.All(tabs, other => Assert.Equal(other.Panel == panel ? Visibility.Visible : Visibility.Collapsed, other.Panel.Visibility));
            Assert.Equal(sharesReason ? Visibility.Visible : Visibility.Collapsed, window.AdminReasonCard.Visibility);
        }
        Assert.Single(scene.Bus.RequestsTo("GET /api/mobile/admin/agents"));
    });

    [Fact]
    public void ATabOpenedBeforeTheListsLoadedLoadsThem() => sta.Run(() =>
    {
        using var scene = new StaWindowAdminScene().Enroll();
        ServeManagementLists(scene.Bus);
        scene.Open();
        var window = scene.Window;

        window.AdminTabDevices.IsChecked = true;
        StaWindowAdminScene.Until(() => window.AdminDevicesSummary.Text.Length > 0, "the Admin lists");

        Assert.Equal("2 devices.", window.AdminDevicesSummary.Text);
    });

    // ---- Direct row actions ------------------------------------------------------------------

    [Fact]
    public void BlockingAnAgentIsReviewedConfirmedWithHelloAndThenSent() => sta.Run(() =>
    {
        using var scene = OpenAdmin();
        var window = scene.Window;
        AnswerControl(scene.Bus, "POST /api/mobile/admin/agents/a1/control", "prox-manager");
        window.ActionReason.Text = "  incident 12  ";

        Press(window, ActionOn(window.AdminAgentList, "prox-manager", "block"));

        Assert.Equal(string.Empty, scene.Notice);
        Assert.Equal(("TARGET\nagent prox-manager\n\nACTION\nBlock\n\nEFFECT\nBlock this agent.\n\nContinue to Windows Hello?", "Review operator action"),
            scene.Platform.Confirmations.Single());
        Assert.Equal(["Block agent prox-manager"], scene.Platform.HelloPrompts);
        var sent = Body(scene.Bus.RequestsTo("POST /api/mobile/admin/agents/a1/control").Single());
        Assert.Equal(("block", "prox-manager", 3, "incident 12", "grant-secret"),
            (Text(sent, "action"), Text(sent, "expected_name"), sent.GetProperty("expected_credential_epoch").GetInt32(), Text(sent, "reason"), Text(sent, "grant_secret")));
        Assert.Equal("prox-manager: Done.", window.AdminResult.Text);
        Assert.Equal(Visibility.Visible, window.AdminResultPanel.Visibility);
        Assert.Equal(Visibility.Collapsed, window.EnrollResultPanel.Visibility);
        Assert.Equal(2, scene.Bus.RequestsTo("GET /api/mobile/admin/agents").Count);
    });

    [Fact]
    public void RotatingAServicePrincipalShowsItsNewSecretOnce() => sta.Run(() =>
    {
        using var scene = OpenAdmin();
        var window = scene.Window;
        AnswerControl(scene.Bus, "POST /api/mobile/admin/service-principals/s1/control", "nightly-audit", secret: "new-secret-value");
        window.ActionReason.Text = "scheduled rotation";

        Press(window, ActionOn(window.AdminSpnList, "nightly-audit", "rotate"));

        Assert.Equal(["Rotate secret service principal nightly-audit"], scene.Platform.HelloPrompts);
        var sent = Body(scene.Bus.RequestsTo("POST /api/mobile/admin/service-principals/s1/control").Single());
        Assert.Equal(("rotate", "nightly-audit", 4), (Text(sent, "action"), Text(sent, "expected_name"), sent.GetProperty("expected_version").GetInt32()));
        Assert.Equal(Visibility.Visible, window.EnrollResultPanel.Visibility);
        Assert.Equal("New credential for nightly-audit", window.EnrollResultTitle.Text);
        Assert.Equal("Shown once and not saved on this PC. The previous secret no longer works.", window.EnrollResultDetail.Text);
        Assert.Equal("new-secret-value", window.EnrollResultSecret.Text);
        Assert.Equal(Visibility.Visible, window.EnrollCopyButton.Visibility);
    });

    [Fact]
    public void ADirectActionWithoutAnAuditReasonGoesNowhere() => sta.Run(() =>
    {
        using var scene = OpenAdmin();
        var window = scene.Window;

        Press(window, ActionOn(window.AdminAgentList, "prox-manager", "block"));

        Assert.Equal("Enter an audit reason before requesting an action.", scene.Notice);
        Assert.Empty(scene.Platform.Confirmations);
        Assert.Empty(scene.Platform.HelloPrompts);
        Assert.Empty(scene.Bus.RequestsTo("POST /api/mobile/admin/agents/a1/control"));
    });

    [Fact]
    public void ADirectActionWithoutOperatorAccessGoesNowhere() => sta.Run(() =>
    {
        using var scene = OpenAdmin(withGrant: false);
        var window = scene.Window;
        window.ActionReason.Text = "incident 12";

        Press(window, ActionOn(window.AdminAgentList, "prox-manager", "block"));

        Assert.Equal("Save operator access on the Access tab first.", scene.Notice);
        Assert.Empty(scene.Platform.Confirmations);
        Assert.Empty(scene.Platform.HelloPrompts);
        Assert.Empty(scene.Bus.RequestsTo("POST /api/mobile/admin/agents/a1/control"));
    });

    [Fact]
    public void DecliningTheReviewStopsBeforeWindowsHello() => sta.Run(() =>
    {
        using var scene = OpenAdmin();
        var window = scene.Window;
        window.ActionReason.Text = "incident 12";
        scene.Platform.ConfirmAnswer = false;

        Press(window, ActionOn(window.AdminAgentList, "prox-manager", "block"));

        Assert.Single(scene.Platform.Confirmations);
        Assert.Empty(scene.Platform.HelloPrompts);
        Assert.Empty(scene.Bus.RequestsTo("POST /api/mobile/admin/agents/a1/control"));
        Assert.Equal(string.Empty, scene.Notice);
        Assert.Equal(Visibility.Collapsed, window.AdminResultPanel.Visibility);
    });

    [Fact]
    public void WithoutWindowsHelloNothingIsSent() => sta.Run(() =>
    {
        using var scene = OpenAdmin();
        var window = scene.Window;
        window.ActionReason.Text = "incident 12";
        scene.Platform.HelloAnswer = false;

        Press(window, ActionOn(window.AdminAgentList, "prox-manager", "block"));

        Assert.Equal(HelloNotCompleted, scene.Notice);
        Assert.Single(scene.Platform.HelloPrompts);
        Assert.Empty(scene.Bus.RequestsTo("POST /api/mobile/admin/agents/a1/control"));
        Assert.Equal(Visibility.Collapsed, window.AdminResultPanel.Visibility);
    });

    [Fact]
    public void ATargetThatChangedFirstIsRefusedAndTheListsAreReloaded() => sta.Run(() =>
    {
        using var scene = OpenAdmin();
        var window = scene.Window;
        scene.Bus.On("POST /api/mobile/admin/agents/a1/control", _ => StaWindowAdminBus.Fail(409, "Agent changed."));
        window.ActionReason.Text = "incident 12";

        Press(window, ActionOn(window.AdminAgentList, "prox-manager", "block"));

        Assert.Equal("prox-manager changed before this ran, so nothing was done. The list has been reloaded.", scene.Notice);
        Assert.Equal(2, scene.Bus.RequestsTo("GET /api/mobile/admin/agents").Count);
        Assert.Equal(Visibility.Collapsed, window.AdminResultPanel.Visibility);
    });

    [Fact]
    public void AnyOtherRefusalIsReportedAsTheBusWordedIt() => sta.Run(() =>
    {
        using var scene = OpenAdmin();
        var window = scene.Window;
        scene.Bus.On("POST /api/mobile/admin/agents/a1/control", _ => StaWindowAdminBus.Fail(403, "Operator grant was revoked."));
        window.ActionReason.Text = "incident 12";

        Press(window, ActionOn(window.AdminAgentList, "prox-manager", "block"));

        Assert.Equal("StruggleBus said: Operator grant was revoked.", scene.Notice);
        Assert.Single(scene.Bus.RequestsTo("GET /api/mobile/admin/agents"));
    });

    [Fact]
    public void AClickThatCarriesNoRowActionDoesNothing() => sta.Run(() =>
    {
        using var scene = OpenAdmin();
        var before = scene.Bus.Requests.Count;

        scene.Window.AdminRowAction_Click(new Button { Tag = "not an action" }, new RoutedEventArgs());
        scene.Window.AdminRowAction_Click(scene.Window, new RoutedEventArgs());
        StaWindowAdminFixture.Drain();

        Assert.Equal(string.Empty, scene.Notice);
        Assert.Empty(scene.Platform.Confirmations);
        Assert.Equal(before, scene.Bus.Requests.Count);
    });

    // ---- Server-confirmed containment --------------------------------------------------------

    [Fact]
    public void RevokingAnotherDeviceUsesTheBusConfirmationThenWindowsHello() => sta.Run(() =>
    {
        using var scene = OpenAdmin();
        var window = scene.Window;
        AnswerContainment(scene.Bus, "old-phone");
        window.ActionReason.Text = " lost phone ";

        Press(window, ActionOn(window.AdminDeviceList, "old-phone", "revoke-device"));

        var asked = Body(scene.Bus.RequestsTo("POST /api/mobile/confirmations").Single());
        Assert.Equal(("revoke-device", "d2"), (Text(asked, "action"), Text(asked, "target_id")));
        Assert.Equal(("TARGET\nold-phone\n\nEFFECT\nContain old-phone.\n\nContinue to Windows Hello?", "Review containment action"),
            scene.Platform.Confirmations.Single());
        Assert.Equal(["Authorize: Contain old-phone."], scene.Platform.HelloPrompts);
        var sent = Body(scene.Bus.RequestsTo("POST /api/mobile/actions").Single());
        Assert.Equal(("confirm-1", "revoke-device", "d2", "grant-secret", "lost phone"),
            (Text(sent, "confirmation_id"), Text(sent, "action"), Text(sent, "target_id"), Text(sent, "grant_secret"), Text(sent, "reason")));
        Assert.Equal("Applied: Contained.", window.AdminResult.Text);
        Assert.Equal("LIVE", window.StatusText.Text);
        Assert.Equal(2, scene.Bus.RequestsTo("GET /api/mobile/admin/devices").Count);
    });

    [Fact]
    public void RevokingThisPcForgetsItsEnrollment() => sta.Run(() =>
    {
        using var scene = OpenAdmin();
        var window = scene.Window;
        AnswerContainment(scene.Bus, "test-pc");
        window.ActionReason.Text = "retiring this PC";

        Press(window, ActionOn(window.AdminDeviceList, "test-pc", "revoke-device"));
        StaWindowAdminScene.Until(() => window.StatusText.Text == "NOT ENROLLED", "the PC to be forgotten");

        Assert.Equal("Applied: Contained.", window.AdminResult.Text);
        Assert.False(File.Exists(AppPaths.File("session.bin")));
        Assert.False(File.Exists(AppPaths.File("operator-grant.bin")));
        Assert.Equal(Visibility.Visible, window.EnrollmentPanel.Visibility);
        Assert.False(window.AdminNav.IsEnabled);
        Assert.Single(scene.Bus.RequestsTo("GET /api/mobile/admin/devices"));
    });

    [Fact]
    public void OnAnOlderBusBlockingAnAgentIsConfirmedByTheBusAndTheRosterIsFollowed() => sta.Run(() =>
    {
        using var scene = OpenAdmin(modernBus: false, arrange: bus =>
            bus.AgentsJson = """[{"id":"a1","name":"prox-manager","description":"","host":"pve1","last_seen_at":null}]""");
        var window = scene.Window;
        AnswerContainment(scene.Bus, "prox-manager");
        window.ActionReason.Text = "runaway";
        // Once blocked, the bus no longer lists the agent.
        scene.Bus.AgentsJson = "[]";

        Press(window, ActionOn(window.AdminAgentList, "prox-manager", "block-agent"));

        var asked = Body(scene.Bus.RequestsTo("POST /api/mobile/confirmations").Single());
        Assert.Equal(("block-agent", "a1"), (Text(asked, "action"), Text(asked, "target_id")));
        Assert.Equal("Applied: Contained.", window.AdminResult.Text);
        Assert.Empty(Rows(window.AdminAgentList));
        Assert.Equal(AdminFlow.LegacyAgents, window.AdminAgentsSummary.Text);
    });

    [Fact]
    public void ContainmentNeedsAnAuditReasonBeforeTheBusIsAsked() => sta.Run(() =>
    {
        using var scene = OpenAdmin();

        Press(scene.Window.Freeze_Click);

        Assert.Equal("Enter an audit reason before requesting an action.", scene.Notice);
        Assert.Empty(scene.Bus.RequestsTo("POST /api/mobile/confirmations"));
    });

    [Fact]
    public void FreezingIsNotPerformedWhenTheReviewIsDeclinedOrHelloFails() => sta.Run(() =>
    {
        using var scene = OpenAdmin();
        var window = scene.Window;
        AnswerContainment(scene.Bus, "all agents");
        window.ActionReason.Text = "incident 12";

        scene.Platform.ConfirmAnswer = false;
        Press(window.Freeze_Click);
        Assert.Empty(scene.Platform.HelloPrompts);
        Assert.Equal(string.Empty, scene.Notice);

        scene.Platform.ConfirmAnswer = true;
        scene.Platform.HelloAnswer = false;
        Press(window.Freeze_Click);
        Assert.Equal(HelloNotCompleted, scene.Notice);

        Assert.Equal(2, scene.Bus.RequestsTo("POST /api/mobile/confirmations").Count);
        Assert.Empty(scene.Bus.RequestsTo("POST /api/mobile/actions"));
        Assert.Equal(Visibility.Collapsed, window.AdminResultPanel.Visibility);
    });

    [Fact]
    public void FreezeAndClearFreezeActOnTheWholeBus() => sta.Run(() =>
    {
        using var scene = OpenAdmin();
        var window = scene.Window;
        window.ActionReason.Text = "incident 12";

        AnswerContainment(scene.Bus, "all agents");
        Press(window.Freeze_Click);
        Assert.Equal("Applied: Contained.", window.AdminResult.Text);

        AnswerContainment(scene.Bus, "all agents", applied: false);
        Press(window.ClearFreeze_Click);
        Assert.Equal("Not applied: Nothing to do.", window.AdminResult.Text);

        var asked = scene.Bus.RequestsTo("POST /api/mobile/confirmations").Select(Body).ToList();
        Assert.Equal([("activate-freeze", "global"), ("clear-freeze", "global")], asked.Select(body => (Text(body, "action"), Text(body, "target_id"))));
        Assert.Equal(2, scene.Platform.HelloPrompts.Count);
    });

    // ---- Operator access ---------------------------------------------------------------------

    [Fact]
    public void SavingOperatorAccessExchangesThePasswordForAGrant() => sta.Run(() =>
    {
        using var scene = OpenAdmin(withGrant: false);
        var window = scene.Window;
        scene.Bus.On("POST /api/mobile/grants", _ => StaWindowAdminBus.Ok("""{"grant_secret":"issued-grant"}"""));
        Assert.StartsWith("Not set up yet.", window.GrantStatusText.Text);
        window.OperatorPassword.Password = "correct horse";
        window.GrantReason.Text = " first setup ";

        Press(window.Grant_Click);

        var sent = Body(scene.Bus.RequestsTo("POST /api/mobile/grants").Single());
        Assert.Equal(("correct horse", "first setup"), (Text(sent, "operator_password"), Text(sent, "reason")));
        Assert.Equal(string.Empty, window.OperatorPassword.Password);
        Assert.Equal("Operator access saved for your Windows account on this PC.", window.AdminResult.Text);
        Assert.StartsWith("Operator access is saved on this PC", window.GrantStatusText.Text);
        Assert.Equal("issued-grant", BusApi.GrantStore.Load(StaWindowAdminBus.DeviceId, out _));
    });

    [Theory]
    [InlineData("", "first setup")]
    [InlineData("correct horse", "  ")]
    public void OperatorAccessNeedsAPasswordAndAReason(string password, string reason) => sta.Run(() =>
    {
        using var scene = OpenAdmin(withGrant: false);
        var window = scene.Window;
        window.OperatorPassword.Password = password;
        window.GrantReason.Text = reason;

        Press(window.Grant_Click);

        Assert.Equal("Enter the operator password and an audit reason.", scene.Notice);
        Assert.Empty(scene.Bus.RequestsTo("POST /api/mobile/grants"));
    });

    // ---- Enrollment --------------------------------------------------------------------------

    [Fact]
    public void TheEnrollFormFollowsTheKindOfEnrollment() => sta.Run(() =>
    {
        using var scene = new StaWindowAdminScene().Open();
        var window = scene.Window;
        Assert.Equal(("Agent name", "Description (optional)", "Create onboarding package"),
            (window.EnrollNameLabel.Text, window.EnrollSecondLabel.Text, window.EnrollCreateButton.Content));
        Assert.Equal(window.FontFamily, window.EnrollSecond.FontFamily);

        window.EnrollKindSpn.IsChecked = true;
        Assert.Equal(("Service principal name", "Agent name prefix", "Create service principal"),
            (window.EnrollNameLabel.Text, window.EnrollSecondLabel.Text, window.EnrollCreateButton.Content));
        Assert.Equal(Visibility.Visible, window.EnrollSecondPanel.Visibility);
        Assert.Same(window.FindResource("Mono"), window.EnrollSecond.FontFamily);
        Assert.Equal(AdminFlow.Form(EnrollmentKind.ServicePrincipal).Hint, window.EnrollHint.Text);

        window.EnrollKindDevice.IsChecked = true;
        Assert.Equal(("Device label", "Create device enrollment"), (window.EnrollNameLabel.Text, window.EnrollCreateButton.Content));
        Assert.Equal(Visibility.Collapsed, window.EnrollSecondPanel.Visibility);

        window.EnrollKindAgent.IsChecked = true;
        Assert.Equal("Agent name", window.EnrollNameLabel.Text);
        Assert.Equal(Visibility.Visible, window.EnrollSecondPanel.Visibility);
    });

    [Fact]
    public void CreatingAnAgentEnrollmentShowsItsPackageOnce() => sta.Run(() =>
    {
        using var scene = OpenAdmin();
        var window = scene.Window;
        scene.Bus.On("POST /api/mobile/enrollments/agents", _ => StaWindowAdminBus.Ok(
            """{"enrollment_id":"e1","agent_name":"adlab-cli-win","expires_at":"2099-01-01T00:00:00Z","package":"PACKAGE-TEXT"}"""));
        window.EnrollName.Text = " adlab-cli-win ";
        window.EnrollSecond.Text = " Lab CLI ";
        window.EnrollReason.Text = " new agent ";

        StaWindowAdminScene.ClickAndWait(window.EnrollCreateButton);

        Assert.Equal(string.Empty, scene.Notice);
        Assert.Equal(["Create an enrollment for agent adlab-cli-win"], scene.Platform.HelloPrompts);
        var sent = Body(scene.Bus.RequestsTo("POST /api/mobile/enrollments/agents").Single());
        Assert.Equal(("adlab-cli-win", "Lab CLI", "new agent", "grant-secret"),
            (Text(sent, "name"), Text(sent, "description"), Text(sent, "reason"), Text(sent, "grant_secret")));
        Assert.Equal("Onboarding package for adlab-cli-win", window.EnrollResultTitle.Text);
        Assert.Equal("PACKAGE-TEXT", window.EnrollResultSecret.Text);
        Assert.Equal(Visibility.Visible, window.EnrollResultPanel.Visibility);
        Assert.Equal((string.Empty, string.Empty), (window.EnrollName.Text, window.EnrollSecond.Text));
    });

    [Fact]
    public void AServicePrincipalTheBusAlreadyHasComesBackWithoutASecret() => sta.Run(() =>
    {
        using var scene = OpenAdmin();
        var window = scene.Window;
        scene.Bus.On("POST /api/mobile/enrollments/service-principals", _ => StaWindowAdminBus.Ok(
            """{"name":"nightly-audit","agent_name_prefix":"audit-worker","credential_secret":null}"""));
        window.EnrollKindSpn.IsChecked = true;
        window.EnrollName.Text = "nightly-audit";
        window.EnrollSecond.Text = "audit-worker";
        window.EnrollReason.Text = "automation";

        StaWindowAdminScene.ClickAndWait(window.EnrollCreateButton);

        Assert.Equal(["Create an enrollment for service principal nightly-audit"], scene.Platform.HelloPrompts);
        var sent = Body(scene.Bus.RequestsTo("POST /api/mobile/enrollments/service-principals").Single());
        Assert.Equal(("nightly-audit", "audit-worker"), (Text(sent, "name"), Text(sent, "agent_name_prefix")));
        Assert.Equal("Service principal nightly-audit", window.EnrollResultTitle.Text);
        Assert.Equal(Visibility.Visible, window.EnrollResultPanel.Visibility);
        Assert.Equal(Visibility.Collapsed, window.EnrollResultSecret.Visibility);
        Assert.Equal(Visibility.Collapsed, window.EnrollCopyButton.Visibility);
    });

    [Fact]
    public void CreatingADeviceEnrollmentShowsThePayloadToPaste() => sta.Run(() =>
    {
        using var scene = OpenAdmin();
        var window = scene.Window;
        scene.Bus.On("POST /api/mobile/enrollments/devices", _ => StaWindowAdminBus.Ok(
            """{"device_label":"spare-laptop","expires_at":"2099-01-01T00:00:00Z","payload":"{\"version\":1}"}"""));
        window.EnrollKindDevice.IsChecked = true;
        window.EnrollName.Text = "spare-laptop";
        window.EnrollReason.Text = "second PC";

        StaWindowAdminScene.ClickAndWait(window.EnrollCreateButton);

        Assert.Equal(["Create an enrollment for device spare-laptop"], scene.Platform.HelloPrompts);
        Assert.Equal("spare-laptop", Text(Body(scene.Bus.RequestsTo("POST /api/mobile/enrollments/devices").Single()), "label"));
        Assert.Equal("Enrollment for spare-laptop", window.EnrollResultTitle.Text);
        Assert.Equal("{\"version\":1}", window.EnrollResultSecret.Text);
    });

    [Fact]
    public void AnIncompleteEnrollmentFormIsRefusedBeforeWindowsHello() => sta.Run(() =>
    {
        using var scene = OpenAdmin();
        var window = scene.Window;
        window.EnrollReason.Text = "new agent";

        StaWindowAdminScene.ClickAndWait(window.EnrollCreateButton);

        Assert.Equal("Enter the agent name.", scene.Notice);
        Assert.Empty(scene.Platform.HelloPrompts);
        Assert.Equal(Visibility.Collapsed, window.EnrollResultPanel.Visibility);
    });

    [Fact]
    public void ABadNameIsExplainedWhileTypingAndRefusedBeforeWindowsHello() => sta.Run(() =>
    {
        using var scene = OpenAdmin();
        var window = scene.Window;
        Assert.Equal(Visibility.Collapsed, window.EnrollNameFeedback.Visibility);

        window.EnrollName.Text = "buildagent";
        window.EnrollReason.Text = "new agent";

        const string problem = "Agent names need at least one hyphen, joining a project and a platform, for example adlab-cli-win.";
        Assert.Equal(Visibility.Visible, window.EnrollNameFeedback.Visibility);
        Assert.Equal(problem, window.EnrollNameFeedback.Text);

        StaWindowAdminScene.ClickAndWait(window.EnrollCreateButton);

        Assert.Equal(problem, scene.Notice);
        Assert.Empty(scene.Platform.HelloPrompts);
        Assert.Equal(Visibility.Collapsed, window.EnrollResultPanel.Visibility);

        window.EnrollName.Text = "build-agent";
        Assert.Equal(Visibility.Collapsed, window.EnrollNameFeedback.Visibility);
        window.EnrollName.Text = "Build Agent";
        Assert.Equal("Will be created as build-agent", window.EnrollNameFeedback.Text);

        window.EnrollKindSpn.IsChecked = true;
        window.EnrollSecond.Text = "audit worker";
        Assert.Equal("Agent name prefixes can only use lowercase letters, digits and hyphens. Remove: space", window.EnrollSecondFeedback.Text);
        window.EnrollKindDevice.IsChecked = true;
        Assert.Equal(Visibility.Collapsed, window.EnrollSecondFeedback.Visibility);
    });

    [Fact]
    public void AnEnrollmentIsNotCreatedWithoutWindowsHello() => sta.Run(() =>
    {
        using var scene = OpenAdmin();
        var window = scene.Window;
        scene.Platform.HelloAnswer = false;
        window.EnrollName.Text = "adlab-cli-win";
        window.EnrollReason.Text = "new agent";

        StaWindowAdminScene.ClickAndWait(window.EnrollCreateButton);

        Assert.Equal(HelloNotCompleted, scene.Notice);
        Assert.Empty(scene.Bus.RequestsTo("POST /api/mobile/enrollments/agents"));
        Assert.Equal("adlab-cli-win", window.EnrollName.Text);
    });

    [Fact]
    public void TheOneTimeSecretCanBeCopiedAndIsGoneOnceCleared() => sta.Run(() =>
    {
        using var scene = OpenAdmin();
        var window = scene.Window;
        AnswerControl(scene.Bus, "POST /api/mobile/admin/service-principals/s1/control", "nightly-audit", secret: "new-secret-value");
        window.ActionReason.Text = "scheduled rotation";
        Press(window, ActionOn(window.AdminSpnList, "nightly-audit", "rotate"));

        window.EnrollCopy_Click(window, new RoutedEventArgs());
        Assert.Equal(["new-secret-value"], scene.Platform.Clipboard);

        window.EnrollClear_Click(window, new RoutedEventArgs());
        Assert.Equal(string.Empty, window.EnrollResultSecret.Text);
        Assert.Equal(Visibility.Collapsed, window.EnrollResultPanel.Visibility);

        window.EnrollCopy_Click(window, new RoutedEventArgs());
        Assert.Single(scene.Platform.Clipboard);
    });

    // ---- Export ------------------------------------------------------------------------------

    private static readonly DateTimeOffset Recent = DateTimeOffset.Now.AddHours(-1);

    private static void RetainTwoMessages(StaWindowAdminBus bus) => bus.MessagesJson =
        $"[{StaWindowAdminBus.MessageJson(8, "general", "prox-manager", "second", Recent)},{StaWindowAdminBus.MessageJson(7, "general", "prox-manager", "=first", Recent.AddMinutes(-5))}]";

    [Fact]
    public void TheExportDatesStartAsTheLastDayAndCanBeClearedOrReset() => sta.Run(() =>
    {
        using var scene = new StaWindowAdminScene().Open();
        var window = scene.Window;
        var from = FeedLogic.ParseLocalBoundary(window.ExportFrom.Text, isUpperBound: false)!.Value;
        var to = FeedLogic.ParseLocalBoundary(window.ExportTo.Text, isUpperBound: true)!.Value;
        Assert.Equal(TimeSpan.FromDays(1) + TimeSpan.FromMinutes(1), to - from);
        Assert.InRange(DateTimeOffset.Now - from, TimeSpan.FromDays(1), TimeSpan.FromDays(1) + TimeSpan.FromMinutes(2));

        window.ClearExportFilter_Click(window, new RoutedEventArgs());
        Assert.Equal((string.Empty, string.Empty), (window.ExportFrom.Text, window.ExportTo.Text));

        window.ExportLastDay_Click(window, new RoutedEventArgs());
        Assert.Matches(@"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}$", window.ExportFrom.Text);
        Assert.Matches(@"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}$", window.ExportTo.Text);
    });

    [Fact]
    public void ExportingWritesTheRetainedMessagesAsCsvWhereTheOperatorChose() => sta.Run(() =>
    {
        using var scene = OpenAdmin(arrange: RetainTwoMessages);
        var window = scene.Window;
        var path = Path.Combine(AppPaths.DataDirectory, "export-test.csv");
        scene.Platform.ExportPath = path;

        Press(window.ExportCsv_Click);

        Assert.Equal(string.Empty, scene.Notice);
        Assert.Matches(@"^strugglebus-messages-\d{8}-\d{6}\.csv$", scene.Platform.SuggestedExportNames.Single());
        var bytes = File.ReadAllBytes(path);
        Assert.Equal(Encoding.UTF8.GetPreamble(), bytes[..3]);
        var lines = Encoding.UTF8.GetString(bytes[3..]).Split(Environment.NewLine);
        Assert.Equal(4, lines.Length);
        Assert.StartsWith("sequence,created_at_utc,", lines[0]);
        Assert.StartsWith("7,", lines[1]);
        Assert.Contains(",'=first,", lines[1]);
        Assert.EndsWith(",true", lines[1]);
        Assert.StartsWith("8,", lines[2]);
        Assert.Equal("Saved export-test.csv with 2 messages.", window.AdminResult.Text);
    });

    [Fact]
    public void CancellingTheSaveDialogExportsNothing() => sta.Run(() =>
    {
        using var scene = OpenAdmin(arrange: RetainTwoMessages);
        var window = scene.Window;

        Press(window.ExportCsv_Click);

        Assert.Single(scene.Platform.SuggestedExportNames);
        Assert.Equal(Visibility.Collapsed, window.AdminResultPanel.Visibility);
        Assert.Equal(string.Empty, scene.Notice);
    });

    [Fact]
    public void AnExportWithNothingInRangeOrBackwardsDatesIsRefused() => sta.Run(() =>
    {
        using var scene = OpenAdmin(arrange: RetainTwoMessages);
        var window = scene.Window;

        window.ExportFrom.Text = "2020-01-01";
        window.ExportTo.Text = "2020-01-02";
        Press(window.ExportCsv_Click);
        Assert.Equal("No retained messages fall inside those dates.", scene.Notice);

        window.ExportFrom.Text = "2020-01-03";
        Press(window.ExportCsv_Click);
        Assert.Equal("The export start must be earlier than the end.", scene.Notice);

        Assert.Empty(scene.Platform.SuggestedExportNames);
    });
}
